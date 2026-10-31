"""Fixed bounded executable and startup observations for the gated direct pair.

No namespace control, kernel attribution, retry, policy operation or mutation is
implemented here. Existing exact RootlessKit message classifiers are reused.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import select
import stat
from typing import TYPE_CHECKING

from scripts import docker_direct_startup_contract as contract

if TYPE_CHECKING:
    from types import ModuleType

    from scripts.docker_direct_startup_active import ControlPort
    from scripts.docker_userns_active import RootPort

ROOTLESSKIT_MAX_BYTES = 32 * 1024 * 1024
LAUNCHER_MAX_BYTES = 4096
ENGINE_VERSION_MAX_BYTES = 64
HASH_BLOCK_BYTES = 1024 * 1024
STARTUP_SECONDS = 45
VERSION_PATTERN = rb"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}"
API_FIELDS = 2
SECURITY_OPTION_MAX_BYTES = 128

ELF_MACHINES = {"amd64": 62, "arm64": 183}
EXPECTED_LOG_CLASS = "child-fork-exec-operation-not-permitted-message"


def _image_file(
    port: ControlPort | RootPort,
    api: ModuleType,
    directory: int,
    components: tuple[str, ...],
    limit: int,
) -> tuple[bytes, str]:
    root = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=directory)
    descriptor = None
    try:
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            os.close(root)
            root = child
            info = os.fstat(root)
            api.require(info.st_uid == 0 and not info.st_mode & 0o7022)
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        before = os.fstat(descriptor)
        api.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1)
        api.require(0 < before.st_size <= limit and not before.st_mode & 0o7022)
        try:
            os.getxattr(descriptor, "security.capability")
        except OSError as error:
            api.require(error.errno == errno.ENODATA)
        else:
            api.require(value=False)
        hasher = hashlib.sha256()
        head = b""
        total = 0
        while chunk := os.read(descriptor, HASH_BLOCK_BYTES):
            total += len(chunk)
            api.require(total <= limit)
            head = (head + chunk[:ENGINE_VERSION_MAX_BYTES])[:ENGINE_VERSION_MAX_BYTES]
            hasher.update(chunk)
            api.check(port.work_until)
        named = os.stat(components[-1], dir_fd=root, follow_symlinks=False)
        api.require(total == before.st_size and api.mark(before) == api.mark(os.fstat(descriptor)) == api.mark(named))
        return head, hasher.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root)


def preflight(port: ControlPort | RootPort, api: ModuleType, container: str) -> None:
    """Bind actual installed tools once without copying canonical payload pins."""
    from scripts import docker_direct_startup_active as control  # noqa: PLC0415 - same closed staged source set.

    api.require(
        not port.record.get("directPreflightIntent") and port.record.get("subject", {}).get("container") == container
    )
    api.require(not port.record["directGate"]["releaseIntent"])
    before = control.inspect_gate(port, api, container)
    subject = port.record["subject"]
    pid = subject["pid"]
    api.require(before["State"]["Pid"] == pid and before["State"]["Running"] is True)
    port.work_until = min(port.work_until, api.time.monotonic_ns() + contract.FAILURE_SECONDS * 1_000_000_000)
    port.record["directPreflightIntent"] = True
    port.commit()
    directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pidfd = os.pidfd_open(pid)
    try:
        task, actor = control.actor_snapshot(port, api, directory, pid)
        api.require(task["startTicks"] == subject["startTicks"] and task["cgroup"] == subject["cgroup"])
        launcher, launcher_hash = _image_file(
            port, api, directory, ("usr", "local", "bin", "start-dockerd"), LAUNCHER_MAX_BYTES
        )
        binary, binary_hash = _image_file(
            port, api, directory, ("usr", "local", "bin", "rootlesskit"), ROOTLESSKIT_MAX_BYTES
        )
        engine, _engine_hash = _image_file(
            port,
            api,
            directory,
            ("usr", "share", "strukturpiloten", "docker", "engine-version"),
            ENGINE_VERSION_MAX_BYTES,
        )
        api.require(launcher.startswith(b"#!/bin/sh\n"))
        api.require(
            binary[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(binary[18:20], "little") == ELF_MACHINES[port.binding.architecture]
        )
        api.require(re.fullmatch(VERSION_PATTERN, engine.strip()) is not None)
        version = port.docker("exec", container, "/usr/local/bin/rootlesskit", "--version")
        api.require(len(version) <= contract.GUEST_BYTES)
        match = re.fullmatch(b"rootlesskit version (" + VERSION_PATTERN + b")\n?", version)
        api.require(match is not None)
        api.require(
            control.actor_snapshot(port, api, directory, pid) == (task, actor)
            and not select.select([pidfd], [], [], 0)[0]
        )
        after = control.inspect_gate(port, api, container)
        api.require(
            after["State"]["Pid"] == pid
            and after["State"]["StartedAt"] == subject["startedAt"]
            and after["State"]["Running"] is True
        )
        port.record["directExecutables"] = {
            "launcherSha256": launcher_hash,
            "rootlesskitSha256": binary_hash,
            "rootlesskitVersion": match[1].decode("ascii"),
            "engineVersion": engine.strip().decode("ascii"),
        }
        port.record["directActor"] = actor
        port.commit()
    finally:
        os.close(pidfd)
        os.close(directory)


def _negative(port: ControlPort | RootPort, api: ModuleType, container: str, code: int) -> dict:
    result = {"kind": "other-failure", "nativeExitCode": code, "engineVersion": None}
    # Retain the original native result before any optional text observation.
    port.record["directStartup"] = result
    port.commit()
    port.work_until = min(port.work_until, api.time.monotonic_ns() + contract.FAILURE_SECONDS * 1_000_000_000)
    try:
        raw = port.docker_logs(container)
        failure = "logs-byte-limit" if len(raw) > contract.JOURNAL_BYTES else None
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeError:
            lines = []
            failure = "logs-invalid-encoding"
        if len(lines) > contract.JOURNAL_RECORDS:
            failure = "logs-record-limit"
        elif any(len(line.encode("utf-8")) > contract.RECORD_BYTES for line in lines):
            failure = "logs-record-byte-limit"
    except Exception:  # noqa: BLE001 - preserve authenticated native status and closed unavailable classification.
        failure = "logs-unavailable"
        lines = []
        raw = b""
    if failure is not None:
        result.update(kind="unknown", diagnosticFailure=failure)
        if port.record.get("readerPending"):
            port.record["retained"] = True
        port.commit()
        return result
    patterns = port.modules.capture.STARTUP_LOG_PATTERNS
    fatal = [line for line in lines if line.startswith("[rootlesskit:parent] error:")]
    classes = [
        next((name for name, pattern in patterns if re.search(pattern, line) is not None), None) for line in fatal
    ]
    if code > 0 and classes and set(classes) == {EXPECTED_LOG_CLASS}:
        result["kind"] = contract.EXPECTED_A
    result["logRecords"] = len(lines)
    result["unclassifiedRecords"] = len(lines) - len(fatal) + classes.count(None)
    result["logSha256"] = api.digest(raw)
    return result


def _readiness(port: ControlPort | RootPort, api: ModuleType, container: str) -> str:
    inner = (
        'if docker info --format "{{json .ServerVersion}}|{{json .SecurityOptions}}" 2>/dev/null; '
        "then :; else printf API_PENDING; fi"
    )
    outer = 'if "$@"; then :; else printf API_EXEC_UNAVAILABLE; fi'
    raw = port.query(
        [
            "/bin/sh",
            "-ec",
            outer,
            "direct-owned-readiness",
            *port.docker_arguments("exec", container, "/bin/sh", "-ec", inner),
        ]
    )
    api.require(len(raw) <= contract.GUEST_BYTES)
    text = raw.decode("ascii").strip()
    if text in {"API_PENDING", "API_EXEC_UNAVAILABLE"}:
        return text
    fields = text.split("|")
    api.require(len(fields) == API_FIELDS)
    version, security = (json.loads(value, object_pairs_hook=api.unique) for value in fields)
    api.require(type(version) is str and re.fullmatch(VERSION_PATTERN.decode("ascii"), version) is not None)
    api.require(
        type(security) is list
        and all(type(value) is str and len(value) <= SECURITY_OPTION_MAX_BYTES for value in security)
    )
    api.require("name=rootless" in security and version == port.record["directExecutables"]["engineVersion"])
    return version


def _post_exec(port: ControlPort | RootPort, api: ModuleType) -> None:
    from scripts import docker_direct_startup_active as control  # noqa: PLC0415 - same closed source.

    subject = port.record["subject"]
    directory = os.open(f"/proc/{subject['pid']}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pidfd = os.pidfd_open(subject["pid"])
    try:
        task, actor = control.actor_snapshot(port, api, directory, subject["pid"])
        api.require(task["startTicks"] == subject["startTicks"] and task["cgroup"] == subject["cgroup"])
        api.require(not select.select([pidfd], [], [], 0)[0])
        api.require(control.actor_snapshot(port, api, directory, subject["pid"]) == (task, actor))
        port.record["directPostExec"] = actor
    finally:
        os.close(pidfd)
        os.close(directory)


def observe(port: ControlPort | RootPort, api: ModuleType, container: str) -> None:
    """Preserve stopped native status before API or cgroup consequence errors."""
    from scripts import docker_direct_startup_active as control  # noqa: PLC0415 - same closed staged source set.

    api.require(port.record["directGate"]["released"] is True and "directExecutables" in port.record)
    api.require(not port.record.get("directObservationTerminal"))
    original_until = port.work_until
    value = control.inspect_gate(port, api, container)
    state = value["State"]
    subject = port.record["subject"]
    api.require(state["StartedAt"] == subject["startedAt"] and type(state["Running"]) is bool)
    if state["Running"] is False:
        code = state["ExitCode"]
        api.require(type(code) is int and 0 <= code <= contract.MAX_NATIVE_EXIT)
        result = _negative(port, api, container, code)
    else:
        api.require(state["Pid"] == subject["pid"])
        startup_end = port.record["directReleaseNs"] + STARTUP_SECONDS * 1_000_000_000
        if api.time.monotonic_ns() >= startup_end:
            result = {"kind": "other-failure", "nativeExitCode": None, "engineVersion": None}
        else:
            port.work_until = min(port.work_until, startup_end)
            version = _readiness(port, api, container)
            after = control.inspect_gate(port, api, container)["State"]
            api.require(after["StartedAt"] == subject["startedAt"] and type(after["Running"]) is bool)
            if after["Running"] is False:
                api.require(type(after["ExitCode"]) is int and 0 <= after["ExitCode"] <= contract.MAX_NATIVE_EXIT)
                port.work_until = original_until
                result = _negative(port, api, container, after["ExitCode"])
            else:
                api.require(after["Pid"] == subject["pid"])
                result = {
                    "kind": "pending" if version in {"API_PENDING", "API_EXEC_UNAVAILABLE"} else "ready",
                    "nativeExitCode": None,
                    "engineVersion": None if version in {"API_PENDING", "API_EXEC_UNAVAILABLE"} else version,
                }
    if result["kind"] == "ready":
        _post_exec(port, api)
    port.record["directObservationTerminal"] = result["kind"] != "pending"
    port.record["directStartup"] = result
    port.commit()
