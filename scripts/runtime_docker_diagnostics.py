"""Non-acceptance, private-read diagnostics for an early rootless Docker failure.

Raw inspect/journal/guest data never enters RuntimeContext.command or its public
log recorder. Only closed fields and task-window record counts leave this module.
"""

# Closed read-only argv and access to the invocation's held ownership are intentional.
# ruff: noqa: EM101, PLR2004, S603

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.runtime_docker_backend import DockerBackend
    from scripts.runtime_tests import RuntimeContext

DIAGNOSTIC_SECONDS = 5
BYTE_LIMIT = 64 * 1024
JOURNAL_RECORD_LIMIT = 64
PROTOCOL_LIMIT = 96 * 1024
GUEST_BYTE_LIMIT = 2048
GUEST_RECORD_LIMIT = 1024
GUEST_LOG_RECORD_LIMIT = 8
DIAGNOSTIC_RECORD_LIMIT = 4096
GUARD_SOURCE_LIMIT = 4096
SERVICE_FIELDS = frozenset(
    {"LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus", "MainPID"}
)
SERVICE_STATES = {
    "LoadState": frozenset({"loaded", "not-found", "error", "bad-setting", "masked", "merged", "stub"}),
    "ActiveState": frozenset(
        {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
    ),
    "SubState": frozenset(
        {
            "dead",
            "running",
            "exited",
            "failed",
            "auto-restart",
            "auto-restart-queued",
            "start-pre",
            "start",
            "start-post",
            "stop",
            "stop-sigterm",
            "stop-sigkill",
            "stop-post",
            "final-sigterm",
            "final-sigkill",
            "reload",
            "reload-signal",
            "reload-notify",
            "condition",
            "cleaning",
        }
    ),
    "Result": frozenset(
        {
            "success",
            "resources",
            "protocol",
            "timeout",
            "exit-code",
            "signal",
            "core-dump",
            "watchdog",
            "start-limit-hit",
            "oom-kill",
            "exec-condition",
            "assert",
            "dependency",
            "skip",
        }
    ),
}
SECURITY_OPTIONS = {
    "apparmor=unconfined": "apparmor-unconfined",
    "seccomp=unconfined": "seccomp-unconfined",
    "label=disable": "selinux-label-disabled",
    "no-new-privileges": "no-new-privileges",
    "no-new-privileges=true": "no-new-privileges",
}
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"owner":{{json (index .Config.Labels "io.strukturpiloten.runtime")}},'
    '"cgroup":{{json .HostConfig.CgroupParent}},"privileged":{{json .HostConfig.Privileged}},'
    '"apparmor":{{json .AppArmorProfile}},"securityOptions":{{json .HostConfig.SecurityOpt}},'
    '"state":{{json .State.Status}},"exitCode":{{json .State.ExitCode}},'
    '"oomKilled":{{json .State.OOMKilled}},"pid":{{json .State.Pid}}}'
)
PRIVATE_DAEMON_FORMAT = '{"root":{{json .DockerRootDir}},"securityOptions":{{json .SecurityOptions}}}'
# Reviewed literal provenance is in docs/runtime-backends.md; these labels describe messages, never causal actors.
STARTUP_LOG_PATTERNS = (
    ("uidmap-helper-message", r"^\[rootlesskit:parent\] error: failed to setup UID/GID map: newuidmap .* failed:"),
    ("gidmap-helper-message", r"^\[rootlesskit:parent\] error: failed to setup UID/GID map: newgidmap .* failed:"),
    (
        "subid-range-message",
        (
            r"^\[rootlesskit:parent\] error: failed to setup UID/GID map: "
            r"failed to compute uid/gid map: [Nn]o sub[ug]id ranges found for user "
        ),
    ),
    ("uidgid-map-message", r"^\[rootlesskit:parent\] error: failed to setup UID/GID map: "),
    ("child-start-message", r"^\[rootlesskit:parent\] error: failed to start the child: "),
    ("rootless-network-message", r"^\[rootlesskit:parent\] error: failed to setup network "),
    ("cgroup-path-message", r"^\[rootlesskit:parent\] error: (?:open|mkdir|write) /sys/fs/cgroup/"),
    ("daemon-socket-message", r"^(?:failed to start daemon: )?failed to load listeners: can't create unix socket "),
    ("daemon-config-message", r"^(?:failed to start daemon: )?unable to configure the Docker daemon with file "),
    ("daemon-network-message", r"^(?:failed to start daemon: )?Error initializing network controller: "),
)
STARTUP_LOG_UNAVAILABLE = frozenset(
    {
        "budget-exhausted",
        "query-unavailable",
        "byte-limit",
        "record-limit",
        "timeout",
        "interrupted",
        "invalid-fields",
        "cleanup-unverified",
    }
)


class _UnavailableError(Exception):
    """Carry only a closed diagnostic-availability reason, never raw output."""


def _valid_timeout_provider(admitted: object) -> bool:
    return (
        isinstance(admitted, tuple)
        and len(admitted) == 3
        and all(isinstance(value, str) for value in admitted)
        and Path(admitted[0]).is_absolute()
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", admitted[1]) is not None
        and admitted[2] in {"prefixed", "unprefixed"}
    )


def qualify_gnu_timeout(ctx: RuntimeContext) -> tuple[str, str, str]:
    """Admit one private GNU path through the invocation's existing command owner."""
    admitted = vars(ctx).get("_gnu_timeout_provider")
    if admitted is not None:
        if not _valid_timeout_provider(admitted):
            reason = "GNU timeout provider admission is invalid"
            raise ValueError(reason)
        return admitted
    candidate = shutil.which("gnutimeout")
    kind = "prefixed"
    if candidate is None:
        candidate, kind = shutil.which("timeout"), "unprefixed"
    if candidate is None:
        reason = "GNU timeout prerequisite is unavailable"
        raise ValueError(reason)
    try:
        executable = str(Path(candidate).resolve(strict=True))
    except OSError, RuntimeError:
        reason = "GNU timeout prerequisite path is unavailable"
        raise ValueError(reason) from None
    first_record = len(ctx.checks)
    try:
        output = ctx.command("qualify GNU timeout provider", [executable, "--version"])
    except Exception:  # noqa: BLE001 - prerequisite errors never publish an arbitrary provider's output/path.
        reason = "GNU timeout prerequisite command failed"
        raise ValueError(reason) from None
    finally:
        # Even a failing provider's recorded error may contain private path/output.
        del ctx.checks[first_record:]
        ctx.checks.append({"name": "GNU timeout provider admission", "status": "failed"})
    banner = output.splitlines()[0] if isinstance(output, str) and output else ""
    observed = re.fullmatch(r"(?:gnu)?timeout \(GNU coreutils\) ([0-9]+(?:\.[0-9]+)+)", banner)
    if observed is None:
        reason = "GNU timeout provider identity is unverified"
        raise ValueError(reason)
    provider = (executable, observed[1], kind)
    ctx._gnu_timeout_provider = provider  # noqa: SLF001 - invocation-private custody, never public evidence.
    ctx.checks[-1].update(
        {
            "name": "GNU timeout provider admission",
            "status": "passed",
            "provider": "gnu-coreutils",
            "version": observed[1],
            "pathKind": kind,
        }
    )
    return provider


def redact_timeout_provider(ctx: RuntimeContext, value: str) -> str:
    """Redact only the admitted watchdog path from a public text copy."""
    provider = vars(ctx).get("_gnu_timeout_provider")
    if provider is None:
        provider = getattr(vars(ctx).get("backend"), "_gnu_timeout_provider", None)
    if not _valid_timeout_provider(provider):
        return value
    executable = provider[0]
    spellings = {executable, shlex.quote(executable)}
    for spelling in (
        repr(executable),
        ascii(executable),
        json.dumps(executable),
        json.dumps(executable, ensure_ascii=False),
    ):
        spellings.update((spelling, spelling[1:-1]))
    for spelling in sorted(spellings, key=len, reverse=True):
        value = value.replace(spelling, "[gnu-timeout]")
    return value


def _read_stdout(
    process: subprocess.Popen[bytes], deadline: float, limit: int = BYTE_LIMIT, interrupted: list[bool] | None = None
) -> bytes:
    output = bytearray()
    if process.stdout is None:
        raise _UnavailableError("query-unavailable")
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _UnavailableError("timeout")
            try:
                if not selector.select(remaining):
                    raise _UnavailableError("timeout")
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
            except KeyboardInterrupt:
                if interrupted is None:
                    raise
                interrupted[0] = True
                continue
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > limit:
                raise _UnavailableError("byte-limit")


def _wait_wrapper(process: subprocess.Popen[bytes], deadline: float, interrupted: list[bool]) -> int:
    while True:
        try:
            return process.wait(timeout=max(0, deadline - time.monotonic()))
        except KeyboardInterrupt:
            interrupted[0] = True
        except subprocess.TimeoutExpired as error:
            raise _UnavailableError("cleanup-unverified") from error


def _drain_query(process: subprocess.Popen[bytes], deadline: float) -> None:
    # start_new_session binds PGID to the held, unreaped direct child's PID.
    # Signal BEFORE wait/poll: keeping that child unreaped prevents PID reuse.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    interrupted = [False]
    _wait_wrapper(process, deadline, interrupted)
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            raise _UnavailableError("cleanup-unverified")
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def _observe_exit(process: subprocess.Popen[bytes], deadline: float) -> None:
    # EOF can precede the inner guard reaping its successful query. Observe
    # natural guard exit WITHOUT releasing its PID/PGID ownership binding.
    while time.monotonic() < deadline:
        observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None:
            if observed.si_pid != process.pid:
                raise _UnavailableError("cleanup-unverified")
            return
        time.sleep(min(0.005, max(0, deadline - time.monotonic())))
    raise _UnavailableError("timeout")


def _read_query(process: subprocess.Popen[bytes], deadline: float) -> bytes:
    if os.getpgid(process.pid) != process.pid:
        raise _UnavailableError("cleanup-unverified")
    output = _read_stdout(process, deadline, BYTE_LIMIT)
    _observe_exit(process, deadline)
    return output


def _spawn_query(
    arguments: list[str], work_deadline: float, remaining: float, timeout_executable: str | None
) -> subprocess.Popen[bytes]:
    if remaining <= 0.05:
        raise _UnavailableError("budget-exhausted")
    if timeout_executable is None or not Path(timeout_executable).is_absolute():
        raise _UnavailableError("query-unavailable")
    work = work_deadline - time.monotonic() - min(0.05, remaining / 16)
    if work <= 0:
        raise _UnavailableError("budget-exhausted")
    # This guard is INSIDE the query's new session and survives owner death.
    # Killing/reaping the outer sudo/timeout owner cannot disarm this guard.
    return subprocess.Popen(
        [timeout_executable, "--signal=KILL", f"{work}s", *arguments],
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def _query_capture(arguments: list[str], deadline: float, timeout_executable: str | None = None) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    # Prepay cleanup and protocol transmission inside the one original budget.
    work_deadline = deadline - min(2.0, remaining * 0.6)
    try:
        process = _spawn_query(arguments, work_deadline, remaining, timeout_executable)
    except _UnavailableError as error:
        return {"status": str(error), "teardownVerified": True}
    raw = b""
    status = "query-unavailable"
    try:
        raw = _read_query(process, work_deadline)
        status = "available"
    except _UnavailableError as error:
        status = str(error)
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception:  # noqa: BLE001 - no raw query/parser failures leave the root-side owner.
        status = "query-unavailable"
    finally:
        try:
            _drain_query(process, deadline - min(0.25, remaining / 8))
        except Exception, KeyboardInterrupt:  # noqa: BLE001 - only an affirmative drain permits a teardown ACK.
            status = "cleanup-unverified"
        if process.stdout is not None:
            process.stdout.close()
    if status == "cleanup-unverified":
        return {"status": status, "teardownVerified": False}
    if process.returncode != 0 and status == "available":
        status = "query-unavailable"
    result: dict[str, Any] = {"status": status, "teardownVerified": True}
    if status == "available":
        result["data"] = base64.b64encode(raw).decode("ascii")
    return result


def _worker_arguments(directory: Path, request: list[str]) -> list[str]:
    if request[0] == "inspect" and len(request) == 2 and re.fullmatch(r"[0-9a-f]{64}", request[1]):
        docker = shutil.which("docker")
        if docker is None:
            raise _UnavailableError("query-unavailable")
        environment = ["env"]
        for variable in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_API_VERSION",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            environment.extend(("-u", variable))
        return [
            *environment,
            docker,
            "--config",
            str(directory / "cli"),
            "--host",
            "unix://" + str(directory / "docker.sock"),
            "--tls=false",
            "inspect",
            "--format",
            INSPECT_FORMAT,
            request[1],
        ]
    if (
        request[0] == "journal"
        and len(request) == 3
        and all(re.fullmatch(r"[0-9]+\.[0-9]{6}", value) for value in request[1:])
    ):
        journalctl = shutil.which("journalctl")
        if journalctl is None:
            raise _UnavailableError("query-unavailable")
        return [
            journalctl,
            "--quiet",
            "--no-pager",
            "--boot=0",
            "--dmesg",
            "--since=@" + request[1],
            "--until=@" + request[2],
            "--output=json",
            "--output-fields=MESSAGE",
            "--lines=65",
            "--grep=rootlesskit",
        ]
    raise _UnavailableError("invalid-fields")


def _guest_guard_contract() -> dict[str, Any]:
    """Load one literal adjacent helper snapshot, never expand root import paths."""
    path = Path(__file__).resolve().with_name("runtime_docker_systemd_guard.py")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= GUARD_SOURCE_LIMIT:
            raise _UnavailableError("query-unavailable")
        source = bytearray()
        while len(source) <= GUARD_SOURCE_LIMIT:
            chunk = os.read(descriptor, GUARD_SOURCE_LIMIT + 1 - len(source))
            if not chunk:
                break
            source.extend(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            len(source) != before.st_size
            or len(source) > GUARD_SOURCE_LIMIT
            or any(getattr(before, field) != getattr(current, field) for current in (after, named) for field in fields)
        ):
            raise _UnavailableError("query-unavailable")
    finally:
        os.close(descriptor)
    namespace: dict[str, Any] = {}
    # Only the checked snapshot of this literal sibling shares the existing source trust boundary.
    exec(compile(source, "[fixed-systemd-guard]", "exec"), namespace)  # noqa: S102
    return namespace


def _guest_worker_arguments(directory: Path, container: str) -> list[str]:
    contract = _guest_guard_contract()
    properties = " ".join("--property=" + field for field in sorted(SERVICE_FIELDS))
    script = (
        'test "$(id -u)" = 0; test "$(cat /proc/1/comm)" = systemd; '
        "LC_ALL=C; export LC_ALL; printf 'user-manager\\n'; "
        f"systemctl show --no-pager user@1000.service {properties}; "
        "printf 'docker-service\\n'; "
        "if test -S /run/user/1000/bus; then "
        + shlex.join(contract["USER_MANAGER"])
        + f" show --no-pager docker.service {properties}; "
        "else printf 'Unavailable=user-bus-absent\\n'; fi"
    )
    # Reuse the fixed private endpoint/environment prefix; replace only the fixed inspect query.
    inspect = _worker_arguments(directory, ["inspect", container])
    return [*inspect[:-4], "exec", container, *contract["guarded_command"]("sh", "-euc", script)]


def _guest_log_arguments(directory: Path, container: str) -> list[str]:
    contract = _guest_guard_contract()
    inspect = _worker_arguments(directory, ["inspect", container])
    return [
        *inspect[:-4],
        "exec",
        container,
        *contract["guarded_command"](
            "sh",
            "-euc",
            'test "$(id -u)" = 0; test "$(cat /proc/1/comm)" = systemd; exec "$@"',
            "--",
            "journalctl",
            "--quiet",
            "--no-pager",
            "--boot=0",
            f"--lines={GUEST_LOG_RECORD_LIMIT}",
            "--output=json",
            "--output-fields=MESSAGE",
            "_UID=1000",
            "_SYSTEMD_USER_UNIT=docker.service",
        ),
    ]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _UnavailableError("invalid-fields")
        result[key] = value
    return result


def _classify_startup_log(raw: bytes) -> dict[str, Any]:
    """Inspect bounded private messages, returning only reviewed message labels."""
    if len(raw) > GUEST_BYTE_LIMIT:
        raise _UnavailableError("byte-limit")
    lines = raw.splitlines()
    if len(lines) > GUEST_LOG_RECORD_LIMIT:
        raise _UnavailableError("record-limit")
    classes: set[str] = set()
    unknown = 0
    allowed = {"MESSAGE", "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID"}
    for line in lines:
        entry = json.loads(line, object_pairs_hook=_unique_object)
        if (
            not isinstance(entry, dict)
            or not entry.keys() <= allowed
            or not isinstance(entry.get("MESSAGE"), str)
            or any(not isinstance(value, str) for value in entry.values())
        ):
            raise _UnavailableError("invalid-fields")
        message = entry["MESSAGE"]
        label = next((name for name, pattern in STARTUP_LOG_PATTERNS if re.search(pattern, message)), None)
        if label is None:
            unknown += 1
        else:
            classes.add(label)
    return {
        "availability": "classified",
        "records": len(lines),
        "unknownRecords": unknown,
        "classes": sorted(classes),
        "attribution": "message-observation-only",
        "managerNoNewPrivs": "not-observed",
    }


def _guest_log_capture(arguments: list[str], deadline: float, timeout_executable: str) -> dict[str, Any]:
    protocol = _query_capture(arguments, deadline, timeout_executable)
    if protocol.get("status") != "available" or protocol.get("teardownVerified") is not True:
        return {
            "status": protocol.get("status")
            if protocol.get("status") in STARTUP_LOG_UNAVAILABLE
            else "query-unavailable",
            "teardownVerified": protocol.get("teardownVerified") is True,
        }
    try:
        projection = _classify_startup_log(base64.b64decode(protocol["data"], validate=True))
    except _UnavailableError as error:
        return {"status": str(error), "teardownVerified": True}
    except Exception:  # noqa: BLE001 - never send raw guest messages or parse failures through the root protocol.
        return {"status": "invalid-fields", "teardownVerified": True}
    return {
        "status": "available",
        "teardownVerified": True,
        "data": base64.b64encode(json.dumps(projection).encode()).decode(),
    }


def _verify_guest_container(raw: bytes, owner: str, container: str) -> None:
    projection = _inspect_projection(
        raw, SimpleNamespace(owner=owner, slice="strukturpiloten" + owner + ".slice"), container
    )
    if projection["state"] != "running" or not projection["hostPidAvailable"] or projection["privileged"] is not True:
        raise _UnavailableError("ownership-unverified")


def _verify_private_daemon(raw: bytes, directory: Path) -> None:
    observed = json.loads(raw)
    if not isinstance(observed, dict) or observed.get("root") != str(directory / "root"):
        raise _UnavailableError("ownership-unverified")
    security = observed.get("securityOptions")
    if (
        not isinstance(security, list)
        or len(security) > 32
        or any(not isinstance(option, str) or "rootless" in option for option in security)
    ):
        raise _UnavailableError("ownership-unverified")


def _guest_owned_capture(
    directory: Path, container: str, owner: str, deadline: float, timeout_executable: str
) -> dict[str, Any]:
    inspect = _worker_arguments(directory, ["inspect", container])
    for arguments, verifier in (
        (
            [*inspect[:-4], "info", "--format", PRIVATE_DAEMON_FORMAT],
            lambda raw: _verify_private_daemon(raw, directory),
        ),
        (inspect, lambda raw: _verify_guest_container(raw, owner, container)),
    ):
        observed = _query_capture(arguments, deadline, timeout_executable)
        if observed.get("status") != "available" or observed.get("teardownVerified") is not True:
            return observed
        try:
            verifier(base64.b64decode(observed["data"], validate=True))
        except Exception:  # noqa: BLE001 - root-observed private daemon and exact ownership must both be affirmative.
            return {"status": "query-unavailable", "teardownVerified": True}
    return {"status": "available", "teardownVerified": True}


def _guest_query_capture(
    directory: Path, request: list[str], deadline: float, timeout_executable: str
) -> dict[str, Any]:
    """Root-side ownership readback precedes every fixed, guarded guest read."""
    if (
        len(request) != 3
        or request[0] not in {"guest-systemd", "guest-startup-log"}
        or re.fullmatch(r"[0-9a-f]{64}", request[1]) is None
        or re.fullmatch(r"[0-9a-f]{32}", request[2]) is None
    ):
        return {"status": "invalid-fields", "teardownVerified": True}
    if deadline - time.monotonic() <= 0.05:
        return {"status": "budget-exhausted", "teardownVerified": True}
    container, owner = request[1:]
    observed = _guest_owned_capture(directory, container, owner, deadline, timeout_executable)
    if observed.get("status") != "available" or observed.get("teardownVerified") is not True:
        return observed
    try:
        if deadline - time.monotonic() <= 0.05:
            return {"status": "budget-exhausted", "teardownVerified": True}
        arguments = (
            _guest_log_arguments(directory, container)
            if request[0] == "guest-startup-log"
            else _guest_worker_arguments(directory, container)
        )
    except Exception:  # noqa: BLE001 - refuse exec on any ownership/source-contract uncertainty.
        return {"status": "query-unavailable", "teardownVerified": True}
    # This ACK covers the host query group only. Guest processes remain owned by exact-container cleanup.
    capture = _guest_log_capture if request[0] == "guest-startup-log" else _query_capture
    return capture(arguments, deadline, timeout_executable)


def _verified_protocol(output: bytes, returncode: int) -> dict[str, Any]:
    protocol = json.loads(output)
    if returncode != 0 or not isinstance(protocol, dict) or protocol.get("teardownVerified") is not True:
        raise _UnavailableError("cleanup-unverified")
    allowed = {
        "available",
        "budget-exhausted",
        "query-unavailable",
        "byte-limit",
        "timeout",
        "interrupted",
        "invalid-fields",
        "record-limit",
    }
    if protocol.get("status") not in allowed:
        raise _UnavailableError("cleanup-unverified")
    return protocol


def _capture(backend: DockerBackend, request: list[str], deadline: float) -> bytes:
    """Accept data only after the fixed root-side owner acknowledges query drain."""
    if backend.diagnostic_reader_pending:
        raise _UnavailableError("cleanup-unverified")
    remaining = backend.command_timeout(deadline - time.monotonic())
    command = backend.privileged(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--capture",
            "--directory",
            str(backend.directory),
            "--deadline-ns",
            str(int(deadline * 1_000_000_000)),
            "--timeout-executable",
            backend.timeout_executable(),
            *request,
        ],
        remaining,
    )
    backend.diagnostic_reader_pending = True
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        # Popen reaps an exec-failed child before raising; no query owner ran.
        backend.diagnostic_reader_pending = False
        raise
    interrupted = [False]
    try:
        try:
            try:
                output = _read_stdout(process, deadline, PROTOCOL_LIMIT, interrupted)
            except (Exception, KeyboardInterrupt) as error:
                raise _UnavailableError("cleanup-unverified") from error
        finally:
            # Never kill sudo/the watchdog: the root owner must reap its query.
            returncode = _wait_wrapper(process, deadline, interrupted)
        protocol = _verified_protocol(output, returncode)
        backend.diagnostic_reader_pending = False
        if interrupted[0]:
            raise KeyboardInterrupt
        if protocol.get("status") != "available":
            raise _UnavailableError(protocol["status"])
        raw = base64.b64decode(protocol["data"], validate=True)
        if len(raw) > BYTE_LIMIT or time.monotonic() >= deadline:
            raise _UnavailableError("timeout")
        backend.check_deadline()
        return raw  # noqa: TRY300 - the finally block must close the private protocol pipe.
    except (ValueError, KeyError, TypeError) as error:
        raise _UnavailableError("cleanup-unverified") from error
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _inspect_projection(raw: bytes, backend: DockerBackend, container: str) -> dict[str, Any]:
    observed = json.loads(raw)
    if not isinstance(observed, dict) or any(
        observed.get(key) != expected
        for key, expected in {"id": container, "owner": backend.owner, "cgroup": backend.slice}.items()
    ):
        raise _UnavailableError("ownership-unverified")
    if any(type(observed.get(key)) is not bool for key in ("privileged", "oomKilled")):
        raise _UnavailableError("invalid-fields")
    if observed.get("state") not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}:
        raise _UnavailableError("invalid-fields")
    if type(observed.get("exitCode")) is not int or not 0 <= observed["exitCode"] <= 255:
        raise _UnavailableError("invalid-fields")
    if type(observed.get("pid")) is not int or not 0 <= observed["pid"] <= 2**31 - 1:
        raise _UnavailableError("invalid-fields")
    apparmor = observed.get("apparmor")
    options = observed.get("securityOptions")
    if options is None:
        options = []
    if (
        "securityOptions" not in observed
        or not isinstance(apparmor, str)
        or not isinstance(options, list)
        or len(options) > 32
        or any(not isinstance(option, str) for option in options)
    ):
        raise _UnavailableError("invalid-fields")
    return {
        "privileged": observed["privileged"],
        "apparmorProfile": {"": "empty", "unconfined": "unconfined", "docker-default": "docker-default"}.get(
            apparmor, "other"
        ),
        "securityOptions": sorted({SECURITY_OPTIONS[option] for option in options if option in SECURITY_OPTIONS}),
        "unknownSecurityOptionCount": sum(option not in SECURITY_OPTIONS for option in options),
        "state": observed["state"],
        "exitCode": observed["exitCode"],
        "oomKilled": observed["oomKilled"],
        "hostPidAvailable": observed["pid"] > 0,
    }


def _journal_projection(raw: bytes) -> dict[str, Any]:
    lines = raw.splitlines()
    if len(lines) > JOURNAL_RECORD_LIMIT:
        raise _UnavailableError("record-limit")
    count = 0
    for line in lines:
        entry = json.loads(line)
        if not isinstance(entry, dict) or not isinstance(entry.get("MESSAGE"), str):
            raise _UnavailableError("invalid-fields")
        fields = shlex.split(entry["MESSAGE"])
        if {"apparmor=DENIED", "operation=userns_create", "comm=rootlesskit"} <= set(fields):
            count += 1
    return {
        "availability": "available",
        "attribution": "host-task-window-only",
        "rootlesskitUsernsDenialRecords": count,
    }


def _journal(backend: DockerBackend, deadline: float, started: float, finished: float) -> dict[str, Any]:
    try:
        if not all(math.isfinite(value) for value in (started, finished)) or not 0 <= finished - started <= 1800:
            return {"availability": "invalid-window", "attribution": "host-task-window-only"}
        journalctl = shutil.which("journalctl")
        if journalctl is None:
            return {"availability": "query-unavailable", "attribution": "host-task-window-only"}
        raw = _capture(backend, ["journal", f"{started:.6f}", f"{finished:.6f}"], deadline)
        return _journal_projection(raw)
    except _UnavailableError as error:
        reason = str(error)
    except KeyboardInterrupt:
        reason = "interrupted"
    except Exception:  # noqa: BLE001 - raw command/parser errors must never escape into public evidence.
        reason = "query-unavailable"
    return {"availability": reason, "attribution": "host-task-window-only"}


def _service_projection(lines: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key not in SERVICE_FIELDS or key in values:
            raise _UnavailableError("invalid-fields")
        if key in SERVICE_STATES:
            if value not in SERVICE_STATES[key]:
                raise _UnavailableError("invalid-fields")
            values[key] = value
        else:
            maximum = {"ExecMainCode": 3, "ExecMainStatus": 255, "MainPID": 2**31 - 1}[key]
            if re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None or int(value) > maximum:
                raise _UnavailableError("invalid-fields")
            values[key] = int(value)
    if values.keys() != SERVICE_FIELDS:
        raise _UnavailableError("invalid-fields")
    return {"availability": "available", **values}


def _guest_projection(raw: bytes) -> dict[str, Any]:
    if len(raw) > GUEST_BYTE_LIMIT:
        raise _UnavailableError("byte-limit")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise _UnavailableError("invalid-fields") from error
    if not lines or lines[0] != "user-manager" or lines.count("docker-service") != 1:
        raise _UnavailableError("invalid-fields")
    boundary = lines.index("docker-service")
    manager = _service_projection(lines[1:boundary])
    service_lines = lines[boundary + 1 :]
    service = (
        {"availability": "user-bus-absent"}
        if service_lines == ["Unavailable=user-bus-absent"]
        else _service_projection(service_lines)
    )
    result = {"availability": "collected", "userManager": manager, "dockerService": service}
    if _record_size(result) > GUEST_RECORD_LIMIT:
        raise _UnavailableError("byte-limit")
    return result


def _record_size(record: dict[str, Any]) -> int:
    return len((json.dumps(record, indent=2) + "\n").encode("utf-8"))


def _with_guest(record: dict[str, Any], guest: dict[str, Any]) -> dict[str, Any]:
    """Keep legacy evidence unchanged when the optional projection cannot fit."""
    try:
        baseline_guest = {key: value for key, value in guest.items() if key != "startupLog"}
        baseline = {**record, "guestSystemd": baseline_guest}
        if _record_size(baseline) > DIAGNOSTIC_RECORD_LIMIT:
            return record
        if "startupLog" not in guest:
            return baseline
    except Exception:  # noqa: BLE001 - failed baseline preview preserves legacy host evidence.
        return record
    try:
        preview = {**record, "guestSystemd": guest}
        if _record_size(preview) <= DIAGNOSTIC_RECORD_LIMIT:
            return preview
    except Exception, KeyboardInterrupt:  # noqa: BLE001 - optional preview preserves valid baseline evidence.
        return baseline
    return baseline


def _startup_log_projection(raw: bytes) -> dict[str, Any]:
    if len(raw) > GUEST_BYTE_LIMIT:
        raise _UnavailableError("byte-limit")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    expected = {"availability", "records", "unknownRecords", "classes", "attribution", "managerNoNewPrivs"}
    if (
        not isinstance(value, dict)
        or value.keys() != expected
        or value["availability"] != "classified"
        or value["attribution"] != "message-observation-only"
        or value["managerNoNewPrivs"] != "not-observed"
        or type(value["records"]) is not int
        or not 0 <= value["records"] <= GUEST_LOG_RECORD_LIMIT
        or type(value["unknownRecords"]) is not int
        or not 0 <= value["unknownRecords"] <= value["records"]
        or not isinstance(value["classes"], list)
        or len(value["classes"]) > value["records"] - value["unknownRecords"]
        or any(
            not isinstance(label, str) or label not in {name for name, _ in STARTUP_LOG_PATTERNS}
            for label in value["classes"]
        )
        or value["classes"] != sorted(set(value["classes"]))
        or (not value["classes"] and value["records"] != value["unknownRecords"])
    ):
        raise _UnavailableError("invalid-fields")
    return value


def _startup_log(backend: DockerBackend, container: str, deadline: float) -> dict[str, Any]:
    try:
        if deadline - time.monotonic() <= 0.05:
            return {"availability": "budget-exhausted", "managerNoNewPrivs": "not-observed"}
        raw = _capture(backend, ["guest-startup-log", container, backend.owner], deadline)
        result = _startup_log_projection(raw)
    except _UnavailableError as error:
        reason = str(error) if str(error) in STARTUP_LOG_UNAVAILABLE else "query-unavailable"
    except KeyboardInterrupt:
        reason = "interrupted"
    except Exception:  # noqa: BLE001 - optional classifier errors cannot erase an already validated service projection.
        reason = "query-unavailable"
    else:
        return result
    return {"availability": reason, "managerNoNewPrivs": "not-observed"}


def _with_startup_log(guest: dict[str, Any], classification: dict[str, Any]) -> dict[str, Any]:
    for optional in (classification, {"availability": "byte-limit", "managerNoNewPrivs": "not-observed"}):
        try:
            preview = {**guest, "startupLog": optional}
            if _record_size(preview) <= GUEST_RECORD_LIMIT:
                return preview
        except Exception, KeyboardInterrupt:  # noqa: BLE001 - optional serialization preserves service evidence.
            return guest
    return guest


def _guest(ctx: RuntimeContext, backend: DockerBackend, container: str, deadline: float) -> dict[str, Any]:
    try:
        if not backend._systemd_guest(ctx, container):  # noqa: SLF001 - reuse exact existing fixture binding.
            return {"availability": "profile-not-applicable"}
        from scripts.runtime_docker_systemd_guard import guarded_command  # noqa: PLC0415 - parent-side only.

        if vars(ctx).get("exec_guard") != guarded_command():
            return {"availability": "placement-unverified"}
        if deadline - time.monotonic() <= 0.05:
            return {"availability": "budget-exhausted"}
        raw = _capture(backend, ["guest-systemd", container, backend.owner], deadline)
        result = _guest_projection(raw)
        # Query-group teardown does not establish guest process exit; exact-container cleanup owns it.
        result["guestProcessCleanup"] = "owned-container-cleanup-required"
        if _record_size(result) > GUEST_RECORD_LIMIT:
            return {"availability": "byte-limit", "guestProcessCleanup": "owned-container-cleanup-required"}
    except _UnavailableError as error:
        reason = str(error)
    except KeyboardInterrupt:
        reason = "interrupted"
    except Exception:  # noqa: BLE001 - optional guest diagnostics cannot replace host evidence or the launch error.
        reason = "query-unavailable"
    else:
        # Optional work cannot erase validated services or change the reader's sticky custody state.
        with suppress(Exception, KeyboardInterrupt):
            result = _with_startup_log(result, _startup_log(backend, container, deadline))
        return result
    return {"availability": reason, "guestProcessCleanup": "owned-container-cleanup-required"}


def _collect(ctx: RuntimeContext, backend: DockerBackend, container: str, started: float) -> dict[str, Any]:
    finished = time.time()
    if (
        not backend.ready
        or backend.cleaning_up
        or backend.deadline is None
        or re.fullmatch(r"[0-9a-f]{64}", container) is None
        or container not in ctx.containers
    ):
        raise _UnavailableError("ownership-unverified")
    deadline = min(time.monotonic() + DIAGNOSTIC_SECONDS, backend.deadline - 60)
    if deadline - time.monotonic() <= 0.01:
        raise _UnavailableError("budget-exhausted")
    raw = _capture(backend, ["inspect", container], deadline)
    projection = _inspect_projection(raw, backend, container)
    if time.monotonic() >= deadline:
        raise _UnavailableError("timeout")
    journal = _journal(backend, deadline, started, finished)
    if time.monotonic() >= deadline:
        raise _UnavailableError("timeout")
    backend.check_deadline()
    record = {"availability": "collected", "container": projection, "kernelJournal": journal}
    record["guestSystemd"] = _guest(ctx, backend, container, deadline)
    return record


def diagnose_rootless_failure(ctx: RuntimeContext, container: str, started: float) -> None:
    """Append only non-acceptance diagnostics, without replacing the launch error."""
    from scripts.runtime_docker_backend import DockerBackend  # noqa: PLC0415 - root capture CLI is stdlib-only under -I.

    backend = getattr(ctx, "backend", None)
    if not isinstance(backend, DockerBackend):
        return
    record: dict[str, Any] = {
        "name": "early rootless Docker launch failure diagnostics",
        "status": "failed",
        "diagnosticOnly": True,
        "acceptanceEvidence": False,
    }
    try:
        collected = _collect(ctx, backend, container, started)
        guest = collected.pop("guestSystemd")
        record.update(collected)
        record = _with_guest(record, guest)
    except _UnavailableError as error:
        record["availability"] = str(error)
    except KeyboardInterrupt:
        record["availability"] = "interrupted"
    except Exception:  # noqa: BLE001 - retain the original launch error, with no raw exception serialization.
        record["availability"] = "query-unavailable"
    ctx.checks.append(record)


def main() -> None:
    """Run only fixed root-side read queries, with host query drain acknowledgement."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, action="store_true")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--deadline-ns", required=True, type=int)
    parser.add_argument("--timeout-executable", required=True, type=Path)
    parser.add_argument("request", nargs="+")
    args = parser.parse_args()
    interrupted = [False]

    def note_interruption(_signum: int, _frame: object) -> None:
        # Do not interrupt root-side group termination/reaping. Its work/select
        # deadlines are already prepaid; the outer root watchdog stays intact.
        interrupted[0] = True

    signal.signal(signal.SIGTERM, note_interruption)
    signal.signal(signal.SIGINT, note_interruption)
    try:
        deadline = args.deadline_ns / 1_000_000_000
        if (
            os.geteuid() != 0
            or not args.directory.is_absolute()
            or not args.timeout_executable.is_absolute()
            or not 0 < deadline - time.monotonic() <= 5
        ):
            result = {"status": "query-unavailable", "teardownVerified": False}
        elif args.request[0] in {"guest-systemd", "guest-startup-log"}:
            result = _guest_query_capture(args.directory, args.request, deadline, str(args.timeout_executable))
        else:
            result = _query_capture(
                _worker_arguments(args.directory, args.request), deadline, str(args.timeout_executable)
            )
        if interrupted[0] and result.get("teardownVerified") is True:
            result = {"status": "interrupted", "teardownVerified": True}
    except Exception:  # noqa: BLE001 - fixed acknowledgement only; never serialize private failures.
        result = {"status": "query-unavailable", "teardownVerified": False}
    try:
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
    except OSError:
        pass  # The owned query has already been reaped even if its caller disappeared.


if __name__ == "__main__":
    main()
