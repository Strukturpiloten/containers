"""Separate Containers scoped-profile qualification entrypoint and native client.

Root execution is allowed only from an immutable root-private stage produced by
the fixed workflow verifier. The old unused admission and DockerLens active CLI
are never active authority. No operation runs merely by importing this module.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import signal
import stat
import sys
import time
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from scripts.docker_userns_qualification import NativeBinding, State

CONSUMER = "containers-ubuntu26-userns-active"
ROOT = Path("/run")
PREFIX = "containers-userns-active."
MAX_STATE = 32768
MAX_SOURCE = 262144
MAX_OUTPUT = 65536
RESERVE_NS = 60_000_000_000
FINALIZER_HEADSTART_NS = 15_000_000_000
PRIVATE_DIRECTORY = 0o700
PRIVATE_FILE = 0o600
IMMUTABLE_FILE = 0o400
START_FIELD = 19
DOCKERD_ARGC = 3
MAX_NAMESPACE = 256
MICROSECONDS = 1_000_000
PRIVATE_RUNTIME_PREFIX = "/tmp/strukturpiloten-runtime-"  # noqa: S108 - exact existing invocation-owned runtime stores.
PYTHON = "/usr/bin/python3.14"
FILES = (
    "scripts/__init__.py",
    "scripts/docker_userns_active.py",
    "scripts/docker_userns_qualification.py",
    "scripts/docker_runner_security.py",
    "scripts/docker_userns_custody_child.py",
    "scripts/docker_userns_policy_source.py",
    "scripts/docker_userns_custody.py",
    "scripts/docker_userns_hosted.py",
    "scripts/docker_userns_dryparse.py",
    "scripts/runtime_docker_diagnostics.py",
    "scripts/runtime_docker_systemd_guard.py",
    ".github/docker-userns-active-admission.json",
    ".github/docker-userns-active-helper-closure.json",
    ".github/docker-userns-policy-source.json",
)


class RefusedError(Exception):
    """A closed refusal; raw paths, labels, exceptions and tool output remain private."""


def require(value: object) -> None:
    """Refuse without exporting the failed operand."""
    if not value:
        reason = "active-scoped-profile-refused"
        raise RefusedError(reason)


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys before interpreting a bounded root record."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def encoded(value: object) -> bytes:
    """Keep durable records finite and deterministic."""
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    require(len(raw) <= MAX_STATE)
    return raw


def digest(raw: bytes) -> str:
    """Hash only held bytes, never a pathname supplied as evidence."""
    return hashlib.sha256(raw).hexdigest()


def mark(info: os.stat_result) -> tuple[int, ...]:
    """Bind full identity around each read and every later use."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def root_bytes(path: Path, limit: int = MAX_STATE) -> bytes:
    """Read one fixed root-owned regular leaf without following its final name."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and not before.st_mode & 0o7022
        )
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) <= limit and mark(before) == mark(os.fstat(descriptor)) == mark(path.lstat()))
        return bytes(raw)
    finally:
        os.close(descriptor)


def verify_stage(stage: Path) -> dict[str, Any]:
    """Authenticate root-private source before importing any staged helper."""
    require(
        os.geteuid() == 0 and stage.parent == ROOT and re.fullmatch(re.escape(PREFIX) + r"[0-9a-f]{32}", stage.name)
    )
    info = stage.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == PRIVATE_DIRECTORY)
    require(stat.S_IMODE((stage / "bootstrap.json").lstat().st_mode) == IMMUTABLE_FILE)
    bootstrap = json.loads(root_bytes(stage / "bootstrap.json"), object_pairs_hook=unique)
    require(
        bootstrap["consumer"] == CONSUMER
        and bootstrap["schemaVersion"] == 1
        and bootstrap["stageIdentity"] == [info.st_dev, info.st_ino]
        and set(bootstrap["files"]) == set(FILES)
    )
    for name, expected in bootstrap["files"].items():
        require(re.fullmatch(r"[0-9a-f]{64}", expected))
        current = stage
        for part in Path(name).parts[:-1]:
            current /= part
            component = current.lstat()
            require(stat.S_ISDIR(component.st_mode) and component.st_uid == 0 and not component.st_mode & 0o077)
        require(stat.S_IMODE((stage / name).lstat().st_mode) == IMMUTABLE_FILE)
        require(digest(root_bytes(stage / name, MAX_SOURCE)) == expected)
    closure = json.loads(
        root_bytes(stage / ".github/docker-userns-active-helper-closure.json"), object_pairs_hook=unique
    )
    require(closure == {"schemaVersion": 1, "consumer": CONSUMER, "stdlibOnly": True, "files": list(FILES)})
    require(
        sys.implementation.name == "cpython"
        and tuple(sys.version_info) == (3, 14, 4, "final", 0)
        and sys.flags.isolated == 1
        and sys.flags.no_site == 1
        and sys.dont_write_bytecode
    )
    return bootstrap


def dependencies(stage: Path) -> SimpleNamespace:
    """Import only after immutable root staging has been independently verified."""
    sys.path.insert(0, str(stage))
    from scripts import docker_userns_custody_child as child  # noqa: PLC0415
    from scripts import docker_userns_dryparse as compiler  # noqa: PLC0415
    from scripts import docker_userns_hosted as host  # noqa: PLC0415
    from scripts import docker_userns_policy_source as source  # noqa: PLC0415
    from scripts import docker_userns_qualification as qualification  # noqa: PLC0415
    from scripts import runtime_docker_diagnostics as capture  # noqa: PLC0415

    return SimpleNamespace(
        child=child, compiler=compiler, host=host, source=source, qualification=qualification, capture=capture
    )


def check(deadline_ns: int) -> None:
    """Use only the pre-existing absolute authority; no expired allowance is renewed."""
    require(type(deadline_ns) is int and time.monotonic_ns() < deadline_ns)


def write_leaf(directory: Path, name: str, value: bytes, mode: int = 0o400) -> None:
    """Create one exclusive known private leaf, durably, before its dependent action."""
    require(re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", name) and len(value) <= MAX_SOURCE)
    descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        require(os.write(descriptor, value) == len(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


class Store:
    """One root-private phase lease, locked across each operation and identity-bound."""

    def __init__(self, stage: Path, name: str, *, create: bool = False) -> None:
        """Require an existing root stage and a closed nonce, never an arbitrary locator."""
        require(re.fullmatch(r"[0-9a-f]{32}", name))
        self.path = stage / "leases" / name
        if create:
            self.path.mkdir(mode=0o700)
            write_leaf(self.path, "lock", b"", 0o600)
        info = self.path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == PRIVATE_DIRECTORY)
        self.identity = (info.st_dev, info.st_ino)
        self.descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.lock = os.open("lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.descriptor)
        lock = os.fstat(self.lock)
        require(
            stat.S_ISREG(lock.st_mode)
            and lock.st_uid == 0
            and lock.st_nlink == 1
            and stat.S_IMODE(lock.st_mode) == PRIVATE_FILE
        )

    @contextmanager
    def locked(self) -> Iterator[None]:
        """No concurrent privileged operation may overtake a durable intent."""
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            named = self.path.lstat()
            held = os.fstat(self.descriptor)
            require((named.st_dev, named.st_ino) == self.identity == (held.st_dev, held.st_ino))
            yield
        finally:
            fcntl.flock(self.lock, fcntl.LOCK_UN)

    def read(self) -> dict[str, Any]:
        """Read the bounded current snapshot; replay cannot substitute another inode."""
        require(
            not any((self.path / name).exists() for name in ("next.json", "probe-retained.json", "owner-retained.json"))
        )
        return json.loads(root_bytes(self.path / "state.json"), object_pairs_hook=unique)

    def write(self, value: dict[str, Any]) -> None:
        """Fsync one atomic state replacement before acknowledging the transition."""
        write_leaf(self.path, "next.json", encoded(value), 0o600)
        os.replace("next.json", "state.json", src_dir_fd=self.descriptor, dst_dir_fd=self.descriptor)
        os.fsync(self.descriptor)

    def close(self) -> None:
        """Release each held descriptor once; a failed close remains a failure."""
        os.close(self.lock)
        os.close(self.descriptor)


class Clock:
    """Adapt only the existing integer monotonic clock for the sealed builder."""

    @staticmethod
    def now_ns() -> int:
        """Return the current monotonic time without allocating a new allowance."""
        return time.monotonic_ns()


def root_preflight(stage: Path, bootstrap: dict[str, Any], modules: SimpleNamespace) -> dict[str, Any]:
    """Check actual fixed OS/tool/content facts, separate from workflow provenance."""
    context = bootstrap["context"]
    admission = json.loads(root_bytes(stage / ".github/docker-userns-active-admission.json"), object_pairs_hook=unique)
    require(
        set(admission)
        == {
            "schemaVersion",
            "consumer",
            "purpose",
            "qualification",
            "sourceManifestSha256",
            "context",
            "cohort",
            "architectures",
            "policyNamespace",
            "parserExecutionNamespace",
            "review",
        }
    )
    require(
        admission["schemaVersion"] == 1
        and admission["consumer"] == CONSUMER
        and admission["purpose"] == "single-candidate-qualification"
        and admission["qualification"] == "none"
    )
    require(digest(root_bytes(stage / ".github/docker-userns-policy-source.json")) == admission["sourceManifestSha256"])
    expected = admission["context"]
    require(
        context["repository"] == expected["repository"] == "Strukturpiloten/containers"
        and context["event"] == expected["event"] == "workflow_dispatch"
        and context["ref"] == expected["ref"] == "refs/heads/TheRealBecks/issue527"
        and context["job"] == expected["job"] == "smoke-build"
        and context["image"] == expected["image"] == "docker-29-conformance-rootless"
        and context["imageOS"] == expected["imageOS"] == "ubuntu26"
        and context["validationProfile"] == expected["validationProfile"] == "docker-rootless-diagnostic"
        and modules.qualification.validation_profile(context["validationProfileRequested"])
        == context["validationProfile"]
        and context["candidate"] == context["workflow"] == context["checkout"]
        and re.fullmatch(r"[0-9a-f]{40}", context["candidate"])
        and re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", context["imageVersion"])
    )
    cohort = admission["cohort"]
    distro_raw, _ = modules.host.read_root(Path("/etc/os-release"), 8192)
    distro = dict(
        line.split("=", 1)
        for line in distro_raw.decode("ascii").splitlines()
        if "=" in line and not line.startswith("#")
    )
    require(
        distro.get("ID", "").strip('"') == cohort["osID"] == "ubuntu"
        and distro.get("VERSION_ID", "").strip('"') == cohort["osVersion"] == "26.04"
    )
    actual = os.uname()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(context["architecture"])
    require(actual.machine == machine)
    if context["architecture"] == "amd64":
        require(actual.machine == cohort["machine"] and actual.release == cohort["kernel"])
    check(bootstrap["deadlineNs"] - RESERVE_NS)
    controls = modules.qualification.observe_controls(bootstrap["deadlineNs"] - RESERVE_NS)
    paths = {
        "parserSha256": (Path("/usr/sbin/apparmor_parser"), 16 * 1024 * 1024),
        "abiSha256": (Path("/etc/apparmor.d/abi/4.0"), 65536),
        "namespaceMaskSha256": (Path("/sys/kernel/security/apparmor/features/namespaces/mask"), 4096),
        "policyVersion9Sha256": (Path("/sys/kernel/security/apparmor/features/policy/versions/v9"), 4096),
        "interpreterSha256": (Path(PYTHON), 16 * 1024 * 1024),
    }
    files = {}
    for key, (path, limit) in paths.items():
        raw, identity = modules.host.read_root(path, limit)
        if context["architecture"] == "amd64" or key not in {"parserSha256", "interpreterSha256"}:
            require(digest(raw) == cohort[key])
        if key in {"parserSha256", "interpreterSha256"}:
            require(raw.startswith(b"\x7fELF") and identity.mode & 0o111 and not identity.mode & 0o7022)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                try:
                    capabilities = os.getxattr(descriptor, "security.capability")
                except OSError as error:
                    require(error.errno == errno.ENODATA)
                    capabilities = b""
                require(not capabilities)
            finally:
                os.close(descriptor)
        files[key] = {"sha256": digest(raw), "identity": asdict(identity)}
    check(bootstrap["deadlineNs"] - RESERVE_NS)
    return {
        "controls": asdict(controls),
        "files": files,
        "osID": distro["ID"].strip('"'),
        "osVersion": distro["VERSION_ID"].strip('"'),
        "machine": actual.machine,
        "kernel": actual.release,
        "imageVersion": context["imageVersion"],
        "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
        "validationProfile": context["validationProfile"],
        "validationProfileRequested": context["validationProfileRequested"],
    }


def compile_worker(bootstrap: dict[str, Any], modules: SimpleNamespace, directory: Path) -> dict[str, Any]:
    """Drop credentials before the unchanged no-load parser wrapper; never load here."""
    record = json.loads(root_bytes(directory / "state.json"), object_pairs_hook=unique)
    deadline = record["binding"]["deadline_ns"] - RESERVE_NS
    check(deadline)
    admission = json.loads(
        root_bytes(directory.parent.parent / ".github/docker-userns-active-admission.json"), object_pairs_hook=unique
    )
    namespace_snapshot(modules, admission)
    policy = root_bytes(directory / "policy", 1024)
    require(digest(policy) == record["policySha256"])
    with modules.source.hold_executable(Path("/usr/sbin/apparmor_parser"), 16 * 1024 * 1024, 0) as parser:
        os.setgroups([])
        os.setresgid(bootstrap["gid"], bootstrap["gid"], bootstrap["gid"])
        os.setresuid(bootstrap["uid"], bootstrap["uid"], bootstrap["uid"])
        output, status = modules.source.bounded_child(
            modules.compiler.PARSER_EXEC,
            modules.source.ExecutableCall(parser, ("apparmor_parser", *modules.compiler.COMPILE)),
            policy,
            deadline / 1_000_000_000,
            4096,
        )
    require(status == 0 and output == b"")
    return {"compiled": True, "qualification": "none", "loadRun": False, "childCleanupVerified": True}


def proc_bytes(directory: int, leaf: str, limit: int = 8192) -> bytes:
    """Read a fixed leaf through one held proc directory, with cap-plus-one enforcement."""
    require(leaf in {"stat", "status", "cgroup", "cmdline", "attr/apparmor/current"})
    descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        raw = os.read(descriptor, limit + 1)
        require(len(raw) <= limit)
        return raw
    finally:
        os.close(descriptor)


def task_snapshot(directory: int, pid: int, uid: int = 0) -> dict[str, Any]:
    """Bind a live root main task without splitting its parenthesized comm incorrectly."""
    filesystem_magic(directory, 0x9FA0)
    raw = proc_bytes(directory, "stat")
    opening, closing = raw.find(b"("), raw.rfind(b")")
    require(opening > 0 and closing > opening and raw[:opening].strip() == str(pid).encode())
    fields = raw[closing + 1 :].split()
    require(len(fields) > START_FIELD and fields[0] not in {b"Z", b"X", b"x"} and fields[START_FIELD].isdigit())
    status = {}
    for line in proc_bytes(directory, "status").splitlines():
        key, separator, value = line.partition(b":")
        if key in {b"Pid", b"Tgid", b"Uid"}:
            require(separator and key not in status)
            status[key] = value.split()
    require(status == {b"Pid": [str(pid).encode()], b"Tgid": [str(pid).encode()], b"Uid": [str(uid).encode()] * 4})
    return {
        "pid": pid,
        "startTicks": int(fields[START_FIELD]),
        "cgroup": proc_bytes(directory, "cgroup").decode("ascii"),
    }


def filesystem_magic(descriptor: int, expected: int) -> None:
    """Require a held directory on the reviewed kernel pseudo filesystem."""
    # Linux statfs starts with native signed long f_type; the oversized aligned
    # buffer accommodates all supported kernel structures without ABI truncation.
    buffer = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.fstatfs(descriptor, ctypes.byref(buffer)) == 0 and buffer[0] == expected)


def namespace_snapshot(_modules: SimpleNamespace, admission: dict[str, Any]) -> dict[str, Any]:
    """Read fresh actor namespace facts through a held genuine securityfs root."""
    expected = admission.get("policyNamespace")
    require(expected == {"name": "root\n", "level": "0\n", "stacked": "no\n"})
    require(
        admission.get("parserExecutionNamespace")
        == {
            "kind": "reviewed-trusted-fixed-os-no-parser-exec-transition-assumption",
            "measuredPostExec": False,
            "requirement": (
                "Fresh actor namespace opens before invoking the held reviewed parser; "
                "no claim of post-exec parser namespace measurement"
            ),
        }
    )
    directory = os.open("/sys/kernel/security/apparmor", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    observed = {}
    try:
        filesystem_magic(directory, 0x73636673)
        for key, leaf in (("name", ".ns_name"), ("level", ".ns_level"), ("stacked", ".stacked")):
            descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                require(stat.S_ISREG(os.fstat(descriptor).st_mode))
                raw = os.read(descriptor, MAX_NAMESPACE + 1)
                require(len(raw) <= MAX_NAMESPACE and raw == expected[key].encode("ascii"))
                observed[key] = digest(raw)
            finally:
                os.close(descriptor)
    finally:
        os.close(directory)
    descriptor = os.open(f"/proc/{os.getpid()}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        filesystem_magic(descriptor, 0x9FA0)
        require(proc_bytes(descriptor, "attr/apparmor/current", 4096) == b"unconfined\n")
    finally:
        os.close(descriptor)
    for kind in ("user", "mnt", "cgroup"):
        current, init = Path("/proc/self/ns") / kind, Path("/proc/1/ns") / kind
        require(current.stat().st_ino == init.stat().st_ino)
        observed[kind] = current.stat().st_ino
    return observed


class RootPort:
    """Concrete fixed root operations under one immutable phase and locked lease."""

    def __init__(
        self, stage: Path, bootstrap: dict[str, Any], modules: SimpleNamespace, store: Store, record: dict[str, Any]
    ) -> None:
        """Consume only an already authenticated stage and phase record."""
        self.stage, self.bootstrap, self.modules, self.store, self.record = stage, bootstrap, modules, store, record
        self.binding = modules.qualification.NativeBinding(**record["binding"])
        self.binding.validate()
        self.admission = json.loads(
            root_bytes(stage / ".github/docker-userns-active-admission.json"), object_pairs_hook=unique
        )
        self.work_until = self.binding.deadline_ns - RESERVE_NS - FINALIZER_HEADSTART_NS
        self.cleanup = False
        self.provider = record["timeoutExecutable"]
        require(self.provider in {"/usr/bin/gnutimeout", "/usr/bin/timeout"})

    def commit(self) -> None:
        """Preserve all uncertainty before returning any result or acquiring further authority."""
        self.store.write(self.record)

    def query(self, arguments: list[str], *, pass_fds: tuple[int, ...] = ()) -> bytes:
        """Reuse the owned query group, original deadline and affirmative drain protocol."""
        end = self.binding.deadline_ns if self.cleanup else self.work_until
        check(end)
        self.record["readerPending"] = True
        self.commit()
        protocol = self.modules.capture._query_capture(  # noqa: SLF001 - preserve reviewed ownership/drain semantics.
            ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", *arguments],
            end / 1_000_000_000,
            self.provider,
            pass_fds=pass_fds,
        )
        require(protocol.get("teardownVerified") is True)
        self.record["readerPending"] = False
        self.commit()
        require(protocol.get("status") == "available")
        raw = base64.b64decode(protocol["data"], validate=True)
        require(len(raw) <= MAX_OUTPUT)
        check(end)
        return raw

    def docker(self, *arguments: str) -> bytes:
        """Use only the exact private socket and a root-owned empty CLI configuration."""
        directory = self.record["daemonDirectory"]
        require(re.fullmatch(re.escape(PRIVATE_RUNTIME_PREFIX) + r"[A-Za-z0-9_-]{8,32}", directory))
        return self.query(
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C",
                "LC_ALL=C",
                "/usr/bin/docker",
                "--config",
                str(self.store.path / "cli"),
                "--host",
                "unix://" + directory + "/docker.sock",
                "--tls=false",
                *arguments,
            ]
        )

    def daemon(self) -> None:
        """Rebind the exact rootful private daemon before every subject operation."""
        directory = Path(self.record["daemonDirectory"])
        socket = (directory / "docker.sock").lstat()
        require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_nlink == 1)
        socket_identity = (socket.st_dev, socket.st_ino)
        raw = self.docker("info", "--format", "{{json .DockerRootDir}}|{{json .SecurityOptions}}")
        root, separator, security = raw.decode("ascii").strip().partition("|")
        options = json.loads(security)
        require(
            separator
            and json.loads(root) == self.record["daemonDirectory"] + "/root"
            and type(options) is list
            and all(type(value) is str for value in options)
            and not any("rootless" in value for value in options)
        )
        info = Path("/sys/fs/cgroup", self.binding.runtime_slice).lstat()
        require(f"{info.st_dev}:{info.st_ino}" == self.binding.slice_identity)
        unit = "strukturpiloten-" + self.binding.owner + "-dockerd.service"
        properties = self.query(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--no-pager",
                "--property=Description,MainPID,ActiveState,ControlGroup,Transient",
            ]
        )
        fields = dict(line.split("=", 1) for line in properties.decode("ascii").splitlines())
        require(
            fields["Description"] == self.binding.owner
            and fields["ActiveState"] == "active"
            and fields["Transient"] == "yes"
            and fields["ControlGroup"] == "/" + self.binding.runtime_slice + "/" + unit
            and re.fullmatch(r"[1-9][0-9]{0,9}", fields["MainPID"])
        )
        descriptor = os.open("/proc/" + fields["MainPID"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = task_snapshot(descriptor, int(fields["MainPID"]))
            command = proc_bytes(descriptor, "cmdline").rstrip(b"\0").split(b"\0")
            require(
                len(command) == DOCKERD_ARGC
                and command[0] in {b"/usr/bin/dockerd", b"/usr/sbin/dockerd"}
                and command[1:] == [b"--config-file", str(directory / "daemon.json").encode()]
            )
            config = self.modules.source.snapshot(directory / "daemon.json", MAX_STATE, self.bootstrap["uid"])
            require(
                json.loads(config.data, object_pairs_hook=unique)
                == {
                    "data-root": str(directory / "root"),
                    "exec-root": str(directory / "runroot"),
                    "pidfile": str(directory / "daemon.pid"),
                    "hosts": ["unix://" + str(directory / "docker.sock")],
                    "containerd": str(directory / "containerd.sock"),
                    "containerd-namespace": "moby",
                    "containerd-plugins-namespace": "plugins.moby",
                    "bridge": "none",
                    "iptables": False,
                    "ip6tables": False,
                    "ip-forward": False,
                    "ip-masq": False,
                    "userland-proxy": True,
                    "features": {"containerd-snapshotter": False},
                    "exec-opts": ["native.cgroupdriver=systemd"],
                    "cgroup-parent": self.binding.runtime_slice,
                }
            )
            require(
                before["cgroup"] == "0::" + fields["ControlGroup"] + "\n"
                and task_snapshot(descriptor, int(fields["MainPID"])) == before
            )
            self.modules.source.recheck(config)
            require(
                ((directory / "docker.sock").lstat().st_dev, (directory / "docker.sock").lstat().st_ino)
                == socket_identity
            )
        finally:
            os.close(descriptor)

    def preflight(self) -> dict[str, Any]:
        """Probe held parser version afresh with durable child lifetime custody."""
        observed = root_preflight(self.stage, self.bootstrap, self.modules)
        end = self.binding.deadline_ns if self.cleanup else self.work_until
        with ExitStack() as stack:
            interpreter = os.open(PYTHON, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, interpreter)
            parser = os.open("/usr/sbin/apparmor_parser", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, parser)
            self.record["childPending"] = True
            self.commit()
            cutoff = min(end - 1_000_000_000, time.monotonic_ns() + 5_000_000_000)
            check(cutoff)
            outcome = self.modules.child.probe(
                self.modules.child.Interpreter(interpreter, self.admission["cohort"]["interpreterSha256"]),
                parser,
                "parser-version",
                self.modules.child.Build("version", self.bootstrap["uid"], self.bootstrap["gid"], cutoff, end),
                Clock(),
            )
            require(outcome.dead is True)
            self.record["childPending"] = False
            self.commit()
            require(re.fullmatch(rb"AppArmor parser version 5\.0\.2\n[^\x00]{0,900}", outcome.policy))
            observed["parserVersion"] = "5.0.2"
        return observed

    def image(self) -> None:
        """Require the actual private daemon's immutable image before policy load."""
        value = json.loads(
            self.docker("image", "inspect", "--format", "{{json .}}", self.binding.config_digest),
            object_pairs_hook=unique,
        )
        require(
            value["Id"] == self.binding.config_digest
            and value["Architecture"] == self.binding.architecture
            and value["Os"] == "linux"
            and value["Config"]["Labels"]["org.opencontainers.image.revision"] == self.binding.candidate
        )

    def admit(self, binding: NativeBinding) -> None:
        """Freshly admit source, fixed content, current scalar controls and same-job provenance."""
        require(binding.digest() == self.record["bindingSha256"])
        context = self.bootstrap["context"]
        require(
            binding.candidate == context["candidate"]
            and binding.run == context["run"]
            and binding.attempt == context["attempt"]
            and binding.job == context["job"]
            and binding.architecture == context["architecture"]
            and binding.image == context["image"]
            and binding.deadline_ns <= self.bootstrap["deadlineNs"]
        )
        observed = self.preflight()
        self.record["preflight"] = observed
        self.commit()
        require(
            binding.architecture == "amd64"
            and self.admission["architectures"]["amd64"] == "experimental-load-candidate"
        )
        for path in (
            Path("/usr/bin/gnutimeout") if self.provider.endswith("gnutimeout") else Path("/usr/bin/timeout"),
            Path("/usr/bin/docker"),
            Path("/usr/bin/systemctl"),
            Path("/usr/bin/systemd-run"),
        ):
            self.modules.host.safe_path(path)
        banner = self.query([self.provider, "--version"]).splitlines()[0]
        require(re.fullmatch(rb"(?:gnu)?timeout \(GNU coreutils\) [0-9]+(?:\.[0-9]+)+", banner))
        self.daemon()
        self.image()
        with ExitStack() as stack:
            interpreter = os.open(PYTHON, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, interpreter)
            sealed = []
            manifest = json.loads(
                root_bytes(self.stage / ".github/docker-userns-policy-source.json"), object_pairs_hook=unique
            )
            for module, spec in zip(self.modules.child.MODULES, manifest["source"]["files"][:2], strict=True):
                raw = root_bytes(self.stage / "sdk" / Path(spec["path"]).name, 65536)
                require(digest(raw) == spec["sha256"] and len(raw) == spec["size"])
                source = self.modules.child.seal(module, raw)
                stack.callback(os.close, source.descriptor)
                sealed.append(source)
            self.record["childPending"] = True
            self.commit()
            outcome = self.modules.child.build(
                self.modules.child.Interpreter(interpreter, self.admission["cohort"]["interpreterSha256"]),
                tuple(sealed),
                self.modules.child.Build(
                    self.record["profileName"],
                    self.bootstrap["uid"],
                    self.bootstrap["gid"],
                    min(self.work_until, time.monotonic_ns() + 5_000_000_000),
                    binding.deadline_ns,
                ),
                Clock(),
            )
            require(outcome.dead is True)
            self.record["childPending"] = False
            self.record["policySha256"] = digest(outcome.policy)
            self.commit()
            write_leaf(self.store.path, "policy", outcome.policy)
        self.record["childPending"] = True
        self.commit()
        compiled = json.loads(
            self.query(
                [
                    PYTHON,
                    "-I",
                    "-B",
                    "-S",
                    str(self.stage / "scripts/docker_userns_active.py"),
                    "compile",
                    str(self.stage),
                    self.store.path.name,
                ]
            ),
            object_pairs_hook=unique,
        )
        require(compiled == {"compiled": True, "qualification": "none", "loadRun": False, "childCleanupVerified": True})
        self.record["childPending"] = False
        self.record["compiled"] = True
        self.commit()

    def guard(self, binding: NativeBinding) -> None:
        """Recheck immutable source, kernel controls, namespace and independent finalizer."""
        check(binding.deadline_ns if self.cleanup else self.work_until)
        verify_stage(self.stage)
        require(digest(root_bytes(self.stage / "bootstrap.json")) == self.record["bootstrapSha256"])
        require(not self.record["readerPending"] and not self.record["childPending"])
        current = self.preflight()
        require(current == self.record["preflight"])
        namespace = namespace_snapshot(self.modules, self.admission)
        if "namespace" in self.record:
            require(namespace == self.record["namespace"])
        else:
            self.record["namespace"] = namespace
            self.commit()
        require(self.record.get("cleanOwnerVerified") is True and self.record.get("ownerReady") is True)
        self.verify_owner("owner")
        self.daemon()
        self.image()

    def persist(self, state: State, container: str | None) -> None:
        """Persist complete context plus intent before its corresponding external effect."""
        self.record["state"], self.record["container"] = state.value, container
        self.record["generation"] += 1
        self.commit()

    def registry(self) -> list[bytes]:
        """Read only the admitted policy namespace's finite profile registry."""
        raw, _ = self.modules.host.read_root(Path("/sys/kernel/security/apparmor/profiles"), MAX_OUTPUT)
        return raw.splitlines(keepends=True)

    def profile_present(self) -> bool:
        """Only the exact canonical name and reviewed unconfined mode match."""
        expected = self.record["profileName"].encode() + b" (unconfined)\n"
        return self.registry().count(expected) == 1

    def profile_absent(self) -> bool:
        """Absence excludes every mode and similarly named stacked/namespace label."""
        name = self.record["profileName"].encode()
        return not any(line == name + b"\n" or line.startswith((name + b" ", name + b"//")) for line in self.registry())

    def parser(self, mode: str) -> None:
        """Run the held exact parser with held policy input; no replace or wildcard operation."""
        require(mode in {"--add", "--remove"} and self.record["compiled"] is True)
        require(namespace_snapshot(self.modules, self.admission) == self.record["namespace"])
        self.verify_owner("owner")
        with self.modules.source.hold_executable(Path("/usr/sbin/apparmor_parser"), 16 * 1024 * 1024, 0) as parser:
            require(parser.file.public()["sha256"] == self.admission["cohort"]["parserSha256"])
            descriptor = os.open(self.store.path / "policy", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(digest(root_bytes(self.store.path / "policy", 1024)) == self.record["policySha256"])
                output = self.query(
                    [
                        f"/proc/self/fd/{parser.descriptor}",
                        *self.modules.compiler.COMMON,
                        mode,
                        f"/proc/self/fd/{descriptor}",
                    ],
                    pass_fds=(parser.descriptor, descriptor),
                )
                require(output == b"")
                parser.check()
            finally:
                os.close(descriptor)

    def load(self) -> None:
        """Never replace a collision or guess whether an unacknowledged load succeeded."""
        require(self.profile_absent())
        self.parser("--add")
        require(self.profile_present())

    def inspect(self, container: str) -> dict[str, Any]:
        """Read only the exact CID through the fresh private endpoint."""
        require(re.fullmatch(r"[0-9a-f]{64}", container))
        raw = self.docker("inspect", "--format", "{{json .}}", container)
        value = json.loads(raw, object_pairs_hook=unique)
        require(
            value["Id"] == container
            and value["Image"] == self.binding.config_digest
            and value["Config"]["Labels"]["io.strukturpiloten.runtime"] == self.binding.owner
            and value["Config"]["Labels"]["io.strukturpiloten.userns-profile"] == self.store.path.name
            and value["Config"]["Labels"]["org.opencontainers.image.revision"] == self.binding.candidate
            and value["HostConfig"]["CgroupParent"] == self.binding.runtime_slice
            and value["AppArmorProfile"] == self.record["profileName"]
        )
        return value

    def bind_subject(self, container: str, binding: NativeBinding) -> None:
        """Verify before/after through one held task and exact container incarnation."""
        self.daemon()
        namespace = namespace_snapshot(self.modules, self.admission)
        before = self.inspect(container)
        pid = before["State"]["Pid"]
        require(type(pid) is int and pid > 0 and before["State"]["Running"] is True)
        descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pidfd = os.pidfd_open(pid)
        try:
            first = task_snapshot(descriptor, pid)
            expected = "0::/" + binding.runtime_slice + "/docker-" + container + ".scope"
            require(
                re.fullmatch(re.escape(expected) + r"(?:/[A-Za-z0-9_.@:-]+)*\n", first["cgroup"])
                and not any(part in {".", ".."} for part in first["cgroup"].split("/"))
            )
            raw = proc_bytes(descriptor, "attr/apparmor/current", 4096)
            match = raw == self.record["profileName"].encode() + b" (unconfined)\n"
            self.record["profileObservation"] = {
                "source": "held-task-attr/apparmor/current",
                "bytes": len(raw),
                "sha256": digest(raw),
                "exactMatch": match,
                "singleLabel": b"//&" not in raw,
                "timing": "post-create",
                "taskIdentityBound": True,
            }
            if not match:
                write_leaf(self.store.path, "profile-mismatch.bin", raw)
            self.commit()
            require(
                match
                and not select.select([pidfd], [], [], 0)[0]
                and task_snapshot(descriptor, pid) == first
                and proc_bytes(descriptor, "attr/apparmor/current", 4096) == raw
                and namespace_snapshot(self.modules, self.admission) == namespace
            )
            after = self.inspect(container)
            require(
                after["State"]["Pid"] == pid
                and after["State"]["StartedAt"] == before["State"]["StartedAt"]
                and after["State"]["Running"] is True
            )
            self.record["subject"] = {
                "container": container,
                "pid": pid,
                "startTicks": first["startTicks"],
                "startedAt": before["State"]["StartedAt"],
                "cgroup": first["cgroup"],
            }
            self.commit()
        finally:
            os.close(pidfd)
            os.close(descriptor)

    def subject_task_absent(self) -> None:
        """Prove the bound task incarnation and its exact recursive scope are absent."""
        subject = self.record.get("subject")
        if subject is None:
            require(self.record.get("container") is None)
            return
        pid = subject["pid"]
        try:
            descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            require(error.errno == errno.ENOENT)
        else:
            try:
                raw = proc_bytes(descriptor, "stat")
                closing = raw.rfind(b")")
                require(closing > 0 and raw[: raw.find(b"(")].strip() == str(pid).encode())
                fields = raw[closing + 1 :].split()
                require(len(fields) > START_FIELD and fields[START_FIELD].isdigit())
                require(int(fields[START_FIELD]) != subject["startTicks"] or fields[0] in {b"Z", b"X", b"x"})
                require(proc_bytes(descriptor, "stat") == raw)
            finally:
                os.close(descriptor)
        self.subject_scope_absent(subject)
        self.record["taskAbsenceVerified"] = True
        self.record["scopeAbsenceVerified"] = True
        self.commit()

    def subject_scope_absent(self, subject: dict[str, Any]) -> None:
        """Require the exact guest scope absent or recursively unpopulated."""
        directory = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            filesystem_magic(directory, 0x63677270)
            runtime = os.open(
                self.binding.runtime_slice,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                info = os.fstat(runtime)
                require(f"{info.st_dev}:{info.st_ino}" == self.binding.slice_identity)
                leaf = "docker-" + subject["container"] + ".scope"
                try:
                    scope = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=runtime)
                except OSError as error:
                    require(error.errno == errno.ENOENT)
                else:
                    try:
                        events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope)
                        try:
                            raw = os.read(events, 257)
                            require(raw in {b"populated 0\nfrozen 0\n", b"populated 0\nfrozen 1\n"})
                        finally:
                            os.close(events)
                    finally:
                        os.close(scope)
            finally:
                os.close(runtime)
        finally:
            os.close(directory)

    def remove_subject(self, container: str | None) -> None:
        """Prove exact guest absence while the independently verified endpoint is still alive."""
        self.cleanup = True
        self.daemon()
        if container is not None:
            ids = self.docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + container).splitlines()
            require(ids in ([], [container.encode()]))
            if ids:
                self.inspect(container)
                self.docker("rm", "--force", "--volumes", container)
            require(self.docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + container) == b"")
        require(
            self.docker(
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                "label=io.strukturpiloten.userns-profile=" + self.store.path.name,
            )
            == b""
        )
        self.daemon()
        self.subject_task_absent()
        self.record["guestAbsenceVerified"] = True
        self.commit()

    def unload(self) -> None:
        """Unloading follows affirmative absence, never a failed or unavailable inspect."""
        require(self.record.get("guestAbsenceVerified") is True and self.profile_present())
        self.parser("--remove")
        require(self.profile_absent())
        self.record["profileAbsenceVerified"] = True
        self.commit()

    def retain(self) -> None:
        """Keep the original intent and every uncertain reader/load/create outcome sticky."""
        self.record["retained"] = True
        self.record["state"] = "retained"
        self.commit()

    def owner_unit(self, kind: str) -> str:
        """Select only this lease's two fixed transient owners."""
        require(kind in {"probe", "owner"})
        return "containers-userns-active-" + self.store.path.name + "-" + kind + ".service"

    def start_owner(self, kind: str) -> dict[str, Any]:
        """Persist exact source/argv/time intent before starting an independent root owner."""
        unit = self.owner_unit(kind)
        arguments = [
            PYTHON,
            "-I",
            "-B",
            "-S",
            str(self.stage / "scripts/docker_userns_active.py"),
            "owner",
            str(self.stage),
            self.store.path.name,
            kind,
        ]
        before = self.query(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"]).strip()
        require(before == b"not-found" and not (self.store.path / (kind + "-ready.json")).exists())
        runtime_us = ((self.binding.deadline_ns - time.monotonic_ns()) // 1_000_000_000 - 2) * 1_000_000
        require(runtime_us > 0)
        self.record.setdefault("ownerIntents", {})[kind] = {
            "unit": unit,
            "argv": arguments,
            "bindingSha256": self.binding.digest(),
            "deadlineNs": self.binding.deadline_ns,
            "workUntilNs": self.work_until,
            "description": self.binding.digest(),
            "runtimeUs": runtime_us,
        }
        self.commit()
        self.query(
            [
                "/usr/bin/systemd-run",
                "--quiet",
                "--unit=" + unit,
                "--slice=system.slice",
                "--property=Description=" + self.binding.digest(),
                "--property=Type=exec",
                "--property=User=root",
                "--property=Group=root",
                "--property=Restart=no",
                "--property=RemainAfterExit=yes",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                f"--property=RuntimeMaxSec={runtime_us}us",
                "--property=TimeoutStopSec=1s",
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C",
                "LC_ALL=C",
                *arguments,
            ]
        )
        ready_path = self.store.path / (kind + "-ready.json")
        while not ready_path.exists():
            check(self.work_until)
            time.sleep(min(0.01, (self.work_until - time.monotonic_ns()) / 1_000_000_000))
        ready = json.loads(root_bytes(ready_path), object_pairs_hook=unique)
        require(
            set(ready)
            == {"schemaVersion", "bindingSha256", "deadlineNs", "pid", "startTicks", "pgid", "cgroup", "namespace"}
            and ready["schemaVersion"] == 1
            and ready["bindingSha256"] == self.binding.digest()
            and ready["deadlineNs"] == self.binding.deadline_ns
            and type(ready["pid"]) is int
            and ready["pid"] > 0
            and ready["cgroup"] == "0::/system.slice/" + unit + "\n"
            and ready["namespace"] == namespace_snapshot(self.modules, self.admission)
        )
        self.record.setdefault("owners", {})[kind] = ready
        self.commit()
        self.verify_owner(kind)
        return ready

    def owner_handle(self, kind: str) -> int:
        """Acquire a pidfd before permitting the independently owned task to exit."""
        ready = self.record["owners"][kind]
        descriptor = os.open(f"/proc/{ready['pid']}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pidfd = os.pidfd_open(ready["pid"])
        try:
            current = task_snapshot(descriptor, ready["pid"])
            require(proc_bytes(descriptor, "attr/apparmor/current", 4096) == b"unconfined\n")
            for kind_name in ("user", "mnt", "cgroup"):
                info = os.stat("ns/" + kind_name, dir_fd=descriptor, follow_symlinks=True)
                require(info.st_ino == ready["namespace"][kind_name])
            require(
                current["startTicks"] == ready["startTicks"]
                and current["cgroup"] == ready["cgroup"]
                and os.getpgid(ready["pid"]) == ready["pgid"]
                and ready["pgid"] != self.record["coordinatorPgid"]
                and ready["pid"] != self.record["coordinatorPid"]
                and proc_bytes(descriptor, "cmdline").rstrip(b"\0").split(b"\0")
                == [arg.encode() for arg in self.record["ownerIntents"][kind]["argv"]]
                and not select.select([pidfd], [], [], 0)[0]
                and task_snapshot(descriptor, ready["pid"]) == current
            )
        except BaseException:
            os.close(pidfd)
            raise
        else:
            return pidfd
        finally:
            os.close(descriptor)

    def verify_owner(self, kind: str) -> None:
        """Revalidate the exact independent finalizer before each policy operation."""
        pidfd = self.owner_handle(kind)
        try:
            raw = self.query(
                [
                    "/usr/bin/systemctl",
                    "show",
                    self.owner_unit(kind),
                    "--no-pager",
                    "--property=LoadState,Description,Transient,ActiveState,MainPID,ControlGroup,KillMode,SendSIGKILL,RemainAfterExit,Restart,User,Group,Type,Slice,FragmentPath,DropInPaths,ActiveEnterTimestampMonotonic,RuntimeMaxUSec,TimeoutStopUSec",
                ]
            )
            fields = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines())
            durations = {
                key: fields.pop(key) for key in ("ActiveEnterTimestampMonotonic", "RuntimeMaxUSec", "TimeoutStopUSec")
            }
            runtime = self.record["ownerIntents"][kind]["runtimeUs"]
            require(durations["ActiveEnterTimestampMonotonic"].isdigit())
            require(duration_us(durations["RuntimeMaxUSec"]) == runtime)
            require(duration_us(durations["TimeoutStopUSec"]) == MICROSECONDS)
            require(
                (int(durations["ActiveEnterTimestampMonotonic"]) + runtime + 1_000_000) * 1000
                <= self.binding.deadline_ns
            )
            require(
                fields
                == {
                    "LoadState": "loaded",
                    "Description": self.binding.digest(),
                    "Transient": "yes",
                    "ActiveState": "active",
                    "MainPID": str(self.record["owners"][kind]["pid"]),
                    "ControlGroup": "/system.slice/" + self.owner_unit(kind),
                    "KillMode": "control-group",
                    "SendSIGKILL": "yes",
                    "RemainAfterExit": "yes",
                    "Restart": "no",
                    "User": "root",
                    "Group": "root",
                    "Type": "exec",
                    "Slice": "system.slice",
                    "FragmentPath": "/run/systemd/transient/" + self.owner_unit(kind),
                    "DropInPaths": "",
                }
            )
            fragment, identity = self.modules.host.read_root(Path(fields["FragmentPath"]), MAX_OUTPUT)
            observed = {"sha256": digest(fragment), "identity": asdict(identity)}
            previous = self.record.setdefault("ownerFragments", {}).get(kind)
            if previous is None:
                self.record["ownerFragments"][kind] = observed
                self.commit()
            else:
                require(previous == observed)
            require(not select.select([pidfd], [], [], 0)[0])
        finally:
            os.close(pidfd)

    def finish_owner(self, kind: str) -> None:
        """Hold the exact owner through release, normal completion and unit absence."""
        pidfd = self.owner_handle(kind)
        unit = self.owner_unit(kind)
        try:
            self.verify_owner(kind)
            write_leaf(self.store.path, kind + "-release", (self.binding.digest() + "\n").encode())
            while not select.select([pidfd], [], [], 0)[0]:
                check(self.binding.deadline_ns if self.cleanup else self.work_until)
                time.sleep(0.01)
            fields = dict(
                line.split("=", 1)
                for line in self.query(
                    [
                        "/usr/bin/systemctl",
                        "show",
                        unit,
                        "--no-pager",
                        "--property=Description,Transient,MainPID,ActiveState,SubState,ExecMainCode,ExecMainStatus",
                    ]
                )
                .decode("ascii")
                .splitlines()
            )
            require(
                fields
                == {
                    "Description": self.binding.digest(),
                    "Transient": "yes",
                    "MainPID": "0",
                    "ActiveState": "active",
                    "SubState": "exited",
                    "ExecMainCode": "1",
                    "ExecMainStatus": "0",
                }
            )
            receipt = json.loads(root_bytes(self.store.path / (kind + "-closed.json")), object_pairs_hook=unique)
            require(
                receipt
                == {
                    "schemaVersion": 1,
                    "bindingSha256": self.binding.digest(),
                    "cause": "normal",
                    "policyMutation": kind == "owner",
                    "deadlineNs": self.binding.deadline_ns,
                }
            )
            self.query(["/usr/bin/systemctl", "stop", unit])
            require(
                self.query(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"]).strip()
                == b"not-found"
            )
            require(not Path("/sys/fs/cgroup/system.slice", unit).exists())
        finally:
            os.close(pidfd)

    def clean_owner(self, binding: NativeBinding) -> None:
        """Prove the new contract's same-source/VM no-policy owner cycle before arming load."""
        require(binding.digest() == self.record["bindingSha256"] and self.record["state"] == "prepared")
        self.record["namespace"] = namespace_snapshot(self.modules, self.admission)
        self.commit()
        self.start_owner("probe")
        write_leaf(self.store.path, "probe-close", (binding.digest() + "\n").encode())
        self.finish_owner("probe")
        self.record["cleanOwnerVerified"] = True
        self.commit()

    def arm(self, binding: NativeBinding) -> None:
        """Require an affirmative independent ready record before a load intent."""
        require(
            binding.digest() == self.record["bindingSha256"]
            and self.record["cleanOwnerVerified"] is True
            and self.record["state"] == "arm-intent"
        )
        self.start_owner("owner")
        self.record["ownerReady"] = True
        self.commit()

    def dispose(self) -> None:
        """Dispose only after the finalizer and every query have affirmative completion."""
        require(
            self.record["state"] == "closed"
            and not self.record["readerPending"]
            and not self.record["childPending"]
            and self.record["guestAbsenceVerified"] is True
            and self.record["profileAbsenceVerified"] is True
            and not self.record["retained"]
        )
        self.finish_owner("owner")
        self.record["ownerTerminationVerified"] = True
        self.commit()
        known = {
            "lock",
            "state.json",
            "policy",
            "probe-ready.json",
            "probe-close",
            "probe-release",
            "probe-closed.json",
            "owner-ready.json",
            "owner-release",
            "owner-closed.json",
            "cli",
        }
        require({path.name for path in self.store.path.iterdir()} == known)
        require({path.name for path in (self.store.path / "cli").iterdir()} == {"config.json"})
        require(root_bytes(self.store.path / "cli/config.json") == b"{}\n")
        (self.store.path / "cli/config.json").unlink()
        (self.store.path / "cli").rmdir()
        for name in sorted(known - {"cli"}):
            root_bytes(self.store.path / name)
            (self.store.path / name).unlink()
        self.store.path.rmdir()
        self.record["custodyDisposed"] = True


def duration_us(raw: str) -> int:
    """Parse only finite systemctl duration tokens, never infinity or fractions."""
    factors = {"h": 3_600_000_000, "min": 60_000_000, "s": 1_000_000, "ms": 1000, "us": 1}
    tokens = raw.split(" ")
    require(1 <= len(tokens) <= len(factors))
    result, previous = 0, 3_600_000_001
    for token in tokens:
        match = re.fullmatch(r"([0-9]{1,12})(h|min|s|ms|us)", token)
        require(match is not None)
        factor = factors[match[2]]
        require(factor < previous)
        previous = factor
        result += int(match[1]) * factor
    return result


def owner_released(port: RootPort, kind: str) -> bool:
    """Read the quiescent terminal handshake without taking the coordinator's lock."""
    store, binding = port.store, port.binding
    release = store.path / (kind + "-release")
    if not release.exists():
        return False
    require(root_bytes(release) == (binding.digest() + "\n").encode())
    if kind == "probe":
        require(root_bytes(store.path / "probe-close") == (binding.digest() + "\n").encode())
    else:
        current = store.read()
        require(
            current["state"] == "closed"
            and current.get("guestAbsenceVerified") is True
            and current.get("profileAbsenceVerified") is True
            and not current["retained"]
            and not current["readerPending"]
            and not current["childPending"]
        )
    return True


def owner_retained(port: RootPort, kind: str, cause: str) -> int:
    """Publish sticky uncertainty independently of a contended mutable snapshot."""
    require(cause in {"cancelled", "coordinator-dead", "deadline", "work-expired", "cleanup-unverified"})
    write_leaf(
        port.store.path,
        kind + "-retained.json",
        encoded(
            {
                "schemaVersion": 1,
                "bindingSha256": port.binding.digest(),
                "deadlineNs": port.binding.deadline_ns,
                "cause": cause,
                "retained": True,
            }
        ),
    )
    return 1


def owner_try_cleanup(port: RootPort) -> bool:
    """Retry only failed lock acquisition; never retry an uncertain cleanup effect."""
    entered = False
    try:
        with port.store.locked():
            entered = True
            current = port.store.read()
            port.record = current
            port.cleanup = True
            safe = current["state"] in {"loaded", "attached"}
            if safe and not current["readerPending"] and not current["childPending"] and not current["retained"]:
                try:
                    port.guard(port.binding)
                    port.remove_subject(current.get("container"))
                    port.persist(port.modules.qualification.State.UNLOAD_INTENT, current.get("container"))
                    port.unload()
                finally:
                    port.retain()
            else:
                port.retain()
    except BlockingIOError as error:
        if entered or error.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
            raise
        return False
    return True


def owner_cause(current: str | None, coordinator: int, cancelled: list[bool]) -> str | None:
    """Latch the first cancellation cause across every nonblocking lock retry."""
    if current is not None:
        return current
    if cancelled[0]:
        return "cancelled"
    if select.select([coordinator], [], [], 0)[0]:
        return "coordinator-dead"
    return None


def owner_terminal_cause(current: str | None, deadline_ns: int, coordinator: int, cancelled: list[bool]) -> str | None:
    """Latch cancellation and original-deadline expiry around durable terminal output."""
    current = owner_cause(current, coordinator, cancelled)
    if time.monotonic_ns() >= deadline_ns:
        current = current or "deadline"
    return current


def owner_loop(port: RootPort, coordinator: int, kind: str, cancelled: list[bool]) -> int:
    """Retry contention within original D while preserving release and cancellation."""
    binding = port.binding
    cause: str | None = None
    while True:
        cause = owner_cause(cause, coordinator, cancelled)
        now = time.monotonic_ns()
        if now >= binding.deadline_ns:
            return owner_retained(port, kind, cause or "deadline")
        if owner_released(port, kind):
            cause = owner_terminal_cause(cause, binding.deadline_ns, coordinator, cancelled)
            if cause is not None:
                return owner_retained(port, kind, cause)
            write_leaf(
                port.store.path,
                kind + "-closed.json",
                encoded(
                    {
                        "schemaVersion": 1,
                        "bindingSha256": binding.digest(),
                        "cause": "normal",
                        "policyMutation": kind == "owner",
                        "deadlineNs": binding.deadline_ns,
                    }
                ),
            )
            cause = owner_terminal_cause(cause, binding.deadline_ns, coordinator, cancelled)
            if cause is not None:
                return owner_retained(port, kind, cause)
            return 0
        if cause is not None or now >= port.work_until:
            try:
                completed = owner_try_cleanup(port)
            except Exception, KeyboardInterrupt:  # noqa: BLE001 - uncertainty never grants another effect attempt.
                return owner_retained(port, kind, cause or "cleanup-unverified")
            if completed:
                return owner_retained(port, kind, cause or "work-expired")
        remaining = binding.deadline_ns - time.monotonic_ns()
        if remaining > 0:
            time.sleep(min(0.02, remaining / 1_000_000_000))


def owner_main(stage: Path, bootstrap: dict[str, Any], modules: SimpleNamespace, name: str, kind: str) -> int:
    """Run independently of coordinator and runtime slice under the original expiry."""
    require(kind in {"probe", "owner"})
    store = Store(stage, name)
    try:
        record = store.read()
        port = RootPort(stage, bootstrap, modules, store, record)
        binding = port.binding
        require(binding.digest() == record["bindingSha256"] and binding.deadline_ns <= bootstrap["deadlineNs"])
        unit = port.owner_unit(kind)
        descriptor = os.open(f"/proc/{os.getpid()}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            observed = task_snapshot(descriptor, os.getpid())
        finally:
            os.close(descriptor)
        require(observed["cgroup"] == "0::/system.slice/" + unit + "\n" and os.getpgid(0) != record["coordinatorPgid"])
        descriptor = os.open(
            f"/proc/{record['coordinatorPid']}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        coordinator = os.pidfd_open(record["coordinatorPid"])
        try:
            require(task_snapshot(descriptor, record["coordinatorPid"], bootstrap["uid"]) == record["coordinatorTask"])
            require(not select.select([coordinator], [], [], 0)[0])
            require(namespace_snapshot(modules, port.admission) == record["namespace"])
            write_leaf(
                store.path,
                kind + "-ready.json",
                encoded(
                    {
                        "schemaVersion": 1,
                        "bindingSha256": binding.digest(),
                        "deadlineNs": binding.deadline_ns,
                        "pid": os.getpid(),
                        "pgid": os.getpgid(0),
                        "startTicks": observed["startTicks"],
                        "cgroup": observed["cgroup"],
                        "namespace": record["namespace"],
                    }
                ),
            )
            cancelled = [False]

            def cancel(_number: int, _frame: object) -> None:
                cancelled[0] = True

            for number in (signal.SIGTERM, signal.SIGINT):
                signal.signal(number, cancel)
            return owner_loop(port, coordinator, kind, cancelled)
        finally:
            os.close(descriptor)
            os.close(coordinator)
    finally:
        store.close()


def request_value(raw_argument: str) -> dict[str, Any]:
    """Read one bounded request; no root helper imports an untrusted request path."""
    require(len(raw_argument) <= MAX_STATE)
    raw = base64.b64decode(raw_argument, validate=True)
    require(len(raw) <= MAX_STATE)
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict)
    return value


def new_record(
    bootstrap: dict[str, Any], modules: SimpleNamespace, request: dict[str, Any], name: str
) -> dict[str, Any]:
    """Bind a phase to its actual unprivileged coordinator and private runtime."""
    require(set(request) == {"binding", "daemonDirectory", "timeoutExecutable", "coordinatorPid"})
    binding = modules.qualification.NativeBinding(**request["binding"])
    binding.validate()
    check(binding.deadline_ns - RESERVE_NS)
    require(binding.deadline_ns <= bootstrap["deadlineNs"])
    pid = request["coordinatorPid"]
    require(type(pid) is int and pid > 1)
    descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pidfd = os.pidfd_open(pid)
    try:
        task = task_snapshot(descriptor, pid, bootstrap["uid"])
        require(not select.select([pidfd], [], [], 0)[0])
        require(binding.runtime_slice not in task["cgroup"])
        pgid = os.getpgid(pid)
        require(pgid != os.getpgid(0) and task_snapshot(descriptor, pid, bootstrap["uid"]) == task)
    finally:
        os.close(pidfd)
        os.close(descriptor)
    return {
        "schemaVersion": 1,
        "binding": asdict(binding),
        "bindingSha256": binding.digest(),
        "bootstrapSha256": digest(root_bytes(Path(bootstrap["stage"]) / "bootstrap.json")),
        "daemonDirectory": request["daemonDirectory"],
        "timeoutExecutable": request["timeoutExecutable"],
        "coordinatorPid": pid,
        "coordinatorPgid": pgid,
        "coordinatorTask": task,
        "profileName": f"dockerlens-127-upstream-rootless-{binding.run}-{binding.attempt}-{name}",
        "state": "prepared",
        "container": None,
        "generation": 0,
        "readerPending": False,
        "childPending": False,
        "retained": False,
    }


def receipt(port: RootPort) -> dict[str, Any]:
    """Export finite qualification evidence without root records or protected values."""
    record = port.record
    return {
        "schemaVersion": 1,
        "consumer": CONSUMER,
        "qualification": "experimental-candidate-only",
        "binding": asdict(port.binding),
        "bindingSha256": port.binding.digest(),
        "lease": port.store.path.name,
        "profileName": record["profileName"],
        "state": record["state"],
        "sourceManifestSha256": port.admission["sourceManifestSha256"],
        "imageVersion": port.bootstrap["context"]["imageVersion"],
        "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
        "validationProfile": port.bootstrap["context"]["validationProfile"],
        "validationProfileRequested": port.bootstrap["context"]["validationProfileRequested"],
        "parserExecutionNamespace": port.admission["parserExecutionNamespace"],
        "cleanOwnerVerified": record.get("cleanOwnerVerified") is True,
        "ownerReady": record.get("ownerReady") is True,
        "ownerTerminationVerified": record.get("ownerTerminationVerified") is True,
        "custodyDisposed": record.get("custodyDisposed") is True,
        "preflight": record.get("preflight"),
        "namespace": record.get("namespace"),
        "guestAbsenceVerified": record.get("guestAbsenceVerified") is True,
        "taskAbsenceVerified": record.get("taskAbsenceVerified") is True,
        "scopeAbsenceVerified": record.get("scopeAbsenceVerified") is True,
        "profileAbsenceVerified": record.get("profileAbsenceVerified") is True,
        "profileObservation": record.get("profileObservation"),
        "retained": record["retained"],
        "readerPending": record["readerPending"],
        "childPending": record["childPending"],
    }


def root_rpc(
    stage: Path, bootstrap: dict[str, Any], modules: SimpleNamespace, route: argparse.Namespace
) -> dict[str, Any]:
    """Serialize every privileged lifecycle effect through identity-bound custody."""
    operation, name = route.operation, route.name
    request = request_value(route.request)
    create = operation == "prepare"
    if create:
        require(name == "new")
        name = secrets.token_hex(16)
    store = Store(stage, name, create=create)
    try:
        with store.locked():
            if create:
                # Stage is an authenticated root locator, never request authority.
                details = {**bootstrap, "stage": str(stage)}
                record = new_record(details, modules, request, name)
                store.write(record)
                (store.path / "cli").mkdir(mode=0o700)
                write_leaf(store.path / "cli", "config.json", b"{}\n", 0o600)
            else:
                require(set(request) == {"bindingSha256", "container"})
                record = store.read()
                require(request["bindingSha256"] == record["bindingSha256"])
            port = RootPort(stage, bootstrap, modules, store, record)
            lease = modules.qualification.ProfileLease(port.binding, port)
            lease.state = modules.qualification.State(record["state"])
            lease.container = record.get("container")
            if operation == "prepare":
                lease.prepare()
            elif operation == "create-intent":
                require(request["container"] is None)
                lease.create_intent()
            elif operation == "bind":
                lease.bind(request["container"])
            elif operation == "close":
                require(request["container"] is None)
                port.cleanup = True
                lease.close()
            else:
                require(operation in {"prepare", "create-intent", "bind", "close"})
            return receipt(port)
    finally:
        store.close()


@contextmanager
def stage_lock(stage: Path) -> Iterator[None]:
    """Serialize lease creation and stage disposal without authorizing stale paths."""
    identity = stage.lstat()
    descriptor = os.open(stage / "lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == PRIVATE_FILE
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require((stage.lstat().st_dev, stage.lstat().st_ino) == (identity.st_dev, identity.st_ino))
        yield
    finally:
        os.close(descriptor)


def dispose_stage(stage: Path, bootstrap: dict[str, Any]) -> None:
    """Delete authenticated source only after every lease has positively closed."""
    require(not list((stage / "leases").iterdir()))
    require(
        {path.name for path in stage.iterdir()} == {"scripts", ".github", "sdk", "leases", "bootstrap.json", "lock"}
    )
    manifest = json.loads(root_bytes(stage / ".github/docker-userns-policy-source.json"), object_pairs_hook=unique)
    expected = {
        "scripts": {Path(name).name for name in FILES if name.startswith("scripts/")},
        ".github": {Path(name).name for name in FILES if name.startswith(".github/")},
        "sdk": {Path(item["path"]).name for item in manifest["source"]["files"]},
        "leases": set(),
    }
    for directory, leaves in expected.items():
        require({path.name for path in (stage / directory).iterdir()} == leaves)
        for name in leaves:
            root_bytes(stage / directory / name, MAX_SOURCE)
            (stage / directory / name).unlink()
        (stage / directory).rmdir()
    require(bootstrap["stageIdentity"] == [stage.lstat().st_dev, stage.lstat().st_ino])
    root_bytes(stage / "lock")
    (stage / "lock").unlink()
    (stage / "bootstrap.json").unlink()
    stage.rmdir()


def main() -> int:
    """Dispatch only authenticated staged root routes with bounded closed output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("prepare", "create-intent", "bind", "close", "compile", "owner", "dispose-stage")
    )
    parser.add_argument("stage", type=Path)
    parser.add_argument("name", nargs="?", default="new")
    parser.add_argument("kind", nargs="?", choices=("probe", "owner"))
    parser.add_argument("--request", default="e30=")
    args = parser.parse_args()
    try:
        bootstrap = verify_stage(args.stage)
        modules = dependencies(args.stage)
        if args.operation == "compile":
            store = Store(args.stage, args.name)
            try:
                result = compile_worker(bootstrap, modules, store.path)
            finally:
                store.close()
        elif args.operation == "owner":
            return owner_main(args.stage, bootstrap, modules, args.name, args.kind)
        elif args.operation == "dispose-stage":
            with stage_lock(args.stage):
                dispose_stage(args.stage, bootstrap)
            result = {"stageDisposed": True}
        else:
            with stage_lock(args.stage):
                result = root_rpc(args.stage, bootstrap, modules, args)
        sys.stdout.buffer.write(encoded(result))
    except Exception, KeyboardInterrupt:  # noqa: BLE001 - root output must never expose private failures.
        sys.stdout.buffer.write(b'{"error":"active-scoped-profile-refused-or-retained-unknown"}\n')
        return 1
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
