"""Verify and isolate the unchanged DockerLens pure policy builder, without loading policy."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from collections.abc import Iterator

CONSUMER = "containers-ubuntu26-userns-dryparse"
MANIFEST = Path(__file__).resolve().parents[1] / ".github/docker-userns-policy-source.json"
FILES = frozenset({"scripts/native-runner-apparmor.py", "scripts/native_outer_diagnostic_capture.py", "LICENSE"})
MAX_SOURCE = 65536
MAX_POLICY = 1024
PRIVATE_DIRECTORY_MODE = 0o700
HTTP_OK = 200
CANCELLED = False
REASONS = frozenset(
    {
        "artifact-bound",
        "builder-context",
        "builder-output",
        "cancelled",
        "checkout-candidate",
        "checkout-layout",
        "child-cleanup-unverified",
        "child-context",
        "child-input",
        "child-output",
        "child-privilege-receipt",
        "child-streams",
        "cohort-changed",
        "compile-refused",
        "config-changed",
        "config-null",
        "deadline",
        "distribution",
        "duplicate-json-key",
        "event-head",
        "event-pr",
        "event-repository",
        "event-schema",
        "file-capabilities",
        "file-capabilities-unknown",
        "file-changed",
        "fd-exec-unsupported",
        "kernel-context",
        "kernel-features",
        "kernel-policy-context",
        "manifest-consumer",
        "manifest-files",
        "manifest-parser",
        "manifest-schema",
        "manifest-source",
        "oversized",
        "parser-version",
        "process-capabilities",
        "process-facts",
        "root-refused",
        "run-identity",
        "runner-image",
        "source-closure",
        "source-custody",
        "source-custody-changed",
        "source-integrity",
        "source-request",
        "source-response",
        "source-size",
        "unavailable",
        "unreviewed-parser-contract",
        "unsafe-executable",
        "unsafe-file",
        "unsafe-system-path",
        "unsupported-context",
        "workflow-candidate",
    }
)
CHILD_RECEIPT = b'{"activeCapabilities":"zero","boundingSetRequiredZero":false,"noNewPrivs":1,"schemaVersion":1}\n'
HASH = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
CHILD_SETUP = """\
import ctypes, os, re, resource, signal, sys
if os.geteuid() == 0:
    raise SystemExit(1)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
    raise SystemExit(1)
with open("/proc/self/status", "rb") as stream:
    raw = stream.read(8193)
if len(raw) > 8192:
    raise SystemExit(1)
for key in (b"CapEff", b"CapPrm", b"CapInh", b"CapAmb", b"NoNewPrivs"):
    values = [line.split(b":", 1)[1].strip() for line in raw.splitlines() if line.startswith(key + b":")]
    if len(values) != 1 or not re.fullmatch(rb"[0-9a-fA-F]{1,16}", values[0]):
        raise SystemExit(1)
    if int(values[0], 16) != (1 if key == b"NoNewPrivs" else 0):
        raise SystemExit(1)
resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(8)
receipt = b'{"activeCapabilities":"zero","boundingSetRequiredZero":false,"noNewPrivs":1,"schemaVersion":1}\\n'
if os.write(int(sys.argv[1]), receipt) != len(receipt):
    raise SystemExit(1)
os.close(int(sys.argv[1]))
"""
BUILDER = """\
import importlib.util
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("canonical_policy", sys.argv[2] + "/native-runner-apparmor.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
value = module.profile_bytes(sys.argv[3])
if type(value) is not bytes or len(value) > 1024:
    raise SystemExit(1)
sys.stdout.buffer.write(value)
"""


class RefusedError(Exception):
    """Only fixed refusal codes may cross the public diagnostic boundary."""

    def __init__(self, reason: str) -> None:
        """Collapse accidental nonclosed reasons before they reach public evidence."""
        super().__init__(reason if reason in REASONS else "unavailable")


def refuse(reason: str) -> NoReturn:
    """Raise only an implementation-owned closed refusal code."""
    raise RefusedError(reason)


def need(condition: object, reason: str) -> None:
    """Refuse a violated implementation-owned condition."""
    if not condition:
        refuse(reason)


def check(deadline: float) -> None:
    """Check a cancellation flag without interrupting spawn or owned cleanup halfway."""
    need(not CANCELLED, "cancelled")
    need(time.monotonic() < deadline, "deadline")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys rather than accepting ambiguous admission."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def read_bounded(descriptor: int, limit: int) -> bytes:
    """Read a fixed finite maximum without following paths."""
    result = bytearray()
    while len(result) <= limit:
        piece = os.read(descriptor, min(65536, limit + 1 - len(result)))
        if not piece:
            return bytes(result)
        result.extend(piece)
    refuse("oversized")


def identity(info: os.stat_result) -> tuple[int, ...]:
    """Private comparison includes ownership, times and link identity."""
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


@dataclass(frozen=True)
class HeldFile:
    """Stable, bounded bytes and private file identity; paths are never published."""

    path: Path
    data: bytes
    facts: tuple[int, ...]

    def public(self) -> dict[str, Any]:
        """Publish only hash, byte count and non-owner file identity."""
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "size": len(self.data),
            "device": self.facts[0],
            "inode": self.facts[1],
            "mode": self.facts[4],
            "links": self.facts[5],
        }


@dataclass(frozen=True)
class HeldExecutable:
    """Keep the exact verified ELF descriptor alive until all parser calls complete."""

    descriptor: int
    file: HeldFile

    def check(self) -> None:
        """Verify held bytes/identity and the named path without reopening for execution."""
        need(
            _snapshot_fd(
                self.descriptor, self.file.path, max(1, len(self.file.data)), self.file.facts[2], executable=True
            )
            == self.file,
            "file-changed",
        )


@dataclass(frozen=True)
class ExecutableCall:
    """Bind an exact descriptor and argv as one child-call argument."""

    executable: HeldExecutable
    argv: tuple[str, ...]


@dataclass(frozen=True)
class SourceCustody:
    """An exact private source closure, including both owned directory identities."""

    directory: Path
    files: tuple[HeldFile, ...]
    directories: tuple[tuple[Path, tuple[int, ...]], ...]

    def check(self) -> None:
        """Refuse directory substitution, extra imports and changed source bytes."""
        for path, facts in self.directories:
            need(identity(path.lstat()) == facts and stat.S_ISDIR(path.lstat().st_mode), "source-custody-changed")
        need(
            {item.name for item in self.directory.iterdir()} == {"scripts", "LICENSE"}
            and {item.name for item in (self.directory / "scripts").iterdir()}
            == {"native-runner-apparmor.py", "native_outer_diagnostic_capture.py"},
            "source-closure",
        )
        for item in self.files:
            recheck(item)


def _pread_bounded(descriptor: int, limit: int) -> bytes:
    content = bytearray()
    while len(content) <= limit:
        raw = os.pread(descriptor, min(65536, limit + 1 - len(content)), len(content))
        if not raw:
            return bytes(content)
        content.extend(raw)
    refuse("oversized")


def _snapshot_fd(descriptor: int, path: Path, limit: int, owner: int, *, executable: bool) -> HeldFile:
    before = os.fstat(descriptor)
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == owner
        and before.st_nlink == 1
        and not before.st_mode & 0o7022,
        "unsafe-file",
    )
    if executable:
        need(before.st_mode & 0o111, "unsafe-executable")
        try:
            capabilities = os.getxattr(descriptor, "security.capability")
        except OSError as error:
            need(error.errno == errno.ENODATA, "file-capabilities-unknown")
        else:
            need(not capabilities, "file-capabilities")
    content = _pread_bounded(descriptor, limit) if executable else read_bounded(descriptor, limit)
    need(identity(before) == identity(os.fstat(descriptor)) == identity(path.lstat()), "file-changed")
    if executable:
        need(content.startswith(b"\x7fELF"), "unsafe-executable")
    return HeldFile(path, content, identity(before))


def snapshot(path: Path, limit: int, owner: int, *, executable: bool = False) -> HeldFile:
    """Snapshot regular nonsymlink bytes; execution requires the separate held-FD context."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        return _snapshot_fd(descriptor, path, limit, owner, executable=executable)
    finally:
        os.close(descriptor)


@contextmanager
def hold_executable(path: Path, limit: int, owner: int) -> Iterator[HeldExecutable]:
    """Hold one verified ELF descriptor across version and compilation, with no path fallback."""
    need(os.execve in os.supports_fd, "fd-exec-unsupported")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        executable = HeldExecutable(descriptor, _snapshot_fd(descriptor, path, limit, owner, executable=True))
        yield executable
        executable.check()
    finally:
        os.close(descriptor)


def recheck(held: HeldFile, *, executable: bool = False) -> None:
    """Require exactly the held bytes and identity, without accepting replacement."""
    current = snapshot(held.path, max(len(held.data), 1), held.facts[2], executable=executable)
    need(current == held, "file-changed")


def manifest(path: Path = MANIFEST) -> dict[str, Any]:
    """Validate the sole source and parser pin authority with a closed schema."""
    held = snapshot(path, MAX_SOURCE, os.geteuid())
    value = json.loads(held.data, object_pairs_hook=unique_object)
    need(
        type(value) is dict and set(value) == {"schemaVersion", "consumer", "qualification", "source", "parser"},
        "manifest-schema",
    )
    need(
        type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 1
        and value["consumer"] == CONSUMER
        and value["qualification"] == "none",
        "manifest-consumer",
    )
    source, parser = value["source"], value["parser"]
    need(
        type(source) is dict
        and set(source) == {"managed", "repository", "ref", "commit", "license", "retrieval", "files"},
        "manifest-source",
    )
    need(
        source["managed"] is True
        and source["repository"] == "Strukturpiloten/docker-lens"
        and source["ref"] == "TheRealBecks/issue127"
        and type(source["commit"]) is str
        and COMMIT.fullmatch(source["commit"])
        and source["license"] == "MPL-2.0"
        and source["retrieval"] == "public-https-immutable-commit",
        "manifest-source",
    )
    need(type(source["files"]) is list and len(source["files"]) == len(FILES), "manifest-files")
    names = set()
    for item in source["files"]:
        need(type(item) is dict and set(item) == {"path", "size", "sha256"}, "manifest-files")
        need(
            type(item["path"]) is str
            and item["path"] in FILES
            and item["path"] not in names
            and type(item["size"]) is int
            and 0 < item["size"] <= MAX_SOURCE
            and type(item["sha256"]) is str
            and HASH.fullmatch(item["sha256"]),
            "manifest-files",
        )
        names.add(item["path"])
    need(
        type(parser) is dict
        and set(parser)
        == {
            "managed",
            "repository",
            "expectedVersion",
            "contractTag",
            "contractCommit",
            "integrity",
        },
        "manifest-parser",
    )
    need(
        parser["managed"] is True
        and parser
        == {
            "managed": True,
            "repository": "apparmor/apparmor",
            "expectedVersion": "5.0.2",
            "contractTag": "v5.0.2",
            "contractCommit": "909affc32a13d14ae3a7ccf44d325ae63ce11baf",
            "integrity": "observed-preinstalled-system-tool-not-vendor-checksum",
        },
        "unreviewed-parser-contract",
    )
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        """Refuse redirection from the immutable public source endpoint."""
        return


def _download(commit: str, name: str, size: int, deadline: float) -> bytes:
    """Fetch only an allowlisted, immutable public HTTPS resource without credentials."""
    need(COMMIT.fullmatch(commit) and name in FILES and 0 < size <= MAX_SOURCE, "source-request")
    check(deadline)
    remaining = deadline - time.monotonic()
    need(remaining > 0, "deadline")
    url = f"https://raw.githubusercontent.com/Strukturpiloten/docker-lens/{commit}/{name}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with opener.open(request, timeout=min(remaining, 3.0)) as response:
        need(response.status == HTTP_OK and response.geturl() == url, "source-response")
        body = bytearray()
        while len(body) <= size:
            check(deadline)
            piece = response.read1(min(4096, size + 1 - len(body)))
            if not piece:
                check(deadline)
                return bytes(body)
            body.extend(piece)
    refuse("source-size")


DOWNLOAD = """\
import importlib.util
spec = importlib.util.spec_from_file_location("containers_source_download", sys.argv[2])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
sys.stdout.buffer.write(module._download(sys.argv[3], sys.argv[4], int(sys.argv[5]), float(sys.argv[6])))
"""


def fetch(commit: str, name: str, size: int, deadline: float) -> bytes:
    """Bound DNS, TLS and response lifetime in the same owned unprivileged child envelope."""
    need(COMMIT.fullmatch(commit) and name in FILES and 0 < size <= MAX_SOURCE, "source-request")
    deadline = min(deadline, time.monotonic() + 3.0)
    content, status = bounded_child(
        DOWNLOAD,
        [str(Path(__file__).resolve()), commit, name, str(size), str(deadline)],
        b"",
        deadline,
        size + 1,
    )
    need(status == 0 and len(content) == size, "source-response")
    return content


def custody(directory: Path, value: dict[str, Any], deadline: float) -> SourceCustody:
    """Create a private, exact closure; verify every byte before any import."""
    info = directory.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == PRIVATE_DIRECTORY_MODE
        and not list(directory.iterdir()),
        "source-custody",
    )
    (directory / "scripts").mkdir(mode=0o700)
    result = []
    for item in value["source"]["files"]:
        content = fetch(value["source"]["commit"], item["path"], item["size"], deadline)
        need(len(content) == item["size"] and hashlib.sha256(content).hexdigest() == item["sha256"], "source-integrity")
        target = directory / item["path"]
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        result.append(snapshot(target, item["size"], os.geteuid()))
    check(deadline)
    return SourceCustody(
        directory, tuple(result), tuple((path, identity(path.lstat())) for path in (directory, directory / "scripts"))
    )


def _capture(process: subprocess.Popen[bytes], receipt: int, deadline: float, limit: int) -> tuple[bytes, bytes]:
    output, proof = bytearray(), bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, (output, limit))
        selector.register(receipt, selectors.EVENT_READ, (proof, 256))
        while selector.get_map():
            check(deadline)
            for key, _ in selector.select(0.05):
                buffer, maximum = key.data
                raw = os.read(key.fd, min(1024, maximum + 1 - len(buffer)))
                buffer.extend(raw)
                need(len(buffer) <= maximum, "child-output")
                if not raw:
                    selector.unregister(key.fileobj)
    return bytes(output), bytes(proof)


def _cleanup(process: subprocess.Popen[bytes]) -> int:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    status = process.wait(timeout=0.5)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return status
    refuse("child-cleanup-unverified")


def bounded_child(
    code: str,
    arguments: list[str] | ExecutableCall,
    data: bytes,
    deadline: float,
    limit: int,
) -> tuple[bytes, int]:
    """Isolate a fixed unprivileged child with a separate pre-exec privilege receipt."""
    need(os.geteuid() != 0 and len(data) <= MAX_POLICY, "child-context")
    check(deadline)
    executable = arguments.executable if isinstance(arguments, ExecutableCall) else None
    if isinstance(arguments, ExecutableCall):
        need(os.execve in os.supports_fd, "fd-exec-unsupported")
        arguments.executable.check()
        arguments = [str(arguments.executable.descriptor), *arguments.argv]
    read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed isolated Python wrapper and verified caller arguments.
            [sys.executable, "-I", "-B", "-c", CHILD_SETUP + code, str(write), *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=ENVIRONMENT,
            close_fds=True,
            start_new_session=True,
            pass_fds=(write,) if executable is None else (write, executable.descriptor),
        )
        os.close(write)
        write = -1
        need(process.stdin is not None and process.stdout is not None, "child-streams")
        # At most 1024 bytes fit an empty pipe atomically; never wait on child input.
        os.set_blocking(process.stdin.fileno(), False)
        need(os.write(process.stdin.fileno(), data) == len(data), "child-input")
        process.stdin.close()
        output, proof = _capture(process, read, deadline, limit)
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            check(deadline)
            time.sleep(0.01)
    finally:
        if write != -1:
            os.close(write)
        os.close(read)
        if process is not None:
            try:
                status = _cleanup(process)
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stdin is not None:
                    process.stdin.close()
    check(deadline)
    if executable is not None:
        executable.check()
    need(proof == CHILD_RECEIPT, "child-privilege-receipt")
    return output, status


def build(held: SourceCustody, name: str, deadline: float) -> bytes:
    """Call only the canonical pure builder, isolated from CLI and root authority."""
    need(
        os.geteuid() != 0
        and re.fullmatch(
            r"dockerlens-127-upstream-rootless-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}",
            name,
        ),
        "builder-context",
    )
    held.check()
    output, status = bounded_child(
        BUILDER,
        [str(held.directory / "scripts"), name],
        b"",
        deadline,
        MAX_POLICY,
    )
    held.check()
    check(deadline)
    need(
        status == 0
        and output.startswith(b"abi <abi/4.0>,\n")
        and len(output) <= MAX_POLICY
        and output.count(name.encode("ascii")) == 1,
        "builder-output",
    )
    return output
