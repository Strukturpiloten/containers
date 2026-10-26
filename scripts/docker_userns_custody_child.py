"""Unused root-custody child boundary; no bootstrap, parser or supervisor adapter."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

MAX_SOURCE = 65536
MAX_INTERPRETER = 16 * 1024 * 1024
MAX_POLICY = 1024
_SEAL_VALUES = tuple(
    getattr(fcntl, name, None) for name in ("F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
)
SEALS = sum(_SEAL_VALUES) if all(type(value) is int for value in _SEAL_VALUES) else None
MODULES = ("canonical_policy", "native_outer_diagnostic_capture")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
CODE = r"""
import ctypes, errno, fcntl, hashlib, importlib.abc, importlib.util, json, os, re, resource, signal, sys
interpreter, receipt, first, second, name, uid, gid, seconds = sys.argv[1:]
uid, gid = int(uid), int(gid)
if uid <= 0 or gid <= 0 or os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
    raise SystemExit(1)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
    raise SystemExit(1)
with open("/proc/self/status", "rb") as stream:
    status = stream.read(8193)
if len(status) > 8192:
    raise SystemExit(1)
for key in (b"CapEff", b"CapPrm", b"CapInh", b"CapAmb", b"NoNewPrivs"):
    values = [row.split(b":", 1)[1].strip() for row in status.splitlines() if row.startswith(key + b":")]
    if len(values) != 1 or not re.fullmatch(rb"[0-9a-fA-F]{1,16}", values[0]):
        raise SystemExit(1)
    if int(values[0], 16) != (1 if key == b"NoNewPrivs" else 0):
        raise SystemExit(1)
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(int(seconds))
os.close(int(interpreter))
records = {}
for module, encoded in zip(("canonical_policy", "native_outer_diagnostic_capture"), (first, second), strict=True):
    descriptor, size, digest = encoded.split(":")
    descriptor, size = int(descriptor), int(size)
    if fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise SystemExit(1)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
        raise SystemExit(1)
    before = os.fstat(descriptor)
    raw = os.pread(descriptor, size + 1, 0)
    after = os.fstat(descriptor)
    stable = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode,
                           item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (stable(before) != stable(after) or before.st_uid != 0
            or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest):
        raise SystemExit(1)
    records[module] = raw
proof = {"schema": 1, "uid": uid, "gid": gid, "groups": [], "nnp": 1, "capabilities": "zero"}
raw = json.dumps(proof, sort_keys=True).encode("ascii")
if os.write(int(receipt), raw) != len(raw):
    raise SystemExit(1)
os.close(int(receipt))
allowed = {0, 1, 2, int(first.split(":")[0]), int(second.split(":")[0])}
for entry in os.listdir("/proc/self/fd"):
    descriptor = int(entry)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise SystemExit(1)
        continue
    if descriptor not in allowed:
        raise SystemExit(1)
class SourceLoader(importlib.abc.MetaPathFinder, importlib.abc.SourceLoader):
    def find_spec(self, fullname, path=None, target=None):
        return importlib.util.spec_from_loader(fullname, self) if fullname in records else None
    def get_filename(self, fullname):
        if fullname not in records:
            raise ImportError
        return "/__containers_verified__/" + fullname + ".py"
    def get_data(self, path):
        names = {self.get_filename(module): module for module in records}
        if path not in names:
            raise OSError
        return records[names[path]]
loader = SourceLoader()
sys.meta_path.insert(0, loader)
spec = loader.find_spec("canonical_policy")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
loader.exec_module(module)
value = module.profile_bytes(name)
if type(value) is not bytes or len(value) > 1024:
    raise SystemExit(1)
sys.stdout.buffer.write(value)
"""


class Clock(Protocol):
    """Provide the parent's original integer monotonic clock."""

    def now_ns(self) -> int:
        """Return monotonic nanoseconds."""
        ...


class Lifetime(StrEnum):
    """Keep actual child lifetime independent of the primary operation result."""

    NEVER_STARTED = "never-started"
    DEAD = "proven-dead"
    UNKNOWN = "unknown"


class ChildError(Exception):
    """Report only a closed child failure and whether group death was proven."""

    def __init__(self, *, dead: bool | None = None, lifetime: Lifetime | None = None) -> None:
        """Retain lifetime uncertainty independently of raw child output."""
        super().__init__("child-refused")
        self.lifetime = lifetime or (
            Lifetime.NEVER_STARTED if dead is None else Lifetime.DEAD if dead else Lifetime.UNKNOWN
        )
        self.dead = self.lifetime is Lifetime.DEAD
        self.pending = self.lifetime is Lifetime.UNKNOWN


@dataclass(frozen=True)
class Interpreter:
    """Require explicit reviewed system-interpreter authority; never use sys.executable."""

    descriptor: int
    sha256: str


@dataclass(frozen=True)
class Source:
    """A sealed read-only descriptor for exactly one canonical module."""

    module: str
    descriptor: int
    size: int
    sha256: str


@dataclass(frozen=True)
class Build:
    """Bind dropped credentials and both original child/cleanup deadlines."""

    name: str
    uid: int
    gid: int
    deadline_ns: int
    cleanup_deadline_ns: int


@dataclass(frozen=True)
class Outcome:
    """Complete output plus independently verified process-group death."""

    policy: bytes
    dead: bool


def _need(value: object, *, dead: bool | None = None) -> None:
    if not value:
        raise ChildError(dead=dead)


def bytes_at(descriptor: int, limit: int) -> bytes:
    """Read finite descriptor bytes without changing its shared offset."""
    content = bytearray()
    while len(content) <= limit:
        raw = os.pread(descriptor, min(65536, limit + 1 - len(content)), len(content))
        if not raw:
            return bytes(content)
        content.extend(raw)
    raise ChildError(dead=False)


def seal(module: str, data: bytes) -> Source:
    """Create immutable read-only source FDs without exposing root directories."""
    _need(
        os.geteuid() == 0
        and module in MODULES
        and 0 < len(data) <= MAX_SOURCE
        and SEALS is not None
        and hasattr(fcntl, "F_ADD_SEALS")
        and hasattr(fcntl, "F_GET_SEALS")
        and hasattr(os, "memfd_create")
        and hasattr(os, "MFD_ALLOW_SEALING")
    )
    descriptor = os.memfd_create("containers-userns-source", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    read_only = None
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        read_only = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
        _need(fcntl.fcntl(read_only, fcntl.F_GET_SEALS) & SEALS == SEALS)
        return Source(module, read_only, len(data), hashlib.sha256(data).hexdigest())
    except BaseException:
        if read_only is not None:
            os.close(read_only)
        raise
    finally:
        os.close(descriptor)


def file_mark(info: os.stat_result) -> tuple[int, ...]:
    """Compare descriptor identity without access timestamps changed by reads."""
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


def _interpreter(value: Interpreter) -> tuple[tuple[int, ...], bytes]:
    info = os.fstat(value.descriptor)
    _need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and info.st_mode & 0o111
        and not info.st_mode & 0o7022
        and fcntl.fcntl(value.descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    )
    try:
        capabilities = os.getxattr(value.descriptor, "security.capability")
    except OSError as error:
        _need(error.errno == errno.ENODATA)
    else:
        _need(not capabilities)
    raw = bytes_at(value.descriptor, MAX_INTERPRETER)
    _need(
        raw.startswith(b"\x7fELF")
        and hashlib.sha256(raw).hexdigest() == value.sha256
        and file_mark(os.fstat(value.descriptor)) == file_mark(info)
    )
    return file_mark(info), raw


def _capture(process: subprocess.Popen[bytes], receipt: int, lease: Build, clock: Clock) -> tuple[bytes, bytes]:
    output, proof = bytearray(), bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, (output, MAX_POLICY))
        selector.register(receipt, selectors.EVENT_READ, (proof, MAX_POLICY))
        while selector.get_map():
            _need(clock.now_ns() < lease.deadline_ns)
            for key, _ in selector.select(0.01):
                content, limit = key.data
                raw = os.read(key.fd, min(1024, limit + 1 - len(content)))
                content.extend(raw)
                _need(len(content) <= limit)
                if not raw:
                    selector.unregister(key.fileobj)
    while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        _need(clock.now_ns() < lease.deadline_ns)
        # The child also owns an independent, nonrenewed wall alarm.
        with selectors.DefaultSelector() as selector:
            selector.select(0.001)
    return bytes(output), bytes(proof)


def _stop(process: subprocess.Popen[bytes], lease: Build, clock: Clock) -> tuple[int | None, bool]:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    remaining = min(500_000_000, lease.cleanup_deadline_ns - clock.now_ns())
    try:
        status = process.wait(timeout=remaining / 1_000_000_000) if remaining > 0 else process.poll()
    except subprocess.TimeoutExpired:
        return None, False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return status, status is not None
    return status, False


def _preflight(
    interpreter: Interpreter, sources: tuple[Source, ...], lease: Build, clock: Clock
) -> tuple[tuple[tuple[int, ...], bytes], int]:
    _need(
        os.geteuid() == 0
        and SEALS is not None
        and hasattr(fcntl, "F_GET_SEALS")
        and type(lease.uid) is int
        and 0 < lease.uid < 2**31
        and type(lease.gid) is int
        and 0 < lease.gid < 2**31
        and tuple(item.module for item in sources) == MODULES
        and re.fullmatch(r"dockerlens-127-upstream-rootless-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}", lease.name)
    )
    seconds = min(5, (lease.deadline_ns - clock.now_ns()) // 1_000_000_000)
    _need(seconds >= 1 and lease.deadline_ns < lease.cleanup_deadline_ns)
    before = _interpreter(interpreter)
    for item in sources:
        _need(
            fcntl.fcntl(item.descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            and fcntl.fcntl(item.descriptor, fcntl.F_GET_SEALS) & SEALS == SEALS
            and os.fstat(item.descriptor).st_uid == 0
            and hashlib.sha256(bytes_at(item.descriptor, item.size)).hexdigest() == item.sha256
        )
    # Hashing must not consume time and then start a child on the earlier allowance.
    seconds = min(5, (lease.deadline_ns - clock.now_ns()) // 1_000_000_000)
    _need(seconds >= 1)
    return before, seconds


def _execute(
    interpreter: Interpreter, sources: tuple[Source, ...], lease: Build, clock: Clock, seconds: int
) -> tuple[bytes, bytes, int | None, Lifetime]:
    try:
        read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    except Exception as error:
        raise ChildError(lifetime=Lifetime.NEVER_STARTED) from error
    process, dead, status = None, False, None
    primary = None
    attempted = False
    try:
        seconds = min(seconds, (lease.deadline_ns - clock.now_ns()) // 1_000_000_000)
        _need(seconds >= 1)
        arguments = [
            str(interpreter.descriptor),
            str(write),
            *(f"{item.descriptor}:{item.size}:{item.sha256}" for item in sources),
            lease.name,
            str(lease.uid),
            str(lease.gid),
            str(seconds),
        ]
        attempted = True
        process = subprocess.Popen(  # noqa: S603 - verified held interpreter, fixed code and descriptor-only inputs.
            [f"/proc/self/fd/{interpreter.descriptor}", "-I", "-B", "-S", "-c", CODE, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,
            user=lease.uid,
            group=lease.gid,
            extra_groups=(),
            pass_fds=(interpreter.descriptor, write, *(item.descriptor for item in sources)),
        )
        os.close(write)
        write = -1
        output, proof = _capture(process, read, lease, clock)
    except (ChildError, OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        primary = error
    finally:
        primary = _close_pipes((write, read), primary)
        if process is not None:
            try:
                status, dead = _stop(process, lease, clock)
            except (ChildError, OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                primary = primary or error
            finally:
                if process.stdout is not None:
                    try:
                        process.stdout.close()
                    except OSError as error:
                        primary = primary or error
    lifetime = Lifetime.DEAD if dead else Lifetime.UNKNOWN if attempted else Lifetime.NEVER_STARTED
    if primary is not None:
        raise ChildError(lifetime=lifetime) from primary
    return output, proof, status, lifetime


def _close_pipes(descriptors: tuple[int, int], primary: Exception | None) -> Exception | None:
    for descriptor in descriptors:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError as error:
                primary = primary or error
    return primary


def build(interpreter: Interpreter, sources: tuple[Source, ...], lease: Build, clock: Clock) -> Outcome:
    """Preserve failure while reporting never-started, proven-dead or unknown lifetime."""
    try:
        before, seconds = _preflight(interpreter, sources, lease, clock)
    except Exception as error:
        raise ChildError(lifetime=Lifetime.NEVER_STARTED) from error
    output, proof, status, lifetime = _execute(interpreter, sources, lease, clock, seconds)
    try:
        _need(
            lifetime is Lifetime.DEAD and status == 0 and clock.now_ns() < lease.deadline_ns,
            dead=lifetime is Lifetime.DEAD,
        )
        try:
            actual = json.loads(proof, object_pairs_hook=_unique)
        except ValueError:
            raise ChildError(dead=lifetime is Lifetime.DEAD) from None
        _need(
            type(actual) is dict
            and all(type(actual.get(key)) is int for key in ("schema", "uid", "gid", "nnp"))
            and actual
            == {"schema": 1, "uid": lease.uid, "gid": lease.gid, "groups": [], "nnp": 1, "capabilities": "zero"}
            and _interpreter(interpreter) == before,
            dead=lifetime is Lifetime.DEAD,
        )
        _need(clock.now_ns() < lease.deadline_ns, dead=lifetime is Lifetime.DEAD)
        return Outcome(output, dead=True)

    except Exception as error:
        raise ChildError(lifetime=lifetime) from error


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        _need(key not in result)
        result[key] = value
    return result
