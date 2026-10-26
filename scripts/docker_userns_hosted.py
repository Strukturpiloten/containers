"""Closed hosted unused-custody experiment: no policy load, guest, or runtime endpoint."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

from scripts import docker_userns_custody as custody
from scripts import docker_userns_custody_child as child

NS = 1_000_000_000
CYCLE_NS = 120 * NS
LIMIT = 32768
PROC_LIMIT = 8192
CGROUP_LIMIT = 4096
START_FIELD = 19
PRIVATE_MODE = 0o700
MAX_RUNTIME_SECONDS = 94
MAX_EVENTS = 4
MAX_LINKS = 32
MIN_EVENTS = 2
MAX_ARTIFACT = 131072
TEARDOWN_NS = 5 * NS
TERM_NS = NS
MAX_CHILDREN = 8
CHILD_LIST_LIMIT = MAX_CHILDREN * 24
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
_CANCELLATION = [False]
CONTROL_PREFIX = "containers-userns-control."
CONTROL_LEAVES = {
    "binding.json",
    "ack.json",
    "receipt.json",
    "observer.sock",
    "owner.sock",
    "failure.json",
    "start.json",
}
FEATURE_PATHS = (
    Path("/sys/module/apparmor/parameters/enabled"),
    Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
    Path("/sys/kernel/security/apparmor/features/namespaces/mask"),
    Path("/sys/kernel/security/apparmor/features/policy/versions/v9"),
)
ENV = child.ENV
PROPERTIES = (
    "LoadState",
    "ActiveState",
    "MainPID",
    "ControlGroup",
    "User",
    "Group",
    "Transient",
    "FragmentPath",
    "DropInPaths",
    "Type",
    "Restart",
    "RuntimeMaxUSec",
    "TimeoutStopUSec",
    "KillMode",
    "SendSIGKILL",
    "Slice",
    "ExecMainStartTimestampMonotonic",
    "ExecMainCode",
    "ExecMainStatus",
)


def need(value: object) -> None:
    """Refuse without including raw privileged inputs in diagnostics."""
    if not value:
        raise custody.CustodyError


def encoded(value: object) -> bytes:
    """Use one bounded canonical wire representation."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    need(len(raw) <= LIMIT)
    return raw


def digest(raw: bytes) -> str:
    """Record custody hashes without treating caller hashes as admission."""
    return hashlib.sha256(raw).hexdigest()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate wire keys."""
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def exact(value: object, keys: set[str]) -> dict[str, Any]:
    """Reject schema extensions as well as missing evidence."""
    need(type(value) is dict and set(value) == keys)
    return value


class Clock:
    """Use current-boot monotonic time throughout the immutable allowance."""

    def __init__(self) -> None:
        """Capture the current boot without relying on workflow metadata."""
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()

    def now_ns(self) -> int:
        """Return the kernel monotonic clock."""
        return time.monotonic_ns()

    def boot_id(self) -> str:
        """Reobserve boot identity without renewing any budget."""
        need(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == self.boot)
        return self.boot


def time_remaining(deadline: int) -> float:
    """Require completion strictly before the original cutoff."""
    result = (deadline - time.monotonic_ns()) / NS
    need(result > 0)
    return result


def remaining(deadline: int) -> float:
    """Reject new work after cancellation while keeping the original teardown cutoff."""
    need(not _CANCELLATION[0])
    return time_remaining(deadline)


@contextmanager
def cancellation_scope() -> Iterator[None]:
    """Defer signals to explicit work checks so fork ownership cannot be interrupted."""
    previous_flag = _CANCELLATION[0]
    previous_handlers = {}
    _CANCELLATION[0] = False

    def cancel(_number: int, _frame: object) -> None:
        _CANCELLATION[0] = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[number] = signal.signal(number, cancel)
        yield
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        _CANCELLATION[0] = previous_flag or _CANCELLATION[0]


def safe_path(path: Path) -> Path:
    """Check every root-owned component traversed by the installed OS symlink chain."""
    need(path.is_absolute())
    pending, resolved, links = list(path.parts[1:]), Path("/"), 0
    root = resolved.lstat()
    need(root.st_uid == 0 and not root.st_mode & 0o022)
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        current = resolved / part
        info = current.lstat()
        need(info.st_uid == 0)
        if stat.S_ISLNK(info.st_mode):
            links += 1
            need(links <= MAX_LINKS)
            target = current.readlink()
            if target.is_absolute():
                resolved = Path("/")
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            need(not info.st_mode & 0o022 and (not pending or stat.S_ISDIR(info.st_mode)))
            resolved = current
    return resolved


def identity(info: os.stat_result) -> custody.FileIdentity:
    """Capture fresh metadata; never compare it to historical host admission."""
    return custody.FileIdentity(
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_root(path: Path, limit: int = LIMIT) -> tuple[bytes, custody.FileIdentity]:
    """Read one exact root file through a no-follow descriptor and recheck identity."""
    need(safe_path(path) == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = identity(os.fstat(descriptor))
        need(stat.S_ISREG(before.mode) and before.owner == 0 and before.links == 1 and not before.mode & 0o7022)
        raw = child.bytes_at(descriptor, limit)
        need(identity(os.fstat(descriptor)) == before and identity(path.lstat()) == before)
        return raw, before
    finally:
        os.close(descriptor)


def group(path: str) -> custody.Group:
    """Bind the actual unified cgroup to its current filesystem identity."""
    need(re.fullmatch(r"/[A-Za-z0-9_.:/-]{0,255}", path) and ".." not in path.split("/") and "//" not in path)
    location = Path("/sys/fs/cgroup" + path)
    info = location.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0)
    return custody.Group(path, info.st_dev, info.st_ino)


def process(pid: int) -> custody.Process:
    """Reobserve PID, start time, all root IDs, process group and exact cgroup."""
    need(type(pid) is int and pid > 1)
    root = Path("/proc") / str(pid)
    first = (root / "stat").read_bytes()
    need(len(first) <= PROC_LIMIT and b")" in first)
    fields = first.rsplit(b")", 1)[1].split()
    need(len(fields) > START_FIELD)
    status = (root / "status").read_bytes()
    rows = [row.split()[1:] for row in status.splitlines() if row.startswith(b"Uid:")]
    need(rows == [[b"0", b"0", b"0", b"0"]])
    cgroups = (root / "cgroup").read_bytes()
    need(len(cgroups) <= CGROUP_LIMIT and re.fullmatch(rb"0::/[A-Za-z0-9_.:/-]*\n", cgroups))
    observed = group(cgroups[3:-1].decode("ascii"))
    need((root / "stat").read_bytes().rsplit(b")", 1)[1].split()[START_FIELD] == fields[START_FIELD])
    return custody.Process(pid, int(fields[START_FIELD]), int(fields[2]), 0, observed)


class HeldProcess:
    """Hold kernel lifetime authority across PID reuse; uncertainty never becomes success."""

    def __init__(self, expected: custody.Process) -> None:
        """Open a pidfd only across stable matching process observations."""
        need(process(expected.pid) == expected)
        self.expected = expected
        self.descriptor = os.pidfd_open(expected.pid, 0)
        try:
            self.live()
        except BaseException:
            os.close(self.descriptor)
            raise

    def dead(self) -> bool:
        """Only pidfd readiness proves the held original process terminated."""
        return bool(select.select([self.descriptor], [], [], 0)[0])

    def live(self) -> None:
        """Check both held lifetime and fresh process identity."""
        need(not self.dead() and process(self.expected.pid) == self.expected and not self.dead())

    def close(self) -> None:
        """Release the exact held descriptor."""
        os.close(self.descriptor)


class ChildCustody:
    """Own one unreaped direct child immediately; PID reuse is impossible until our reap."""

    def __init__(self, pid: int) -> None:
        """Retain fork/Popen provenance before any fallible pidfd or pipe observation."""
        need(type(pid) is int and pid > 1)
        self.pid, self.descriptor, self.expected = pid, None, None
        self.reaped, self.uncertain, self.status = False, False, None

    def state(self) -> object:
        """Require current kernel child membership; ECHILD is uncertainty, never absence proof."""
        need(not self.reaped and not self.uncertain)
        selector, identifier = (os.P_PID, self.pid) if self.descriptor is None else (os.P_PIDFD, self.descriptor)
        value = os.waitid(selector, identifier, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        need(value is None or value.si_pid == self.pid)
        return value

    def hold(self) -> None:
        """Capture a pidfd immediately, checking child status on both sides."""
        self.state()
        self.descriptor = os.pidfd_open(self.pid, 0)
        self.state()

    def bind(self, expected: custody.Process) -> None:
        """Add the existing exact root PID/start/PGID/cgroup identity to the held child."""
        need(expected.pid == self.pid and expected.pgid == self.pid and self.descriptor is not None)
        self.expected = expected
        self.live()

    def dead(self) -> bool:
        """Record death only from the unreaped child's kernel exit status."""
        return self.reaped or self.state() is not None

    def live(self) -> None:
        """Retain both child membership and the exact observed root identity."""
        need(self.expected is not None and not self.dead() and process(self.pid) == self.expected and not self.dead())

    def signal(self, number: int, deadline: int) -> None:
        """Signal only a still-unreaped child after a fresh waitable-child proof."""
        need(number in {signal.SIGTERM, signal.SIGKILL})
        time_remaining(deadline)
        if self.state() is not None:
            return
        if self.descriptor is None:
            # Single-thread/no-competing-reaper invariant keeps this direct child PID unreused.
            os.kill(self.pid, number)
        else:
            signal.pidfd_send_signal(self.descriptor, number)
        time_remaining(deadline)

    def reap(self, deadline: int) -> bool:
        """Record the exact status before reaping; never use launcher status as descendant proof."""
        time_remaining(deadline)
        if self.state() is None:
            return False
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        need(pid == self.pid)
        self.status, self.reaped = status, True
        time_remaining(deadline)
        return True

    def cleanup(self, deadline: int) -> dict[str, Any]:
        """Bound TERM/KILL/reap by the original D and keep any uncertainty sticky."""
        if not self.reaped and not self.uncertain:
            try:
                self.signal(signal.SIGTERM, deadline)
                term_until = min(deadline - TERM_NS, time.monotonic_ns() + TERM_NS)
                while not self.dead() and time.monotonic_ns() < term_until:
                    select.select([], [], [], min(0.01, time_remaining(term_until)))
                if not self.dead():
                    self.signal(signal.SIGKILL, deadline)
                while not self.dead():
                    select.select([], [], [], min(0.01, time_remaining(deadline)))
                need(self.reap(deadline))
            except custody.CustodyError, OSError, ValueError:
                self.uncertain = True
        return {
            "pid": self.pid,
            "pidfdHeld": self.descriptor is not None,
            "reaped": self.reaped,
            "status": self.status,
            "lifetime": "proven-dead-reaped" if self.reaped and not self.uncertain else "unknown",
        }

    def close(self) -> None:
        """Close only this process's held descriptor; closing is never termination proof."""
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


def child_absent() -> bool:
    """Require kernel ECHILD, never an empty /proc listing alone."""
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return False


def direct_children() -> tuple[int, ...]:
    """Read only this single-thread process's bounded kernel child list, not /proc-wide state."""
    with (Path("/proc/self/task") / str(os.getpid()) / "children").open("rb") as stream:
        raw = stream.read(CHILD_LIST_LIMIT + 1)
    need(len(raw) <= CHILD_LIST_LIMIT and re.fullmatch(rb"(?:[1-9][0-9]* ?)*", raw))
    pids = tuple(int(value) for value in raw.split())
    need(len(pids) <= MAX_CHILDREN and len(set(pids)) == len(pids))
    return pids


def reaper_invariant() -> None:
    """Use one kernel thread and a fresh default SIGCHLD disposition retaining waitable children."""
    need({item.name for item in Path("/proc/self/task").iterdir()} == {str(os.getpid())})
    # CPython installs a fresh sigaction, clearing SIG_IGN/SA_NOCLDWAIT before any child exists.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    need(signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL and child_absent())


def peer(connection: socket.socket, expected: HeldProcess) -> dict[str, int]:
    """Authenticate each connected peer by kernel credentials and held process identity."""
    pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(pid == expected.expected.pid and uid == 0 and gid == 0)
    expected.live()
    return {"pid": pid, "uid": uid, "gid": gid, "startTicks": expected.expected.start_ticks}


def receive(connection: socket.socket, deadline: int) -> dict[str, Any]:
    """Receive a single bounded framed message without a renewed timeout."""
    data = bytearray()
    while b"\n" not in data:
        connection.settimeout(min(0.1, remaining(deadline)))
        try:
            raw = connection.recv(min(4096, LIMIT + 1 - len(data)))
        except TimeoutError:
            continue
        need(raw)
        data.extend(raw)
        need(len(data) <= LIMIT)
    need(data.endswith(b"\n") and data.count(b"\n") == 1)
    result = json.loads(data, object_pairs_hook=unique)
    need(type(result) is dict)
    remaining(deadline)
    return result


def send(connection: socket.socket, value: object, deadline: int) -> None:
    """Send one closed message within the original cutoff."""
    connection.settimeout(remaining(deadline))
    connection.sendall(encoded(value) + b"\n")
    remaining(deadline)


class Control:
    """Separate finite root-only control store; never nests locks with custody."""

    def __init__(self, path: Path, *, create: bool = False) -> None:
        """Create or authenticate one private finite control directory."""
        need(path.parent == Path("/run") and re.fullmatch(re.escape(CONTROL_PREFIX) + r"[0-9a-f]{32}", path.name))
        if create:
            path.mkdir(mode=0o700)
        self.path = path
        self.phase = "control"
        self.mark = path.lstat()
        need(safe_path(path) == path and stat.S_IMODE(self.mark.st_mode) == PRIVATE_MODE and self.mark.st_uid == 0)
        self.check()

    def check(self) -> None:
        """Refuse replacement or any unrecognized control leaf."""
        info = self.path.lstat()
        need(
            (info.st_dev, info.st_ino) == (self.mark.st_dev, self.mark.st_ino)
            and stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == PRIVATE_MODE
        )
        need({item.name for item in self.path.iterdir()} <= CONTROL_LEAVES)
        for item_path in self.path.iterdir():
            name = item_path.name
            item = (self.path / name).lstat()
            need(item.st_uid == 0 and item.st_nlink == 1 and not item.st_mode & 0o077)
            expected_mode = 0o600 if name.endswith(".sock") else 0o400
            need(stat.S_IMODE(item.st_mode) == expected_mode)
            need(stat.S_ISSOCK(item.st_mode) if name.endswith(".sock") else stat.S_ISREG(item.st_mode))

    def write(self, name: str, value: object, deadline: int) -> None:
        """Durably create one finite immutable leaf; never overwrite unknown state."""
        need(name in CONTROL_LEAVES and name.endswith(".json"))
        remaining(deadline)
        self.check()
        descriptor = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.check()
        remaining(deadline)

    def read(self, name: str) -> dict[str, Any]:
        """Read a strict root-owned bounded control file."""
        need(name in CONTROL_LEAVES and name.endswith(".json"))
        self.check()
        raw, _ = read_root(self.path / name)
        value = json.loads(raw, object_pairs_hook=unique)
        need(type(value) is dict)
        return value

    def failure(self, error: Exception, deadline: int) -> None:
        """Keep the first closed diagnostic only; it can never authorize readiness/cleanup."""
        need(self.phase in {"control", "admission", "prepare", "binding", "arm", "commit", "close", "finish", "owner"})
        locator = error.locator if isinstance(error, custody.CustodyError) else None
        pending = error.child_pending if isinstance(error, custody.CustodyError) else None
        self.write(
            "failure.json",
            {
                "schema": 1,
                "diagnosticOnly": True,
                "phase": self.phase,
                "ns": time.monotonic_ns(),
                "custodyLocator": asdict(locator) if locator else None,
                "childPending": pending,
            },
            deadline,
        )

    def listen(self, name: str) -> socket.socket:
        """Create only a fixed finite private Unix listener."""
        need(name in {"observer.sock", "owner.sock"})
        self.check()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path / name))
        (self.path / name).chmod(0o600)
        listener.listen(3)
        return listener

    def connect(self, name: str, expected: HeldProcess, deadline: int) -> socket.socket:
        """Connect and authenticate the exact held server, not just its pathname."""
        self.check()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(remaining(deadline))
            connection.connect(str(self.path / name))
            peer(connection, expected)
        except BaseException:
            connection.close()
            raise
        else:
            return connection

    def dispose(self, deadline: int) -> None:
        """Remove only the inspected finite leaves after owner and coordinator death."""
        self.check()
        for name in sorted(item.name for item in self.path.iterdir()):
            remaining(deadline)
            (self.path / name).unlink()
        remaining(deadline)
        self.path.rmdir()
        remaining(deadline)


def read_record(locator: custody.Locator) -> custody.Record:
    """Strict nonmutating durable read; unresolved intent is deliberately not settled."""
    with custody._store(locator) as store:  # noqa: SLF001 - adapter reads the foundation's strict locked schema.
        return store.load()


def record_from(value: object) -> custody.Record:
    """Use the foundation's single exact record decoder, never a permissive duplicate."""
    return custody._decode(value)  # noqa: SLF001 - same strict persisted wire schema.


def intent_digest(intent: custody.ArmIntent) -> str:
    """Bind readiness to the complete exact lease and attempted generation."""
    return digest(encoded(asdict(intent)))


def owner_from(value: object) -> custody.Owner:
    """Reject owner/schema extensions before interpreting process identity."""
    item = exact(value, {"service", "process"})
    proc = custody._process_from(item["process"])  # noqa: SLF001 - reuse strict nested wire decoder.
    return custody.Owner(item["service"], proc)


@dataclass(frozen=True)
class StartBinding:
    """Root-created immutable start authority narrows W to arm's original handshake end."""

    control: Control
    intent: custody.ArmIntent
    started_ns: int
    until_ns: int
    file_identity: custody.FileIdentity
    sha256: str

    @classmethod
    def create(cls, control: Control, intent: custody.ArmIntent, until_ns: int, clock: Clock) -> StartBinding:
        """Persist once before the only service start; never compute a replacement end."""
        lease = intent.lease
        started = clock.now_ns()
        need(
            type(until_ns) is int
            and started < until_ns <= lease.work_until_ns
            and until_ns - started <= custody.HANDSHAKE_NS
        )
        control.write(
            "start.json",
            {
                "schema": 1,
                "intentSha256": intent_digest(intent),
                "leaseSha256": digest(encoded(asdict(lease))),
                "generation": intent.generation,
                "control": {"device": control.mark.st_dev, "inode": control.mark.st_ino},
                "custody": asdict(custody.Locator(lease.nonce, lease.directory)),
                "startedNs": started,
                "handshakeUntilNs": until_ns,
            },
            until_ns,
        )
        result = cls.load(control, intent)
        result.ready(clock)
        return result

    @classmethod
    def load(cls, control: Control, intent: custody.ArmIntent) -> StartBinding:
        """Validate closed root state against the independently supplied exact intent."""
        control.check()
        raw, info = read_root(control.path / "start.json")
        value = exact(
            json.loads(raw, object_pairs_hook=unique),
            {
                "schema",
                "intentSha256",
                "leaseSha256",
                "generation",
                "control",
                "custody",
                "startedNs",
                "handshakeUntilNs",
            },
        )
        lease = intent.lease
        need(
            type(value["schema"]) is int
            and value["schema"] == 1
            and type(value["generation"]) is int
            and value["generation"] == intent.generation
        )
        need(value["intentSha256"] == intent_digest(intent) and value["leaseSha256"] == digest(encoded(asdict(lease))))
        need(
            value["control"] == {"device": control.mark.st_dev, "inode": control.mark.st_ino}
            and value["custody"] == asdict(custody.Locator(lease.nonce, lease.directory))
        )
        started, until = value["startedNs"], value["handshakeUntilNs"]
        need(
            type(started) is int
            and type(until) is int
            and lease.start_ns <= started < until <= lease.work_until_ns
            and until - started <= custody.HANDSHAKE_NS
        )
        return cls(control, intent, started, until, info, digest(raw))

    def stable(self) -> None:
        """Recheck protected identity and content, rather than trusting a caller digest."""
        self.control.check()
        raw, info = read_root(self.control.path / "start.json")
        need(info == self.file_identity and digest(raw) == self.sha256)

    def ready(self, clock: Clock) -> None:
        """Enforce the original absolute end before and after intent-read/READY operations."""
        self.stable()
        need(clock.boot_id() == self.intent.lease.boot and self.started_ns <= clock.now_ns() < self.until_ns)


class HostPort:
    """Observe the current manually admitted OS cohort using root-held fresh files."""

    def __init__(self, stage: Path, receipt: dict[str, Any], clock: Clock, stack: ExitStack) -> None:
        """Check the selected manual admission against the verified active closure."""
        self.stage, self.receipt, self.clock, self.stack = stage, receipt, clock, stack
        self.request: custody.Request | None = None
        self.probes: list[dict[str, Any]] = []
        manifest, _ = read_root(stage / ".github/docker-userns-policy-source.json")
        raw, _ = read_root(stage / ".github/docker-userns-unused-admission.json")
        value = exact(
            json.loads(raw, object_pairs_hook=unique),
            {"schemaVersion", "consumer", "qualification", "sourceManifestSha256", "contracts", "cohort", "review"},
        )
        need(value["schemaVersion"] == 1 and value["consumer"] == custody.CONSUMER and value["qualification"] == "none")
        need(value["sourceManifestSha256"] == digest(manifest))
        contracts = value["contracts"]
        need(
            type(contracts) is dict
            and set(contracts)
            == {
                "scripts/docker_userns_custody.py",
                "scripts/docker_userns_custody_child.py",
                "scripts/docker_userns_hosted.py",
                "scripts/docker_userns_policy_source.py",
                ".github/docker-userns-helper-closure.json",
            }
        )
        for path, expected in contracts.items():
            need(digest(read_root(stage / path, child.MAX_SOURCE * 4)[0]) == expected)
        cohort = dict(exact(value["cohort"], set(custody.Cohort.__dataclass_fields__)))
        cohort["namespace_mask"] = tuple(cohort["namespace_mask"])
        authority = custody.BootstrapAuthority(
            receipt["interpreter"]["sha256"], tuple(receipt["helpers"]["scripts/" + name] for name in custody.HELPERS)
        )
        self.admission = custody.Admission(manifest, digest(manifest), custody.Cohort(**cohort), authority)
        self.interpreter = os.open(receipt["interpreter"]["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, self.interpreter)
        need(digest(child.bytes_at(self.interpreter, child.MAX_INTERPRETER)) == authority.interpreter_sha256)

    def observe(self, request: custody.Request) -> custody.Observation:
        """Sample actual current authority and run a fixed nonroot version-only query."""
        self.request = request
        distro = dict(
            line.split("=", 1)
            for line in safe_path(Path("/etc/os-release")).read_text().splitlines()
            if "=" in line and not line.startswith("#")
        )
        actual = self.admission.cohort
        need(
            distro.get("ID", "").strip('"') == actual.os_id
            and distro.get("VERSION_ID", "").strip('"') == actual.os_version
        )
        need(os.uname().machine == actual.architecture and os.uname().release == actual.kernel)
        need(
            self.receipt["context"]["imageOS"] == actual.image_os
            and self.receipt["context"]["imageVersion"] == actual.image_version
        )
        paths = (Path("/usr/sbin/apparmor_parser"), Path("/etc/apparmor.d/abi/4.0"), *FEATURE_PATHS)
        files = tuple(
            read_root(path, child.MAX_INTERPRETER if index == 0 else child.MAX_SOURCE)
            for index, path in enumerate(paths)
        )
        parser = os.open(paths[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(identity(os.fstat(parser)) == files[0][1])
            try:
                capabilities = os.getxattr(parser, "security.capability")
            except OSError as error:
                need(error.errno == errno.ENODATA)
                capabilities = b""
            need(
                capabilities == b""
                and digest(files[0][0]) == actual.parser_sha256
                and digest(files[1][0]) == actual.abi_sha256
            )
            cutoff = min(request.original_deadline_ns - custody.CLEANUP_NS, self.clock.now_ns() + 5 * NS)
            result = child.probe(
                child.Interpreter(self.interpreter, self.admission.bootstrap.interpreter_sha256),
                parser,
                "parser-version",
                child.Build("version", request.uid, request.gid, cutoff, cutoff + NS),
                self.clock,
            )
            need(result.dead and re.fullmatch(rb"AppArmor parser version 5\.0\.2\n[^\x00]{0,900}", result.policy))
            need(read_root(paths[0], child.MAX_INTERPRETER) == files[0])
            self.probes.append(
                {
                    "kind": "parser-version",
                    "version": "5.0.2",
                    "uid": request.uid,
                    "gid": request.gid,
                    "savedIds": "nonzero-equal",
                    "groups": [],
                    "capabilities": "zero",
                    "nnp": 1,
                    "lifetime": "proven-dead",
                    "boundingSetRequiredZero": False,
                }
            )
        finally:
            os.close(parser)
        helpers = tuple(read_root(self.stage / "scripts" / name, child.MAX_SOURCE * 4) for name in custody.HELPERS)
        return custody.Observation(
            request.run,
            actual,
            self.clock.boot_id(),
            process(os.getpid()),
            files[0][0],
            files[1][0],
            tuple(item[0] for item in files[2:]),
            tuple(item[1] for item in files),
            child.Interpreter(self.interpreter, self.admission.bootstrap.interpreter_sha256),
            tuple(item[0] for item in helpers),
            tuple(item[1] for item in helpers),
            str(paths[0]),
            str(paths[1]),
            capabilities,
        )

    def reobserve(self, observation: custody.Observation) -> custody.Observation:
        """Repeat the same current-run facts; caller rejects any changed identity/content."""
        need(self.request is not None)
        repeated = self.observe(self.request)
        need(repeated == observation)
        return repeated


def command(argv: list[str], deadline: int) -> bytes:
    """Run only reviewed root-owned systemd management commands with a finite allowance."""
    need(argv[0] in {"/usr/bin/systemctl", "/usr/bin/systemd-run"} or argv == ["/usr/bin/env", "--version"])
    safe_path(Path(argv[0]))
    result = subprocess.run(  # noqa: S603 - closed root-owned systemd argv, no shell.
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        cwd="/",
        timeout=min(1.0, remaining(deadline)),
        check=False,
    )
    remaining(deadline)
    need(result.returncode == 0 and len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT)
    return result.stdout


def manager(unit: str, deadline: int) -> dict[str, str]:
    """Read one exact nonce-derived service's closed manager properties."""
    need(re.fullmatch(r"containers-userns-unused-[0-9a-f]{32}\.service", unit))
    raw = command(
        ["/usr/bin/systemctl", "show", "--no-pager", "--all", "--property=" + ",".join(PROPERTIES), "--", unit],
        deadline,
    )
    result = {}
    for row in raw.decode("utf-8", "strict").splitlines():
        key, separator, value = row.partition("=")
        need(separator and key in PROPERTIES and key not in result)
        result[key] = value
    need(set(result) == set(PROPERTIES))
    return result


def timespan(value: str) -> int:
    """Decode systemctl's finite timespans, refusing infinity and unknown units."""
    units = {"us": 1000, "ms": 1_000_000, "s": NS, "min": 60 * NS, "h": 3600 * NS}
    result = 0
    for word in value.split():
        match = re.fullmatch(r"([0-9]+)(us|ms|s|min|h)", word)
        need(match is not None)
        result += int(match[1]) * units[match[2]]
    need(result > 0)
    return result


class SupervisorPort:
    """One nonrenewing transient service; inspect never opens custody or performs RPC."""

    def __init__(self, stage: Path, control: Control, clock: Clock, stack: ExitStack) -> None:
        """Capture trusted staging and control authority before any custody lock."""
        self.stage, self.control, self.clock, self.stack = stage, control, clock, stack
        self.held: HeldProcess | None = None
        self.ack: dict[str, Any] | None = None
        self.start: StartBinding | None = None
        bound = self.control.read("binding.json")
        self.bootstrap = bound["bootstrap"]
        coordinator = custody._process_from(bound["record"]["lease"]["coordinator"])  # noqa: SLF001
        self.coordinator = HeldProcess(coordinator) if coordinator.pid == os.getpid() else None
        if self.coordinator is not None:
            stack.callback(self.coordinator.close)
        self.argv: list[str] = []

    def arguments(self, _lease: custody.Lease) -> list[str]:
        """Return only the verified closure's fixed owner entry point."""
        bootstrap = self.bootstrap
        return [
            bootstrap["interpreter"]["path"],
            "-I",
            "-B",
            "-S",
            "-c",
            (
                "import sys;sys.path.insert(0,sys.argv[1]);from scripts.docker_userns_hosted import owner_entry;"
                "raise SystemExit(owner_entry(sys.argv[1],sys.argv[2]))"
            ),
            str(self.stage),
            str(self.control.path),
        ]

    def observe_live(self, lease: custody.Lease, expected: custody.Owner | None, deadline: int) -> custody.Owner:
        """Check manager ownership, exact argv, activation budget and kernel process/cgroup."""
        unit = "containers-userns-unused-" + lease.nonce + ".service"
        state = manager(unit, deadline)
        need(state["LoadState"] == "loaded" and state["ActiveState"] == "active" and state["Transient"] == "yes")
        need(state["User"] in {"", "root", "0"} and state["Group"] in {"", "root", "0"} and not state["DropInPaths"])
        need(state["Type"] == "exec" and state["Restart"] == "no" and state["Slice"] == "system.slice")
        need(state["KillMode"] == "control-group" and state["SendSIGKILL"] == "yes")
        fragment = Path("/run/systemd/transient") / unit
        need(state["FragmentPath"] == str(fragment))
        fragment_raw, fragment_identity = read_root(fragment)
        activation = int(state["ExecMainStartTimestampMonotonic"]) * 1000
        need(lease.start_ns <= activation <= self.clock.now_ns())
        need(
            timespan(state["TimeoutStopUSec"]) == 5 * NS
            and activation + timespan(state["RuntimeMaxUSec"]) + 20 * NS < lease.deadline_ns
        )
        owner = custody.Owner(unit.removesuffix(".service"), process(int(state["MainPID"])))
        need(state["ControlGroup"] == owner.process.cgroup.path)
        need(
            owner.process.cgroup.path == "/system.slice/" + unit
            and group(owner.process.cgroup.path) == owner.process.cgroup
        )
        need(owner.process.pgid != lease.coordinator.pgid and owner.process.pid != lease.coordinator.pid)
        need(
            owner.process.cgroup.path != lease.runtime_slice.path
            and not owner.process.cgroup.path.startswith(lease.runtime_slice.path + "/")
        )
        argv = self.argv
        need(argv)
        actual_argv = (Path("/proc") / str(owner.process.pid) / "cmdline").read_bytes()
        need(actual_argv == b"\0".join(item.encode() for item in argv) + b"\0")
        environment = (Path("/proc") / str(owner.process.pid) / "environ").read_bytes()
        need(len(environment) <= LIMIT and environment.endswith(b"\0"))
        pairs = [item.split(b"=", 1) for item in environment[:-1].split(b"\0")]
        need(len(pairs) == len(ENV) and dict(pairs) == {key.encode(): value.encode() for key, value in ENV.items()})
        if expected is not None:
            need(owner == expected)
        if self.held is None:
            self.held = HeldProcess(owner.process)
            self.stack.callback(self.held.close)
        need(self.held.expected == owner.process)
        self.held.live()
        self.manager_evidence = {
            "properties": state,
            "fragmentSha256": digest(fragment_raw),
            "fragmentIdentity": asdict(fragment_identity),
            "argvSha256": digest(actual_argv),
        }
        remaining(deadline)
        return owner

    def start_unused_owner(self, intent: custody.ArmIntent, deadline_ns: int) -> custody.OwnerObservation:
        """Start once, authenticate READY, and retain any ambiguous start as failure."""
        lease = intent.lease
        unit = "containers-userns-unused-" + lease.nonce + ".service"
        self.start = StartBinding.create(self.control, intent, deadline_ns, self.clock)
        need(manager(unit, deadline_ns)["LoadState"] == "not-found")
        self.argv = self.arguments(lease)
        runtime = (lease.deadline_ns - self.clock.now_ns()) // NS - 26
        need(1 <= runtime <= MAX_RUNTIME_SECONDS)
        safe_path(Path("/usr/bin/env"))
        command(
            [
                "/usr/bin/systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + unit,
                "--slice=system.slice",
                "--property=Type=exec",
                "--property=Restart=no",
                "--property=RuntimeMaxSec=" + str(runtime),
                "--property=RuntimeRandomizedExtraSec=0",
                "--property=TimeoutStartSec=2",
                "--property=TimeoutStopSec=5",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                "--property=User=root",
                "--property=Group=root",
                "--property=UMask=0077",
                "--property=StandardOutput=null",
                "--property=StandardError=null",
                "--",
                "/usr/bin/env",
                "-i",
                *(key + "=" + value for key, value in ENV.items()),
                *self.argv,
            ],
            deadline_ns,
        )
        owner = self.observe_live(lease, None, deadline_ns)
        # Socket creation can lag Type=exec. No restart or alternate owner is allowed.
        while not (self.control.path / "owner.sock").exists():
            self.held.live()
            select.select([], [], [], min(0.005, remaining(deadline_ns)))
        with self.control.connect("owner.sock", self.held, deadline_ns) as connection:
            send(connection, {"kind": "ready", "intent": intent_digest(intent)}, deadline_ns)
            self.ack = receive(connection, deadline_ns)
        self.validate_ack(intent, owner)
        self.control.write("ack.json", self.ack, deadline_ns)
        self.start.ready(self.clock)
        return self.inspect_owner(lease, owner, deadline_ns)

    def validate_ack(self, intent: custody.ArmIntent, owner: custody.Owner) -> None:
        """Require readiness for this exact generation, boot, lease and held service."""
        value = exact(
            self.ack,
            {
                "schema",
                "intent",
                "owner",
                "readyNs",
                "coordinatorPidfd",
                "leaseSha256",
                "handshakeUntilNs",
                "startSha256",
            },
        )
        need(value["schema"] == 1 and value["intent"] == intent_digest(intent) and owner_from(value["owner"]) == owner)
        need(value["coordinatorPidfd"] is True and value["leaseSha256"] == digest(encoded(asdict(intent.lease))))
        if self.start is None:
            self.start = StartBinding.load(self.control, intent)
        self.start.stable()
        need(value["handshakeUntilNs"] == self.start.until_ns and value["startSha256"] == self.start.sha256)
        need(
            self.start.intent == intent
            and type(value["readyNs"]) is int
            and self.start.started_ns <= value["readyNs"] < self.start.until_ns
        )
        need(
            type(value["readyNs"]) is int
            and intent.lease.start_ns <= value["readyNs"] <= self.clock.now_ns()
            and self.clock.now_ns() - value["readyNs"] < custody.HANDSHAKE_NS
        )

    def inspect_owner(self, lease: custody.Lease, owner: custody.Owner, deadline_ns: int) -> custody.OwnerObservation:
        """Read only manager, pidfd and kernel state; no RPC and no custody-lock recursion."""
        need(self.ack is not None and owner_from(self.ack["owner"]) == owner)
        if self.coordinator is not None:
            self.coordinator.live()
        self.observe_live(lease, owner, deadline_ns)
        if self.coordinator is not None:
            self.coordinator.live()
        return custody.OwnerObservation(
            lease,
            owner,
            self.clock.now_ns(),
            custody.Lifetime.LIVE,
            acknowledged=True,
            service_root_owned=True,
            group_absent=False,
            cgroup_absent=False,
        )

    def request_close(self, lease: custody.Lease, owner: custody.Owner, deadline_ns: int) -> None:
        """Send only a normal-close hint to the exact already-bound owner."""
        self.inspect_owner(lease, owner, deadline_ns)
        with self.control.connect("owner.sock", self.held, deadline_ns) as connection:
            send(connection, {"kind": "close", "intent": self.ack["intent"]}, deadline_ns)
            need(receive(connection, deadline_ns) == {"accepted": True})

    def observe_termination(self, lease: custody.Lease, owner: custody.Owner) -> custody.OwnerObservation:
        """Require held process death, empty group, missing cgroup and collected exact unit."""
        need(self.held is not None and self.held.expected == owner.process and self.held.dead())
        try:
            os.killpg(owner.process.pgid, 0)
        except ProcessLookupError:
            pass
        else:
            raise custody.CustodyError
        need(absent(Path("/sys/fs/cgroup" + owner.process.cgroup.path)))
        self.termination_evidence = manager(owner.service + ".service", lease.deadline_ns)
        need(self.termination_evidence["LoadState"] == "not-found")
        return custody.OwnerObservation(
            lease,
            owner,
            self.clock.now_ns(),
            custody.Lifetime.DEAD,
            acknowledged=True,
            service_root_owned=True,
            group_absent=True,
            cgroup_absent=True,
        )


def binding(control: Control, stage: Path) -> tuple[custody.Record, custody.ArmIntent, custody.Locator, dict[str, Any]]:
    """Bind a finite control directory to exact custody, original observer and helper closure."""
    value = exact(control.read("binding.json"), {"record", "observer", "bootstrap", "control", "stage"})
    need(
        value["stage"] == str(stage)
        and value["control"] == {"device": control.mark.st_dev, "inode": control.mark.st_ino}
    )
    record = record_from(value["record"])
    locator = custody.Locator(record.lease.nonce, record.lease.directory)
    custody._validate(record, locator)  # noqa: SLF001 - authenticate the complete frozen record schema.
    need(record.state is custody.State.PREPARED and not record.owner_attempted and record.owner is None)
    intent = custody.ArmIntent(record.lease, record.generation + 1)
    return record, intent, locator, value


@dataclass(frozen=True)
class OwnerContext:
    """Closed immutable owner-loop bindings, kept separate from its finite flags."""

    control: Control
    intent: custody.ArmIntent
    locator: custody.Locator
    coordinator: HeldProcess
    observer: HeldProcess
    supervisor: SupervisorPort
    owner: custody.Owner
    clock: Clock
    start: StartBinding


class OwnerLoop:
    """Closed authenticated service loop, with durable ARMED required before finalization."""

    def __init__(self, context: OwnerContext) -> None:
        """Capture only immutable lease/identity bindings and two finite event flags."""
        self.control, self.intent, self.locator = context.control, context.intent, context.locator
        self.coordinator, self.observer, self.supervisor = context.coordinator, context.observer, context.supervisor
        self.owner, self.clock, self.start = context.owner, context.clock, context.start
        self.committed, self.close_requested, self.terminated = False, False, False
        lease = self.intent.lease
        self.ack = {
            "schema": 1,
            "intent": intent_digest(self.intent),
            "owner": asdict(self.owner),
            "readyNs": self.clock.now_ns(),
            "coordinatorPidfd": True,
            "leaseSha256": digest(encoded(asdict(lease))),
            "handshakeUntilNs": self.start.until_ns,
            "startSha256": self.start.sha256,
        }
        self.supervisor.ack = self.ack
        self.events: list[dict[str, Any]] = [
            {"kind": "READY", "ns": self.clock.now_ns(), "generation": self.intent.generation}
        ]

    def term(self, _number: int, _frame: object) -> None:
        """Mark cancellation without renewing the lease or doing work in a signal handler."""
        self.terminated = True

    def handle(self, connection: socket.socket) -> None:
        """Authenticate both directions and accept only four closed messages."""
        lease = self.intent.lease
        creds = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        expected = self.coordinator if creds[0] == self.coordinator.expected.pid else self.observer
        peer(connection, expected)
        request = exact(
            receive(connection, min(lease.deadline_ns, self.clock.now_ns() + custody.HANDSHAKE_NS)), {"kind", "intent"}
        )
        need(request["intent"] == self.ack["intent"])
        if request["kind"] in {"ready", "observe"}:
            need(request["kind"] == ("ready" if expected is self.coordinator else "observe"))
            if request["kind"] == "ready":
                self.start.ready(self.clock)
                send(connection, self.ack, self.start.until_ns)
                self.start.ready(self.clock)
            else:
                self.start.stable()
                send(connection, self.ack, lease.deadline_ns)
            return
        need(expected is self.coordinator)
        current = read_record(self.locator)
        need(current.owner == self.owner and current.lease == lease)
        if request["kind"] == "commit":
            need(
                not self.committed
                and current.state is custody.State.ARMED
                and current.generation == self.intent.generation + 1
                and self.clock.now_ns() < lease.work_until_ns
            )
            self.committed = True
            self.events.append({"kind": "ARMED_SEEN", "ns": self.clock.now_ns(), "generation": current.generation})
            send(connection, {"committed": True}, lease.deadline_ns)
        elif request["kind"] == "close":
            need(self.committed and current.state is custody.State.CLOSING and current.cause is custody.Cause.NORMAL)
            self.close_requested = True
            send(connection, {"accepted": True}, lease.deadline_ns)
        else:
            raise custody.CustodyError

    def finish(self) -> bool:
        """Finalize only a durably bound owner, retaining failed/never-armed attempts."""
        lease = self.intent.lease
        dead = self.coordinator.dead()
        if not (self.close_requested or dead or self.terminated or self.clock.now_ns() >= lease.work_until_ns):
            return False
        current = read_record(self.locator)
        need(
            current.state in {custody.State.ARMED, custody.State.CLOSING}
            and current.owner == self.owner
            and current.lease == lease
        )
        observation = self.supervisor.inspect_owner(
            lease, self.owner, min(lease.deadline_ns, self.clock.now_ns() + custody.HANDSHAKE_NS)
        )
        dead = self.coordinator.dead()
        if dead:
            self.events.append(
                {
                    "kind": "COORDINATOR_DEATH",
                    "ns": self.clock.now_ns(),
                    "pid": lease.coordinator.pid,
                    "startTicks": lease.coordinator.start_ticks,
                }
            )
            cause = custody.Cause.CANCELLED
        elif self.terminated or current.cause is custody.Cause.CANCELLED:
            cause = custody.Cause.CANCELLED
        elif self.close_requested:
            cause = custody.Cause.NORMAL
        else:
            cause = custody.Cause.CANCELLED if self.terminated else custody.Cause.EXPIRY
        receipt = custody.finalize_unused(self.locator, observation, cause, self.clock)
        # A cancellation first seen during the durable operation cannot become accepted normal evidence.
        need(not (self.terminated or self.coordinator.dead()) or receipt.cause is custody.Cause.CANCELLED)
        self.events.append({"kind": "FINALIZED", "ns": self.clock.now_ns(), "cause": cause.value})
        need(len(self.events) <= MAX_EVENTS)
        self.control.write(
            "receipt.json",
            {
                "schema": 1,
                "receipt": asdict(receipt),
                "events": self.events,
                "owner": asdict(self.owner),
                "leaseSha256": self.ack["leaseSha256"],
            },
            lease.deadline_ns,
        )
        # Persistence may observe new cancellation; terminal metadata is never rewritten to hide it.
        after_death = self.coordinator.dead()
        need(not self.terminated or receipt.cause is custody.Cause.CANCELLED)
        need(not after_death or (dead and receipt.cause is custody.Cause.CANCELLED))
        need(self.clock.now_ns() < lease.deadline_ns)
        return True


def owner_main(stage_name: str, control_name: str) -> int:
    """Run an independent root service, holding the coordinator pidfd before READY."""
    os.umask(0o077)
    need(os.geteuid() == 0)
    stage, control, clock = Path(stage_name), Control(Path(control_name)), Clock()
    _, intent, locator, value = binding(control, stage)
    lease = intent.lease
    with ExitStack() as stack:
        coordinator = HeldProcess(lease.coordinator)
        observer = HeldProcess(custody._process_from(value["observer"]))  # noqa: SLF001 - exact frozen wire schema.
        stack.callback(coordinator.close)
        stack.callback(observer.close)
        start = StartBinding.load(control, intent)
        start.ready(clock)
        custody.read_owner_intent(locator, intent, clock)
        start.ready(clock)
        listener = control.listen("owner.sock")
        stack.callback(listener.close)
        supervisor = SupervisorPort(stage, control, clock, stack)
        supervisor.argv = supervisor.arguments(lease)
        owner = supervisor.observe_live(lease, None, start.until_ns)
        start.ready(clock)
        loop = OwnerLoop(OwnerContext(control, intent, locator, coordinator, observer, supervisor, owner, clock, start))
        signal.signal(signal.SIGTERM, loop.term)
        while True:
            ready = select.select([listener, coordinator.descriptor], [], [], min(0.02, remaining(lease.deadline_ns)))[
                0
            ]
            if listener in ready:
                connection, _ = listener.accept()
                with connection:
                    loop.handle(connection)
            if loop.finish():
                return 0


def owner_entry(stage_name: str, control_name: str) -> int:
    """Retain a diagnostic on service refusal without retrying or accepting its receipt."""
    try:
        return owner_main(stage_name, control_name)
    except Exception as error:  # noqa: BLE001 - closed retained diagnostic, never raw privileged output.
        with suppress(custody.CustodyError, OSError, ValueError):
            control = Control(Path(control_name))
            _, intent, _, _ = binding(control, Path(stage_name))
            control.phase = "owner"
            control.failure(error, intent.lease.deadline_ns)
        return 1


def commit_notice(supervisor: SupervisorPort, intent: custody.ArmIntent) -> None:
    """Notify outside custody's lock, only after durable ARMED and the final budget check."""
    deadline = min(intent.lease.work_until_ns, supervisor.clock.now_ns() + custody.HANDSHAKE_NS)
    with supervisor.control.connect("owner.sock", supervisor.held, deadline) as connection:
        send(connection, {"kind": "commit", "intent": intent_digest(intent)}, deadline)
        need(receive(connection, deadline) == {"committed": True})


def coordinator_main(
    stage: Path, control: Control, bootstrap: dict[str, Any], observer: custody.Process, deadline: int
) -> int:
    """Prepare/arm as the actual root caller, then await its independent observer."""
    clock = Clock()
    with ExitStack() as stack:
        control.phase = "admission"
        host = HostPort(stage, bootstrap, clock, stack)
        context = bootstrap["context"]
        run = custody.Run(
            context["candidate"],
            context["head"],
            context["base"],
            context["run"],
            context["attempt"],
            "userns-custody-unused",
            "Strukturpiloten/containers",
            492,
            "TheRealBecks/issue442-main-reconciled",
            "github-hosted",
            "pull_request",
            "github-pr-merge",
        )
        actual = process(os.getpid())
        need(actual.cgroup.path != "/")
        request = custody.Request(run, deadline, bootstrap["uid"], bootstrap["gid"], actual.cgroup)
        source_fds = []
        for name, leaf in zip(custody.SOURCE_PATHS, custody.LEAVES, strict=True):
            descriptor = os.open(stage / "sdk" / leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, descriptor)
            source_fds.append(custody.SourceFD(name, descriptor))
        control.phase = "prepare"
        locator = custody.prepare_unused(host.admission, request, tuple(source_fds), host, clock)
        record = read_record(locator)
        control.phase = "binding"
        control.write(
            "binding.json",
            {
                "record": asdict(record),
                "observer": asdict(observer),
                "bootstrap": bootstrap,
                "control": {"device": control.mark.st_dev, "inode": control.mark.st_ino},
                "stage": str(stage),
            },
            record.lease.work_until_ns,
        )
        supervisor = SupervisorPort(stage, control, clock, stack)
        control.phase = "arm"
        custody.arm_unused(locator, supervisor, clock)
        armed = read_record(locator)
        need(armed.state is custody.State.ARMED and armed.owner is not None)
        intent = custody.ArmIntent(armed.lease, armed.generation - 1)
        committed_ns = clock.now_ns()
        need(committed_ns < armed.lease.work_until_ns)
        control.phase = "commit"
        commit_notice(supervisor, intent)
        held_observer = HeldProcess(observer)
        stack.callback(held_observer.close)
        with control.connect("observer.sock", held_observer, armed.lease.work_until_ns) as connection:
            send(
                connection,
                {
                    "kind": "ARM_COMMITTED",
                    "generation": armed.generation,
                    "ns": committed_ns,
                    "intent": intent_digest(intent),
                    "probes": host.probes,
                },
                armed.lease.work_until_ns,
            )
            response = receive(connection, armed.lease.deadline_ns)
            need(response == {"kind": "close"})
            control.phase = "close"
            custody.request_close_unused(locator, supervisor, clock)
            send(connection, {"kind": "CLOSE_REQUESTED"}, armed.lease.deadline_ns)
            control.phase = "finish"
            need(receive(connection, armed.lease.deadline_ns) == {"kind": "finish"})
        return 0


def closed_receipt(control: Control, record: custody.Record, *, killed: bool, committed_ns: int) -> dict[str, Any]:
    """Check independently expected event order and the exact closed durable receipt."""
    value = exact(control.read("receipt.json"), {"schema", "receipt", "events", "owner", "leaseSha256"})
    need(value["schema"] == 1 and owner_from(value["owner"]) == record.owner)
    need(value["leaseSha256"] == digest(encoded(asdict(record.lease))))
    expected_cause = custody.Cause.CANCELLED if killed else custody.Cause.NORMAL
    receipt = exact(value["receipt"], set(custody.Receipt.__dataclass_fields__))
    need(
        receipt["nonce"] == record.lease.nonce
        and receipt["lease_sha256"] == value["leaseSha256"]
        and receipt["cause"] == expected_cause
        and receipt["qualification"] == "none"
        and receipt["outcome"] == "closed-unused"
    )
    events = value["events"]
    need(type(events) is list and MIN_EVENTS <= len(events) <= MAX_EVENTS)
    expected = ["READY", "ARMED_SEEN", *(["COORDINATOR_DEATH"] if killed else []), "FINALIZED"]
    need([item["kind"] for item in events] == expected)
    stamps = [item["ns"] for item in events]
    need(all(type(stamp) is int and record.lease.start_ns <= stamp < record.lease.deadline_ns for stamp in stamps))
    need(stamps == sorted(stamps) and events[1]["ns"] >= committed_ns)
    schemas = {
        "READY": {"kind", "ns", "generation"},
        "ARMED_SEEN": {"kind", "ns", "generation"},
        "COORDINATOR_DEATH": {"kind", "ns", "pid", "startTicks"},
        "FINALIZED": {"kind", "ns", "cause"},
    }
    for event in events:
        exact(event, schemas[event["kind"]])
    need(events[0]["generation"] == record.generation - 1 and events[1]["generation"] == record.generation)
    need(events[-1]["cause"] == expected_cause)
    if killed:
        need(
            events[-2]["pid"] == record.lease.coordinator.pid
            and events[-2]["startTicks"] == record.lease.coordinator.start_ticks
        )
    current = read_record(custody.Locator(record.lease.nonce, record.lease.directory))
    need(
        current.state is custody.State.CLOSED
        and current.owner == record.owner
        and current.lease == record.lease
        and current.generation == receipt["generation"]
        and current.cause is expected_cause
    )
    return value


@dataclass(frozen=True)
class CyclePlan:
    """A fresh cycle remains capped by the original root-bootstrap job allowance."""

    stage: Path
    bootstrap: dict[str, Any]
    deadline: int
    killed: bool


@dataclass(frozen=True)
class ArmedCycle:
    """Independent observer's authenticated durable arm and exact held owner."""

    record: custody.Record
    supervisor: SupervisorPort
    message: dict[str, Any]
    credentials: dict[str, int]


def absent(path: Path) -> bool:
    """Absence must be ENOENT, never a suppressed permission or observation error."""
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


class CycleObserver:
    """Independent root observer, outside both the coordinator and finalizer lifetimes."""

    def __init__(self, plan: CyclePlan, result: dict[str, Any]) -> None:
        """Retain exact owned locators in the artifact even if later proof fails."""
        self.plan, self.result, self.clock = plan, result, Clock()
        self.coordinator: ChildCustody | None = None
        self.control = Control(Path("/run") / (CONTROL_PREFIX + os.urandom(16).hex()), create=True)
        self.observer = process(os.getpid())
        result.update(
            {
                "cycle": "coordinator-sigkill" if plan.killed else "normal",
                "outcome": "retained-unknown",
                "controlLocator": str(self.control.path),
                "deadlineNs": plan.deadline,
                "observer": asdict(self.observer),
            }
        )

    def spawn(self, listener: socket.socket) -> ChildCustody:
        """Hold the fork immediately and grant work only after the exact identity handshake."""
        end = min(self.plan.deadline - custody.CLEANUP_NS, self.clock.now_ns() + custody.HANDSHAKE_NS)
        remaining(end)
        descriptors = []
        try:
            read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            descriptors.extend((read, write))
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            descriptors.extend((gate_read, gate_write))
            pid = os.fork()
            if pid == 0:
                listener.close()
                os.close(read)
                os.close(gate_write)
                try:
                    os.setsid()
                    raw = encoded(asdict(process(os.getpid()))) + b"\n"
                    remaining(end)
                    need(os.write(write, raw) == len(raw))
                    os.close(write)
                    need(select.select([gate_read], [], [], remaining(end))[0] and os.read(gate_read, 2) == b"G")
                    remaining(end)
                    os.close(gate_read)
                    status = coordinator_main(
                        self.plan.stage, self.control, self.plan.bootstrap, self.observer, self.plan.deadline
                    )
                except Exception as error:  # noqa: BLE001 - closed diagnostic, never raw privileged output.
                    with suppress(custody.CustodyError, OSError, ValueError):
                        self.control.failure(error, self.plan.deadline)
                    status = 1
                os._exit(status)
            self.coordinator = ChildCustody(pid)
            self.result["forkChildPid"] = pid
            self.coordinator.hold()
            os.close(write)
            descriptors.remove(write)
            os.close(gate_read)
            descriptors.remove(gate_read)
            raw = self.identity_frame(read, end)
            actual = custody._process_from(json.loads(raw, object_pairs_hook=unique))  # noqa: SLF001
            self.coordinator.bind(actual)
            remaining(end)
            need(os.write(gate_write, b"G") == 1)
            remaining(end)
        except Exception:
            if self.coordinator is not None:
                self.result["coordinatorCleanup"] = self.coordinator.cleanup(self.plan.deadline)
            raise
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
        return self.coordinator

    def identity_frame(self, descriptor: int, end: int) -> bytes:
        """Read one bounded frame under the held child and original fork-handshake cutoff."""
        raw = bytearray()
        while b"\n" not in raw:
            self.coordinator.state()
            need(select.select([descriptor], [], [], remaining(end))[0])
            piece = os.read(descriptor, LIMIT + 1 - len(raw))
            need(piece)
            raw.extend(piece)
            need(len(raw) <= LIMIT)
        need(raw.endswith(b"\n") and raw.count(b"\n") == 1)
        remaining(end)
        return bytes(raw)

    def authenticate(self, connection: socket.socket, coordinator: HeldProcess, stack: ExitStack) -> ArmedCycle:
        """Accept only durable ARMED followed by authenticated original owner readiness."""
        need(absent(self.control.path / "failure.json"))
        credentials = peer(connection, coordinator)
        message = exact(
            receive(connection, self.plan.deadline - custody.CLEANUP_NS),
            {"kind", "generation", "ns", "intent", "probes"},
        )
        record, intent, locator, bound = binding(self.control, self.plan.stage)
        self.result["custody"] = asdict(locator)
        need(
            bound["observer"] == asdict(self.observer)
            and bound["bootstrap"] == self.plan.bootstrap
            and record.lease.coordinator == coordinator.expected
        )
        need(
            record.lease.deadline_ns == self.plan.deadline and record.lease.runtime_slice == coordinator.expected.cgroup
        )
        armed = read_record(locator)
        need(armed.state is custody.State.ARMED and armed.lease == record.lease and armed.owner is not None)
        need(
            message["kind"] == "ARM_COMMITTED"
            and message["generation"] == armed.generation
            and message["intent"] == intent_digest(intent)
            and armed.generation == intent.generation + 1
        )
        need(type(message["ns"]) is int and record.lease.start_ns <= message["ns"] < record.lease.work_until_ns)
        supervisor = SupervisorPort(self.plan.stage, self.control, self.clock, stack)
        supervisor.argv = supervisor.arguments(armed.lease)
        supervisor.ack = self.control.read("ack.json")
        supervisor.validate_ack(intent, armed.owner)
        supervisor.inspect_owner(
            armed.lease, armed.owner, min(armed.lease.work_until_ns, self.clock.now_ns() + custody.HANDSHAKE_NS)
        )
        with self.control.connect("owner.sock", supervisor.held, armed.lease.work_until_ns) as owner_connection:
            send(owner_connection, {"kind": "observe", "intent": message["intent"]}, armed.lease.work_until_ns)
            need(receive(owner_connection, armed.lease.work_until_ns) == supervisor.ack)
        self.result.update(
            {
                "ack": supervisor.ack,
                "coordinator": asdict(coordinator.expected),
                "armCommittedNs": message["ns"],
                "workUntilNs": armed.lease.work_until_ns,
            }
        )
        return ArmedCycle(armed, supervisor, message, credentials)

    def owner_death(self, armed: ArmedCycle) -> custody.OwnerObservation:
        """Wait within D for the held process, then prove cgroup/unit absence separately."""
        record, supervisor = armed.record, armed.supervisor
        while not supervisor.held.dead():
            select.select([supervisor.held.descriptor], [], [], min(0.02, remaining(record.lease.deadline_ns)))
        while True:
            state = manager(record.owner.service + ".service", record.lease.deadline_ns)
            if state["LoadState"] == "not-found" and absent(Path("/sys/fs/cgroup" + record.owner.process.cgroup.path)):
                break
            need(state["MainPID"] in {"0", str(record.owner.process.pid)})
            select.select([], [], [], min(0.02, remaining(record.lease.deadline_ns)))
        return supervisor.observe_termination(record.lease, record.owner)

    def complete(self, connection: socket.socket, coordinator: HeldProcess, armed: ArmedCycle) -> None:
        """Exercise one trigger; require event order, exact deaths and finite disposal."""
        record, message = armed.record, armed.message
        lease, kill_ns = record.lease, None
        if self.plan.killed:
            coordinator.live()
            kill_ns = self.clock.now_ns()
            need(message["ns"] <= kill_ns < lease.work_until_ns)
            signal.pidfd_send_signal(coordinator.descriptor, signal.SIGKILL)
        else:
            send(connection, {"kind": "close"}, lease.work_until_ns)
            need(receive(connection, lease.deadline_ns) == {"kind": "CLOSE_REQUESTED"})
        death = self.owner_death(armed)
        receipt = closed_receipt(self.control, record, killed=self.plan.killed, committed_ns=message["ns"])
        if self.plan.killed:
            need(coordinator.dead() and receipt["events"][-2]["ns"] >= kill_ns)
        else:
            coordinator.live()
            send(connection, {"kind": "finish"}, lease.deadline_ns)
        while not coordinator.dead():
            select.select([coordinator.descriptor], [], [], min(0.02, remaining(lease.deadline_ns)))
        need(coordinator.reap(lease.deadline_ns))
        waited, status = coordinator.pid, coordinator.status
        correct_exit = (
            os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            if self.plan.killed
            else os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        )
        need(waited == coordinator.expected.pid and correct_exit)
        locator = custody.Locator(lease.nonce, lease.directory)
        need(absent(self.control.path / "failure.json"))
        custody.dispose_unused(locator, death, self.clock)
        need(absent(Path("/run") / (custody.PREFIX + locator.nonce)))
        self.control.dispose(lease.deadline_ns)
        need(absent(self.control.path))
        remaining(lease.deadline_ns)
        self.result.update(
            {
                "outcome": "closed-disposed-unused",
                "boundaryKind": "unused-coordinator",
                "exclusionGroup": asdict(coordinator.expected.cgroup),
                "coordinatorPeer": armed.credentials,
                "coordinatorExit": -signal.SIGKILL if self.plan.killed else 0,
                "killNs": kill_ns,
                "receipt": receipt,
                "ownerTermination": asdict(death),
                "ownerManager": armed.supervisor.manager_evidence,
                "terminationManager": armed.supervisor.termination_evidence,
                "probes": message["probes"],
                "builderPrivilege": {
                    "uid": lease.uid,
                    "gid": lease.gid,
                    "savedIds": "nonzero-equal",
                    "groups": [],
                    "nnp": 1,
                    "activeCapabilities": "zero",
                    "boundingSetRequiredZero": False,
                    "sourceDescriptors": "sealed-readonly",
                    "lifetime": "proven-dead",
                },
                "unusedFacts": {"state": "closed_unused", "policyLoad": "never", "containerCreate": "never"},
                "custodyDisposed": True,
                "controlDisposed": True,
                "unitAbsent": True,
                "cgroupAbsent": True,
            }
        )

    def run(self) -> None:
        """Clean up the exact fork child on every observer error, within original D."""
        with ExitStack() as stack:
            listener = self.control.listen("observer.sock")
            stack.callback(listener.close)
            try:
                coordinator = self.spawn(listener)
                while not select.select(
                    [listener], [], [], min(0.02, remaining(self.plan.deadline - custody.CLEANUP_NS))
                )[0]:
                    coordinator.live()
                connection, _ = listener.accept()
                with connection:
                    armed = self.authenticate(connection, coordinator, stack)
                    self.complete(connection, coordinator, armed)
            finally:
                if self.coordinator is not None:
                    if not self.coordinator.reaped:
                        self.result["coordinatorCleanup"] = self.coordinator.cleanup(self.plan.deadline)
                    self.coordinator.close()


def cycle(plan: CyclePlan, result: dict[str, Any]) -> None:
    """Refuse a late cycle rather than manufacturing a new cleanup reserve."""
    remaining(plan.deadline - custody.CLEANUP_NS)
    observer = CycleObserver(plan, result)
    try:
        observer.run()
    except Exception:
        with suppress(custody.CustodyError, OSError, ValueError):
            failure = exact(
                observer.control.read("failure.json"),
                {"schema", "diagnosticOnly", "phase", "ns", "custodyLocator", "childPending"},
            )
            need(failure["schema"] == 1 and failure["diagnosticOnly"] is True)
            result["diagnostic"] = failure
        raise


def audit_stage(stage: Path, bootstrap: dict[str, Any]) -> dict[str, Any]:
    """Recheck root-held helper/source hashes and fresh identities across both cycles."""
    result = {}
    for name, expected in bootstrap["helpers"].items():
        raw, info = read_root(stage / name, child.MAX_SOURCE * 4)
        need(digest(raw) == expected)
        result[name] = {"sha256": expected, "identity": asdict(info)}
    manifest = json.loads(read_root(stage / ".github/docker-userns-policy-source.json")[0], object_pairs_hook=unique)
    specs = {item["path"]: item for item in manifest["source"]["files"]}
    for name, leaf in zip(custody.SOURCE_PATHS, custody.LEAVES, strict=True):
        raw, info = read_root(stage / "sdk" / leaf, child.MAX_SOURCE)
        need(len(raw) == specs[name]["size"] and digest(raw) == specs[name]["sha256"])
        result["sdk/" + leaf] = {"sha256": digest(raw), "identity": asdict(info)}
    for name in ("bootstrap.json", "probe"):
        raw, info = read_root(stage / name)
        if name == "bootstrap.json":
            need(json.loads(raw, object_pairs_hook=unique) == bootstrap)
        result[name] = {"sha256": digest(raw), "identity": asdict(info)}
    return result


def installed_tools(deadline: int) -> dict[str, Any]:
    """Record actual preinstalled systemd tools under the explicit OS-integrity exception."""
    result = {}
    for name in ("/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/env"):
        path = safe_path(Path(name))
        raw, info = read_root(path, child.MAX_INTERPRETER)
        need(raw.startswith(b"\x7fELF"))
        version = command([name, "--version"], deadline).decode("ascii", "strict").splitlines()[0]
        need(re.fullmatch(r"[^\x00\n]{1,256}", version))
        if name != "/usr/bin/env":
            need(re.fullmatch(r"systemd [0-9][^\x00]{0,256}", version))
        result[name] = {
            "path": str(path),
            "sha256": digest(raw),
            "identity": asdict(info),
            "version": version,
            "integrity": "preinstalled-root-owned-OS-tool-not-publisher-checksum",
        }
    return result


def write_denial_probe(stage: Path, bootstrap: dict[str, Any], clock: Clock) -> dict[str, Any]:
    """Intersect one parent phase cap with original W/D, without renewing either allowance."""
    deadline = bootstrap["deadlineNs"]
    work_until = deadline - custody.CLEANUP_NS
    entry = clock.now_ns()
    need(type(deadline) is int and entry < work_until)
    phase_work = min(work_until, entry + custody.CHILD_NS)
    phase_cleanup = min(deadline, entry + custody.CHILD_NS + NS)
    remaining(phase_work)
    with ExitStack() as stack:
        host = HostPort(stage, bootstrap, clock, stack)
        descriptor = os.open(stage / "probe", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, descriptor)
        need(clock.now_ns() < phase_work)
        outcome = child.probe(
            child.Interpreter(host.interpreter, host.admission.bootstrap.interpreter_sha256),
            descriptor,
            "write-denial",
            child.Build("write-denial", bootstrap["uid"], bootstrap["gid"], phase_work, phase_cleanup),
            clock,
        )
        remaining(phase_work)
        need(clock.now_ns() < phase_work and outcome.dead and outcome.policy == b"write-denied\n")
    need(clock.now_ns() < phase_work)
    return {
        "denied": True,
        "synthetic": True,
        "lifetime": "proven-dead",
        "workUntilNs": work_until,
        "deadlineNs": deadline,
        "phaseWorkUntilNs": phase_work,
        "phaseCleanupUntilNs": phase_cleanup,
    }


class ObserverProcess(subprocess.Popen):
    """Keep ChildCustody as the sole reaper, including unknown completion."""

    def __del__(self) -> None:
        """Do not poll/reap implicitly or fabricate an exit status during destruction."""


@dataclass(frozen=True)
class CaptureOutcome:
    """Bounded capture facts; failed family cleanup never becomes hosted acceptance."""

    stdout: bytes
    stderr: bytes
    returncode: int | None
    accepted: bool
    proof: dict[str, Any]


def enable_subreaper() -> None:
    """Set/read back a process-local Linux subreaper before the sole child exists."""
    need(
        os.geteuid() == 0
        and hasattr(os, "pidfd_open")
        and hasattr(os, "P_PIDFD")
        and hasattr(signal, "pidfd_send_signal")
    )
    reaper_invariant()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    value = ctypes.c_int()
    need(libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.addressof(value), 0, 0, 0) == 0 and value.value == 0)
    need(libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0)
    need(libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.addressof(value), 0, 0, 0) == 0 and value.value == 1)


def family_cleanup(owned: dict[int, ChildCustody], deadline: int) -> dict[str, Any]:
    """Drain only kernel-proven direct/adopted children; never a process group or service."""
    records = {}
    unknown = False
    try:
        while True:
            time_remaining(deadline)
            for pid in direct_children():
                if pid not in owned:
                    need(len(owned) < MAX_CHILDREN)
                    child_hold = ChildCustody(pid)
                    owned[pid] = child_hold
                    child_hold.hold()
            for pid, child_hold in owned.items():
                if not child_hold.reaped:
                    records[str(pid)] = child_hold.cleanup(deadline)
                    unknown = unknown or records[str(pid)]["lifetime"] == "unknown"
            if unknown or child_absent():
                break
            select.select([], [], [], min(0.01, time_remaining(deadline)))
        time_remaining(deadline)
        empty = child_absent()
    except custody.CustodyError, OSError, ValueError:
        unknown, empty = True, False
    return {
        "scope": "observer-descendants-only",
        "children": records,
        "kernelEchild": empty,
        "complete": empty and not unknown,
        "systemdOwners": "outside-family-custody",
    }


def read_observer(
    process_handle: ObserverProcess,
    owned: ChildCustody,
    deadline: int,
    buffers: dict[str, bytearray],
    eof: dict[str, bool],
) -> None:
    """Read cap-plus-one while alive; require both EOF and exact status before success."""
    with selectors.DefaultSelector() as selector:
        for name, stream, limit in (
            ("stdout", process_handle.stdout, MAX_ARTIFACT),
            ("stderr", process_handle.stderr, LIMIT),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, limit))
        while selector.get_map() or not owned.dead():
            remaining(deadline)
            for key, _ in selector.select(min(0.02, remaining(deadline))):
                name, limit = key.data
                raw = os.read(key.fd, min(4096, limit + 1 - len(buffers[name])))
                buffers[name].extend(raw)
                need(len(buffers[name]) <= limit)
                if not raw:
                    eof[name] = True
                    selector.unregister(key.fileobj)
        remaining(deadline)
        need(owned.reap(deadline))


def capture_observer(stage: Path, bootstrap: dict[str, Any]) -> CaptureOutcome:
    """Launch only the verified observer, under one original D and child-only teardown."""
    deadline = bootstrap["deadlineNs"]
    need(type(deadline) is int)
    remaining(deadline - custody.CLEANUP_NS)
    enable_subreaper()
    process_handle, observer = None, None
    owned: dict[int, ChildCustody] = {}
    buffers, eof = {"stdout": bytearray(), "stderr": bytearray()}, {"stdout": False, "stderr": False}
    complete, failed, family = False, False, {}
    code = (
        "import sys;sys.path.insert(0,sys.argv[1]);from scripts.docker_userns_hosted import main;"
        "raise SystemExit(main(sys.argv[1]))"
    )
    with cancellation_scope():
        try:
            remaining(deadline - custody.CLEANUP_NS)
            process_handle = ObserverProcess(
                [bootstrap["interpreter"]["path"], "-I", "-B", "-S", "-c", code, str(stage)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=ENV,
                cwd="/",
                close_fds=True,
                start_new_session=True,
            )
            observer = ChildCustody(process_handle.pid)
            owned[observer.pid] = observer
            observer.hold()
            remaining(deadline - custody.CLEANUP_NS)
            read_observer(process_handle, observer, deadline - TEARDOWN_NS, buffers, eof)
            complete = bool(observer.reaped and observer.status == 0 and all(eof.values()) and child_absent())
            remaining(deadline)
        except Exception:  # noqa: BLE001 - retain bounded facts; never accept timeout/cancellation/unknown cleanup.
            failed = True
        finally:
            if not complete or failed or _CANCELLATION[0]:
                failed = True
                family = family_cleanup(owned, deadline)
            else:
                family = {
                    "scope": "observer-descendants-only",
                    "children": {},
                    "kernelEchild": True,
                    "complete": True,
                    "systemdOwners": "outside-family-custody",
                }
            if process_handle is not None:
                if observer is not None and observer.reaped and observer.status is not None:
                    process_handle.returncode = os.waitstatus_to_exitcode(observer.status)
                for stream in (process_handle.stdout, process_handle.stderr):
                    if stream is not None:
                        stream.close()
            for child_hold in owned.values():
                child_hold.close()
    # Restoration propagates the scope's sticky cancellation before any acceptance decision.
    status = (
        os.waitstatus_to_exitcode(observer.status) if observer is not None and observer.status is not None else None
    )
    proof = {
        "cancelled": _CANCELLATION[0],
        "stdoutEof": eof["stdout"],
        "stderrEof": eof["stderr"],
        "stdoutBytes": len(buffers["stdout"]),
        "stderrBytes": len(buffers["stderr"]),
        "statusKnown": status is not None,
        "family": family,
        "deadlineNs": deadline,
    }
    accepted = complete and not failed and not _CANCELLATION[0] and time.monotonic_ns() < deadline
    return CaptureOutcome(bytes(buffers["stdout"]), bytes(buffers["stderr"]), status, accepted, proof)


def observer_main(stage_name: str) -> int:
    """Emit one bounded nonqualifying artifact; unknown ownership retains root-owned data."""
    os.umask(0o077)
    need(os.geteuid() == 0)
    stage = Path(stage_name)
    bootstrap = json.loads(read_root(stage / "bootstrap.json")[0], object_pairs_hook=unique)
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "consumer": custody.CONSUMER,
        "qualification": "none",
        "policy_load_run": False,
        "container_run": False,
        "scope": "hosted-unused-custody",
        "outcome": "retained-unknown",
        "bootstrap": bootstrap,
        "cycles": [],
    }
    status = 1
    try:
        need(
            type(bootstrap["uid"]) is int
            and bootstrap["uid"] > 0
            and type(bootstrap["gid"]) is int
            and bootstrap["gid"] > 0
        )
        result["systemTools"] = installed_tools(bootstrap["deadlineNs"])
        result["staging"] = audit_stage(stage, bootstrap)
        result["writeProbe"] = write_denial_probe(stage, bootstrap, Clock())
        for killed in (False, True):
            progress = {}
            result["cycles"].append(progress)
            plan = CyclePlan(stage, bootstrap, min(bootstrap["deadlineNs"], time.monotonic_ns() + CYCLE_NS), killed)
            cycle(plan, progress)
            need(audit_stage(stage, bootstrap) == result["staging"])
        need(installed_tools(bootstrap["deadlineNs"]) == result["systemTools"])
        result["outcome"] = "closed-disposed-unused"
        status = 0
    except Exception:  # noqa: BLE001 - preserve unresolved custody and avoid exposing protected raw inputs.
        result["retainedStage"] = str(stage)
    need(len(json.dumps(result).encode()) <= MAX_ARTIFACT)
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return status


def main(stage_name: str) -> int:
    """Install deferred cancellation before observer work and retain exact child ownership."""
    reaper_invariant()
    with cancellation_scope():
        status = observer_main(stage_name)
    return 1 if _CANCELLATION[0] else status
