"""Unused-only custody foundation; hosted adapters are kept in a separate module."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from contextlib import AbstractContextManager

from scripts import docker_userns_custody_child as child

ROOT = Path("/run")
PREFIX = "containers-userns-unused."
CONSUMER = "containers-ubuntu26-userns-unused"
MAX_STATE = 32768
MAX_TOTAL_NS = 1_800_000_000_000
CLEANUP_NS = 60_000_000_000
HANDSHAKE_NS = 2_000_000_000
CHILD_NS = 5_000_000_000
SHA = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
NONCE = re.compile(r"[0-9a-f]{32}")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SOURCE_PATHS = ("scripts/native-runner-apparmor.py", "scripts/native_outer_diagnostic_capture.py", "LICENSE")
LEAVES = ("builder", "capture", "license")
HELPERS = ("docker_userns_custody.py", "docker_userns_custody_child.py")
MODES = {
    "lock": 0o600,
    "journal": 0o600,
    "state.json": 0o600,
    "builder": 0o400,
    "capture": 0o400,
    "license": 0o400,
    "policy": 0o400,
}
ROOT_MODE = 0o700
PRIVATE_MODE = 0o600
MAX_JOURNAL = 32
MAX_FEATURE = 4096
SELF_STAT_LIMIT = 8192
START_FIELD = 19
FEATURES = ("enabled", "restriction", "namespace_mask", "policy_v9")
FILE_ROLES = ("parser", "abi", *FEATURES)
PULL_REQUEST = 492


class State(StrEnum):
    """No mutation-capable lifecycle state exists."""

    PREPARING = "preparing"
    PREPARED = "prepared"
    ARM_INTENT = "arm_intent"
    ARMED = "armed_unused"
    CLOSING = "closing_unused"
    CLOSED = "closed_unused"
    RETAINED = "retained"


class Cause(StrEnum):
    """Keep cancellation separate from successful normal closure."""

    NORMAL = "normal"
    EXPIRY = "expiry"
    CANCELLED = "cancelled"


class Lifetime(StrEnum):
    """Require independently observed lifetime, never a PID-only inference."""

    LIVE = "live"
    DEAD = "dead"
    UNKNOWN = "unknown"


class CustodyError(Exception):
    """Expose only a closed refusal, plus an optional non-authorizing locator."""

    def __init__(self, locator: Locator | None = None, *, child_pending: bool | None = None) -> None:
        """Retain private custody when an operation cannot be established."""
        super().__init__("unused-custody-refused")
        self.locator = locator
        self.child_pending = child_pending


def _work(observer: child.WorkObserver | None, site: str | None) -> AbstractContextManager[None]:
    return child.work(observer, "CUSTODY", site, (CustodyError, child.ChildError))


def _observe[T](
    observer: child.WorkObserver | None, site: str, operation: Callable[..., T], /, *args: object, **kwargs: object
) -> T:
    with _work(observer, site):
        return operation(*args, **kwargs)


def _pairs(observer: child.WorkObserver | None) -> Callable[..., dict[str, Any]]:
    return _unique if observer is None else partial(_unique, observer=observer)


def _need(value: object, *, observer: child.WorkObserver | None = None, work_site: str | None = None) -> None:
    if not value:
        child.refused(observer, "CUSTODY", work_site)
        raise CustodyError


def _integer(value: object, *, minimum: int = 0, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_INTEGER_G01"):
        _need(type(value) is int and value >= minimum)


def _token(value: object, pattern: re.Pattern[str], *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_TOKEN_G01"):
        _need(type(value) is str and pattern.fullmatch(value))


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _unique(pairs: list[tuple[str, Any]], *, observer: child.WorkObserver | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        with _work(observer, "C_UNIQUE_G01"):
            _need(key not in result)
        result[key] = value
    return result


@dataclass(frozen=True)
class FileIdentity:
    """Fresh filesystem facts; never used as cross-run admission."""

    device: int
    inode: int
    owner: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class DirectoryIdentity:
    """Stable root directory binding, excluding mutable directory timestamps."""

    device: int
    inode: int


@dataclass(frozen=True)
class Group:
    """An observed cgroup path and filesystem identity."""

    path: str
    device: int
    inode: int


@dataclass(frozen=True)
class Process:
    """Bind PID reuse, original kill group and cgroup placement."""

    pid: int
    start_ticks: int
    pgid: int
    uid: int
    cgroup: Group


@dataclass(frozen=True)
class Run:
    """Separate executed merge candidate from the event head/base."""

    candidate: str
    head: str
    base: str
    workflow_run: str
    attempt: str
    job: str
    repository: str
    pull_request: int
    head_ref: str
    provider: str
    event: str
    checkout_identity: str


@dataclass(frozen=True)
class Cohort:
    """Reviewed semantic/content authority, with no previous-run inode or process facts."""

    os_id: str
    os_version: str
    architecture: str
    kernel: str
    image_os: str
    image_version: str
    parser_version: str
    parser_sha256: str
    abi_sha256: str
    namespace_mask: tuple[str, ...]


@dataclass(frozen=True)
class BootstrapAuthority:
    """Explicit separately reviewed bootstrap input; no installed bootstrap is supplied."""

    interpreter_sha256: str
    helper_sha256: tuple[str, str]


@dataclass(frozen=True)
class Admission:
    """Reviewed code/data only; no artifact-to-admission conversion or production default."""

    manifest: bytes
    manifest_sha256: str
    cohort: Cohort
    bootstrap: BootstrapAuthority | None


@dataclass(frozen=True)
class Request:
    """Bound run, dropped credentials and the caller's original aggregate deadline."""

    run: Run
    original_deadline_ns: int
    uid: int
    gid: int
    # Compatibility field: the actual unused coordinator exclusion cgroup, never a runtime slice.
    runtime_slice: Group


@dataclass(frozen=True)
class Observation:
    """Facts freshly obtained through the future root host-observation port."""

    run: Run
    cohort: Cohort
    boot: str
    coordinator: Process
    parser: bytes
    abi: bytes
    features: tuple[bytes, bytes, bytes, bytes]
    identities: tuple[FileIdentity, ...]
    interpreter: child.Interpreter | None
    helpers: tuple[bytes, bytes]
    helper_identities: tuple[FileIdentity, FileIdentity]
    parser_path: str
    abi_path: str
    parser_capabilities: bytes | None


class HostPort(Protocol):
    """Observe the actual host; this unit implements no adapter."""

    def observe(self, request: Request) -> Observation:
        """Reobserve current context, bytes and root bootstrap evidence."""
        ...

    def reobserve(self, observation: Observation) -> Observation:
        """Return fresh evidence to check per-invocation stability."""
        ...


class Clock(child.Clock, Protocol):
    """Bind integer monotonic time to the current boot."""

    def boot_id(self) -> str:
        """Return the captured current boot identity."""
        ...


@dataclass(frozen=True)
class SourceSpec:
    """Authority from the existing reviewed manifest, not a second operational pin."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class SourceFD:
    """Caller source bytes are read through bounded already-open descriptors only."""

    path: str
    descriptor: int


@dataclass(frozen=True)
class Locator:
    """A locator alone never authorizes caller-controlled state."""

    nonce: str
    directory: DirectoryIdentity


@dataclass(frozen=True)
class Lease:
    """Complete immutable owner ACK authority, including original deadlines and current identities."""

    schema: int
    consumer: str
    nonce: str
    directory: DirectoryIdentity
    run: Run
    boot: str
    start_ns: int
    deadline_ns: int
    work_until_ns: int
    coordinator: Process
    # Compatibility field: the actual unused coordinator exclusion cgroup, never a runtime slice.
    runtime_slice: Group
    manifest_sha256: str
    source_commit: str
    sources: tuple[SourceSpec, ...]
    cohort: Cohort
    identities: tuple[FileIdentity, ...]
    policy_name: str
    policy_sha256: str | None
    uid: int
    gid: int


@dataclass(frozen=True)
class ArmIntent:
    """Exact durable attempted arm generation; READY does not authorize finalization."""

    lease: Lease
    generation: int


@dataclass(frozen=True)
class Owner:
    """One exact service/process instance, never a freely supplied unit name."""

    service: str
    process: Process


@dataclass(frozen=True)
class OwnerObservation:
    """Explicit port evidence; a test fake is not production authentication."""

    lease: Lease
    owner: Owner
    observed_ns: int
    lifetime: Lifetime
    acknowledged: bool
    service_root_owned: bool
    group_absent: bool
    cgroup_absent: bool


class SupervisorPort(Protocol):
    """Only unused ownership operations; no shell, parser or arbitrary command API."""

    def start_unused_owner(self, intent: ArmIntent, deadline_ns: int) -> OwnerObservation:
        """Start one unused owner and return its observed ACK."""
        ...

    def inspect_owner(self, lease: Lease, owner: Owner, deadline_ns: int) -> OwnerObservation:
        """Independently reobserve that exact owner before readiness."""
        ...

    def request_close(self, lease: Lease, owner: Owner, deadline_ns: int) -> None:
        """Ask the already bound owner to finalize unused custody."""
        ...

    def observe_termination(self, lease: Lease, owner: Owner) -> OwnerObservation:
        """Independently prove that bound owner's complete termination."""
        ...


@dataclass(frozen=True)
class Record:
    """Closed durable state; load/create facts are always structurally never."""

    lease: Lease
    generation: int
    state: State
    child_pending: bool
    owner: Owner | None
    cause: Cause | None
    owner_attempted: bool = False
    policy_load: str = "never"
    container_create: str = "never"


@dataclass(frozen=True)
class Receipt:
    """Closing unused metadata grants no profile, guest, cleanup or native qualification."""

    nonce: str
    lease_sha256: str
    generation: int
    cause: Cause
    qualification: str = "none"
    outcome: str = "closed-unused"


def _group(value: Group, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_GROUP_G01"):
        _need(
            type(value) is Group
            and type(value.path) is str
            and re.fullmatch(r"/[A-Za-z0-9_.:/-]{0,255}", value.path)
            and ".." not in value.path.split("/")
            and "//" not in value.path
        )
    _integer(value.device, **child.observer_args(observer))
    _integer(value.inode, minimum=1, **child.observer_args(observer))


def _process(value: Process, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_PROCESS_G01"):
        _need(type(value) is Process and type(value.uid) is int and value.uid == 0)
    for number in (value.pid, value.start_ticks, value.pgid):
        _integer(number, minimum=1, **child.observer_args(observer))
    _group(value.cgroup, **child.observer_args(observer))


def _run(value: Run, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_RUN_G01"):
        _need(
            type(value) is Run
            and value.repository == "Strukturpiloten/containers"
            and type(value.pull_request) is int
            and value.pull_request == PULL_REQUEST
            and value.head_ref == "TheRealBecks/issue442-main-reconciled"
            and value.provider == "github-hosted"
            and value.event == "pull_request"
            and value.checkout_identity == "github-pr-merge"
        )
    for number in (value.candidate, value.head, value.base):
        _token(number, COMMIT, **child.observer_args(observer))
    for number in (value.workflow_run, value.attempt):
        with _work(observer, "C_RUN_G02"):
            _need(type(number) is str and re.fullmatch(r"[1-9][0-9]{0,19}", number))
    with _work(observer, "C_RUN_G03"):
        _need(type(value.job) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value.job))


def _file(value: FileIdentity, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_FILE_G01"):
        _need(
            type(value) is FileIdentity
            and value.owner == 0
            and value.links == 1
            and stat.S_ISREG(value.mode)
            and not value.mode & 0o7022
        )
    for number in asdict(value).values():
        _integer(number, **child.observer_args(observer))
    with _work(observer, "C_FILE_G02"):
        _need(value.inode > 0)


def _cohort(value: Cohort, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_COHORT_G01"):
        _need(
            type(value) is Cohort
            and value.os_id == "ubuntu"
            and value.os_version == "26.04"
            and value.architecture == "x86_64"
            and value.image_os == "ubuntu26"
            and value.parser_version == "5.0.2"
        )
    with _work(observer, "C_COHORT_G02"):
        _need(
            re.fullmatch(r"[A-Za-z0-9_.+-]{1,96}", value.kernel) and re.fullmatch(r"[0-9.]{1,64}", value.image_version)
        )
    _token(value.parser_sha256, SHA, **child.observer_args(observer))
    _token(value.abi_sha256, SHA, **child.observer_args(observer))
    with _work(observer, "C_COHORT_G03"):
        _need(
            type(value.namespace_mask) is tuple
            and value.namespace_mask == tuple(sorted(set(value.namespace_mask)))
            and "userns_create" in value.namespace_mask
            and all(type(item) is str and re.fullmatch(r"[a-z_]{1,40}", item) for item in value.namespace_mask)
        )


def _manifest(
    admission: Admission, *, observer: child.WorkObserver | None = None
) -> tuple[str, tuple[SourceSpec, ...]]:
    with _work(observer, "C_MANIFEST_G01"):
        _need(
            type(admission) is Admission
            and type(admission.manifest) is bytes
            and len(admission.manifest) <= child.MAX_SOURCE
        )
    _token(admission.manifest_sha256, SHA, **child.observer_args(observer))
    with _work(observer, "C_MANIFEST_G02"):
        _need(_digest(admission.manifest) == admission.manifest_sha256)
    value = _observe(observer, "C_MANIFEST_W01", json.loads, admission.manifest, object_pairs_hook=_pairs(observer))
    with _work(observer, "C_MANIFEST_G03"):
        _need(
            type(value) is dict
            and set(value) == {"schemaVersion", "consumer", "qualification", "source", "parser"}
            and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1
            and value["consumer"] == "containers-ubuntu26-userns-dryparse"
            and value["qualification"] == "none"
        )
    source = value["source"]
    with _work(observer, "C_MANIFEST_G04"):
        _need(
            type(source) is dict
            and set(source) == {"managed", "repository", "ref", "commit", "license", "retrieval", "files"}
            and source["managed"] is True
            and source["repository"] == "Strukturpiloten/docker-lens"
            and source["license"] == "MPL-2.0"
            and source["retrieval"] == "public-https-immutable-commit"
            and type(source["ref"]) is str
            and re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", source["ref"])
        )
    _token(source["commit"], COMMIT, **child.observer_args(observer))
    with _work(observer, "C_MANIFEST_G05"):
        _need(type(source["files"]) is list and len(source["files"]) == len(SOURCE_PATHS))
    records = {}
    for item in source["files"]:
        with _work(observer, "C_MANIFEST_G06"):
            _need(
                type(item) is dict
                and set(item) == {"path", "size", "sha256"}
                and type(item["path"]) is str
                and item["path"] in SOURCE_PATHS
                and item["path"] not in records
            )
        _integer(item["size"], minimum=1, **child.observer_args(observer))
        with _work(observer, "C_MANIFEST_G07"):
            _need(item["size"] <= child.MAX_SOURCE)
        _token(item["sha256"], SHA, **child.observer_args(observer))
        records[item["path"]] = SourceSpec(**item)
    with _work(observer, "C_MANIFEST_G08"):
        _need(
            type(value["parser"]) is dict and value["parser"].get("expectedVersion") == admission.cohort.parser_version
        )
    parser = value["parser"]
    with _work(observer, "C_MANIFEST_G09"):
        _need(
            set(parser) == {"managed", "repository", "expectedVersion", "contractTag", "contractCommit", "integrity"}
            and parser["managed"] is True
            and parser["repository"] == "apparmor/apparmor"
            and parser["contractTag"] == "v" + admission.cohort.parser_version
            and parser["integrity"] == "observed-preinstalled-system-tool-not-vendor-checksum"
        )
    _token(parser["contractCommit"], COMMIT, **child.observer_args(observer))
    return source["commit"], tuple(records[name] for name in SOURCE_PATHS)


def _self_start(*, observer: child.WorkObserver | None = None) -> int:
    with _observe(observer, "C_SELF_START_OPEN", Path("/proc/self/stat").open, "rb") as stream:
        raw = _observe(observer, "C_SELF_START_W01", stream.read, SELF_STAT_LIMIT + 1)
    with _work(observer, "C_SELF_START_G01"):
        _need(len(raw) <= SELF_STAT_LIMIT and b")" in raw)
    fields = raw.rsplit(b")", 1)[1].split()
    with _work(observer, "C_SELF_START_G02"):
        _need(len(fields) > START_FIELD and fields[START_FIELD].isdigit())
    return int(fields[START_FIELD])


def _caller(process: Process, *, observer: child.WorkObserver | None = None) -> None:
    _need(
        process.pid == os.getpid()
        and process.pgid == os.getpgid(0)
        and process.start_ticks == _self_start(**child.observer_args(observer))
        and os.geteuid() == 0,
        observer=observer,
        work_site="C_CALLER_G01",
    )


def _root(*, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_ROOT_G01"):
        _need(os.geteuid() == 0)


def _clock(clock: Clock, lease: Lease | None = None, *, observer: child.WorkObserver | None = None) -> int:
    now, boot = _observe(observer, "C_CLOCK_W01", clock.now_ns), clock.boot_id()
    _integer(now, **child.observer_args(observer))
    _token(boot, BOOT, **child.observer_args(observer))
    if lease is not None:
        with _work(observer, "C_CLOCK_G01"):
            _need(boot == lease.boot and now >= lease.start_ns)
    return now


def _start(clock: Clock, *, observer: child.WorkObserver | None = None) -> tuple[int, str]:
    boot = clock.boot_id()
    _token(boot, BOOT, **child.observer_args(observer))
    now = _clock(clock, **child.observer_args(observer))
    _need(clock.boot_id() == boot, observer=observer, work_site="C_START_G01")
    return now, boot


def _budget(clock: Clock, lease: Lease, until: int | None = None, *, observer: child.WorkObserver | None = None) -> int:
    """Reject new work and accepted completion at the same original current-boot cutoff."""
    limit = lease.deadline_ns if until is None else until
    _integer(limit, **child.observer_args(observer))
    with _work(observer, "C_BUDGET_G01"):
        _need(limit <= lease.deadline_ns)
    now = _clock(clock, lease, **child.observer_args(observer))
    with _work(observer, "C_BUDGET_G02"):
        _need(now < limit)
    return now


def _persist(
    store: _Store, record: Record, clock: Clock, until: int | None = None, *, observer: child.WorkObserver | None = None
) -> None:
    _budget(clock, record.lease, until, **child.observer_args(observer))
    store.save(record)
    _budget(clock, record.lease, until, **child.observer_args(observer))


def _observation(
    admission: Admission,
    request: Request,
    observation: Observation,
    clock: Clock,
    *,
    observer: child.WorkObserver | None = None,
) -> None:
    _cohort(admission.cohort, **child.observer_args(observer))
    _need(
        type(observation) is Observation
        and observation.cohort == admission.cohort
        and observation.run == request.run
        and observation.boot == clock.boot_id()
        and type(observation.parser) is bytes
        and type(observation.abi) is bytes
        and 0 < len(observation.parser) <= child.MAX_INTERPRETER
        and 0 < len(observation.abi) <= child.MAX_SOURCE
        and observation.parser.startswith(b"\x7fELF")
        and observation.parser_path == "/usr/sbin/apparmor_parser"
        and observation.abi_path == "/etc/apparmor.d/abi/4.0"
        and observation.parser_capabilities == b""
        and _digest(observation.parser) == admission.cohort.parser_sha256
        and _digest(observation.abi) == admission.cohort.abi_sha256,
        observer=observer,
        work_site="C_OBSERVATION_G01",
    )
    _process(observation.coordinator, **child.observer_args(observer))
    _caller(observation.coordinator, **child.observer_args(observer))
    with _work(observer, "C_OBSERVATION_G02"):
        _need(request.runtime_slice == observation.coordinator.cgroup and request.runtime_slice.path != "/")
    with _work(observer, "C_OBSERVATION_G03"):
        _need(
            len(observation.features) == len(FEATURES)
            and all(type(item) is bytes and len(item) <= MAX_FEATURE for item in observation.features)
        )
    enabled, restricted, mask, version = observation.features
    with _work(observer, "C_OBSERVATION_G04"):
        _need(
            enabled == b"Y\n"
            and restricted == b"1\n"
            and version == b"yes\n"
            and re.fullmatch(rb"[a-z_ \n]{1,4096}", mask)
            and tuple(sorted(set(mask.decode("ascii").split()))) == admission.cohort.namespace_mask
        )
    with _work(observer, "C_OBSERVATION_G05"):
        _need(len(observation.identities) == len(FILE_ROLES))
    with _work(observer, "C_OBSERVATION_G06"):
        _need(observation.identities[0].mode & 0o111)
    for identity in (*observation.identities, *observation.helper_identities):
        _file(identity, **child.observer_args(observer))
    authority = admission.bootstrap
    with _work(observer, "C_OBSERVATION_G07"):
        _need(
            type(authority) is BootstrapAuthority
            and observation.interpreter is not None
            and observation.interpreter.sha256 == authority.interpreter_sha256
            and type(authority.helper_sha256) is tuple
            and len(authority.helper_sha256) == len(HELPERS)
            and len(observation.helpers) == len(HELPERS)
            and len(observation.helper_identities) == len(HELPERS)
        )
    for digest in (authority.interpreter_sha256, *authority.helper_sha256):
        _token(digest, SHA, **child.observer_args(observer))
    with _work(observer, "C_OBSERVATION_G08"):
        _need(
            all(type(data) is bytes and len(data) <= child.MAX_SOURCE for data in observation.helpers)
            and tuple(_digest(data) for data in observation.helpers) == authority.helper_sha256
        )


def _identity(info: os.stat_result) -> DirectoryIdentity:
    return DirectoryIdentity(info.st_dev, info.st_ino)


def _directory(info: os.stat_result, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_DIRECTORY_G01"):
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == ROOT_MODE)


@dataclass(frozen=True)
class _Store:
    directory: int
    locator: Locator
    observer: child.WorkObserver | None = None

    def read(self, name: str) -> bytes:
        descriptor = _observe(
            self.observer,
            "C_STORE_READ_W01",
            os.open,
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=self.directory,
        )
        try:
            before = _observe(self.observer, "C_STORE_READ_W02", os.fstat, descriptor)
            with _work(self.observer, "C_STORE_READ_G01"):
                _need(
                    stat.S_ISREG(before.st_mode)
                    and before.st_uid == 0
                    and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == MODES[name]
                )
            data = _observe(
                self.observer,
                "C_STORE_READ_W03",
                child.bytes_at,
                descriptor,
                MAX_STATE if name == "state.json" else child.MAX_SOURCE,
                **child.observer_args(self.observer),
            )
            with _work(self.observer, "C_STORE_READ_G02"):
                _need(
                    child.file_mark(os.fstat(descriptor)) == child.file_mark(before)
                    and _identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False)) == _identity(before)
                )
            with _work(self.observer, "C_STORE_READ_G03"):
                _need(name != "lock" or not data)
            return data
        finally:
            os.close(descriptor)

    def write(self, name: str, data: bytes, mode: int) -> None:
        with _work(self.observer, "C_STORE_WRITE_G01"):
            _need(
                name in {*MODES, "state.next"}
                and len(data) <= (MAX_STATE if name == "state.next" else child.MAX_SOURCE)
            )
        descriptor = _observe(
            self.observer,
            "C_STORE_WRITE_W01",
            os.open,
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=self.directory,
        )
        try:
            with os.fdopen(_observe(self.observer, "C_STORE_WRITE_DUP", os.dup, descriptor), "wb") as stream:
                _observe(self.observer, "C_STORE_WRITE_W02", stream.write, data)
                _observe(self.observer, "C_STORE_WRITE_W03", stream.flush)
                _observe(self.observer, "C_STORE_WRITE_W04", os.fsync, stream.fileno())
            info = _observe(self.observer, "C_STORE_WRITE_W05", os.fstat, descriptor)
            with _work(self.observer, "C_STORE_WRITE_G02"):
                _need(info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode)
            with _work(self.observer, "C_STORE_WRITE_G03"):
                _need(_identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False)) == _identity(info))
        finally:
            os.close(descriptor)

    def save(self, record: Record) -> None:
        _validate(record, self.locator, **child.observer_args(self.observer))
        data = _observe(self.observer, "C_STORE_SAVE_W01", _json, asdict(record))
        journal = self.read("journal").splitlines()
        with _work(self.observer, "C_STORE_SAVE_G01"):
            _need(len(journal) < MAX_JOURNAL)
        if journal:
            previous = _decode(
                json.loads(self.read("state.json"), object_pairs_hook=_pairs(self.observer)),
                **child.observer_args(self.observer),
            )
            with _work(self.observer, "C_STORE_SAVE_G02"):
                _need(
                    record.generation == previous.generation + 1
                    and record.state in _transitions().get(previous.state, set())
                )
            with _work(self.observer, "C_STORE_SAVE_G03"):
                _need(
                    record.lease == previous.lease
                    or (
                        previous.state is State.PREPARING
                        and record.state is State.PREPARED
                        and record.lease == replace(previous.lease, policy_sha256=record.lease.policy_sha256)
                    )
                )
            _journal(journal, previous, **child.observer_args(self.observer))
        else:
            with _work(self.observer, "C_STORE_SAVE_G04"):
                _need(record.generation == 1 and record.state is State.PREPARING)
        self.write("state.next", data, 0o600)
        _observe(
            self.observer,
            "C_STORE_SAVE_STATE_REPLACE",
            os.replace,
            "state.next",
            "state.json",
            src_dir_fd=self.directory,
            dst_dir_fd=self.directory,
        )
        _observe(self.observer, "C_STORE_SAVE_W02", os.fsync, self.directory)
        descriptor = _observe(
            self.observer,
            "C_STORE_SAVE_W03",
            os.open,
            "journal",
            os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.directory,
        )
        try:
            entry = (
                _observe(
                    self.observer, "C_STORE_SAVE_W04", _json, {"generation": record.generation, "sha256": _digest(data)}
                )
                + b"\n"
            )
            with _work(self.observer, "C_STORE_SAVE_G05"):
                _need(os.write(descriptor, entry) == len(entry))
            _observe(self.observer, "C_STORE_SAVE_W05", os.fsync, descriptor)
        finally:
            os.close(descriptor)
        _observe(self.observer, "C_STORE_SAVE_W06", os.fsync, self.directory)

    def load(self) -> Record:
        _observe(self.observer, "C_STORE_LOAD_W01", os.lseek, self.directory, 0, os.SEEK_SET)
        names = set(_observe(self.observer, "C_STORE_LOAD_W02", os.listdir, self.directory))
        with _work(self.observer, "C_STORE_LOAD_G01"):
            _need(names <= set(MODES) and {"lock", "journal", "state.json"} <= names)
        for name in names:
            self.read(name)
        record = _decode(
            json.loads(self.read("state.json"), object_pairs_hook=_pairs(self.observer)),
            **child.observer_args(self.observer),
        )
        _validate(record, self.locator, **child.observer_args(self.observer))
        _journal(self.read("journal").splitlines(), record, **child.observer_args(self.observer))
        if record.state not in {State.PREPARING, State.RETAINED}:
            with _work(self.observer, "C_STORE_LOAD_G02"):
                _need(names == set(MODES))
        for leaf, spec in zip(LEAVES, record.lease.sources, strict=True):
            if leaf in names:
                data = self.read(leaf)
                with _work(self.observer, "C_STORE_LOAD_G03"):
                    _need(len(data) == spec.size and _digest(data) == spec.sha256)
        if "policy" in names and record.lease.policy_sha256 is not None:
            _need(
                _digest(self.read("policy")) == record.lease.policy_sha256,
                observer=self.observer,
                work_site="C_STORE_LOAD_G04",
            )
        return record


@contextmanager
def _store(locator: Locator, *, observer: child.WorkObserver | None = None) -> Iterator[_Store]:
    _root(**child.observer_args(observer))
    with _work(observer, "C_STORE_G01"):
        _need(type(locator) is Locator and type(locator.directory) is DirectoryIdentity)
    _integer(locator.directory.device, **child.observer_args(observer))
    _integer(locator.directory.inode, minimum=1, **child.observer_args(observer))
    _token(locator.nonce, NONCE, **child.observer_args(observer))
    root, directory, lock = None, None, None
    try:
        root = _observe(
            observer, "C_STORE_W01", os.open, ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        info = _observe(observer, "C_STORE_W02", os.fstat, root)
        with _work(observer, "C_STORE_G02"):
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        name = PREFIX + locator.nonce
        directory = _observe(
            observer,
            "C_STORE_W03",
            os.open,
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root,
        )
        _directory(_observe(observer, "C_STORE_W04", os.fstat, directory), **child.observer_args(observer))
        with _work(observer, "C_STORE_G03"):
            _need(
                _identity(os.fstat(directory))
                == locator.directory
                == _identity(os.stat(name, dir_fd=root, follow_symlinks=False))
            )
        lock = _observe(
            observer, "C_STORE_W05", os.open, "lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
        )
        lock_info = _observe(observer, "C_STORE_W06", os.fstat, lock)
        with _work(observer, "C_STORE_G04"):
            _need(
                stat.S_ISREG(lock_info.st_mode)
                and lock_info.st_uid == 0
                and lock_info.st_nlink == 1
                and stat.S_IMODE(lock_info.st_mode) == PRIVATE_MODE
            )
        _observe(observer, "C_STORE_W07", fcntl.flock, lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield _Store(directory, locator, **child.observer_args(observer))
        _directory(_observe(observer, "C_STORE_W08", os.fstat, directory), **child.observer_args(observer))
        with _work(observer, "C_STORE_G05"):
            _need(_identity(os.fstat(directory)) == _identity(os.stat(name, dir_fd=root, follow_symlinks=False)))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise CustodyError(locator) from error
    finally:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)
        if root is not None:
            os.close(root)


def _exact(value: object, keys: set[str], *, observer: child.WorkObserver | None = None) -> dict[str, Any]:
    with _work(observer, "C_EXACT_G01"):
        _need(type(value) is dict and set(value) == keys)
    return value


def _group_from(value: object, *, observer: child.WorkObserver | None = None) -> Group:
    return Group(**_exact(value, {"path", "device", "inode"}, **child.observer_args(observer)))


def _process_from(value: object, *, observer: child.WorkObserver | None = None) -> Process:
    data = _exact(value, {"pid", "start_ticks", "pgid", "uid", "cgroup"}, **child.observer_args(observer))
    return Process(**{**data, "cgroup": _group_from(data["cgroup"], **child.observer_args(observer))})


def _decode(value: object, *, observer: child.WorkObserver | None = None) -> Record:
    data = _exact(
        value,
        {
            "lease",
            "generation",
            "state",
            "child_pending",
            "owner",
            "cause",
            "owner_attempted",
            "policy_load",
            "container_create",
        },
        **child.observer_args(observer),
    )
    lease = _exact(data["lease"], set(Lease.__dataclass_fields__), **child.observer_args(observer))
    lease = Lease(
        **{
            **lease,
            "directory": DirectoryIdentity(
                **_exact(lease["directory"], {"device", "inode"}, **child.observer_args(observer))
            ),
            "run": Run(**_exact(lease["run"], set(Run.__dataclass_fields__), **child.observer_args(observer))),
            "coordinator": _process_from(lease["coordinator"], **child.observer_args(observer)),
            "runtime_slice": _group_from(lease["runtime_slice"], **child.observer_args(observer)),
            "sources": tuple(
                SourceSpec(**_exact(item, {"path", "size", "sha256"}, **child.observer_args(observer)))
                for item in lease["sources"]
            ),
            "cohort": Cohort(
                **{
                    **_exact(lease["cohort"], set(Cohort.__dataclass_fields__), **child.observer_args(observer)),
                    "namespace_mask": tuple(lease["cohort"]["namespace_mask"]),
                }
            ),
            "identities": tuple(
                FileIdentity(**_exact(item, set(FileIdentity.__dataclass_fields__), **child.observer_args(observer)))
                for item in lease["identities"]
            ),
        }
    )
    owner = None
    if data["owner"] is not None:
        fields = _exact(data["owner"], {"service", "process"}, **child.observer_args(observer))
        owner = Owner(fields["service"], _process_from(fields["process"], **child.observer_args(observer)))
    return Record(
        lease,
        data["generation"],
        State(data["state"]),
        data["child_pending"],
        owner,
        Cause(data["cause"]) if data["cause"] is not None else None,
        data["owner_attempted"],
        data["policy_load"],
        data["container_create"],
    )


def _validate(record: Record, locator: Locator, *, observer: child.WorkObserver | None = None) -> None:
    lease = record.lease
    with _work(observer, "C_VALIDATE_G01"):
        _need(
            type(record) is Record
            and type(lease) is Lease
            and lease.schema == 1
            and type(lease.schema) is int
            and lease.consumer == CONSUMER
            and lease.nonce == locator.nonce
            and lease.directory == locator.directory
            and record.policy_load == "never"
            and record.container_create == "never"
            and type(record.state) is State
            and type(record.child_pending) is bool
            and type(record.owner_attempted) is bool
        )
    _token(lease.nonce, NONCE, **child.observer_args(observer))
    _token(lease.boot, BOOT, **child.observer_args(observer))
    _token(lease.manifest_sha256, SHA, **child.observer_args(observer))
    _token(lease.source_commit, COMMIT, **child.observer_args(observer))
    _run(lease.run, **child.observer_args(observer))
    _process(lease.coordinator, **child.observer_args(observer))
    _group(lease.runtime_slice, **child.observer_args(observer))
    with _work(observer, "C_VALIDATE_G02"):
        _need(lease.runtime_slice == lease.coordinator.cgroup and lease.runtime_slice.path != "/")
    _cohort(lease.cohort, **child.observer_args(observer))
    _integer(record.generation, minimum=1, **child.observer_args(observer))
    for value in (lease.start_ns, lease.deadline_ns, lease.work_until_ns):
        _integer(value, **child.observer_args(observer))
    with _work(observer, "C_VALIDATE_G03"):
        _need(
            lease.deadline_ns - lease.start_ns <= MAX_TOTAL_NS
            and lease.start_ns < lease.work_until_ns == lease.deadline_ns - CLEANUP_NS
        )
    with _work(observer, "C_VALIDATE_G04"):
        _need(
            tuple(item.path for item in lease.sources) == SOURCE_PATHS
            and len(lease.identities) == len(FILE_ROLES)
            and lease.policy_name
            == f"dockerlens-127-upstream-rootless-{lease.run.workflow_run}-{lease.run.attempt}-{lease.nonce}"
        )
    for item in lease.sources:
        _integer(item.size, minimum=1, **child.observer_args(observer))
        with _work(observer, "C_VALIDATE_G05"):
            _need(item.size <= child.MAX_SOURCE)
        _token(item.sha256, SHA, **child.observer_args(observer))
    for item in lease.identities:
        _file(item, **child.observer_args(observer))
    _integer(lease.uid, minimum=1, **child.observer_args(observer))
    _integer(lease.gid, minimum=1, **child.observer_args(observer))
    if record.state not in {State.PREPARING, State.RETAINED}:
        with _work(observer, "C_VALIDATE_G06"):
            _need(not record.child_pending)
        _token(lease.policy_sha256, SHA, **child.observer_args(observer))
    _phase(record, **child.observer_args(observer))


def _phase(record: Record, *, observer: child.WorkObserver | None = None) -> None:
    lease = record.lease
    if record.owner is not None:
        _process(record.owner.process, **child.observer_args(observer))
        with _work(observer, "C_PHASE_G01"):
            _need(record.owner.service == "containers-userns-unused-" + lease.nonce)
    if record.state in {State.ARM_INTENT, State.ARMED}:
        with _work(observer, "C_PHASE_G02"):
            _need(record.owner_attempted)
    if record.state is State.PREPARED:
        with _work(observer, "C_PHASE_G03"):
            _need(not record.owner_attempted and record.owner is None)
    if record.state is State.PREPARING:
        with _work(observer, "C_PHASE_G04"):
            _need(not record.owner_attempted and record.owner is None)
    if record.state is State.ARMED or (record.state in {State.CLOSING, State.CLOSED} and record.owner_attempted):
        with _work(observer, "C_PHASE_G05"):
            _need(record.owner is not None)
    if record.state is State.CLOSED:
        with _work(observer, "C_PHASE_G06"):
            _need(type(record.cause) is Cause)


def _journal(lines: list[bytes], record: Record, *, observer: child.WorkObserver | None = None) -> None:
    with _work(observer, "C_JOURNAL_G01"):
        _need(0 < len(lines) <= MAX_JOURNAL)
    previous = 0
    for line in lines:
        entry = _exact(
            json.loads(line, object_pairs_hook=_pairs(observer)),
            {"generation", "sha256"},
            **child.observer_args(observer),
        )
        _integer(entry["generation"], minimum=1, **child.observer_args(observer))
        _token(entry["sha256"], SHA, **child.observer_args(observer))
        with _work(observer, "C_JOURNAL_G02"):
            _need(entry["generation"] == previous + 1)
        previous = entry["generation"]
    with _work(observer, "C_JOURNAL_G03"):
        _need(previous == record.generation and entry["sha256"] == _digest(_json(asdict(record))))


def _transitions() -> dict[State, set[State]]:
    return {
        State.PREPARING: {State.PREPARING, State.PREPARED, State.RETAINED},
        State.PREPARED: {State.ARM_INTENT, State.CLOSING, State.RETAINED},
        State.ARM_INTENT: {State.ARMED, State.RETAINED},
        State.ARMED: {State.CLOSING, State.RETAINED},
        State.CLOSING: {State.CLOSING, State.CLOSED, State.RETAINED},
    }


def _next(record: Record, state: State, *, observer: child.WorkObserver | None = None, **fields: object) -> Record:
    with _work(observer, "C_NEXT_G01"):
        _need(state in _transitions().get(record.state, set()))
    return replace(record, state=state, generation=record.generation + 1, **fields)


def _retain(store: _Store, record: Record, clock: Clock, *, pending: bool | None = None) -> None:
    with child.muted(store.observer):
        _budget(clock, record.lease)
        record = store.load()
        if record.state not in {State.RETAINED, State.CLOSED}:
            retained = _next(record, State.RETAINED, child_pending=record.child_pending if pending is None else pending)
            _persist(store, retained, clock)


def _settled(store: _Store, clock: Clock, *, work: bool = False) -> Record:
    record = store.load()
    _budget(clock, record.lease, record.lease.work_until_ns if work else None)
    if record.state in {State.PREPARING, State.ARM_INTENT} or record.child_pending:
        _retain(store, record, clock)
        raise CustodyError(store.locator)
    return record


def _initial(clock: Clock, boot: str, until: int, *, observer: child.WorkObserver | None = None) -> None:
    _need(
        _clock(clock, **child.observer_args(observer)) < until and clock.boot_id() == boot,
        observer=observer,
        work_site="C_INITIAL_G01",
    )


def _create(clock: Clock, boot: str, until: int, *, observer: child.WorkObserver | None = None) -> Locator:
    _initial(clock, boot, until, **child.observer_args(observer))
    nonce = _observe(observer, "C_CREATE_W01", secrets.token_hex, 16)
    name = PREFIX + nonce
    root = _observe(
        observer, "C_CREATE_W02", os.open, ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        parent = _observe(observer, "C_CREATE_W03", os.fstat, root)
        with _work(observer, "C_CREATE_G01"):
            _need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022)
        _initial(clock, boot, until, **child.observer_args(observer))
        _observe(observer, "C_CREATE_W04", os.mkdir, name, ROOT_MODE, dir_fd=root)
        _initial(clock, boot, until, **child.observer_args(observer))
        directory = _observe(
            observer,
            "C_CREATE_W05",
            os.open,
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root,
        )
        try:
            _directory(_observe(observer, "C_CREATE_W06", os.fstat, directory), **child.observer_args(observer))
            locator = Locator(nonce, _identity(_observe(observer, "C_CREATE_W07", os.fstat, directory)))
            for leaf in ("lock", "journal"):
                _initial(clock, boot, until, **child.observer_args(observer))
                descriptor = _observe(
                    observer,
                    "C_CREATE_W08",
                    os.open,
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory,
                )
                os.close(descriptor)
                _initial(clock, boot, until, **child.observer_args(observer))
            _observe(observer, "C_CREATE_W09", os.fsync, directory)
        finally:
            os.close(directory)
        _observe(observer, "C_CREATE_W10", os.fsync, root)
        _initial(clock, boot, until, **child.observer_args(observer))
    finally:
        os.close(root)
    return locator


@dataclass(frozen=True)
class _Preparation:
    host: HostPort
    observation: Observation
    clock: Clock
    observer: child.WorkObserver | None = None


@dataclass(frozen=True)
class _PrepareArgs:
    admission: Admission
    request: Request
    source_fds: tuple[SourceFD, ...]
    host: HostPort | None
    clock: Clock

    def observe(self, observer: child.WorkObserver | None = None) -> Locator:
        """Enter the one private implementation without retaining inputs in the observer."""
        return _prepare_observed(self, observer)


def preparation_input(
    admission: Admission, request: Request, source_fds: tuple[SourceFD, ...], host: HostPort | None, clock: Clock
) -> _PrepareArgs:
    """Group only the hosted adapter's original five inputs; this grants no authority."""
    return _PrepareArgs(admission, request, source_fds, host, clock)


def prepare_unused(
    admission: Admission, request: Request, source_fds: tuple[SourceFD, ...], host: HostPort | None, clock: Clock
) -> Locator:
    """Keep the legacy operational signature and default unobserved behavior."""
    return _prepare_observed(_PrepareArgs(admission, request, source_fds, host, clock))


def _prepare_observed(arguments: _PrepareArgs, observer: child.WorkObserver | None = None) -> Locator:
    admission, request, source_fds, host, clock = (
        arguments.admission,
        arguments.request,
        arguments.source_fds,
        arguments.host,
        arguments.clock,
    )
    """Prepare finite root custody; no default host/bootstrap authority or parser execution exists."""
    _root(**child.observer_args(observer))
    with _work(observer, "C_PREPARE_UNUSED_G01"):
        _need(host is not None and type(request) is Request)
    _run(request.run, **child.observer_args(observer))
    _group(request.runtime_slice, **child.observer_args(observer))
    _integer(request.uid, minimum=1, **child.observer_args(observer))
    _integer(request.gid, minimum=1, **child.observer_args(observer))
    _integer(request.original_deadline_ns, **child.observer_args(observer))
    start, boot = _start(clock, **child.observer_args(observer))
    deadline = min(request.original_deadline_ns, start + MAX_TOTAL_NS)
    with _work(observer, "C_PREPARE_UNUSED_G02"):
        _need(deadline - start > CLEANUP_NS + 1_000_000_000)
    commit, specs = _manifest(admission, **child.observer_args(observer))
    _initial(clock, boot, deadline - CLEANUP_NS, **child.observer_args(observer))
    observation = host.observe(request)
    _observation(admission, request, observation, clock, **child.observer_args(observer))
    with _work(observer, "C_PREPARE_UNUSED_G03"):
        _need(observation.boot == boot)
    _need(
        _clock(clock, **child.observer_args(observer)) < deadline - CLEANUP_NS and clock.boot_id() == boot,
        observer=observer,
        work_site="C_PREPARE_UNUSED_G04",
    )
    with _work(observer, "C_PREPARE_UNUSED_G05"):
        _need(tuple(item.path for item in source_fds) == SOURCE_PATHS)
    locator = _create(clock, boot, deadline - CLEANUP_NS, **child.observer_args(observer))
    nonce = locator.nonce
    lease = Lease(
        1,
        CONSUMER,
        nonce,
        locator.directory,
        request.run,
        observation.boot,
        start,
        deadline,
        deadline - CLEANUP_NS,
        observation.coordinator,
        request.runtime_slice,
        admission.manifest_sha256,
        commit,
        specs,
        observation.cohort,
        observation.identities,
        f"dockerlens-127-upstream-rootless-{request.run.workflow_run}-{request.run.attempt}-{nonce}",
        None,
        request.uid,
        request.gid,
    )
    with _store(locator, **child.observer_args(observer)) as store:
        record = Record(lease=lease, generation=1, state=State.PREPARING, child_pending=False, owner=None, cause=None)
        _persist(store, record, clock, lease.work_until_ns, **child.observer_args(observer))
        _populate(store, record, source_fds, _Preparation(host, observation, clock, **child.observer_args(observer)))
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(observer))
    _budget(clock, lease, lease.work_until_ns, **child.observer_args(observer))
    return locator


def _populate(store: _Store, record: Record, source_fds: tuple[SourceFD, ...], context: _Preparation) -> None:
    lease = record.lease
    host, observation, clock = context.host, context.observation, context.clock
    sealed = []
    pending = False
    invoked = False
    try:
        for index, (item, spec, leaf) in enumerate(zip(source_fds, lease.sources, LEAVES, strict=True)):
            _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
            before = _observe(context.observer, "C_POPULATE_W01", os.fstat, item.descriptor)
            with _work(context.observer, "C_POPULATE_G01"):
                _need(
                    stat.S_ISREG(before.st_mode)
                    and before.st_nlink == 1
                    and fcntl.fcntl(item.descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                )
            data = _observe(
                context.observer,
                "C_POPULATE_W02",
                child.bytes_at,
                item.descriptor,
                spec.size,
                **child.observer_args(context.observer),
            )
            with _work(context.observer, "C_POPULATE_G02"):
                _need(
                    len(data) == spec.size
                    and _digest(data) == spec.sha256
                    and child.file_mark(os.fstat(item.descriptor)) == child.file_mark(before)
                )
            _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
            store.write(leaf, data, 0o400)
            _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
            if index < len(child.MODULES):
                sealed.append(
                    child.seal(child.MODULES[index], store.read(leaf), **child.observer_args(context.observer))
                )
                _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        _need(host.reobserve(observation) == observation, observer=context.observer, work_site="C_POPULATE_G03")
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        record = _next(record, State.PREPARING, child_pending=True, **child.observer_args(context.observer))
        _persist(store, record, clock, lease.work_until_ns, **child.observer_args(context.observer))
        pending = True
        invoked = True
        outcome = child.build(
            observation.interpreter,
            tuple(sealed),
            child.Build(
                lease.policy_name,
                lease.uid,
                lease.gid,
                min(lease.work_until_ns, _clock(clock, lease, **child.observer_args(context.observer)) + CHILD_NS),
                lease.deadline_ns,
            ),
            clock,
            **child.observer_args(context.observer),
        )
        _need(type(outcome) is child.Outcome and outcome.dead is True)
        pending = False
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        _need(
            host.reobserve(observation) == observation
            and _clock(clock, lease, **child.observer_args(context.observer)) < lease.work_until_ns
            and type(outcome.policy) is bytes
            and len(outcome.policy) <= child.MAX_POLICY
            and outcome.policy.startswith(b"abi <abi/4.0>,\n")
            and outcome.policy.count(lease.policy_name.encode("ascii")) == 1,
            observer=context.observer,
            work_site="C_POPULATE_G05",
        )
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        store.write("policy", outcome.policy, 0o400)
        _budget(clock, lease, lease.work_until_ns, **child.observer_args(context.observer))
        lease = replace(lease, policy_sha256=_digest(outcome.policy))
        _persist(
            store,
            replace(
                _next(record, State.PREPARED, child_pending=False, **child.observer_args(context.observer)), lease=lease
            ),
            clock,
            lease.work_until_ns,
            **child.observer_args(context.observer),
        )
    except Exception as error:
        if invoked and isinstance(error, child.ChildError):
            pending = error.pending
        with suppress(CustodyError):
            _retain(store, record, clock, pending=pending)
        raise CustodyError(store.locator, child_pending=pending) from error
    finally:
        for item in sealed:
            os.close(item.descriptor)


def _outside(owner: Owner, lease: Lease) -> None:
    _process(owner.process)
    group, runtime = owner.process.cgroup, lease.runtime_slice
    _need(
        owner.service == "containers-userns-unused-" + lease.nonce
        and owner.process.pid != lease.coordinator.pid
        and owner.process.pgid != lease.coordinator.pgid
        and (group.device, group.inode) != (runtime.device, runtime.inode)
        and group.path != runtime.path
        and not group.path.startswith(runtime.path.rstrip("/") + "/")
    )


def _owner(observation: OwnerObservation, lease: Lease, clock: Clock, lifetime: Lifetime) -> None:
    _observed(observation, lease, clock, lifetime)
    _need(observation.acknowledged and observation.service_root_owned)
    _outside(observation.owner, lease)
    if lifetime is Lifetime.DEAD:
        _need(observation.group_absent and observation.cgroup_absent)
    else:
        _need(not observation.group_absent and not observation.cgroup_absent)


def _observed(observation: OwnerObservation, lease: Lease, clock: Clock, lifetime: Lifetime) -> None:
    _need(
        type(observation) is OwnerObservation
        and observation.lease == lease
        and observation.lifetime is lifetime
        and all(
            type(value) is bool
            for value in (
                observation.acknowledged,
                observation.service_root_owned,
                observation.group_absent,
                observation.cgroup_absent,
            )
        )
    )
    now = _clock(clock, lease)
    _integer(observation.observed_ns)
    _need(0 <= now - observation.observed_ns <= HANDSHAKE_NS)


def _coordinator(observation: OwnerObservation, lease: Lease, clock: Clock, lifetime: Lifetime) -> None:
    _observed(observation, lease, clock, lifetime)
    _need(
        observation.owner == Owner("coordinator", lease.coordinator)
        and not observation.acknowledged
        and not observation.service_root_owned
    )
    _need(observation.group_absent if lifetime is Lifetime.DEAD else not observation.group_absent)


def read_owner_intent(locator: Locator, expected: ArmIntent, clock: Clock) -> ArmIntent:
    """Read strict unresolved intent before W; the hosted start binder also enforces its original handshake end."""
    _need(type(expected) is ArmIntent and type(expected.lease) is Lease)
    _integer(expected.generation, minimum=1)
    with _store(locator) as store:
        record = store.load()
        _budget(clock, record.lease, record.lease.work_until_ns)
        _need(
            record.state is State.ARM_INTENT
            and record.owner_attempted
            and record.owner is None
            and not record.child_pending
            and ArmIntent(record.lease, record.generation) == expected
        )
    _budget(clock, expected.lease, expected.lease.work_until_ns)
    return expected


def arm_unused(locator: Locator, supervisor: SupervisorPort | None, clock: Clock) -> None:
    """Persist one intent; authenticate outside the lock; commit only unchanged intent."""
    with _store(locator) as store:
        record = _settled(store, clock, work=True)
        _caller(record.lease.coordinator)
        now = _clock(clock, record.lease)
        _need(record.state is State.PREPARED and supervisor is not None and now < record.lease.work_until_ns)
        record = _next(record, State.ARM_INTENT, owner_attempted=True)
        end = min(record.lease.work_until_ns, now + HANDSHAKE_NS)
        _persist(store, record, clock, end)
    intent = ArmIntent(record.lease, record.generation)
    try:
        _budget(clock, record.lease, end)
        observation = supervisor.start_unused_owner(intent, end)
        _budget(clock, record.lease, end)
        _owner(observation, record.lease, clock, Lifetime.LIVE)
        with _store(locator) as store:
            current = store.load()
            _need(current == record)
            _caller(current.lease.coordinator)
            _budget(clock, record.lease, end)
            # Only manager/pidfd/kernel readback here: no RPC or custody reopen.
            repeated = supervisor.inspect_owner(record.lease, observation.owner, end)
            _budget(clock, record.lease, end)
            _owner(repeated, record.lease, clock, Lifetime.LIVE)
            _need(repeated.owner == observation.owner)
            _persist(store, _next(record, State.ARMED, owner=observation.owner), clock, end)
        _budget(clock, record.lease, end)
    except Exception as error:
        # Never overwrite changed/foreign/terminal state after releasing the lock.
        with suppress(CustodyError, OSError, ValueError), _store(locator) as store:
            if store.load() == record:
                _retain(store, record, clock)
        raise CustodyError(locator) from error


def request_close_unused(locator: Locator, supervisor: SupervisorPort | None, clock: Clock) -> None:
    """Request only the already bound owner; release the lock before its handler may run."""
    with _store(locator) as store:
        record = _settled(store, clock)
        closed = record.state is State.CLOSED
        if not closed:
            now = _clock(clock, record.lease)
            _need(
                record.state is State.ARMED
                and record.owner is not None
                and supervisor is not None
                and now < record.lease.deadline_ns
            )
            end = min(record.lease.deadline_ns, now + HANDSHAKE_NS)
            try:
                _budget(clock, record.lease, end)
                observation = supervisor.inspect_owner(record.lease, record.owner, end)
                _budget(clock, record.lease, end)
                _owner(observation, record.lease, clock, Lifetime.LIVE)
                _need(observation.owner == record.owner and _clock(clock, record.lease) < end)
            except Exception as error:
                _retain(store, record, clock)
                raise CustodyError(locator) from error
            record = _next(record, State.CLOSING, cause=Cause.NORMAL)
            _persist(store, record, clock, end)
    if closed:
        _budget(clock, record.lease)
        return
    try:
        _budget(clock, record.lease, end)
        supervisor.request_close(record.lease, record.owner, end)
        _budget(clock, record.lease, end)
    except Exception as error:
        if _clock(clock, record.lease) < record.lease.deadline_ns:
            with _store(locator) as store:
                _retain(store, store.load(), clock)
        raise CustodyError(locator) from error
    _budget(clock, record.lease, end)


def _receipt(record: Record) -> Receipt:
    _need(record.state is State.CLOSED and record.cause is not None)
    return Receipt(record.lease.nonce, _digest(_json(asdict(record.lease))), record.generation, record.cause)


def finalize_unused(locator: Locator, owner_observation: OwnerObservation, cause: Cause, clock: Clock) -> Receipt:
    """Close unused custody only as its exact current owner, preserving cancellation."""
    with _store(locator) as store:
        record = _settled(store, clock)
        now = _clock(clock, record.lease)
        _need(type(cause) is Cause)
        if record.owner is None:
            _need(record.state in {State.PREPARED, State.CLOSING, State.CLOSED} and not record.owner_attempted)
            _coordinator(owner_observation, record.lease, clock, Lifetime.LIVE)
        else:
            _owner(owner_observation, record.lease, clock, Lifetime.LIVE)
            _need(owner_observation.owner == record.owner)
        _caller(owner_observation.owner.process)
        if record.state is not State.CLOSED:
            _need(record.state in {State.PREPARED, State.ARMED, State.CLOSING})
            _need(cause is not Cause.EXPIRY or record.lease.work_until_ns <= now)
            actual = Cause.CANCELLED if Cause.CANCELLED in (record.cause, cause) else cause
            closing = _next(record, State.CLOSING, cause=actual)
            _persist(store, closing, clock)
            record = _next(closing, State.CLOSED)
            _persist(store, record, clock)
        _budget(clock, record.lease)
        receipt = _receipt(record)
    _budget(clock, record.lease)
    return receipt


def dispose_unused(locator: Locator, supervisor_observation: OwnerObservation | None, clock: Clock) -> None:
    """Unlink only known leaves after closed unused state and independently proven owner death."""
    with _store(locator) as store:
        record = _settled(store, clock)
        _need(record.state is State.CLOSED and not record.child_pending and supervisor_observation is not None)
        if record.owner is None:
            _need(not record.owner_attempted)
            _coordinator(supervisor_observation, record.lease, clock, Lifetime.DEAD)
        else:
            _owner(supervisor_observation, record.lease, clock, Lifetime.DEAD)
            _need(supervisor_observation.owner == record.owner)
        _need(
            supervisor_observation.owner.process.pid != os.getpid()
            or supervisor_observation.owner.process.start_ticks != _self_start()
        )
        for name in MODES:
            _budget(clock, record.lease)
            store.read(name)
            _budget(clock, record.lease)
        for name in MODES:
            _budget(clock, record.lease)
            os.unlink(name, dir_fd=store.directory)
            _budget(clock, record.lease)
        _budget(clock, record.lease)
        os.fsync(store.directory)
        _budget(clock, record.lease)
    _budget(clock, record.lease)
    root = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _need(_identity(os.stat(PREFIX + locator.nonce, dir_fd=root, follow_symlinks=False)) == locator.directory)
        _budget(clock, record.lease)
        os.rmdir(PREFIX + locator.nonce, dir_fd=root)
        _budget(clock, record.lease)
        os.fsync(root)
        _budget(clock, record.lease)
    finally:
        os.close(root)
    _budget(clock, record.lease)
