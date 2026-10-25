"""Bounded OOM evidence only; never classify an outer OOM flag as expected."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext

MAX_BYTES = 65536
MAX_GROUPS = 32
SNAPSHOT_SECONDS = 10
MAX_FILE_BYTES = 4096
STARTTIME_INDEX = 19
EVENT_FIELDS = 2
HOST_ARGUMENTS = 3
MAX_MONITOR_FDS = 64
MAX_MONITOR_READS = 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_MONITOR_BYTES = 2 * MAX_BINARY_BYTES + 512 * 1024
MAX_PATH_COMPONENTS = 64
MAX_PACKAGE_BYTES = 16384
INSTALLED_MONITOR = "/usr/bin/conmon"
MONITOR_CLEANUP_SECONDS = 0.5
MARKER_COUNT = 2
IN_MODIFY = 2
PACKAGE_FIELDS = ("binaryPackage", "binaryVersion", "sourcePackage", "sourceVersion", "architecture")
MEMORY_FILES = (
    "memory.max",
    "memory.current",
    "memory.peak",
    "memory.swap.max",
    "memory.swap.current",
    "memory.events",
    "memory.events.local",
)


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _text(path: Path, limit: int = MAX_FILE_BYTES) -> str:
    with path.open("rb", buffering=0) as stream:
        data = bytearray()
        while True:
            part = stream.read(limit + 1 - len(data))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                break
    _require(len(data) <= limit, "diagnostic file exceeded its byte bound")
    return data.decode("utf-8").strip()


def _group_path(value: str) -> str:
    _require(
        len(value) <= MAX_FILE_BYTES
        and (value == "/" or re.fullmatch(r"(?:/[A-Za-z0-9_.@:-]+)+", value) is not None)
        and not any(part in {".", ".."} for part in value.split("/")),
        "diagnostic cgroup path was unsafe",
    )
    return value


def _chain(path: str, *, stop: str = "/") -> list[str]:
    paths = []
    while True:
        _require(len(paths) < MAX_GROUPS, "diagnostic cgroup chain exceeded its count bound")
        paths.append(path)
        if path == stop:
            return paths
        _require(path != "/", "diagnostic cgroup chain escaped the owned subtree")
        path = path.rsplit("/", 1)[0] or "/"


def _process(pid: int) -> dict[str, str]:
    _require(type(pid) is int and pid > 1, "diagnostic process PID was invalid")
    proc = Path("/proc") / str(pid)
    fields = _text(proc / "stat").rsplit(") ", 1)[1].split()
    _require(
        len(fields) > STARTTIME_INDEX and fields[STARTTIME_INDEX].isdigit(),
        "diagnostic process birth identity was invalid",
    )
    executable = str((proc / "exe").readlink())
    _require(len(executable) <= MAX_FILE_BYTES, "diagnostic executable link exceeded its byte bound")
    return {
        "starttime": fields[STARTTIME_INDEX],
        "cgroup": _text(proc / "cgroup"),
        "exe": executable,
    }


class _MonitorReads:
    """Fixed read-only monitor budget shared by binary, fdinfo and markers."""

    def __init__(self, deadline: float) -> None:
        self.deadline = min(deadline, time.monotonic() + SNAPSHOT_SECONDS) - MONITOR_CLEANUP_SECONDS
        self.bytes = 0
        self.calls = 0

    def check(self) -> None:
        _require(time.monotonic() < self.deadline, "diagnostic monitor deadline expired")

    def read(self, descriptor: int, maximum: int) -> bytes:
        self.check()
        _require(self.calls < MAX_MONITOR_READS, "diagnostic monitor read count exceeded its bound")
        _require(self.bytes + maximum <= MAX_MONITOR_BYTES, "diagnostic monitor aggregate byte bound exceeded")
        self.calls += 1
        raw = os.read(descriptor, maximum)
        self.bytes += len(raw)
        self.check()
        return raw

    def file(self, path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            _require(stat.S_ISREG(os.fstat(descriptor).st_mode), "diagnostic monitor file was not regular")
            raw = bytearray()
            while True:
                part = self.read(descriptor, maximum + 1 - len(raw))
                if not part:
                    return bytes(raw)
                raw.extend(part)
                _require(len(raw) <= maximum, "diagnostic monitor file exceeded its byte bound")
        finally:
            os.close(descriptor)


def _identity(info: os.stat_result) -> dict[str, int]:
    return {
        name: getattr(info, "st_" + name)
        for name in ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
    }


def _executable(proc: Path, reads: _MonitorReads) -> dict[str, Any]:
    # Follow ONLY the kernel's exact PID executable reference, hold that inode,
    # hash it, and never execute it or resolve/execute its advertised pathname.
    descriptor = os.open(proc / "exe", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_BINARY_BYTES,
            "diagnostic monitor binary was unsupported or exceeded its size bound",
        )
        digest, size = hashlib.sha256(), 0
        while True:
            raw = reads.read(descriptor, min(MAX_BYTES, MAX_BINARY_BYTES + 1 - size))
            if not raw:
                break
            size += len(raw)
            _require(size <= MAX_BINARY_BYTES, "diagnostic monitor binary exceeded its byte bound")
            digest.update(raw)
        _require(
            size == before.st_size and _identity(before) == _identity(os.fstat(descriptor)),
            "diagnostic monitor binary identity changed",
        )
        return {"stat": _identity(before), "sha256": digest.hexdigest(), "bytesRead": size}
    finally:
        os.close(descriptor)


def _argument(arguments: list[str], names: set[str]) -> str:
    found = []
    for index, argument in enumerate(arguments):
        if argument in names:
            _require(index + 1 < len(arguments), "diagnostic monitor argument lacked its value")
            found.append(arguments[index + 1])
        elif any(argument.startswith(name + "=") for name in names):
            found.append(argument.split("=", 1)[1])
    _require(len(found) == 1 and bool(found[0]), "diagnostic monitor argument was missing or ambiguous")
    return found[0]


def _package_query(operation: str, reads: _MonitorReads) -> str:
    """Only the two fixed, already-installed dpkg-query calls below."""
    reads.check()
    commands = {
        "owner": ["/usr/bin/dpkg-query", "-S", INSTALLED_MONITOR],
        "version": [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n",
            "conmon",
        ],
    }
    _require(operation in commands, "diagnostic package query operation was unsupported")
    with subprocess.Popen(  # noqa: S603 — closed read-only argv, fixed executable.
        commands[operation],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        close_fds=True,
    ) as process:
        try:
            _require(process.stdout is not None, "diagnostic package output pipe unavailable")
            descriptor = process.stdout.fileno()
            os.set_blocking(descriptor, False)
            raw = bytearray()
            while True:
                reads.check()
                ready, _, _ = select.select([descriptor], [], [], max(0, reads.deadline - time.monotonic()))
                _require(bool(ready), "diagnostic package query deadline expired")
                part = reads.read(descriptor, MAX_PACKAGE_BYTES + 1 - len(raw))
                if not part:
                    break
                raw.extend(part)
                _require(len(raw) <= MAX_PACKAGE_BYTES, "diagnostic package query exceeded its byte bound")
            _require(
                process.wait(timeout=max(0.001, reads.deadline - time.monotonic())) == 0,
                "diagnostic fixed package query failed",
            )
            return raw.decode("utf-8").strip()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=max(0.001, reads.deadline + MONITOR_CLEANUP_SECONDS - time.monotonic()))


def _installed_recheck(executable: dict[str, Any]) -> None:
    directory = _open_directory(Path(INSTALLED_MONITOR).parent)
    try:
        descriptor = os.open(
            Path(INSTALLED_MONITOR).name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            _require(
                _identity(os.fstat(descriptor)) == executable["stat"],
                "diagnostic installed monitor path identity changed",
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def _installed_package(
    identity: dict[str, str], executable: dict[str, Any], reads: _MonitorReads, previous: dict[str, Any] | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "availability": "unresolved",
        "sourceAttribution": "unresolved; package metadata is not payload authenticity or upstream source proof",
    }
    try:
        _require(identity["exe"] == INSTALLED_MONITOR, "diagnostic monitor was not the supported installed path")
        directory = _open_directory(Path(INSTALLED_MONITOR).parent)
        try:
            descriptor = os.open(
                Path(INSTALLED_MONITOR).name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            try:
                before = os.fstat(descriptor)
                _require(
                    _identity(before) == executable["stat"],
                    "diagnostic installed monitor inode differed from running executable",
                )
                digest, size = hashlib.sha256(), 0
                while True:
                    raw = reads.read(descriptor, min(MAX_BYTES, MAX_BINARY_BYTES + 1 - size))
                    if not raw:
                        break
                    size += len(raw)
                    _require(size <= MAX_BINARY_BYTES, "diagnostic installed monitor exceeded its byte bound")
                    digest.update(raw)
                _require(
                    size == before.st_size
                    and digest.hexdigest() == executable["sha256"]
                    and _identity(before) == _identity(os.fstat(descriptor)),
                    "diagnostic installed/running monitor bytes changed or differed",
                )
                result["installedExecutable"] = {
                    "path": INSTALLED_MONITOR,
                    "stat": _identity(before),
                    "sha256": digest.hexdigest(),
                }
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        if previous is not None:
            _require(
                previous.get("installedExecutable") == result["installedExecutable"],
                "diagnostic installed package executable binding changed",
            )
            _installed_recheck(executable)
            return copy.deepcopy(previous)
        owner = _package_query("owner", reads)
        _require(
            re.fullmatch(r"conmon(?::[a-z0-9]+)?: " + re.escape(INSTALLED_MONITOR), owner) is not None,
            "diagnostic monitor package ownership was unsupported or ambiguous",
        )
        package = _package_query("version", reads)
        fields = package.split("\t")
        _require(
            len(fields) == len(PACKAGE_FIELDS)
            and all(fields)
            and re.fullmatch(r"conmon(?::[a-z0-9]+)?", fields[0]) is not None,
            "diagnostic monitor package metadata was incomplete",
        )
        _require(
            all(re.fullmatch(r"[A-Za-z0-9.+:~_-]+", field) is not None for field in fields),
            "diagnostic monitor package metadata contained unsupported fields",
        )
        result["packageClaim"] = dict(zip(PACKAGE_FIELDS, fields, strict=True))
        result["ownershipClaim"] = owner
        metadata = Path("/var/lib/dpkg/info") / (fields[0] + ".md5sums")
        try:
            entries = reads.file(metadata, MAX_BYTES).decode("ascii").splitlines()
            matches = [row.split() for row in entries if row.split()[-1:] == [INSTALLED_MONITOR.lstrip("/")]]
            _require(
                len(matches) == 1
                and len(matches[0]) == EVENT_FIELDS
                and re.fullmatch(r"[0-9a-f]{32}", matches[0][0]) is not None,
                "diagnostic package checksum entry missing or ambiguous",
            )
            result["packageRecordedChecksum"] = {
                "algorithm": "md5",
                "value": matches[0][0],
                "verification": "local package metadata only; not authenticity proof",
            }
        except (OSError, ValueError, UnicodeError) as error:
            result["packageRecordedChecksum"] = {
                "availability": "unresolved",
                "reason": f"{type(error).__name__}: {error}",
            }
        _installed_recheck(executable)
        result["availability"] = "observed-unverified-metadata"
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        result["reason"] = f"{type(error).__name__}: {error}"
    return result


def _watch_device(value: str) -> tuple[int, int]:
    _require(re.fullmatch(r"[0-9a-fA-F]{1,8}", value) is not None, "diagnostic inotify device format unsupported")
    device = int(value, 16)
    # Linux fdinfo prints RAW kernel s_dev (12 major / 20 minor bits), not
    # userspace dev_t or new_encode_dev. This is an ABI observation, not an
    # attestation of the running kernel's source/version.
    return device >> 20, device & ((1 << 20) - 1)


def _inotify(proc: Path, reads: _MonitorReads) -> list[dict[str, int]]:
    watches = []
    with os.scandir(proc / "fd") as entries:
        for count, entry in enumerate(entries, 1):
            reads.check()
            _require(count <= MAX_MONITOR_FDS, "diagnostic monitor FD count exceeded its bound")
            _require(entry.name.isdigit(), "diagnostic monitor FD name was invalid")
            if str(Path(entry.path).readlink()) != "anon_inode:inotify":
                continue
            raw = reads.file(proc / "fdinfo" / entry.name).decode("ascii")
            for row in raw.splitlines():
                if not row.startswith("inotify "):
                    continue
                parts = [part.split(":", 1) for part in row.split()[1:]]
                _require(all(len(part) == EVENT_FIELDS for part in parts), "diagnostic inotify watch was malformed")
                fields = dict(parts)
                _require(
                    len(fields) == len(parts) and {"wd", "ino", "sdev", "mask"} <= fields.keys(),
                    "diagnostic inotify watch was malformed",
                )
                _require(
                    all(re.fullmatch(r"[0-9a-fA-F]{1,16}", fields[key]) for key in ("wd", "ino", "mask")),
                    "diagnostic inotify watch format unsupported",
                )
                if not int(fields["mask"], 16) & IN_MODIFY:
                    continue
                major, minor = _watch_device(fields["sdev"])
                watches.append(
                    {
                        "fd": int(entry.name),
                        "wd": int(fields["wd"], 16),
                        "rawKernelDevice": fields["sdev"],
                        "inode": int(fields["ino"], 16),
                        "major": major,
                        "minor": minor,
                    }
                )
                _require(len(watches) <= MAX_MONITOR_FDS, "diagnostic inotify watch count exceeded its bound")
    _require(bool(watches), "diagnostic monitor had no observed inotify watch")
    return sorted(watches, key=lambda watch: (watch["fd"], watch["wd"]))


def _event_candidates(root: Path, outer: str, paths: list[str], reads: _MonitorReads) -> list[dict[str, Any]]:
    """Only the existing PID1-to-owned-outer chain, never a descendant scan."""
    _require(0 < len(paths) <= MAX_GROUPS, "diagnostic owned cgroup count exceeded its bound")
    result = []
    for path in paths:
        _group_path(path)
        _require(path == outer or path.startswith(outer + "/"), "diagnostic event candidate escaped the owned subtree")
        directory = root / path.lstrip("/")
        reads.check()
        before = directory.stat(follow_symlinks=False)
        _require(stat.S_ISDIR(before.st_mode), "diagnostic owned cgroup directory was unsafe")
        event = directory / "memory.events"
        try:
            descriptor = os.open(event, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        else:
            try:
                info = os.fstat(descriptor)
                _require(
                    stat.S_ISREG(info.st_mode) and info.st_dev == before.st_dev,
                    "diagnostic memory.events candidate was unsafe",
                )
                linked = event.stat(follow_symlinks=False)
                _require((info.st_dev, info.st_ino) == (linked.st_dev, linked.st_ino), "diagnostic event inode changed")
                result.append(
                    {
                        "path": path,
                        "inode": info.st_ino,
                        "major": os.major(info.st_dev),
                        "minor": os.minor(info.st_dev),
                        "directoryIdentity": {"dev": before.st_dev, "ino": before.st_ino},
                    }
                )
            finally:
                os.close(descriptor)
        _require(
            (before.st_dev, before.st_ino) == (directory.stat().st_dev, directory.stat().st_ino),
            "diagnostic owned cgroup changed during traversal",
        )
    return result


def _match_watch(watches: list[dict[str, int]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    matched = [
        (watch, candidate)
        for watch in watches
        for candidate in candidates
        if all(watch[key] == candidate[key] for key in ("inode", "major", "minor"))
    ]
    _require(len(matched) == 1, "diagnostic monitor watch was missing or ambiguous in the owned subtree")
    watch, candidate = matched[0]
    return {
        "availability": "observed",
        "file": "memory.events",
        **candidate,
        "fd": watch["fd"],
        "wd": watch["wd"],
        "rawKernelDevice": watch.get("rawKernelDevice"),
        "deviceEncoding": "Linux raw kernel dev_t; 20 minor bits",
    }


def _owned_parts(directory: str, path: str) -> tuple[Path, tuple[str, ...]]:
    root, target = Path(directory), Path(path)
    _require(
        root.is_absolute() and target.is_absolute() and str(root) == directory and str(target) == path,
        "diagnostic marker path was not canonical and absolute",
    )
    _require(
        len(path) <= MAX_FILE_BYTES and ".." not in target.parts and len(target.parts) <= MAX_PATH_COMPONENTS,
        "diagnostic marker path was unsafe",
    )
    relative = target.relative_to(root)
    _require(bool(relative.parts), "diagnostic marker escaped the isolated store")
    return root, relative.parts


def _open_directory(path: Path) -> int:
    _require(
        path.is_absolute() and len(path.parts) <= MAX_PATH_COMPONENTS, "diagnostic directory path exceeded its bound"
    )
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            _require(part not in {".", ".."}, "diagnostic directory path was unsafe")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    else:
        return descriptor


def _markers(context: dict[str, Any], reads: _MonitorReads) -> dict[str, Any]:
    directory, candidates = context["directory"], copy.deepcopy(context["candidates"])
    _require(len(candidates) == MARKER_COUNT, "diagnostic marker candidate count was invalid")
    descriptor = _open_directory(Path(directory))
    try:
        info = os.fstat(descriptor)
        identity = {"dev": info.st_dev, "inode": info.st_ino}
        _require(context.get("directoryIdentity", identity) == identity, "diagnostic isolated store identity changed")
        observations = []
        for candidate in candidates:
            reads.check()
            _root, parts = _owned_parts(directory, candidate["path"])
            parent = os.dup(descriptor)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                parent_stat = os.fstat(parent)
                parent_identity = {
                    key: getattr(parent_stat, "st_" + key) for key in ("dev", "ino", "mode", "uid", "gid")
                }
                _require(
                    candidate.get("parentIdentity", parent_identity) == parent_identity,
                    "diagnostic marker parent identity changed",
                )
                candidate["parentIdentity"] = parent_identity
                try:
                    marker = os.open(
                        parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                    )
                except FileNotFoundError:
                    observations.append({**candidate, "availability": "missing"})
                else:
                    try:
                        before = os.fstat(marker)
                        _require(
                            stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE_BYTES,
                            "diagnostic OOM marker type, links or size was unsafe",
                        )
                        raw = reads.read(marker, MAX_FILE_BYTES + 1)
                        _require(
                            len(raw) <= MAX_FILE_BYTES and _identity(before) == _identity(os.fstat(marker)),
                            "diagnostic OOM marker exceeded its bound or changed",
                        )
                        linked = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                        _require(
                            (before.st_dev, before.st_ino) == (linked.st_dev, linked.st_ino),
                            "diagnostic OOM marker path changed",
                        )
                        observations.append(
                            {
                                **candidate,
                                "availability": "present",
                                "stat": _identity(before),
                                "bytesRead": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                            }
                        )
                    finally:
                        os.close(marker)
                after = os.fstat(parent)
                _require(
                    parent_identity == {key: getattr(after, "st_" + key) for key in parent_identity},
                    "diagnostic marker parent changed during observation",
                )
                linked_parent = _open_directory(Path(candidate["path"]).parent)
                try:
                    linked = os.fstat(linked_parent)
                    _require(
                        parent_identity == {key: getattr(linked, "st_" + key) for key in parent_identity},
                        "diagnostic marker parent pathname changed",
                    )
                finally:
                    os.close(linked_parent)
            finally:
                os.close(parent)
        return {
            "directory": directory,
            "directoryIdentity": identity,
            "candidates": candidates,
            "observations": observations,
            "interpretation": "candidate paths only; installed monitor/source mapping unresolved",
        }
    finally:
        os.close(descriptor)


def _monitor(
    request: dict[str, Any], identity: dict[str, str], paths: list[str], reads: _MonitorReads
) -> dict[str, Any]:
    exact, pid, outer = request["container"], request["state"]["ConmonPid"], request["state"]["CgroupPath"]
    directory, previous = request["directory"], request.get("monitor")
    proc = Path("/proc") / str(pid)
    arguments = reads.file(proc / "cmdline").decode("utf-8").rstrip("\0").split("\0")
    _require(
        _argument(arguments, {"-c", "--cid"}) == exact, "diagnostic monitor command did not bind the exact container ID"
    )
    if previous is not None:
        _require(
            all(previous[key] == value for key, value in {**identity, "pid": pid, "container": exact}.items()),
            "diagnostic monitor identity changed across snapshots",
        )
    executable = _executable(proc, reads)
    if previous is not None:
        _require(previous["executable"] == executable, "diagnostic monitor executable changed across snapshots")
    package = _installed_package(
        identity, executable, reads, previous["packageMetadata"] if previous is not None else None
    )
    persist = _argument(arguments, {"--persist-dir"})
    bundle = _argument(arguments, {"-b", "--bundle"})
    candidates = [
        {"argument": "--persist-dir", "argumentValue": persist, "path": str(Path(persist) / "oom")},
        {"argument": "--bundle", "argumentValue": bundle, "path": str(Path(bundle) / "oom")},
    ]
    for candidate in candidates:
        _require(
            exact in Path(candidate["argumentValue"]).parts, "diagnostic marker parent did not carry the exact CID"
        )
        _owned_parts(directory, candidate["argumentValue"])
        _owned_parts(directory, candidate["path"])
    marker_context = {"directory": directory, "candidates": candidates}
    if previous is not None:
        old_markers = previous["markers"]
        _require(
            old_markers["directory"] == directory
            and [
                {key: candidate[key] for key in ("argument", "argumentValue", "path")}
                for candidate in old_markers["candidates"]
            ]
            == candidates,
            "diagnostic marker arguments changed across snapshots",
        )
        marker_context = old_markers
    result = {
        **identity,
        "pid": pid,
        "container": exact,
        "executable": executable,
        "packageMetadata": package,
        "actualVersion": None,
        "versionAttribution": "unresolved; executable SHA256 is not package/source correspondence",
        "watchedCgroupPath": None,
        "markers": _markers(marker_context, reads),
    }
    watch = None
    prior_watch = previous.get("watch", {}) if previous is not None else {}
    expected_watch = (
        prior_watch if prior_watch.get("availability") == "observed" else prior_watch.get("expectedObservedWatch")
    )
    try:
        watches = _inotify(proc, reads)
        event_candidates = _event_candidates(Path("/sys/fs/cgroup"), outer, paths, reads)
        watch = _match_watch(watches, event_candidates)
        _require(
            watches == _inotify(proc, reads)
            and event_candidates == _event_candidates(Path("/sys/fs/cgroup"), outer, paths, reads),
            "diagnostic monitor watch identity changed",
        )
        if expected_watch is not None:
            _require(watch == expected_watch, "diagnostic monitor watch identity changed across snapshots")
        result["watch"] = watch
        result["watchedCgroupPath"] = watch["path"]
    except (OSError, ValueError) as error:
        result["watch"] = {"availability": "unresolved", "reason": f"{type(error).__name__}: {error}"}
        if watch is not None:
            result["watch"]["observedCandidate"] = watch
        if expected_watch is not None:
            # Retain the original observed identity through unresolved captures,
            # never silently accept the new target on the next lifecycle sample.
            result["watch"]["expectedObservedWatch"] = expected_watch
    _require(identity == _process(pid), "diagnostic monitor birth identity changed")
    _require(
        arguments == reads.file(proc / "cmdline").decode("utf-8").rstrip("\0").split("\0"),
        "diagnostic monitor arguments changed during observation",
    )
    result["identityVerified"] = True
    return result


def _mount(path: Path) -> str:
    rows = [row for row in _text(path, MAX_BYTES).splitlines() if row.split()[4] == "/sys/fs/cgroup"]
    _require(len(rows) == 1 and " - cgroup2 " in rows[0], "diagnostic cgroup2 mount was missing or ambiguous")
    # Preserve both per-mount and superblock options, including memory_localevents.
    return rows[0]


def _memory_group(root: Path, path: str) -> dict[str, Any]:
    directory = root / path.lstrip("/")
    try:
        inode = directory.stat().st_ino
    except FileNotFoundError:
        return {"path": path, "availability": "missing"}
    values: dict[str, Any] = {}
    missing = []
    for name in MEMORY_FILES:
        try:
            raw = _text(directory / name)
        except FileNotFoundError:
            missing.append(name)
            continue
        if name.startswith("memory.events"):
            events = {}
            for row in raw.splitlines():
                parts = row.split()
                _require(
                    len(parts) == EVENT_FIELDS and parts[0] not in events and parts[1].isdigit(),
                    "diagnostic memory events were malformed",
                )
                events[parts[0]] = int(parts[1])
            _require({"max", "oom", "oom_kill"} <= events.keys(), "diagnostic OOM event counters were missing")
            values[name] = events
        else:
            _require(raw == "max" or raw.isdigit(), "diagnostic memory value was malformed")
            values[name] = raw if raw == "max" else int(raw)
    _require(directory.stat().st_ino == inode, "diagnostic cgroup inode changed during readback")
    return {"path": path, "inode": inode, "values": values, "missingFiles": missing, "availability": "observed"}


def _collect(request: dict[str, Any]) -> dict[str, Any]:
    exact, state, scope = request["container"], request["state"], request["scope"]
    _require(re.fullmatch(r"[0-9a-f]{64}", exact) is not None, "diagnostic container ID was not exact")
    outer = _group_path(state["CgroupPath"])
    _require(outer.endswith("/libpod-" + exact + ".scope"), "diagnostic outer cgroup did not bind the exact ID")
    _require(state["Running"] is True, "diagnostic guest was not running")
    pid, conmon = state["Pid"], state["ConmonPid"]
    before, monitor = _process(pid), _process(conmon)
    match = re.fullmatch(r"0::([^\n]+)", before["cgroup"])
    _require(match is not None, "diagnostic host PID cgroup was not unified")
    current = _group_path(match[1])
    _require(current == outer or current.startswith(outer + "/"), "diagnostic host PID escaped the exact outer cgroup")
    guest_root = Path(f"/proc/{pid}/root/sys/fs/cgroup")
    root_inode = guest_root.stat().st_ino
    host_root = Path("/sys/fs/cgroup")
    guest_paths = _chain(_group_path(scope)) if scope is not None else ["/"]
    candidates = _chain(current, stop=outer)
    _require(len(guest_paths) + len(candidates) <= MAX_GROUPS, "diagnostic combined chain exceeded its count bound")
    matches = [path for path in candidates if (host_root / path.lstrip("/")).stat().st_ino == root_inode]
    _require(len(matches) == 1, "diagnostic guest root did not bind exactly one owned host cgroup")
    host_paths = _chain(matches[0], stop=outer)
    reads = _MonitorReads(request.get("deadline", time.monotonic() + SNAPSHOT_SECONDS))
    monitor_snapshot = _monitor(request, monitor, candidates, reads)
    result = {
        "hostCgroup2Mount": _mount(Path("/proc/self/mountinfo")),
        "guestCgroup2Mount": _mount(Path(f"/proc/{pid}/mountinfo")),
        "hostInit": before,
        "guestRoot": {"inode": root_inode, "hostPath": matches[0]},
        "outerCgroupPath": outer,
        "conmon": monitor_snapshot,
        "guestChain": [_memory_group(guest_root, path) for path in guest_paths],
        "hostOuterChain": [_memory_group(host_root, path) for path in host_paths],
    }
    _require(before == _process(pid) and monitor == _process(conmon), "diagnostic process identity changed")
    _require(guest_root.stat().st_ino == root_inode, "diagnostic namespace root identity changed")
    return result


def _collect_after_exit(request: dict[str, Any]) -> dict[str, Any]:
    exact, state, monitor = request["container"], request["state"], request["monitor"]
    _require(
        re.fullmatch(r"[0-9a-f]{64}", exact) is not None
        and state["Running"] is False
        and type(state["Pid"]) is int
        and state["Pid"] == 0,
        "diagnostic post-exit state was not exact and terminal",
    )
    _require(
        monitor["container"] == exact and monitor["identityVerified"] is True and monitor["starttime"].isdigit(),
        "diagnostic post-exit monitor had no verified live identity",
    )
    _require(monitor["markers"]["directory"] == request["directory"], "diagnostic post-exit isolated store changed")
    for candidate in monitor["markers"]["candidates"]:
        argument = candidate["argumentValue"]
        _require(
            candidate["argument"] in {"--persist-dir", "--bundle"}
            and exact in Path(argument).parts
            and candidate["path"] == str(Path(argument) / "oom")
            and "parentIdentity" in candidate,
            "diagnostic post-exit marker lacked its actual CID-bound parent",
        )
    reads = _MonitorReads(request["deadline"])
    return {
        "container": exact,
        "monitorIdentity": {key: monitor[key] for key in ("pid", "starttime", "exe")},
        "markers": _markers(monitor["markers"], reads),
        "limits": "retained live monitor identity; no post-exit proc or guest reads; source mapping unresolved",
    }


class OomDiagnostics:
    """Retain read-only observations without changing lifecycle admission or cleanup."""

    def __init__(self, ctx: RuntimeContext, container: str) -> None:
        """Bind diagnostic state to the existing invocation's exact owned guest."""
        self.ctx = ctx
        self.container = container
        self.scope: str | None = None
        self.scope_inode: int | None = None
        self.baseline: dict[str, Any] | None = None
        self.monitor_context: dict[str, Any] | None = None
        self.exit_observed = False
        self.custody: subprocess.Popen[bytes] | None = None
        self.custody_started = False
        self.last_watch: dict[str, Any] | None = None

    def _custody_exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        _require(self.custody is not None, "diagnostic custody was not armed")
        process = self.custody
        _require(process.stdin is not None and process.stdout is not None, "diagnostic custody pipes unavailable")
        deadline = time.monotonic() + min(2, self.ctx.timeout)
        payload = (json.dumps(request) + "\n").encode("utf-8")
        _require(len(payload) <= MAX_BYTES, "diagnostic custody request exceeded bound")
        descriptor = process.stdin.fileno()
        while payload:
            _, ready, _ = select.select([], [descriptor], [], max(0, deadline - time.monotonic()))
            _require(bool(ready), "diagnostic custody request deadline expired")
            payload = payload[os.write(descriptor, payload) :]
        raw = bytearray()
        while not raw.endswith(b"\n"):
            _require(len(raw) <= MAX_BYTES, "diagnostic custody response exceeded bound")
            ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
            _require(bool(ready), "diagnostic custody response deadline expired")
            part = os.read(process.stdout.fileno(), MAX_BYTES + 1 - len(raw))
            _require(bool(part), "diagnostic custody closed without response")
            raw.extend(part)
        _require(len(raw) <= MAX_BYTES and raw.count(b"\n") == 1, "diagnostic custody response framing invalid")
        return json.loads(raw)

    def _custody_sample(self, phase: str, *, request: dict[str, Any] | None = None) -> None:
        record: dict[str, Any] = {
            "name": "owned systemd OOM custody",
            "phase": phase,
            "attribution": "unresolved",
        }
        try:
            record["snapshot"] = self._custody_exchange(
                request or {"phase": phase, "lastSnapshotConmonWatch": self.last_watch}
            )
            record["availability"] = record["snapshot"].get("availability", "observed")
        except Exception as error:  # noqa: BLE001 — evidence cannot replace the native result.
            record.update(availability="error", reason=type(error).__name__)
        self.ctx.observations.append(record)

    def _start_custody(self, state: dict[str, Any], snapshot: dict[str, Any]) -> None:
        if self.custody_started:
            return
        try:
            _require(self.monitor_context is not None, "diagnostic custody lacks original monitor metadata")
            now = time.monotonic()
            work_deadline = getattr(self.ctx, "runtime_deadline", None)
            expiry = work_deadline + 40 if type(work_deadline) in {int, float} else now + self.ctx.timeout + 40
            request = {
                "pid": state["Pid"],
                "starttime": snapshot["hostInit"]["starttime"],
                "markers": self.monitor_context["markers"],
                "watch": self.monitor_context["watch"],
                # Absolute expiry is independent of the driver's survival. It
                # never renews a native work or shutdown allowance.
                "deadline": min(now + 640, expiry),
            }
            self.custody_started = True
            self.custody = subprocess.Popen(  # noqa: S603 — fixed helper, existing exact privilege boundary.
                [*self.ctx._sudo, sys.executable, "-I", str(Path(__file__).with_name("runtime_oom_watch.py"))],  # noqa: SLF001
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                close_fds=True,
                bufsize=0,
            )
            _require(self.custody.stdin is not None, "diagnostic custody input unavailable")
            os.set_blocking(self.custody.stdin.fileno(), False)
            self._custody_sample("armed", request=request)
        except Exception as error:  # noqa: BLE001 — diagnostic startup cannot suppress original work.
            self.ctx.observations.append(
                {
                    "name": "owned systemd OOM custody",
                    "phase": "armed",
                    "availability": "error",
                    "reason": type(error).__name__,
                    "attribution": "unresolved",
                }
            )

    def before_stop(self) -> None:
        """Observe before dispatch; actual guarded request delivery stays unresolved."""
        if self.custody_started:
            self._custody_sample("before-stop-request")

    def _before_inner_custody(self, phase: str, state: dict[str, Any], snapshot: dict[str, Any]) -> None:
        if phase == "before-inner-memory":
            self._start_custody(state, snapshot)

    def _after_snapshot_custody(self, phase: str) -> None:
        if self.custody_started and phase in {"after-inner-memory", "before-shutdown"}:
            self._custody_sample(phase)

    def close(self) -> None:
        """EOF closes read-only host custody; uncertain cleanup remains diagnostic."""
        process, self.custody = self.custody, None
        if process is None:
            return
        availability = "observed"
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=MONITOR_CLEANUP_SECONDS)
            _require(process.returncode == 0, "diagnostic custody helper failed")
        except Exception:  # noqa: BLE001 — no host mutation or shutdown admission on cleanup failure.
            availability = "unresolved"
        finally:
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except OSError:
                    availability = "unresolved"
        self.ctx.observations.append(
            {
                "name": "owned systemd OOM custody",
                "phase": "cleanup",
                "availability": availability,
                "attribution": "unresolved",
                "limits": "EOF requested; independent absolute helper expiry remains in force",
            }
        )

    def snapshot(self, phase: str, *, scope: str | None = None, scope_inode: int | None = None) -> None:
        """Record missing/invalid evidence as unresolved, never obstruct owned shutdown."""
        if scope is not None:
            self.scope, self.scope_inode = scope, scope_inode
        record: dict[str, Any] = {
            "name": "owned systemd OOM diagnostic",
            "phase": phase,
            "availability": "unavailable",
            "attribution": "unresolved",
            "limits": ("non-atomic snapshots; separate bounded custody observer; source correspondence unresolved"),
        }
        # Only fixed read-only inspect/collector calls use this copy. Its command
        # outcomes remain verbatim observations, never native admission checks.
        collection = copy.copy(self.ctx)
        collection.checks = []
        record["commands"] = collection.checks
        deadline = time.monotonic() + min(SNAPSHOT_SECONDS, self.ctx.timeout)

        def remaining() -> float:
            value = deadline - time.monotonic()
            _require(value > 0, "diagnostic snapshot deadline expired")
            return value

        try:
            _require(self.container in self.ctx.containers, "diagnostic container was not tracked")
            _require(re.fullmatch(r"[0-9a-f]{64}", self.container) is not None, "diagnostic container ID was not exact")
            raw = collection.podman(
                "read owned OOM diagnostic OCI state",
                "inspect",
                "--format",
                "{{json .State}}",
                self.container,
                timeout=remaining(),
            )
            _require(len(raw) <= MAX_BYTES, "diagnostic OCI state exceeded its byte bound")
            state = json.loads(raw)
            record["ociState"] = state
            request = {
                "container": self.container,
                "state": state,
                "scope": self.scope,
                "deadline": deadline,
                "directory": str(self.ctx.directory),
                "monitor": self.monitor_context,
            }
            raw = collection.command(
                "read exact owned OOM cgroup diagnostic",
                [
                    *self.ctx._sudo,  # noqa: SLF001 — preserve the existing exact host privilege boundary.
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    "--snapshot",
                    json.dumps(request),
                ],
                timeout=remaining(),
            )
            _require(len(raw) <= MAX_BYTES, "diagnostic snapshot exceeded its byte bound")
            snapshot = json.loads(raw)
            record["snapshot"] = snapshot
            self.last_watch = copy.deepcopy(snapshot.get("conmon", {}).get("watch"))
            if snapshot.get("conmon", {}).get("identityVerified") is True:
                self.monitor_context = copy.deepcopy(snapshot["conmon"])
            leaf = snapshot["guestChain"][0]
            if self.scope is not None and leaf.get("availability") == "observed":
                _require(
                    leaf["inode"] == self.scope_inode, "diagnostic inner scope inode did not match its association"
                )
            if phase == "before-inner-memory":
                _require(leaf.get("availability") == "observed", "diagnostic baseline inner scope was missing")
            if self.baseline is not None:
                record["baselineDelta"] = _deltas(self.baseline, snapshot)
            elif phase == "before-inner-memory":
                self.baseline = snapshot
            record["availability"] = "observed"
            self._before_inner_custody(phase, state, snapshot)
        except Exception as error:  # noqa: BLE001 — evidence-only boundary must not obstruct native shutdown.
            self.last_watch = None
            record["availability"] = "error"
            record["reason"] = f"{type(error).__name__}: {error}"
        self.ctx.observations.append(record)
        self._after_snapshot_custody(phase)

    def after_exit(self, exact_cid: str, state: dict[str, Any]) -> None:
        """One host-only marker sample before cleanup; never re-open a dead PID."""
        if self.exit_observed:
            return
        self.exit_observed = True
        if self.custody_started:
            self._custody_sample("after-exit")
        record: dict[str, Any] = {
            "name": "owned systemd OOM diagnostic",
            "phase": "after-exit",
            "availability": "unavailable",
            "attribution": "unresolved",
            "ociState": copy.deepcopy(state),
        }
        collection = copy.copy(self.ctx)
        collection.checks = []
        record["commands"] = collection.checks
        try:
            _require(
                exact_cid == self.container and exact_cid in self.ctx.containers,
                "diagnostic post-exit ID was not the exact owned guest",
            )
            _require(self.monitor_context is not None, "diagnostic post-exit marker parents were not observed live")
            deadline = time.monotonic() + min(SNAPSHOT_SECONDS, self.ctx.timeout)
            request = {
                "container": exact_cid,
                "state": state,
                "monitor": self.monitor_context,
                "directory": str(self.ctx.directory),
                "deadline": deadline,
            }
            raw = collection.command(
                "read exact owned post-exit OOM markers",
                [
                    *self.ctx._sudo,  # noqa: SLF001 — existing host privilege boundary, no guest exec.
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    "--after-exit",
                    json.dumps(request),
                ],
                timeout=min(SNAPSHOT_SECONDS, self.ctx.timeout),
            )
            _require(len(raw) <= MAX_BYTES, "diagnostic post-exit response exceeded its byte bound")
            record["snapshot"] = json.loads(raw)
            record["availability"] = "observed"
        except Exception as error:  # noqa: BLE001 — optional observation cannot change shutdown admission.
            record["availability"] = "error"
            record["reason"] = f"{type(error).__name__}: {error}"
        self.ctx.observations.append(record)


def _deltas(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    _require(before["guestRoot"] == after["guestRoot"], "diagnostic root identity changed across snapshots")
    result = {}
    for view in ("guestChain", "hostOuterChain"):
        old = {group["path"]: group for group in before[view]}
        changes = []
        for group in after[view]:
            previous = old.get(group["path"], {})
            change: dict[str, Any] = {"path": group["path"], "availability": "unresolved"}
            if "inode" in group and group.get("inode") == previous.get("inode"):
                change["events"] = {}
                for name in ("memory.events", "memory.events.local"):
                    first, last = previous["values"].get(name), group["values"].get(name)
                    if first is not None and last is not None:
                        _require(first.keys() == last.keys(), "diagnostic counter fields changed across snapshots")
                        _require(
                            all(last[key] >= value for key, value in first.items()), "diagnostic counters regressed"
                        )
                        change["events"][name] = {key: last[key] - value for key, value in first.items()}
                change["availability"] = "same-inode"
            changes.append(change)
        result[view] = changes
    return result


if __name__ == "__main__":
    _require(
        len(sys.argv) == HOST_ARGUMENTS and sys.argv[1] in {"--snapshot", "--after-exit"},
        "diagnostic invocation was invalid",
    )
    _require(len(sys.argv[2]) <= MAX_BYTES, "diagnostic request exceeded its byte bound")
    collector = _collect if sys.argv[1] == "--snapshot" else _collect_after_exit
    payload = json.dumps(collector(json.loads(sys.argv[2])))
    _require(len(payload) <= MAX_BYTES, "diagnostic response exceeded its byte bound")
    sys.stdout.write(payload + "\n")
