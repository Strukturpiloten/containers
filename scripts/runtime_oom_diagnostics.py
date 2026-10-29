"""Bounded OOM evidence only; never classify an outer OOM flag as expected."""

from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
from contextlib import ExitStack
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


def _custody_reply(process: subprocess.Popen[bytes], deadline: float) -> dict[str, Any]:
    _require(process.stdout is not None, "diagnostic custody output unavailable")
    raw = bytearray()
    while not raw.endswith(b"\n"):
        _require(time.monotonic() < deadline, "diagnostic custody response deadline expired")
        _require(len(raw) <= MAX_BYTES, "diagnostic custody response exceeded bound")
        ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
        _require(bool(ready), "diagnostic custody response deadline expired")
        part = os.read(process.stdout.fileno(), MAX_BYTES + 1 - len(raw))
        _require(bool(part), "diagnostic custody closed without response")
        raw.extend(part)
    _require(
        time.monotonic() < deadline and len(raw) <= MAX_BYTES and raw.count(b"\n") == 1,
        "diagnostic custody response framing or deadline invalid",
    )
    value = json.loads(raw)
    _require(isinstance(value, dict), "diagnostic custody response was not an object")
    return value


# Intentional closed wire duplication avoids importing the standalone ctypes helper.
CUSTODY_FAILURE_GUARDS = frozenset(
    {
        "custody-deadline",
        "custody-read-budget",
        "directory-event-budget",
        "marker-event-budget",
        "protocol-input",
        "protocol-phase",
        "protocol-output",
        "directory-path",
        "original-pid-identity",
        "original-pid-descriptor",
        "custody-deadline-config",
        "original-watch",
        "inotify-unavailable",
        "cgroup-path",
        "cgroup-directory-identity",
        "conmon-event-identity",
        "store-identity",
        "marker-count",
        "marker-path",
        "marker-parent-identity",
        "marker-watch",
        "marker-file",
        "counter-content",
        "inotify-framing",
        "inotify-watch-loss",
        "marker-rename",
        "completed-marker-path",
        "completed-marker-descriptor",
        "completed-marker-identity",
        "completed-marker-content",
        "completed-marker-bracket",
        "marker-identity",
        "marker-completion",
        "marker-version",
    }
)

TERMINAL_ERROR_CLASSES = frozenset(
    {
        "OSError",
        "BlockingIOError",
        "ChildProcessError",
        "ConnectionError",
        "BrokenPipeError",
        "ConnectionAbortedError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "FileExistsError",
        "FileNotFoundError",
        "InterruptedError",
        "IsADirectoryError",
        "NotADirectoryError",
        "PermissionError",
        "ProcessLookupError",
        "TimeoutError",
        "ValueError",
        "UnicodeError",
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        "UnicodeTranslateError",
        "JSONDecodeError",
        "KeyError",
        "IndexError",
        "TypeError",
        "AttributeError",
    }
)
TERMINAL_UNCERTAINTIES = frozenset(
    {
        "marker existed before observer",
        "conmon watch continuity unresolved",
        "marker link continuity unresolved at completed read",
        "marker recreated",
        "marker creation identity unresolved",
        "marker rewritten after completed observation",
        "marker deleted or moved",
        "completed marker content unresolved",
        "original marker parent removed or moved",
        "completed marker changed during post-read bracket",
        "original PID exited before stop boundary",
        "marker present without observed creation",
        "marker or parent custody recheck unresolved",
        "held counter read unresolved",
    }
)
TERMINAL_CONTENT_LIMITS = "close-observed stable read; future contents and writer identity unresolved"
TERMINAL_UINT64_MAX = (1 << 64) - 1
TERMINAL_UINT32_MAX = (1 << 32) - 1
TERMINAL_INT32_MAX = (1 << 31) - 1
TERMINAL_STAT_NS_MAX = (1 << 95) - 1
TERMINAL_READ_NS_MAX = 640 * 1_000_000_000
TERMINAL_MAX_EVENTS = 32
TERMINAL_EVENT_MASK = 0x100 | 8 | 2 | 0x80 | 0x200
TERMINAL_DIRECTORY_FLAG = 0x40000000


def _terminal_uint(value: object, maximum: int = TERMINAL_UINT64_MAX) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _terminal_object(value: object, fields: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict) and value.keys() == fields, "diagnostic custody nested object schema invalid")
    return value


def _terminal_file_identity(value: object) -> dict[str, Any]:
    identity = _terminal_object(value, {"dev", "ino", "mode", "uid", "gid", "nlink"})
    _require(
        all(_terminal_uint(number) for number in identity.values())
        and identity["ino"] > 0
        and all(_terminal_uint(identity[key], TERMINAL_UINT32_MAX) for key in ("mode", "uid", "gid"))
        and stat.S_ISREG(identity["mode"])
        and identity["nlink"] == 1,
        "diagnostic custody marker identity invalid",
    )
    return identity


def _terminal_counters(value: object) -> None:
    views = _terminal_object(value, {"memory.events", "memory.events.local"})
    for counters in views.values():
        fields = _terminal_object(counters, {"max", "oom", "oom_kill"})
        _require(all(_terminal_uint(number) for number in fields.values()), "diagnostic custody counters invalid")


def _terminal_watch(value: object, expected: dict[str, Any] | None) -> None:
    watch = _terminal_object(
        value,
        {
            "availability",
            "file",
            "path",
            "inode",
            "major",
            "minor",
            "fd",
            "wd",
            "rawKernelDevice",
            "deviceEncoding",
            "directoryIdentity",
        },
    )
    directory = _terminal_object(watch["directoryIdentity"], {"dev", "ino"})
    _require(
        all(_terminal_uint(number) for number in directory.values())
        and directory["ino"] > 0
        and watch["availability"] == "observed"
        and watch["file"] == "memory.events"
        and watch["deviceEncoding"] == "Linux raw kernel dev_t; 20 minor bits"
        and _terminal_uint(watch["inode"])
        and watch["inode"] > 0
        and _terminal_uint(watch["major"], (1 << 12) - 1)
        and _terminal_uint(watch["minor"], (1 << 20) - 1)
        and _terminal_uint(watch["fd"], TERMINAL_INT32_MAX)
        and _terminal_uint(watch["wd"], TERMINAL_INT32_MAX)
        and watch["wd"] > 0
        and isinstance(watch["path"], str)
        and isinstance(watch["rawKernelDevice"], str),
        "diagnostic custody watch fields invalid",
    )
    _group_path(watch["path"])
    _require(
        _watch_device(watch["rawKernelDevice"]) == (watch["major"], watch["minor"])
        and (os.major(directory["dev"]), os.minor(directory["dev"])) == (watch["major"], watch["minor"])
        and expected is not None
        and watch == expected,
        "diagnostic custody terminal watch differs from its original owned source",
    )


def _terminal_completion(value: object) -> dict[str, Any]:
    completed = _terminal_object(
        value,
        {
            "fileIdentity",
            "version",
            "observedWriteEpoch",
            "observedMonotonicNs",
            "bytesRead",
            "sha256",
            "linkedAtCapture",
            "readIntervalMonotonicNs",
            "limits",
        },
    )
    identity = _terminal_file_identity(completed["fileIdentity"])
    version = _terminal_object(completed["version"], {"dev", "ino", "size", "mtime_ns", "ctime_ns"})
    interval = _terminal_object(completed["readIntervalMonotonicNs"], {"start", "end"})
    _require(
        _terminal_uint(version["dev"])
        and _terminal_uint(version["ino"])
        and version["ino"] > 0
        and (version["dev"], version["ino"]) == (identity["dev"], identity["ino"])
        and _terminal_uint(version["size"], MAX_FILE_BYTES)
        and all(
            type(version[key]) is int and -TERMINAL_STAT_NS_MAX <= version[key] <= TERMINAL_STAT_NS_MAX
            for key in ("mtime_ns", "ctime_ns")
        )
        and _terminal_uint(completed["bytesRead"], MAX_FILE_BYTES)
        and completed["bytesRead"] == version["size"]
        and _terminal_uint(completed["observedWriteEpoch"], TERMINAL_MAX_EVENTS)
        and _terminal_uint(completed["observedMonotonicNs"])
        and all(_terminal_uint(number) for number in interval.values())
        and interval["start"] <= completed["observedMonotonicNs"] <= interval["end"]
        and interval["end"] - interval["start"] <= TERMINAL_READ_NS_MAX
        and type(completed["linkedAtCapture"]) is bool
        and isinstance(completed["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", completed["sha256"]) is not None
        and completed["limits"] == TERMINAL_CONTENT_LIMITS,
        "diagnostic custody completed content invalid",
    )
    return completed


def _terminal_event(event: object) -> None:
    required = {"candidate", "mask", "observedMonotonicNs", "originalPidAlive"}
    optional = {"fileIdentity", "counters", "availability", "completedContent"}
    _require(
        isinstance(event, dict)
        and required <= event.keys() <= required | optional
        and _terminal_uint(event["candidate"], MARKER_COUNT - 1)
        and _terminal_uint(event["mask"], TERMINAL_UINT32_MAX)
        and bool(event["mask"] & TERMINAL_EVENT_MASK)
        and not event["mask"] & ~(TERMINAL_EVENT_MASK | TERMINAL_DIRECTORY_FLAG)
        and _terminal_uint(event["observedMonotonicNs"])
        and type(event["originalPidAlive"]) is bool
        and event.get("availability", "unresolved") == "unresolved",
        "diagnostic custody terminal event schema invalid",
    )
    if "fileIdentity" in event:
        _require(event["mask"] & 0x100, "diagnostic custody identity lacks creation event")
        _terminal_file_identity(event["fileIdentity"])
    if "counters" in event:
        _require(event["mask"] & 0x100, "diagnostic custody counters lack creation event")
        _terminal_counters(event["counters"])
    if "completedContent" in event:
        _require(event["mask"] & 8, "diagnostic custody completion lacks close event")
        completed = _terminal_completion(event["completedContent"])
        _require(
            event["observedMonotonicNs"] <= completed["readIntervalMonotonicNs"]["start"]
            and ("fileIdentity" not in event or event["fileIdentity"] == completed["fileIdentity"]),
            "diagnostic custody completion event identity or interval invalid",
        )


def _terminal_custody_record(value: dict[str, Any], *, expected_watch: dict[str, Any] | None = None) -> None:
    required = {"schemaVersion", "attribution", "availability", "reason"}
    optional = {"events", "originalConmonWatch", "exitObservedMonotonicNs", "uncertainty"}
    _require(
        value.keys() - {"failureGuard"} in (required, required | optional)
        and type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 1
        and value["attribution"] == "unresolved"
        and value["availability"] == "error"
        and isinstance(value["reason"], str)
        and value["reason"] in TERMINAL_ERROR_CLASSES,
        "diagnostic custody terminal schema invalid",
    )
    _require(
        "failureGuard" not in value
        or (type(value["failureGuard"]) is str and value["failureGuard"] in CUSTODY_FAILURE_GUARDS),
        "diagnostic custody terminal failure guard invalid",
    )
    if value.keys() - {"failureGuard"} == required:
        return
    _terminal_watch(value["originalConmonWatch"], expected_watch)
    _require(
        isinstance(value["events"], list)
        and len(value["events"]) <= TERMINAL_MAX_EVENTS
        and (value["exitObservedMonotonicNs"] is None or _terminal_uint(value["exitObservedMonotonicNs"]))
        and isinstance(value["uncertainty"], list)
        and len(value["uncertainty"]) <= len(TERMINAL_UNCERTAINTIES)
        and all(isinstance(reason, str) and reason in TERMINAL_UNCERTAINTIES for reason in value["uncertainty"])
        and len(set(value["uncertainty"])) == len(value["uncertainty"]),
        "diagnostic custody terminal fields invalid",
    )
    for event in value["events"]:
        _terminal_event(event)


# Docker's outer-only observer has no lifecycle or conmon authority. Its output
# vocabulary is closed; raw command results, operands and host paths stay private.
DOCKER_EVENT_FILES = ("memory.events", "memory.events.local")
DOCKER_CHECKS = (
    "ownedContainer",
    "containerIncarnation",
    "ownedSlice",
    "hostProcess",
    "cgroup2Mount",
    "outerCgroup",
    "stableRead",
)
DOCKER_STATUSES = {
    "observed",
    "unavailable",
    "missing",
    "unsupported",
    "malformed",
    "oversized",
    "changed",
    "regressed",
    "timeout",
    "error",
    "not-sampled",
}
DOCKER_COUNTER_MAX = (1 << 64) - 1
DOCKER_COUNTER_DIGITS = 20
DOCKER_EVENT_KEYS = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill", "sock_throttled"}
DOCKER_COUNTER_PHASES = {"before-inner-memory", "after-inner-memory"}
DOCKER_STARTED_MAX = 128
DOCKER_EXIT_MAX = 255
MOUNT_MIN_FIELDS = 10
MOUNT_SEPARATOR_MIN = 6
DOCKER_SLICE_FIELDS = {"Id", "Names", "LoadState", "ActiveState", "ControlGroup"}


class _DockerObservationError(ValueError):
    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(status)


def _docker_require(condition: object, status: str = "malformed") -> None:
    if not condition:
        raise _DockerObservationError(status)


def _docker_record() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "availability": "unavailable",
        "attribution": "unresolved",
        "authority": "observation-only",
        "bindingChecks": dict.fromkeys(DOCKER_CHECKS, False),
        "bindings": {},
        "counters": {name: {"availability": "unavailable"} for name in DOCKER_EVENT_FILES},
        "sampleWindowMonotonicNs": [time.monotonic_ns(), time.monotonic_ns()],
    }


def _docker_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _docker_identity(descriptor: int) -> tuple[int, int]:
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def _docker_filesystem(descriptor: int, expected: int) -> None:
    # Linux statfs starts with a native long f_type; overallocate the remaining
    # architecture-specific structure and expose none of it in public evidence.
    buffer = ctypes.create_string_buffer(256)
    operation = ctypes.CDLL(None, use_errno=True).fstatfs
    operation.argtypes = [ctypes.c_int, ctypes.c_void_p]
    operation.restype = ctypes.c_int
    _docker_require(operation(descriptor, buffer) == 0, "unsupported")
    _docker_require(ctypes.c_long.from_buffer(buffer).value == expected, "unsupported")


class _DockerOuterRead:
    """Held nofollow descriptors and one original, nonrenewable read deadline."""

    def __init__(self, stack: ExitStack, deadline: float) -> None:
        self.stack = stack
        self.deadline = deadline

    def check(self) -> None:
        _docker_require(time.monotonic() < self.deadline, "timeout")

    def directory(self, path: str, *, parent: int | None = None) -> int:
        self.check()
        _docker_require(len(path) <= MAX_FILE_BYTES and len(Path(path).parts) <= MAX_PATH_COMPONENTS)
        if parent is None:
            descriptor = _open_directory(Path(path))
        else:
            _docker_require(path != "" and "/" not in path and path not in {".", ".."})
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        self.stack.callback(os.close, descriptor)
        return descriptor

    def descend(self, root: int, path: str) -> int:
        _group_path(path)
        result = root
        for part in path.strip("/").split("/"):
            if part:
                result = self.directory(part, parent=result)
        return result

    def text(self, parent: int, name: str, maximum: int = MAX_FILE_BYTES) -> str:
        self.check()
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            _docker_require(
                stat.S_ISREG(os.fstat(descriptor).st_mode) and os.fstat(descriptor).st_dev == os.fstat(parent).st_dev,
                "unsupported",
            )
            raw = bytearray()
            while True:
                self.check()
                part = os.read(descriptor, maximum + 1 - len(raw))
                self.check()
                if not part:
                    return raw.decode("ascii")
                raw.extend(part)
                _docker_require(len(raw) <= maximum, "oversized")
        finally:
            os.close(descriptor)

    def process(self, descriptor: int, pid: int) -> tuple[str, str]:
        raw = self.text(descriptor, "stat")
        prefix, separator, fields = raw.rpartition(") ")
        values = fields.split()
        _docker_require(separator and prefix.startswith(str(pid) + " (") and len(values) > STARTTIME_INDEX)
        _docker_require(values[0] not in {"Z", "X"}, "changed")
        start = values[STARTTIME_INDEX]
        _docker_require(start.isascii() and start.isdecimal() and int(start) > 0)
        membership = self.text(descriptor, "cgroup").strip()
        _docker_require(membership.startswith("0::") and "\n" not in membership, "unsupported")
        _group_path(membership[3:])
        return start, membership[3:]

    def stable_host(self, held: dict[str, int], expected: dict[str, Any]) -> int:
        """Reject replacement visible through either held or freshly opened fds."""
        _docker_require(expected["process"] == self.process(held["process"], expected["pid"]), "changed")
        linked_process = self.directory(str(expected["pid"]), parent=held["proc"])
        _docker_require(
            _docker_identity(held["process"]) == _docker_identity(linked_process)
            and expected["process"] == self.process(linked_process, expected["pid"]),
            "changed",
        )
        linked_root = self.directory("/sys/fs/cgroup")
        _docker_filesystem(linked_root, 0x63677270)
        _docker_require(_docker_identity(held["root"]) == _docker_identity(linked_root), "changed")
        _docker_require(
            _docker_mount(self.text(held["collector"], "mountinfo", MAX_BYTES), linked_root)[0] == expected["mount"],
            "changed",
        )
        return linked_root

    def events(self, scope: int) -> dict[str, Any]:
        """Keep unsupported or malformed files distinct from actual zero counters."""
        result = {}
        for filename in DOCKER_EVENT_FILES:
            try:
                values = _docker_events(self.text(scope, filename))
                result[filename] = {"availability": "observed", "values": values}
            except FileNotFoundError:
                result[filename] = {"availability": "missing"}
            except (UnicodeError, _DockerObservationError) as error:
                result[filename] = {
                    "availability": error.status if isinstance(error, _DockerObservationError) else "malformed"
                }
        return result


def _docker_events(raw: str) -> dict[str, int]:
    _docker_require(len(raw) <= MAX_FILE_BYTES, "oversized")
    result = {}
    for row in raw.splitlines():
        parts = row.split()
        _docker_require(
            len(parts) == EVENT_FIELDS
            and parts[0] in DOCKER_EVENT_KEYS
            and parts[0] not in result
            and parts[1].isascii()
            and parts[1].isdecimal()
            and len(parts[1]) <= DOCKER_COUNTER_DIGITS
        )
        value = int(parts[1])
        _docker_require(value <= DOCKER_COUNTER_MAX)
        result[parts[0]] = value
    _docker_require({"low", "high", "max", "oom", "oom_kill"} <= result.keys() and result.keys() <= DOCKER_EVENT_KEYS)
    return result


def _docker_mount(raw: str, descriptor: int) -> tuple[str, bool]:
    rows = [
        row.split()
        for row in raw.splitlines()
        if len(row.split()) >= MOUNT_MIN_FIELDS and row.split()[4] == "/sys/fs/cgroup"
    ]
    _docker_require(len(rows) == 1, "unsupported")
    _docker_require(
        not any(
            len(row.split()) >= MOUNT_MIN_FIELDS and row.split()[4].startswith("/sys/fs/cgroup/")
            for row in raw.splitlines()
        ),
        "unsupported",
    )
    row = rows[0]
    separator = row.index("-") if "-" in row else -1
    _docker_require(separator >= MOUNT_SEPARATOR_MIN and len(row) == separator + 4, "unsupported")
    info = os.fstat(descriptor)
    _docker_require(
        row[3] == "/"
        and row[separator + 1] == "cgroup2"
        and row[2] == f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
        "unsupported",
    )
    return " ".join(row), "memory_localevents" in (row[5] + "," + row[-1]).split(",")


def _docker_outer_request(request: dict[str, Any]) -> tuple[str, int, str, str]:
    _docker_require(
        request.keys() == {"container", "startedAt", "pid", "sliceName", "slicePath", "sliceIdentity", "deadline"}
    )
    cid, pid = request["container"], request["pid"]
    _docker_require(isinstance(cid, str) and re.fullmatch(r"[a-f0-9]{64}", cid) is not None)
    _docker_require(type(pid) is int and pid > 1)
    _docker_require(isinstance(request["startedAt"], str) and 0 < len(request["startedAt"]) <= DOCKER_STARTED_MAX)
    name = request["sliceName"]
    _docker_require(
        isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*\.slice", name) is not None
    )
    parts = name.removesuffix(".slice").split("-")
    expected_slice = "/" + "/".join("-".join(parts[:index]) + ".slice" for index in range(1, len(parts) + 1))
    _docker_require(request["slicePath"] == expected_slice, "unsupported")
    _docker_require(
        isinstance(request["sliceIdentity"], str)
        and re.fullmatch(r"[0-9]+:[0-9]+", request["sliceIdentity"]) is not None
    )
    _docker_require(
        type(request["deadline"]) in {int, float}
        and time.monotonic() < request["deadline"] <= time.monotonic() + SNAPSHOT_SECONDS,
        "timeout",
    )
    outer = expected_slice + "/docker-" + cid + ".scope"
    return cid, pid, expected_slice, outer


def _collect_docker_outer(request: dict[str, Any]) -> dict[str, Any]:
    """Read just the owned outer scope; never interpret the guest hook's path."""
    record = _docker_record()
    checks = record["bindingChecks"]
    try:
        cid, pid, expected_slice, outer = _docker_outer_request(request)
        with ExitStack() as stack:
            reads = _DockerOuterRead(stack, request["deadline"])
            proc = reads.directory("/proc")
            _docker_filesystem(proc, 0x9FA0)
            process = reads.directory(str(pid), parent=proc)
            collector = reads.directory(str(os.getpid()), parent=proc)
            original = reads.process(process, pid)
            _docker_require(original[1] in {outer, outer + "/init.scope"}, "unsupported")
            checks["hostProcess"] = True
            root = reads.directory("/sys/fs/cgroup")
            _docker_filesystem(root, 0x63677270)
            mount, localevents = _docker_mount(reads.text(collector, "mountinfo", MAX_BYTES), root)
            checks["cgroup2Mount"] = True
            owned_slice = reads.descend(root, expected_slice)
            slice_identity = _docker_identity(owned_slice)
            _docker_require(":".join(map(str, slice_identity)) == request["sliceIdentity"], "changed")
            checks["ownedSlice"] = True
            scope = reads.directory("docker-" + cid + ".scope", parent=owned_slice)
            scope_identity = _docker_identity(scope)
            member = scope if original[1] == outer else reads.directory("init.scope", parent=scope)
            member_identity = _docker_identity(member)
            _docker_require(
                scope_identity[0] == slice_identity[0] == member_identity[0] == os.fstat(root).st_dev, "unsupported"
            )
            checks["outerCgroup"] = True
            record["counters"] = reads.events(scope)
            # Re-resolve from fixed roots, in addition to checking held objects:
            # an unlinked old fd must not hide process, cgroup or mount replacement.
            linked_root = reads.stable_host(
                {"process": process, "proc": proc, "root": root, "collector": collector},
                {"process": original, "pid": pid, "mount": mount},
            )
            linked_slice = reads.descend(linked_root, expected_slice)
            linked_scope = reads.directory("docker-" + cid + ".scope", parent=linked_slice)
            linked_member = linked_scope if original[1] == outer else reads.directory("init.scope", parent=linked_scope)
            _docker_require(
                slice_identity == _docker_identity(linked_slice)
                and scope_identity == _docker_identity(linked_scope)
                and member_identity == _docker_identity(linked_member),
                "changed",
            )
            reads.check()
            checks["stableRead"] = True
            record["bindings"] = {
                "containerIncarnation": _docker_hash([cid, request["startedAt"]]),
                "hostProcess": _docker_hash([pid, original[0], _docker_identity(process)]),
                "outerCgroup": _docker_hash(
                    [expected_slice, slice_identity, outer, scope_identity, original[1], member_identity]
                ),
                "mount": _docker_hash([mount, _docker_identity(root)]),
            }
            record["mountSemantics"] = {"root": "full-hierarchy", "memoryLocalevents": localevents}
            record["availability"] = "observed"
    except _DockerObservationError as error:
        record["availability"] = error.status
    except FileNotFoundError:
        record["availability"] = "missing"
    except OSError, ValueError, TypeError, KeyError:
        record["availability"] = "error"
    record["sampleWindowMonotonicNs"][1] = time.monotonic_ns()
    return record


def _docker_validate_record(value: object) -> dict[str, Any]:
    """Reject collector stdout unless every public field has a closed schema."""
    _docker_require(isinstance(value, dict))
    template = _docker_record()
    _docker_require(value.keys() in (template.keys(), template.keys() | {"mountSemantics"}))
    _docker_require(value["schemaVersion"] == 1 and type(value["schemaVersion"]) is int)
    _docker_require(
        value["availability"] in DOCKER_STATUSES
        and value["attribution"] == "unresolved"
        and value["authority"] == "observation-only"
    )
    checks, bindings = value["bindingChecks"], value["bindings"]
    _docker_require(
        isinstance(checks, dict)
        and checks.keys() == set(DOCKER_CHECKS)
        and all(type(item) is bool for item in checks.values())
    )
    _docker_require(
        isinstance(bindings, dict)
        and bindings.keys() in (set(), {"containerIncarnation", "hostProcess", "outerCgroup", "mount"})
    )
    _docker_require(
        all(isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item) is not None for item in bindings.values())
    )
    window = value["sampleWindowMonotonicNs"]
    _docker_require(
        isinstance(window, list)
        and len(window) == EVENT_FIELDS
        and all(type(item) is int and item >= 0 for item in window)
        and window[0] <= window[1]
        and window[1] - window[0] <= SNAPSHOT_SECONDS * 1_000_000_000
    )
    _docker_require(isinstance(value["counters"], dict) and value["counters"].keys() == set(DOCKER_EVENT_FILES))
    for counter in value["counters"].values():
        _docker_require(isinstance(counter, dict) and counter.get("availability") in DOCKER_STATUSES)
        _docker_require(
            counter.keys()
            == ({"availability", "values"} if counter["availability"] == "observed" else {"availability"})
        )
        if counter["availability"] == "observed":
            _docker_require(
                isinstance(counter["values"], dict)
                and all(type(item) is int and 0 <= item <= DOCKER_COUNTER_MAX for item in counter["values"].values())
            )
            _docker_events("\n".join(f"{key} {item}" for key, item in counter["values"].items()))
    if "mountSemantics" in value:
        _docker_require(
            value["mountSemantics"].keys() == {"root", "memoryLocalevents"}
            and value["mountSemantics"]["root"] == "full-hierarchy"
            and type(value["mountSemantics"]["memoryLocalevents"]) is bool
        )
    if value["availability"] == "observed":
        _docker_require(
            bool(bindings)
            and all(checks[key] for key in DOCKER_CHECKS if key not in {"ownedContainer", "containerIncarnation"})
            and "mountSemantics" in value
        )
    return copy.deepcopy(value)


def _docker_slice(raw: str, slice_name: str) -> str:
    _docker_require(len(raw) <= MAX_BYTES, "oversized")
    rows = [row.split("=", 1) for row in raw.splitlines()]
    _docker_require(all(len(row) == EVENT_FIELDS for row in rows) and len(rows) == len(DOCKER_SLICE_FIELDS))
    state = dict(rows)
    _docker_require(state.keys() == DOCKER_SLICE_FIELDS)
    _docker_require(
        state["Id"] == slice_name
        and state["Names"] == slice_name
        and state["LoadState"] == "loaded"
        and state["ActiveState"] == "active",
        "changed",
    )
    _group_path(state["ControlGroup"])
    return state["ControlGroup"]


def _docker_public_state(state: object) -> dict[str, Any]:
    """Project finite OCI fields independently of live-process/counter support."""
    _docker_require(state is not None, "unavailable")
    _docker_require(isinstance(state, dict))
    public_state = {}
    for key in ("Running", "OOMKilled"):
        if key in state:
            _docker_require(type(state[key]) is bool)
            public_state[key] = state[key]
    if "ExitCode" in state:
        _docker_require(type(state["ExitCode"]) is int and 0 <= state["ExitCode"] <= DOCKER_EXIT_MAX)
        public_state["ExitCode"] = state["ExitCode"]
    return public_state


def _docker_inspect(raw: str, container: str, slice_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    value = json.loads(raw)
    _docker_require(isinstance(value, dict) and value.keys() == {"id", "state", "parent"})
    _docker_require(value["id"] == container and value["parent"] == slice_name, "changed")
    return value["state"], _docker_public_state(value["state"])


def _docker_incarnation(state: dict[str, Any]) -> tuple[str, int]:
    _docker_require(state.get("Running") is True, "unavailable")
    pid, started = state.get("Pid"), state.get("StartedAt")
    _docker_require(type(pid) is int and pid > 1)
    _docker_require(isinstance(started, str) and 0 < len(started) <= DOCKER_STARTED_MAX)
    return started, pid


def _docker_deltas(before: dict[str, Any] | None, after: dict[str, Any]) -> dict[str, Any]:
    result = {name: {"availability": "unavailable"} for name in DOCKER_EVENT_FILES}
    if before is None or before["availability"] != "observed" or after["availability"] != "observed":
        return result
    if not all(before["bindingChecks"].values()) or not all(after["bindingChecks"].values()):
        return result
    if before["bindings"] != after["bindings"] or before["mountSemantics"] != after["mountSemantics"]:
        return {name: {"availability": "changed"} for name in DOCKER_EVENT_FILES}
    if before["sampleWindowMonotonicNs"][1] > after["sampleWindowMonotonicNs"][0]:
        return {name: {"availability": "changed"} for name in DOCKER_EVENT_FILES}
    for name in DOCKER_EVENT_FILES:
        first, last = before["counters"][name], after["counters"][name]
        if first["availability"] != "observed" or last["availability"] != "observed":
            continue
        if first["values"].keys() != last["values"].keys():
            result[name] = {"availability": "changed"}
        elif any(last["values"][key] < value for key, value in first["values"].items()):
            result[name] = {"availability": "regressed"}
        else:
            result[name] = {
                "availability": "observed",
                "values": {key: last["values"][key] - value for key, value in first["values"].items()},
            }
    return result


class OomDiagnostics:
    """Retain read-only observations without changing lifecycle admission or cleanup."""

    def __init__(self, ctx: RuntimeContext, container: str) -> None:
        """Bind diagnostic state to the existing invocation's exact owned guest."""
        self.ctx = ctx
        self.container = container
        self.scope: str | None = None
        self.scope_inode: int | None = None
        self.baseline: dict[str, Any] | None = None
        self.docker_baseline: dict[str, Any] | None = None
        self.monitor_context: dict[str, Any] | None = None
        self.exit_observed = False
        self.custody: subprocess.Popen[bytes] | None = None
        self.custody_started = False
        self.last_watch: dict[str, Any] | None = None
        self.custody_terminal: dict[str, Any] | None = None
        self.custody_watch: dict[str, Any] | None = None
        self.custody_terminal_unavailable: dict[str, Any] | None = None

    def _retire_custody_reply(self, receipt: str) -> dict[str, Any]:
        self.custody_terminal_unavailable = {
            "schemaVersion": 1,
            "availability": "unavailable",
            "attribution": "unresolved",
            "reason": "terminal-record-unavailable-or-invalid",
            "terminalReceipt": receipt,
        }
        return copy.deepcopy(self.custody_terminal_unavailable)

    def _closed_custody_reply(self, process: subprocess.Popen[bytes], deadline: float) -> dict[str, Any]:
        try:
            terminal = _custody_reply(process, deadline)
            _terminal_custody_record(terminal, expected_watch=self.custody_watch)
        except Exception:  # noqa: BLE001 — absent/late/invalid terminal evidence stays explicitly unavailable.
            return self._retire_custody_reply("input-closed")
        self.custody_terminal = copy.deepcopy(terminal)
        return {**terminal, "terminalReceipt": "buffered-after-input-closed"}

    def _custody_exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        _require(self.custody is not None, "diagnostic custody was not armed")
        if self.custody_terminal is not None:
            return {**copy.deepcopy(self.custody_terminal), "terminalReceipt": "previously-retained-terminal"}
        if self.custody_terminal_unavailable is not None:
            return {
                **copy.deepcopy(self.custody_terminal_unavailable),
                "terminalReceipt": "previously-retired-terminal",
            }
        process = self.custody
        _require(process.stdin is not None and process.stdout is not None, "diagnostic custody pipes unavailable")
        deadline = time.monotonic() + min(2, self.ctx.timeout)
        if process.poll() is not None:
            return self._closed_custody_reply(process, deadline)
        payload = (json.dumps(request) + "\n").encode("utf-8")
        _require(len(payload) <= MAX_BYTES, "diagnostic custody request exceeded bound")
        descriptor = process.stdin.fileno()
        try:
            try:
                while payload:
                    _, ready, _ = select.select([], [descriptor], [], max(0, deadline - time.monotonic()))
                    _require(bool(ready), "diagnostic custody request deadline expired")
                    payload = payload[os.write(descriptor, payload) :]
            except BrokenPipeError:
                return self._closed_custody_reply(process, deadline)
            value = _custody_reply(process, deadline)
            if value.get("availability") == "error":
                _terminal_custody_record(value, expected_watch=self.custody_watch)
                self.custody_terminal = copy.deepcopy(value)
        except Exception:
            # Failed exchanges cannot admit a late response under a new budget.
            self._retire_custody_reply("exchange-failed")
            raise
        return value

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
            self.custody_watch = copy.deepcopy(request["watch"])
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

    def _docker_oci_snapshot(self, phase: str) -> None:
        """Retain OCI-only hooks without allocating a host collector allowance."""
        collection = copy.copy(self.ctx)
        collection.checks = []
        state: object = {}
        availability = "not-sampled"
        try:
            _docker_require(self.container in self.ctx.containers, "unavailable")
            _docker_require(re.fullmatch(r"[0-9a-f]{64}", self.container) is not None)
            raw = collection.podman(
                "read owned OOM diagnostic OCI state",
                "inspect",
                "--format",
                "{{json .State}}",
                self.container,
                timeout=min(SNAPSHOT_SECONDS, self.ctx.timeout),
            )
            _docker_require(len(raw) <= MAX_BYTES, "oversized")
            state = json.loads(raw)
        except _DockerObservationError as error:
            availability = error.status
        except subprocess.TimeoutExpired:
            availability = "timeout"
        except Exception:  # noqa: BLE001 — optional OCI evidence cannot alter native failures.
            availability = "error"
        self._backend_not_applicable(phase, state, availability=availability)

    def _docker_snapshot(self, phase: str) -> None:
        if phase in DOCKER_COUNTER_PHASES:
            self._docker_memory_snapshot(phase)
        else:
            self._docker_oci_snapshot(phase)

    def _docker_memory_snapshot(self, phase: str) -> None:
        record = _docker_record()
        record.update(
            {
                "name": "owned systemd OOM diagnostic",
                "phase": phase,
                "sources": {
                    "conmonProcess": "not-applicable",
                    "conmonWatch": "not-applicable",
                    "conmonMarkers": "not-applicable",
                },
            }
        )
        # Neither raw commands nor exception operands cross this boundary.
        collection = copy.copy(self.ctx)
        collection.checks = []
        try:
            backend = self.ctx.backend
            _docker_require(self.container in self.ctx.containers, "unavailable")
            _docker_require(re.fullmatch(r"[0-9a-f]{64}", self.container) is not None)
            deadline = time.monotonic() + backend.command_timeout(min(SNAPSHOT_SECONDS, self.ctx.timeout))
            if getattr(self.ctx, "runtime_deadline", None) is not None:
                deadline = min(deadline, self.ctx.runtime_deadline)

            def remaining() -> float:
                value = deadline - time.monotonic()
                _docker_require(value > 0, "timeout")
                return backend.command_timeout(value)

            def inspect() -> tuple[str, int]:
                raw = collection.podman(
                    "read private owned Docker OOM state",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"state":{{json .State}},"parent":{{json .HostConfig.CgroupParent}}}',
                    self.container,
                    timeout=remaining(),
                )
                _docker_require(len(raw) <= MAX_BYTES, "oversized")
                state, public_state = _docker_inspect(raw, self.container, backend.slice)
                record["ociState"] = public_state
                return _docker_incarnation(state)

            def slice_path() -> str:
                raw = collection.command(
                    "read private owned Docker OOM slice",
                    backend.privileged(
                        [
                            "systemctl",
                            "show",
                            backend.slice,
                            "--no-pager",
                            "--all",
                            "--property=Id,Names,LoadState,ActiveState,ControlGroup",
                        ],
                        remaining(),
                    ),
                    timeout=remaining(),
                )
                return _docker_slice(raw, backend.slice)

            original = inspect()
            record["bindingChecks"]["ownedContainer"] = True
            path = slice_path()
            _docker_require(backend.slice_identity is not None, "unavailable")
            request = {
                "container": self.container,
                "startedAt": original[0],
                "pid": original[1],
                "sliceName": backend.slice,
                "slicePath": path,
                "sliceIdentity": backend.slice_identity,
                "deadline": deadline,
            }
            raw = collection.command(
                "read private owned Docker outer OOM counters",
                backend.privileged(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(Path(__file__).resolve()),
                        "--docker-outer",
                        json.dumps(request),
                    ],
                    remaining(),
                ),
                timeout=remaining(),
            )
            _docker_require(len(raw) <= MAX_BYTES, "oversized")
            snapshot = _docker_validate_record(json.loads(raw))
            # Always read back Docker incarnation and systemd slice after the
            # host reader, even if the reader returned partial/unavailable data.
            _docker_require(inspect() == original and slice_path() == path, "changed")
            backend.check_deadline()
            remaining()
            snapshot["bindingChecks"]["ownedContainer"] = True
            snapshot["bindingChecks"]["containerIncarnation"] = True
            if snapshot["availability"] == "observed":
                _docker_require(
                    snapshot["bindings"]["containerIncarnation"] == _docker_hash([self.container, original[0]]),
                    "changed",
                )
            record.update(snapshot)
            record["baselineDelta"] = _docker_deltas(self.docker_baseline, snapshot)
            if phase == "before-inner-memory":
                self.docker_baseline = copy.deepcopy(snapshot)
        except _DockerObservationError as error:
            record["availability"] = error.status
        except subprocess.TimeoutExpired:
            record["availability"] = "timeout"
        except Exception:  # noqa: BLE001 — diagnostics cannot replace the original native failure.
            record["availability"] = "error"
        record["sampleWindowMonotonicNs"][1] = time.monotonic_ns()
        self.ctx.observations.append(record)

    def _backend_not_applicable(self, phase: str, state: object, *, availability: str = "not-sampled") -> bool:
        if getattr(self.ctx, "outer_engine", "podman") != "docker":
            return False
        record = _docker_record()
        record.update(
            {
                "name": "owned systemd OOM diagnostic",
                "phase": phase,
                "availability": availability,
                "sources": {
                    "conmonProcess": "not-applicable",
                    "conmonWatch": "not-applicable",
                    "conmonMarkers": "not-applicable",
                },
            }
        )
        try:
            record["ociState"] = _docker_public_state(state)
        except _DockerObservationError as error:
            record["availability"] = error.status
        self.ctx.observations.append(record)
        return True

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
        """Dispatch observations without altering either backend's admission."""
        if getattr(self.ctx, "outer_engine", "podman") == "docker":
            self._docker_snapshot(phase)
        else:
            self._podman_snapshot(phase, scope=scope, scope_inode=scope_inode)

    def _podman_snapshot(self, phase: str, *, scope: str | None = None, scope_inode: int | None = None) -> None:
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
            if self._backend_not_applicable(phase, state):
                return
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
        if self._backend_not_applicable("after-exit", state):
            return
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
        len(sys.argv) == HOST_ARGUMENTS and sys.argv[1] in {"--snapshot", "--after-exit", "--docker-outer"},
        "diagnostic invocation was invalid",
    )
    _require(len(sys.argv[2]) <= MAX_BYTES, "diagnostic request exceeded its byte bound")
    collector = {"--snapshot": _collect, "--after-exit": _collect_after_exit, "--docker-outer": _collect_docker_outer}[
        sys.argv[1]
    ]
    payload = json.dumps(collector(json.loads(sys.argv[2])))
    _require(len(payload) <= MAX_BYTES, "diagnostic response exceeded its byte bound")
    sys.stdout.write(payload + "\n")
