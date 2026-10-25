"""Read-only, expiring custody of one already-bound guest and two OOM markers.

Standalone host helper: no discovery, process arguments, environment or runtime
commands. Inotify timestamps are observation times, never kernel event times.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import select
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any

MAX_BYTES = 65536
MAX_FILE = 4096
MAX_EVENTS = 32
MAX_READS = 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_REQUESTS = 8
MAX_SECONDS = 640
MAX_COMPONENTS = 64
STARTTIME_INDEX = 19
MARKER_COUNT = 2
MAX_COUNTER_DIGITS = 20
IN_CREATE = 0x100
IN_CLOSE_WRITE = 8
IN_MODIFY = 2
IN_MOVED_TO = 0x80
IN_DELETE = 0x200
IN_MOVE_SELF = 0x800
IN_DELETE_SELF = 0x400
IN_IGNORED = 0x8000
IN_Q_OVERFLOW = 0x4000
EVENT_HEADER = struct.Struct("iIII")


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _identity(descriptor: int) -> dict[str, int]:
    info = os.fstat(descriptor)
    return {key: getattr(info, "st_" + key) for key in ("dev", "ino", "mode", "uid", "gid", "nlink")}


def _directory(path: Path) -> int:
    _require(path.is_absolute() and len(path.parts) <= MAX_COMPONENTS, "directory outside bound")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            _require(part not in {".", ".."}, "unsafe directory component")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _birth(pid: int) -> str:
    with (Path("/proc") / str(pid) / "stat").open("rb", buffering=0) as stream:
        raw = stream.read(MAX_FILE + 1)
    _require(len(raw) <= MAX_FILE, "process stat exceeded bound")
    fields = raw.decode("ascii").rsplit(") ", 1)[1].split()
    _require(len(fields) > STARTTIME_INDEX and fields[STARTTIME_INDEX].isdigit(), "invalid process birth")
    return fields[STARTTIME_INDEX]


class MarkerCustody:
    """Hold original kernel identities; uncertainty is sticky and never admission."""

    def __init__(self, request: dict[str, Any]) -> None:
        """Bracket initial metadata with kernel descriptors or close partial state."""
        self.fds: list[int] = []
        self.markers: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.reasons: list[str] = []
        self.reads = 0
        self.bytes = 0
        self.event_count = 0
        self.created = time.monotonic()
        self.deadline = request["deadline"]
        self.pid = request["pid"]
        self.starttime = request["starttime"]
        self.before_stop_observed = False
        self.exited_at: int | None = None
        self.watch = request["watch"]
        try:
            _require(type(self.pid) is int and self.pid > 1, "invalid original PID")
            _require(
                type(self.deadline) in {int, float}
                and math.isfinite(self.deadline)
                and self.created < self.deadline <= self.created + MAX_SECONDS,
                "invalid custody deadline",
            )
            _require(self.watch["availability"] == "observed", "original conmon watch unresolved")
            libc = ctypes.CDLL(None, use_errno=True)
            libc.pidfd_open.argtypes = [ctypes.c_int, ctypes.c_uint]
            libc.pidfd_open.restype = ctypes.c_int
            self.pidfd = libc.pidfd_open(self.pid, 0)
            _require(self.pidfd >= 0, "original PID descriptor unavailable")
            self._hold(self.pidfd)
            _require(_birth(self.pid) == self.starttime and self.pid_alive(), "original PID changed before custody")
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_init1.restype = ctypes.c_int
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            libc.inotify_add_watch.restype = ctypes.c_int
            self.inotify = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
            _require(self.inotify >= 0, "inotify unavailable")
            self._hold(self.inotify)
            self._arm_markers(request["markers"], libc)
            group = Path(self.watch["path"])
            _require(group.is_absolute() and ".." not in group.parts, "unsafe owned cgroup")
            parent = self._hold(_directory(Path("/sys/fs/cgroup") / str(group).lstrip("/")))
            self.group_identity = _identity(parent)
            _require(
                {key: self.group_identity[key] for key in ("dev", "ino")} == self.watch["directoryIdentity"],
                "original watched cgroup directory changed",
            )
            self.counters = {}
            for name in ("memory.events", "memory.events.local"):
                descriptor = self._hold(
                    os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                )
                self.counters[name] = descriptor
            info = os.fstat(self.counters["memory.events"])
            _require(
                (info.st_ino, os.major(info.st_dev), os.minor(info.st_dev))
                == (self.watch["inode"], self.watch["major"], self.watch["minor"]),
                "original conmon event inode changed",
            )
            self.baseline = self._counters()
            self.sample("armed")
        except BaseException:
            self.close()
            raise

    def _arm_markers(self, context: dict[str, Any], libc: ctypes.CDLL) -> None:
        root = Path(context["directory"])
        root_fd = self._hold(_directory(root))
        _require(
            {"dev": os.fstat(root_fd).st_dev, "inode": os.fstat(root_fd).st_ino} == context["directoryIdentity"],
            "original store changed",
        )
        candidates = context["candidates"]
        _require(len(candidates) == MARKER_COUNT, "ambiguous marker count")
        names = set()
        for candidate in candidates:
            path = Path(candidate["path"])
            _require(path.name == "oom" and path.is_relative_to(root), "marker escaped original store")
            _require(str(path) == candidate["path"] and ".." not in path.parts, "unsafe marker path")
            parent = self._hold(_directory(path.parent))
            identity = _identity(parent)
            _require(
                {key: identity[key] for key in candidate["parentIdentity"]} == candidate["parentIdentity"],
                "original marker parent changed",
            )
            name = (identity["dev"], identity["ino"], path.name)
            _require(name not in names, "ambiguous duplicate marker")
            names.add(name)
            wd = libc.inotify_add_watch(
                self.inotify,
                os.fsencode(f"/proc/self/fd/{parent}"),
                IN_CREATE | IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_DELETE | IN_MOVE_SELF | IN_DELETE_SELF,
            )
            _require(wd >= 0, "marker directory watch unavailable")
            marker = {
                "parent": parent,
                "path": path,
                "identity": identity,
                "wd": wd,
                "file": None,
                "closedWrite": False,
                "writeEpoch": 0,
                "completedContents": [],
                "pathLost": False,
            }
            self.markers.append(marker)
            try:
                self._open_marker(marker)
            except FileNotFoundError:
                pass
            else:
                self._uncertain("marker existed before observer")

    def _hold(self, descriptor: int) -> int:
        self.fds.append(descriptor)
        return descriptor

    def _uncertain(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)

    def _read(self, descriptor: int, maximum: int) -> bytes:
        _require(time.monotonic() < self.deadline, "custody deadline expired")
        _require(self.reads < MAX_READS and self.bytes + maximum <= MAX_TOTAL_BYTES, "custody read budget exhausted")
        self.reads += 1
        raw = os.read(descriptor, maximum)
        self.bytes += len(raw)
        return raw

    def pid_alive(self) -> bool:
        """Read the held pidfd and verify starttime only while it remains live."""
        ready, _, _ = select.select([self.pidfd], [], [], 0)
        if ready:
            if self.exited_at is None:
                self.exited_at = time.monotonic_ns()
            return False
        _require(_birth(self.pid) == self.starttime, "original PID start identity changed")
        return True

    def observe_watch(self, watch: dict[str, Any] | None) -> None:
        """Keep the original watch when later lifecycle readback is uncertain."""
        if watch != self.watch:
            self._uncertain("conmon watch continuity unresolved")

    def _open_marker(self, marker: dict[str, Any]) -> None:
        descriptor = os.open("oom", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=marker["parent"])
        self._hold(descriptor)
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe marker file")
        marker["file"] = descriptor
        marker["fileIdentity"] = _identity(descriptor)

    def _counters(self) -> dict[str, dict[str, int]]:
        result = {}
        for name, descriptor in self.counters.items():
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = self._read(descriptor, MAX_FILE + 1)
            _require(len(raw) <= MAX_FILE, "counter read exceeded bound")
            values = {}
            for row in raw.decode("ascii").splitlines():
                key, value = row.split()
                _require(
                    key not in values and value.isdigit() and len(value) <= MAX_COUNTER_DIGITS, "invalid counter read"
                )
                values[key] = int(value)
            _require({"oom", "oom_kill", "max"} <= values.keys(), "incomplete counters")
            # Fixed privacy-safe fields; complete counters remain in the
            # existing lifecycle snapshots, including new kernel fields.
            result[name] = {key: values[key] for key in ("max", "oom", "oom_kill")}
        return result

    def _queued_events(self, raw: bytes) -> list[tuple[int, int, int, bytes]]:
        result = []
        offset = 0
        while offset < len(raw):
            _require(offset + EVENT_HEADER.size <= len(raw), "partial inotify header")
            wd, mask, cookie, length = EVENT_HEADER.unpack_from(raw, offset)
            self.event_count += 1
            _require(self.event_count <= MAX_EVENTS, "directory event count exceeded bound")
            offset += EVENT_HEADER.size
            _require(offset + length <= len(raw), "partial inotify name")
            name = raw[offset : offset + length].rstrip(b"\0")
            offset += length
            result.append((wd, mask, cookie, name))
        return result

    @staticmethod
    def _version(info: os.stat_result) -> dict[str, int]:
        return {key: getattr(info, "st_" + key) for key in ("dev", "ino", "size", "mtime_ns", "ctime_ns")}

    def _capture_completed(self, marker: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic_ns()
        descriptor = marker["file"]
        _require(not marker["pathLost"], "close event no longer binds original marker path")
        _require(descriptor is not None, "close event lacks original marker descriptor")
        before = os.fstat(descriptor)
        _require(
            all(
                _identity(descriptor)[key] == marker["fileIdentity"][key]
                for key in ("dev", "ino", "mode", "uid", "gid")
            )
            and before.st_nlink in {0, 1},
            "completed marker identity changed",
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = self._read(descriptor, MAX_FILE + 1)
        _require(
            len(raw) == before.st_size <= MAX_FILE and self._version(before) == self._version(os.fstat(descriptor)),
            "partial or changing completed marker read",
        )
        completed = {
            "fileIdentity": marker["fileIdentity"],
            "version": self._version(before),
            "observedWriteEpoch": marker["writeEpoch"],
            "observedMonotonicNs": time.monotonic_ns(),
            "bytesRead": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "linkedAtCapture": before.st_nlink == 1,
            "readIntervalMonotonicNs": {"start": started, "end": time.monotonic_ns()},
            "limits": "close-observed stable read; future contents and writer identity unresolved",
        }
        if before.st_nlink == 0:
            self._uncertain("marker link continuity unresolved at completed read")
        return completed

    def _marker_event(
        self, marker: dict[str, Any], event: dict[str, Any], *, superseded: bool, capture: bool
    ) -> dict[str, Any] | None:
        mask = event["mask"]
        if mask & IN_CREATE:
            if marker["file"] is not None:
                marker["pathLost"] = True
                self._uncertain("marker recreated")
            else:
                try:
                    self._open_marker(marker)
                    event["fileIdentity"] = marker["fileIdentity"]
                    event["counters"] = self._counters()
                except OSError, ValueError:
                    self._uncertain("marker creation identity unresolved")
                    event["availability"] = "unresolved"
        if mask & IN_MODIFY:
            marker["closedWrite"] = False
            marker["writeEpoch"] += 1
            if marker["completedContents"]:
                self._uncertain("marker rewritten after completed observation")
        if mask & (IN_DELETE | IN_MOVED_TO):
            marker["pathLost"] = True
            marker["closedWrite"] = False
            self._uncertain("marker deleted or moved")
        if mask & IN_CLOSE_WRITE:
            marker["closedWrite"] = False
            try:
                _require(capture and not superseded, "close event not independently bracketed")
                return self._capture_completed(marker)
            except OSError, ValueError:
                marker["closedWrite"] = False
                self._uncertain("completed marker content unresolved")
                event["availability"] = "unresolved"
        return None

    def _pending_events(self) -> list[tuple[int, int, int, bytes]]:
        try:
            raw = self._read(self.inotify, MAX_BYTES)
        except BlockingIOError:
            return []
        return self._queued_events(raw)

    def _consume_events(
        self, queued: list[tuple[int, int, int, bytes]], *, capture: bool
    ) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
        proposed = []
        for index, (wd, mask, cookie, name) in enumerate(queued):
            _require(not mask & (IN_Q_OVERFLOW | IN_IGNORED), "inotify overflow or watch lost")
            _require(cookie == 0, "marker rename event unresolved")
            if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                self._uncertain("original marker parent removed or moved")
            if name != b"oom":
                continue
            _require(len(self.events) < MAX_EVENTS, "marker event count exceeded bound")
            matches = [marker for marker in self.markers if marker["wd"] == wd]
            _require(len(matches) == 1, "ambiguous marker watch event")
            marker = matches[0]
            event = {
                "candidate": self.markers.index(marker),
                "mask": mask,
                "observedMonotonicNs": time.monotonic_ns(),
                "originalPidAlive": self.pid_alive(),
            }
            self.events.append(event)
            superseded = any(
                later_wd == wd and later_name == name and later_mask & (IN_MODIFY | IN_CREATE | IN_MOVED_TO)
                for later_wd, later_mask, _cookie, later_name in queued[index + 1 :]
            )
            completed = self._marker_event(marker, event, superseded=superseded, capture=capture)
            if completed is not None:
                proposed.append((marker, event, completed))
        return proposed

    def _finish_capture(
        self,
        marker: dict[str, Any],
        event: dict[str, Any],
        completed: dict[str, Any],
        following: list[tuple[int, int, int, bytes]],
    ) -> None:
        changed = any(
            wd == marker["wd"]
            and (
                (name == b"oom" and mask & (IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_CLOSE_WRITE))
                or mask & (IN_DELETE_SELF | IN_MOVE_SELF)
            )
            for wd, mask, _cookie, name in following
        )
        try:
            _require(
                not changed
                and not marker["pathLost"]
                and marker["writeEpoch"] == completed["observedWriteEpoch"]
                and self._version(os.fstat(marker["file"])) == completed["version"],
                "proposed completion changed during post-read event bracket",
            )
        except OSError, ValueError:
            marker["closedWrite"] = False
            self._uncertain("completed marker changed during post-read bracket")
            event["availability"] = "unresolved"
            return
        marker["completedContents"].append(completed)
        marker["closedWrite"] = True
        event["completedContent"] = completed

    def drain(self) -> None:
        """Bracket proposed close captures with one non-recursive post-read drain."""
        proposed = self._consume_events(self._pending_events(), capture=True)
        if not proposed:
            return
        # Later events may have arrived after the first queue read but before
        # the content read. Process them without recursively capturing another
        # close; no proposed content is published until this bracket finishes.
        following = self._pending_events()
        self._consume_events(following, capture=False)
        for marker, event, completed in proposed:
            self._finish_capture(marker, event, completed, following)

    def sample(self, phase: str) -> dict[str, Any]:
        """Bracket a lifecycle boundary without treating any result as acceptance."""
        _require(time.monotonic() < self.deadline, "custody deadline expired")
        self.drain()
        alive = self.pid_alive()
        if phase == "before-stop-request":
            if not alive:
                self._uncertain("original PID exited before stop boundary")
            self.before_stop_observed = True
        elif not alive and not self.before_stop_observed:
            self._uncertain("original PID exited before stop boundary")
        observations = []
        for marker in self.markers:
            observation = {
                "parentIdentity": marker["identity"],
                "availability": "missing",
                "completedContents": marker["completedContents"],
            }
            try:
                linked = self._hold(_directory(marker["path"].parent))
                _require(_identity(linked) == marker["identity"], "original marker parent path replaced")
                self.fds.remove(linked)
                os.close(linked)
                if marker["file"] is not None:
                    descriptor = marker["file"]
                    before = os.fstat(descriptor)
                    _require(_identity(descriptor) == marker["fileIdentity"], "held marker identity changed")
                    _require(marker["closedWrite"], "marker write completion unobserved")
                    linked_file = os.stat("oom", dir_fd=marker["parent"], follow_symlinks=False)
                    _require(
                        (before.st_dev, before.st_ino) == (linked_file.st_dev, linked_file.st_ino), "marker replaced"
                    )
                    completed = marker["completedContents"][-1]
                    _require(
                        self._version(before) == completed["version"]
                        and marker["writeEpoch"] == completed["observedWriteEpoch"],
                        "held marker differs from completed version",
                    )
                    observation.update(
                        availability="held",
                        fileIdentity=marker["fileIdentity"],
                        bytesRead=completed["bytesRead"],
                        sha256=completed["sha256"],
                    )
                else:
                    try:
                        os.stat("oom", dir_fd=marker["parent"], follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        self._uncertain("marker present without observed creation")
                        observation["availability"] = "unresolved"
            except OSError, ValueError:
                self._uncertain("marker or parent custody recheck unresolved")
                observation["availability"] = "unresolved"
            observations.append(observation)
        try:
            counters = self._counters()
        except OSError, ValueError:
            self._uncertain("held counter read unresolved")
            counters = {"availability": "unresolved"}
        return {
            "schemaVersion": 1,
            "phase": phase,
            "attribution": "unresolved",
            "originalPid": self.pid,
            "pidfdIdentity": _identity(self.pidfd),
            "originalStarttime": self.starttime,
            "originalPidAlive": alive,
            "exitObservedMonotonicNs": self.exited_at,
            "beforeStopBoundaryObserved": self.before_stop_observed,
            "stopDelivery": "unresolved; observation precedes command dispatch and its placement guard",
            "originalConmonWatch": self.watch,
            "originalCgroupDirectoryIdentity": self.group_identity,
            "baselineCounters": self.baseline,
            "counters": counters,
            "markers": observations,
            "events": self.events,
            "uncertainty": self.reasons,
            "limits": "read-only custody; observation times only; no writer or source attribution",
        }

    def close(self) -> None:
        """Release only observer descriptors, including partially constructed state."""
        while self.fds:
            os.close(self.fds.pop())


def _reply(value: dict[str, Any]) -> None:
    raw = (json.dumps(value) + "\n").encode("utf-8")
    _require(len(raw) <= MAX_BYTES, "custody response exceeded bound")
    deadline = time.monotonic() + 0.5
    descriptor = sys.stdout.fileno()
    os.set_blocking(descriptor, False)
    while raw:
        _, ready, _ = select.select([], [descriptor], [], max(0, deadline - time.monotonic()))
        _require(bool(ready), "custody output deadline expired")
        raw = raw[os.write(descriptor, raw) :]


def _line(deadline: float) -> bytes:
    descriptor = sys.stdin.fileno()
    os.set_blocking(descriptor, False)
    raw = bytearray()
    while not raw.endswith(b"\n"):
        ready, _, _ = select.select([descriptor], [], [], max(0, deadline - time.monotonic()))
        _require(bool(ready), "custody input deadline expired")
        part = os.read(descriptor, MAX_BYTES + 1 - len(raw))
        if not part:
            _require(not raw, "partial custody input")
            return b""
        raw.extend(part)
        _require(len(raw) <= MAX_BYTES, "custody input exceeded bound")
    _require(raw.count(b"\n") == 1, "ambiguous custody input")
    return bytes(raw)


def main() -> None:
    """Serve a fixed bounded line protocol; EOF, expiry and errors release custody."""
    observer = None
    try:
        raw = _line(time.monotonic() + 2)
        _require(len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "invalid custody request")
        observer = MarkerCustody(json.loads(raw))
        _reply(observer.sample("armed"))
        requests = 0
        while requests < MAX_REQUESTS:
            ready, _, _ = select.select(
                [sys.stdin.fileno(), observer.inotify, observer.pidfd],
                [],
                [],
                max(0, observer.deadline - time.monotonic()),
            )
            _require(bool(ready), "custody deadline expired")
            observer.drain()
            if observer.pidfd in ready:
                observer.pid_alive()
                # A readable pidfd stays ready forever; only the directory and
                # control pipe need polling once the original exit is retained.
                ready, _, _ = select.select(
                    [sys.stdin.fileno(), observer.inotify], [], [], max(0, observer.deadline - time.monotonic())
                )
                _require(bool(ready), "custody deadline expired")
                observer.drain()
            if sys.stdin.fileno() not in ready:
                continue
            requests += 1
            raw = _line(observer.deadline)
            if not raw:
                return
            _require(len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "invalid custody phase request")
            request = json.loads(raw)
            phase = request["phase"]
            _require(
                phase in {"after-inner-memory", "before-shutdown", "before-stop-request", "after-exit"}, "unknown phase"
            )
            observer.observe_watch(request.get("lastSnapshotConmonWatch"))
            _reply(observer.sample(phase))
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError) as error:
        record = {
            "schemaVersion": 1,
            "attribution": "unresolved",
            "availability": "error",
            "reason": type(error).__name__,
        }
        if observer is not None:
            record["events"] = observer.events
            record["originalConmonWatch"] = observer.watch
            record["exitObservedMonotonicNs"] = observer.exited_at
            record["uncertainty"] = observer.reasons
        _reply(record)
    finally:
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    main()
