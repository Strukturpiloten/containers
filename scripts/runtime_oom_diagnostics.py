"""Bounded OOM evidence only; never classify an outer OOM flag as expected."""

from __future__ import annotations

import copy
import json
import re
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
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
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
    return {
        "starttime": fields[STARTTIME_INDEX],
        "cgroup": _text(proc / "cgroup"),
        "exe": str((proc / "exe").readlink()),
    }


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
    arguments = _text(Path(f"/proc/{conmon}/cmdline")).split("\0")
    _require(
        any(arguments[index] in {"-c", "--cid"} and value == exact for index, value in enumerate(arguments[1:])),
        "diagnostic monitor command did not bind the exact container ID",
    )
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
    result = {
        "hostCgroup2Mount": _mount(Path("/proc/self/mountinfo")),
        "guestCgroup2Mount": _mount(Path(f"/proc/{pid}/mountinfo")),
        "hostInit": before,
        "guestRoot": {"inode": root_inode, "hostPath": matches[0]},
        "outerCgroupPath": outer,
        "conmon": {
            **monitor,
            "pid": conmon,
            "actualVersion": None,
            "versionAttribution": "unresolved; no monitor executable is launched or version-attested",
            "watchedCgroupPath": None,
        },
        "guestChain": [_memory_group(guest_root, path) for path in guest_paths],
        "hostOuterChain": [_memory_group(host_root, path) for path in host_paths],
    }
    _require(before == _process(pid) and monitor == _process(conmon), "diagnostic process identity changed")
    _require(guest_root.stat().st_ino == root_inode, "diagnostic namespace root identity changed")
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

    def snapshot(self, phase: str, *, scope: str | None = None, scope_inode: int | None = None) -> None:
        """Record missing/invalid evidence as unresolved, never obstruct owned shutdown."""
        if scope is not None:
            self.scope, self.scope_inode = scope, scope_inode
        record: dict[str, Any] = {
            "name": "owned systemd OOM diagnostic",
            "phase": phase,
            "availability": "unavailable",
            "attribution": "unresolved",
            "limits": (
                "non-atomic snapshots; no host ancestors or observer through shutdown; monitor watched path unknown"
            ),
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
            request = {"container": self.container, "state": state, "scope": self.scope, "deadline": deadline}
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
        except Exception as error:  # noqa: BLE001 — evidence-only boundary must not obstruct native shutdown.
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
    _require(len(sys.argv) == HOST_ARGUMENTS and sys.argv[1] == "--snapshot", "diagnostic invocation was invalid")
    _require(len(sys.argv[2]) <= MAX_BYTES, "diagnostic request exceeded its byte bound")
    payload = json.dumps(_collect(json.loads(sys.argv[2])))
    _require(len(payload) <= MAX_BYTES, "diagnostic response exceeded its byte bound")
    sys.stdout.write(payload + "\n")
