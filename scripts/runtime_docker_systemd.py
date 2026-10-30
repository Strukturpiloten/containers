"""Fail-closed guest systemd contract for dedicated Docker conformance images."""

# Fixed guest paths/argv and explicit failures are intentional evidence.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import shutil
import signal as signals
import tarfile
import time
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime
from http import HTTPStatus
from itertools import pairwise
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from scripts.runtime_docker_systemd_guard import PLACEMENT_GUARD, USER_MANAGER, guarded_command  # noqa: F401 - preserve public re-exports.
from scripts.runtime_errors import ProbeError
from scripts.runtime_oom_diagnostics import DOCKER_CHECKS, DOCKER_EXIT_MAX, OomDiagnostics
from scripts.runtime_resource_budgets import verify_outer_container_limits

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import BinaryIO

    from scripts.runtime_resource_budgets import IsolatedStoreDiskBudget
    from scripts.runtime_tests import RuntimeContext

MEMORY_BYTES = 32 * 1024**2
INNER_PIDS = 16
MAX_VERSION_REPORT = 4096
STARTUP_SECONDS = 45
MAX_PLACEMENT_SAMPLES = 45
MAX_PLACEMENT_READBACK = 4000
PLACEMENT_SAMPLE_SECONDS = 2
PLACEMENT_POLL_SECONDS = 1
SYSTEMD_OPTIONS = (
    "--runtime",
    "crun",
    "--systemd=always",
    "--annotation",
    "run.oci.systemd.subgroup=container",
)
DOCKER_SYSTEMD_OPTIONS = (
    "--tmpfs",
    "/run:rw,nosuid,nodev,size=64m,mode=755",
    "--tmpfs",
    "/run/lock:rw,nosuid,nodev,size=16m,mode=755",
)
MAX_CGROUP_DEPTH = 32
MAX_CGROUP_PATH = 4096
MAX_HIERARCHY_READBACK = 256 * 1024
HIERARCHY_ROW_FIELDS = 6
MAX_SCOPE_PROCESSES = 64
MAX_MEMORY_READBACK = 64 * 1024
MAX_ALLOCATOR_TELEMETRY = 8192
ASSOCIATION_ROW_FIELDS = 10
UID_FIELD_COUNT = 4
EVENT_ROW_FIELDS = 2
MIN_PID_ANCESTRY = 2
UID_MAP_FIELDS = 3
CGROUP2_MAGIC = "63677270"
MEMORY_VALUE_FIELDS = frozenset(
    {"memory.max", "memory.current", "memory.swap.max", "memory.swap.current", "memory.events"}
)
RESOURCE_START_FILE = "/tmp/resource-start"  # noqa: S108 — inside the exact owned disposable guest only.
# Read-only snapshots, bounded walks and stable identities; never create/migrate cgroups.
HIERARCHY_READBACK_COMMAND = r"""
kind=$1; mode=$2; unit=$3
case "$kind:$mode" in service:rootful|service:rootless|scope:rootful|scope:rootless) ;; *) exit 1;; esac
manager() {
    if [ "$mode" = rootless ]; then
        runuser -u dockertest -- env HOME=/home/docker XDG_RUNTIME_DIR=/run/user/1000 \
          DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user "$@"
    else systemctl "$@"; fi
}
safe_group() {
    test "${#1}" -le 4096
    printf '%s\n' "$1" | LC_ALL=C grep -Eq '^(/[A-Za-z0-9_.@:-]+)+$'
    case "$1/" in */./*|*/../*) exit 1;; esac
}
walk() {
    group=$1; depth=0
    while :; do
        test "$depth" -le 32; depth=$((depth+1))
        case " $seen " in *" $group "*) ;; *)
            directory=/sys/fs/cgroup$group
            identity=$(stat -c '%i:%u' "$directory")
            group_type=$(cat "$directory/cgroup.type")
            available=$(cat "$directory/cgroup.controllers")
            subtree=$(cat "$directory/cgroup.subtree_control")
            processes=$(tr '\n' ' ' < "$directory/cgroup.procs")
            printf 'group-%s=%s|%s|%s|%s|%s|%s\n' "$phase" "$group" \
              "$identity" "$group_type" "$available" "$subtree" "$processes"
            seen="$seen $group";;
        esac
        test "$group" != / || break
        group=${group%/*}; group=${group:-/}
    done
}
process() {
    role=$1; pid=$2
    case "$pid" in ''|*[!0-9]*) exit 1;; esac
    test "$pid" -gt 1
    leaf=$(cut -d: -f3 /proc/$pid/cgroup); safe_group "$leaf"
    printf 'process-%s=%s|%s|%s|%s|%s|%s\n' "$phase" "$role" "$pid" \
      "$(awk '/^Uid:/ {print $2,$3,$4,$5}' /proc/$pid/status)" "$leaf" \
      "$(readlink /proc/$pid/exe)" "$(cat /proc/$pid/stat)"
    walk "$leaf"
}
for phase in before after; do
    seen=
    if [ "$kind" = service ]; then
        properties=$(manager show "$unit" --property ControlGroup --property MainPID \
          --property Delegate --property ActiveState)
    else
        properties=$(manager show "$unit" --property ControlGroup --property Delegate --property ActiveState)
    fi
    printf '%s\n' "$properties" | while IFS= read -r property; do
        printf 'unit-%s=%s\n' "$phase" "$property"
    done
    target=$(printf '%s\n' "$properties" | sed -n 's/^ControlGroup=//p'); safe_group "$target"
    walk "$target"
    if [ "$mode" = rootless ]; then
        properties=$(systemctl show user@1000.service --property ControlGroup --property MainPID \
          --property Delegate --property ActiveState)
        printf '%s\n' "$properties" | while IFS= read -r property; do
            printf 'manager-%s=%s\n' "$phase" "$property"
        done
        delegated=$(printf '%s\n' "$properties" | sed -n 's/^ControlGroup=//p'); safe_group "$delegated"
        walk "$delegated"
        process manager "$(printf '%s\n' "$properties" | sed -n 's/^MainPID=//p')"
    fi
    if [ "$kind" = service ]; then
        process main "$(manager show "$unit" --property MainPID --value)"
        daemon=$(pgrep -x dockerd); process daemon "$daemon"
    else
        matches=$(find /sys/fs/cgroup -xdev -maxdepth 32 -type d -name "$unit")
        test "$matches" = "/sys/fs/cgroup$target"
        printf 'scope-%s=%s\n' "$phase" "$matches"
        count=0
        for pid in $(cat "/sys/fs/cgroup$target/cgroup.procs"); do
            count=$((count+1)); test "$count" -le 64
            process "probe-$pid" "$pid"
        done
        test "$count" -gt 0
    fi
done
"""


MEMORY_ASSOCIATION_COMMAND = r"""
scope=$1; allocator=$2; owned=$3
LC_ALL=C; export LC_ALL
bounded() {
    data=$(head -c "$(($2+1))" "$1" && printf x) || return 1
    data=${data%x}
    test "${#data}" -le "$2" || return 1
    printf '%s' "$data"
}
identity() {
    role=$1; pid=$2
    case "$pid" in ''|*[!0-9]*) exit 1;; esac
    test "$pid" -gt 1
    status=$(bounded "/proc/$pid/status" 4096)
    uids=$(printf '%s\n' "$status" | sed -n 's/^Uid:[[:space:]]*//p')
    nspid=$(printf '%s\n' "$status" | sed -n 's/^NSpid:[[:space:]]*//p')
    test "${#uids}" -le 128; test "${#nspid}" -le 512
    group=$(bounded "/proc/$pid/cgroup" 4096)
    stat_value=$(bounded "/proc/$pid/stat" 1024)
    exe=$(readlink "/proc/$pid/exe"); test "${#exe}" -le 1024
    pidns=$(readlink "/proc/$pid/ns/pid"); test "${#pidns}" -le 128
    cgroupns=$(readlink "/proc/$pid/ns/cgroup"); test "${#cgroupns}" -le 128
    userns=$(readlink "/proc/$pid/ns/user"); test "${#userns}" -le 128
    uidmap=$(bounded "/proc/$pid/uid_map" 4096)
    uidmap=$(printf '%s' "$uidmap" | tr '\n' ';')
    printf 'association-%s-%s=%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "$phase" "$role" "$pid" "$uids" "$group" "$exe" "$stat_value" "$nspid" "$pidns" "$cgroupns" "$userns" "$uidmap"
}
for phase in before after; do
    identity allocator "$allocator"
    daemon=$(pgrep -x dockerd); identity daemon "$daemon"
    ancestry=$(docker-resource-probe --pid-ancestry "$allocator" "$daemon")
    test "${#ancestry}" -le 1024
    printf 'association-%s-ancestry=%s\n' "$phase" "$ancestry"
    docker_pid=$(docker inspect --format '{{.State.Pid}}' "$owned")
    test "${#docker_pid}" -le 32
    printf 'association-%s-docker-pid=%s\n' "$phase" "$docker_pid"
    printf 'association-%s-scope-inode=%s\n' "$phase" "$(stat -c %i "/sys/fs/cgroup$scope")"
    printf 'association-%s-mount-inode=%s\n' "$phase" "$(stat -c %i "/proc/$allocator/root/sys/fs/cgroup")"
    printf 'association-%s-mount-type=%s\n' "$phase" "$(stat -f -c %t "/proc/$allocator/root/sys/fs/cgroup")"
    if [ "$phase" = before ]; then
        for file in memory.max memory.current memory.swap.max memory.swap.current memory.events; do
            value=$(bounded "/sys/fs/cgroup$scope/$file" 1024)
            if [ "$file" = memory.events ]; then value=$(printf '%s' "$value" | tr '\n' ';'); fi
            printf 'scope-%s=%s\n' "$file" "$value"
        done
    fi
done
"""


# Passive observation only: no daemon requests or cgroup/service changes before admission.
PLACEMENT_READBACK_COMMAND = r"""
LC_ALL=C; export LC_ALL
bounded() {
    value=$(head -c 4001 "$1" && printf x) || exit 80
    value=${value%x}
    test "${#value}" -le 4000 || { printf 'placement field exceeded bound\n' >&2; exit 81; }
    printf '%s' "$value"
}
init=$(bounded /proc/1/cgroup)
current=$(bounded /proc/self/cgroup)
case "$current" in 0::/*) ;; *) printf 'invalid placement cgroup format\n' >&2; exit 82;; esac
current_path=${current#0::}
printf '%s\n' "$current_path" | grep -Eq '^/([A-Za-z0-9_.@:-]+(/[A-Za-z0-9_.@:-]+)*)?$'
case "$current_path/" in */./*|*/../*) exit 83;; esac
owner=$(stat -c '%u' /sys/fs/cgroup)
procs=$(bounded /sys/fs/cgroup/cgroup.procs)
procs=$(printf '%s' "$procs" | tr '\n' ' ')
available=$(bounded /sys/fs/cgroup/cgroup.controllers)
subtree=$(bounded /sys/fs/cgroup/cgroup.subtree_control)
leaf=$(bounded "/sys/fs/cgroup$current_path/cgroup.subtree_control")
report=$(printf 'init=%s\ncurrent=%s\nroot-owner=%s\nroot-procs=%s\n' "$init" "$current" "$owner" "$procs"
    printf 'root-controllers=%s\nroot-subtree=%s\nleaf-subtree=%s' "$available" "$subtree" "$leaf")
test "${#report}" -le 4000 || { printf 'placement report exceeded bound\n' >&2; exit 84; }
printf '%s' "$report"
"""

BOOT_BOUNDARY_UNITS = frozenset(
    {
        "systemd-sysctl.service",
        "systemd-timesyncd.service",
        "systemd-journald-audit.socket",
        "systemd-tmpfiles-setup.service",
        "systemd-tmpfiles-clean.service",
    }
)
JOURNAL_SOCKETS = frozenset({"systemd-journald.socket", "systemd-journald-dev-log.socket"})
JOURNAL_ACTIVE_SUBSTATES = frozenset({"listening", "running"})
NETLINK_AUDIT_PROTOCOL = 9
NETLINK_HEADER = ("sk", "Eth", "Pid", "Groups", "Rmem", "Wmem", "Dump", "Locks", "Drops", "Inode")
UNIX_HEADER = ("Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path")
JOURNAL_ENDPOINTS = {
    "/run/systemd/journal/socket": 2,
    "/run/systemd/journal/dev-log": 2,
    "/run/systemd/journal/stdout": 1,
}
UNIX_STREAM_TYPE = 1
UNIX_LISTEN_FLAG = 0x10000
UNIX_DATAGRAM_STATES = frozenset({1, 3})
PROC_STAT_STARTTIME_INDEX = 18
JOURNAL_SINGLE_FIELDS = frozenset(
    {
        "triggered-by",
        "drop-in",
        "unit-capabilities",
        "journal-pid",
        "journal-netns",
        "init-netns",
        "CapEff",
        "CapPrm",
        "CapBnd",
        "fd-count-before",
        "fd-count-after",
        "journal-pid-after",
        "journal-stat-before",
        "journal-stat-after",
        "journal-exe-before",
        "journal-exe-after",
        "journal-netns-after",
        "init-netns-after",
        "systemd-version",
    }
)
JOURNAL_BOUNDARY_COMMAND = (
    "for unit in " + " ".join(sorted(BOOT_BOUNDARY_UNITS)) + "; do "
    'enabled=$(systemctl is-enabled "$unit" || :); '
    'active=$(systemctl show "$unit" --property ActiveState --value); '
    'printf "masked-unit=%s:%s:%s\\n" "$unit" "$enabled" "$active"; '
    'test "$enabled" = masked; test "$active" = inactive; done; '
    "for unit in " + " ".join(sorted(JOURNAL_SOCKETS)) + "; do "
    'active=$(systemctl show "$unit" --property ActiveState --value); '
    'sub=$(systemctl show "$unit" --property SubState --value); '
    'printf "normal-socket=%s:%s:%s\\n" "$unit" "$active" "$sub"; '
    'test "$active" = active; case "$sub" in listening|running) ;; *) exit 92;; esac; done; '
    "triggered=$(systemctl show systemd-journald.service --property TriggeredBy --value); "
    'printf "triggered-by=%s\\n" "$triggered"; '
    "dropins=$(systemctl show systemd-journald.service --property DropInPaths --value); "
    'printf %s "$dropins" | grep -qwF /etc/systemd/system/systemd-journald.service.d/boundary.conf; '
    'test "$(cat /etc/systemd/system/systemd-journald.service.d/boundary.conf)" = '
    '"$(cat /usr/share/strukturpiloten/docker/journal-boundary)"; '
    "grep -qFx 'CapabilityBoundingSet=~CAP_AUDIT_CONTROL' "
    "/etc/systemd/system/systemd-journald.service.d/boundary.conf; "
    'printf "drop-in=verified\\n"; '
    "caps=$(systemctl show systemd-journald.service --property CapabilityBoundingSet --value); "
    'test -n "$caps"; ! printf %s "$caps" | grep -qi audit_control; '
    'printf "unit-capabilities=%s\\n" "$caps"; '
    "pid=$(systemctl show systemd-journald.service --property MainPID --value); "
    'case "$pid" in ""|*[!0-9]*) exit 91;; esac; test "$pid" -gt 1; '
    'printf "journal-pid=%s\\n" "$pid"; '
    'printf "journal-stat-before=%s\\n" "$(cat /proc/$pid/stat)"; '
    'printf "journal-exe-before=%s\\n" "$(readlink /proc/$pid/exe)"; '
    'printf "journal-netns=%s\\n" "$(readlink /proc/$pid/ns/net)"; '
    'printf "init-netns=%s\\n" "$(readlink /proc/1/ns/net)"; '
    'journal_fds() { phase="$1"; fds=0; for fd in /proc/$pid/fd/*; do '
    'test -L "$fd"; target=$(readlink "$fd"); fds=$((fds+1)); '
    'printf "fd-%s=%s:%s\\n" "$phase" "${fd##*/}" "$target"; done; '
    'test "$fds" -gt 0; printf "fd-count-%s=%s\\n" "$phase" "$fds"; }; '
    "journal_fds before; "
    'awk \'$1 == "CapEff:" || $1 == "CapPrm:" || $1 == "CapBnd:" '
    '{name=$1; sub(/:$/, "", name); print name "=" $2}\' /proc/$pid/status; '
    'printf "netlink-table-begin\\n"; cat /proc/$pid/net/netlink; printf "netlink-table-end\\n"; '
    'printf "unix-table-begin\\n"; cat /proc/$pid/net/unix; printf "unix-table-end\\n"; '
    "journal_fds after; "
    'printf "journal-stat-after=%s\\n" "$(cat /proc/$pid/stat)"; '
    'printf "journal-exe-after=%s\\n" "$(readlink /proc/$pid/exe)"; '
    'printf "journal-netns-after=%s\\n" "$(readlink /proc/$pid/ns/net)"; '
    'printf "init-netns-after=%s\\n" "$(readlink /proc/1/ns/net)"; '
    'printf "journal-pid-after=%s\\n" "$(systemctl show systemd-journald.service --property MainPID --value)"; '
    "version=$(dpkg-query --show --showformat='${Version}' systemd); "
    'grep -qFx "systemd=$version" /usr/share/strukturpiloten/docker/conformance-packages; '
    'printf "systemd-version=%s\\n" "$version"'
)


def startup_deadline(ctx: RuntimeContext) -> float:
    """Share the original startup allowance, including an explicitly smaller override."""
    if not math.isfinite(ctx.timeout) or ctx.timeout <= 0:
        raise ProbeError("systemd startup timeout must be finite and positive")
    return time.monotonic() + min(STARTUP_SECONDS, ctx.timeout)


def startup_remaining(ctx: RuntimeContext, deadline: float, *, maximum: float | None = None) -> float:
    """Return a positive command timeout without renewing the shared deadline."""
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0 or not math.isfinite(ctx.timeout) or ctx.timeout <= 0:
        raise ProbeError("systemd startup deadline expired")
    if maximum is not None and (not math.isfinite(maximum) or maximum <= 0):
        raise ProbeError("systemd startup command cap must be finite and positive")
    return min(remaining, ctx.timeout, maximum if maximum is not None else remaining)


def _placement_fields(output: str) -> dict[str, str]:
    if len(output.encode("utf-8")) > MAX_PLACEMENT_READBACK:
        raise ProbeError("passive placement readback exceeded its byte bound")
    fields = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ProbeError("passive placement readback was malformed or duplicated")
        fields[key] = value
    if set(fields) != {
        "init",
        "current",
        "root-owner",
        "root-procs",
        "root-controllers",
        "root-subtree",
        "leaf-subtree",
    }:
        raise ProbeError("passive placement readback fields were missing or unknown")
    return fields


def _placement_controllers(value: str) -> set[str]:
    controllers = value.split()
    if len(controllers) != len(set(controllers)) or any(
        not re.fullmatch(r"[a-z][a-z0-9_]*", item) for item in controllers
    ):
        raise ProbeError("passive placement controller readback was malformed")
    return set(controllers)


def _placement_observation(output: str) -> dict[str, Any]:
    fields = _placement_fields(output)
    paths = []
    for key in ("init", "current"):
        if not fields[key].startswith("0::"):
            raise ProbeError("passive placement process cgroup was malformed")
        paths.append(_cgroup_path(fields[key].removeprefix("0::"), allow_root=True))
    init, current = paths
    available = _placement_controllers(fields["root-controllers"])
    subtree = _placement_controllers(fields["root-subtree"])
    leaf = _placement_controllers(fields["leaf-subtree"])
    required = {"cpu", "memory", "pids"}
    procs = fields["root-procs"].split()
    if fields["root-owner"] != "0" or not required <= available or not subtree <= available or not leaf <= available:
        raise ProbeError("passive placement root ownership or controller availability was invalid")
    if any(not re.fullmatch(r"[1-9][0-9]{0,9}", pid) for pid in procs) or len(procs) != len(set(procs)):
        raise ProbeError("passive placement root membership was malformed")
    if procs and "memory" in subtree:
        raise ProbeError("passive placement populated root distributed memory")
    if current == "/" and leaf != subtree:
        raise ProbeError("passive placement root and leaf readbacks disagreed for the same cgroup")
    if init == "/" and current == "/":
        state, reason = "EARLY_ROOT", "PID 1 and passive observer still occupy the namespace root"
    elif init != "/" and current == "/":
        state, reason = "EXEC_ROOT", "passive observer has not yet joined the nonroot PID 1 leaf"
    else:
        state, reason = _placement_nonroot_state(init, current, procs, subtree, leaf)
    return {
        "state": state,
        "reason": reason,
        "init": init,
        "current": current,
        "rootOwner": fields["root-owner"],
        "rootProcesses": procs,
        "rootControllers": sorted(available),
        "rootSubtree": sorted(subtree),
        "leafSubtree": sorted(leaf),
    }


def _placement_nonroot_state(
    init: str, current: str, procs: list[str], subtree: set[str], leaf: set[str]
) -> tuple[str, str]:
    if init == "/" or current != init:
        raise ProbeError("passive placement observer occupied an unexpected nonroot cgroup")
    if procs or leaf:
        raise ProbeError("passive placement root was populated or PID 1 leaf distributed controllers")
    if not {"cpu", "memory", "pids"} <= subtree:
        return "PENDING_DELEGATION", "namespace root has not yet enabled all required subtree controllers"
    return "READY", "exact nonroot PID 1 leaf, empty root, and required delegation are ready"


def wait_for_placement(ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, deadline: float) -> None:
    """Observe bounded boot states; never run daemon work or admit through a failed read."""
    first = last = None
    samples = 0
    try:
        for _sample in range(MAX_PLACEMENT_SAMPLES):
            budget.checkpoint()
            timeout = startup_remaining(ctx, deadline, maximum=PLACEMENT_SAMPLE_SECONDS)
            output = ctx.podman(
                "observe passive systemd startup placement",
                "exec",
                container,
                "sh",
                "-euc",
                PLACEMENT_READBACK_COMMAND,
                timeout=timeout,
            )
            samples += 1
            budget.checkpoint()
            startup_remaining(ctx, deadline)
            last = _placement_observation(output)
            if first is None:
                first = last
            if last["state"] == "READY":
                ctx.checks.append(
                    {
                        "name": "systemd passive placement readiness",
                        "status": "passed",
                        "samples": samples,
                        "first": first,
                        "last": last,
                    }
                )
                return
            time.sleep(min(PLACEMENT_POLL_SECONDS, startup_remaining(ctx, deadline)))
    except ProbeError as error:
        ctx.checks.append(
            {
                "name": "systemd passive placement readiness",
                "status": "failed",
                "samples": samples,
                "first": first if first is not None else {"state": "FATAL", "reason": str(error)[:1000]},
                "last": {"state": "FATAL", "reason": str(error)[:1000], "observation": last},
                "error": str(error)[:1000],
            }
        )
        raise
    error = "systemd placement exceeded its bounded startup sample count"
    ctx.checks.append(
        {
            "name": "systemd passive placement readiness",
            "status": "failed",
            "samples": samples,
            "first": first,
            "last": {"state": "FATAL", "reason": error, "observation": last},
        }
    )
    raise ProbeError(error)


def _netlink_audit_inodes(lines: list[str]) -> set[int]:
    table = [line.split() for line in lines]
    if not table or table[0] != list(NETLINK_HEADER):
        raise ProbeError("journald netlink header is missing or malformed")
    audit_inodes: set[int] = set()
    for row in table[1:]:
        if (
            len(row) != len(NETLINK_HEADER)
            or not re.fullmatch(r"[0-9a-fA-F]+", row[0])
            or not re.fullmatch(r"[0-9a-fA-F]+", row[3])
            or any(not re.fullmatch(r"[0-9]+", row[index]) for index in (1, 2, 4, 5, 6, 7, 8, 9))
        ):
            raise ProbeError("journald netlink row is malformed")
        if int(row[1]) == NETLINK_AUDIT_PROTOCOL:
            audit_inodes.add(int(row[9]))
    return audit_inodes


def _readback_table(lines: list[str], name: str) -> tuple[list[str], list[str]]:
    begin, finish = f"{name}-table-begin", f"{name}-table-end"
    if lines.count(begin) != 1 or lines.count(finish) != 1:
        message = f"journald {name} readback is missing or duplicated"
        raise ProbeError(message)
    start, end = lines.index(begin), lines.index(finish)
    if end <= start + 1:
        message = f"journald {name} table is missing"
        raise ProbeError(message)
    return lines[start + 1 : end], [*lines[:start], *lines[end + 1 :]]


def _unix_journal_inodes(lines: list[str]) -> dict[str, int]:
    if not lines or lines[0].split() != list(UNIX_HEADER):
        raise ProbeError("journald UNIX socket header is missing or malformed")
    endpoints: dict[str, int] = {}
    seen_inodes: set[int] = set()
    for line in lines[1:]:
        row = line.split(maxsplit=7)
        if (
            len(row) not in (len(UNIX_HEADER) - 1, len(UNIX_HEADER))
            or not re.fullmatch(r"[0-9a-fA-F]+:", row[0])
            or any(not re.fullmatch(r"[0-9a-fA-F]+", row[index]) for index in (1, 2, 3, 4, 5))
            or not re.fullmatch(r"[0-9]+", row[6])
            or int(row[2], 16) != 0
        ):
            raise ProbeError("journald UNIX socket row is malformed")
        inode = int(row[6])
        if inode and inode in seen_inodes:
            raise ProbeError("journald UNIX socket inode is duplicated")
        seen_inodes.add(inode)
        if len(row) == len(UNIX_HEADER) and row[7] in JOURNAL_ENDPOINTS:
            _match_journal_endpoint(row, endpoints)
    if set(endpoints) != set(JOURNAL_ENDPOINTS):
        raise ProbeError("all three normal journald UNIX endpoints must be present")
    return endpoints


def _match_journal_endpoint(row: list[str], endpoints: dict[str, int]) -> None:
    path, inode, socket_type, flags = row[7], int(row[6]), int(row[4], 16), int(row[3], 16)
    if socket_type != JOURNAL_ENDPOINTS[path] or inode <= 0:
        raise ProbeError("normal journald UNIX endpoint type or inode is invalid")
    # Accepted stdout connections share the pathname but are not the listener.
    if socket_type == UNIX_STREAM_TYPE and flags == 0:
        return
    expected_flags = UNIX_LISTEN_FLAG if socket_type == UNIX_STREAM_TYPE else 0
    allowed_states = {1} if socket_type == UNIX_STREAM_TYPE else UNIX_DATAGRAM_STATES
    if flags != expected_flags or int(row[5], 16) not in allowed_states or path in endpoints:
        raise ProbeError("normal journald UNIX endpoint flags, state or uniqueness is invalid")
    endpoints[path] = inode


def _journal_readback_fields(output: str) -> tuple[dict[str, list[str]], set[int], dict[str, int]]:
    netlink, lines = _readback_table(output.splitlines(), "netlink")
    unix, lines = _readback_table(lines, "unix")
    audit_inodes = _netlink_audit_inodes(netlink)
    endpoints = _unix_journal_inodes(unix)
    fields: dict[str, list[str]] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator:
            raise ProbeError("journald process readback is malformed")
        fields.setdefault(key, []).append(value)
    repeated = {"masked-unit", "normal-socket", "fd-before", "fd-after"}
    if set(fields) != repeated | JOURNAL_SINGLE_FIELDS or any(len(fields[key]) != 1 for key in JOURNAL_SINGLE_FIELDS):
        raise ProbeError("journald mandatory process readback is missing, unknown or duplicated")
    return fields, audit_inodes, endpoints


def _verify_journal_unit_fields(fields: dict[str, list[str]], values: dict[str, str]) -> list[str]:
    if set(fields["masked-unit"]) != {f"{unit}:masked:inactive" for unit in BOOT_BOUNDARY_UNITS} or len(
        fields["masked-unit"]
    ) != len(BOOT_BOUNDARY_UNITS):
        raise ProbeError("guest boot helpers must be masked and inactive")
    normal = set(fields["normal-socket"])
    allowed = {f"{unit}:active:{substate}" for unit in JOURNAL_SOCKETS for substate in JOURNAL_ACTIVE_SUBSTATES}
    if (
        not normal.issubset(allowed)
        or {value.partition(":")[0] for value in normal} != JOURNAL_SOCKETS
        or len(fields["normal-socket"]) != len(JOURNAL_SOCKETS)
    ):
        raise ProbeError("both normal journald socket units must be active with listening or running substates")
    triggered = values["triggered-by"].split()
    if (
        not JOURNAL_SOCKETS.issubset(triggered)
        or not set(triggered).issubset(JOURNAL_SOCKETS | {"systemd-journald-audit.socket"})
        or len(triggered) != len(set(triggered))
    ):
        raise ProbeError("journald socket dependencies are missing or unsupported")
    if (
        values["drop-in"] != "verified"
        or not re.fullmatch(r"cap_[a-z0-9_]+(?: cap_[a-z0-9_]+)*", values["unit-capabilities"])
        or "audit_control" in values["unit-capabilities"].lower()
    ):
        raise ProbeError("journald drop-in or capability readback is invalid")
    return triggered


def _verify_journal_process_fields(
    fields: dict[str, list[str]], values: dict[str, str], audit_inodes: set[int], endpoints: dict[str, int]
) -> tuple[set[int], dict[int, str], int]:
    starttime = _verify_journal_identity(values)
    descriptors = _journal_descriptors(fields, values)
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]*", values["systemd-version"]):
        raise ProbeError("journald systemd package version is malformed")
    for name in ("CapEff", "CapPrm", "CapBnd"):
        if not re.fullmatch(r"[0-9a-fA-F]{16}", values[name]) or int(values[name], 16) & (1 << 30):
            raise ProbeError("journald must not retain CAP_AUDIT_CONTROL in effective, permitted or bounding sets")
    socket_inodes = _journal_socket_inodes([value for value in descriptors.values() if value.startswith("socket:")])
    if socket_inodes & audit_inodes:
        raise ProbeError("journald owns a NETLINK_AUDIT socket descriptor")
    if not set(endpoints.values()).issubset(socket_inodes):
        raise ProbeError("journald must own the FDs of all three normal UNIX endpoints")
    return socket_inodes, descriptors, starttime


def _verify_journal_identity(values: dict[str, str]) -> int:
    if (
        not re.fullmatch(r"net:\[[1-9][0-9]*\]", values["journal-netns"])
        or len({values[key] for key in ("journal-netns", "init-netns", "journal-netns-after", "init-netns-after")}) != 1
    ):
        raise ProbeError("journald network namespace identity is missing, changed or invalid")
    if (
        not re.fullmatch(r"[0-9]+", values["journal-pid"])
        or int(values["journal-pid"]) <= 1
        or values["journal-pid"] != values["journal-pid-after"]
        or values["journal-exe-before"] not in {"/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald"}
        or values["journal-exe-before"] != values["journal-exe-after"]
    ):
        raise ProbeError("journald main PID or executable identity is missing, changed or invalid")
    before = _journal_starttime(values["journal-stat-before"], values["journal-pid"])
    after = _journal_starttime(values["journal-stat-after"], values["journal-pid"])
    if before != after:
        raise ProbeError("journald process start time changed during readback")
    return before


def _journal_starttime(stat: str, pid: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*) \(.+\) [RSDZTtWXPI] ((?:-?[0-9]+ )*-?[0-9]+)", stat)
    if not match or match[1] != pid:
        raise ProbeError("journald process stat identity is malformed")
    numbers = match[2].split()
    if len(numbers) <= PROC_STAT_STARTTIME_INDEX or int(numbers[PROC_STAT_STARTTIME_INDEX]) <= 0:
        raise ProbeError("journald process stat start time is missing or malformed")
    return int(numbers[PROC_STAT_STARTTIME_INDEX])


def _journal_descriptors(fields: dict[str, list[str]], values: dict[str, str]) -> dict[int, str]:
    snapshots: list[dict[int, str]] = []
    for phase in ("before", "after"):
        count = values[f"fd-count-{phase}"]
        if not re.fullmatch(r"[0-9]+", count) or int(count) <= 0:
            raise ProbeError("journald descriptor count is missing or malformed")
        descriptors: dict[int, str] = {}
        for value in fields[f"fd-{phase}"]:
            match = re.fullmatch(r"([0-9]+):(.+)", value)
            if not match or int(match[1]) in descriptors:
                raise ProbeError("journald descriptor snapshot is malformed or duplicated")
            descriptors[int(match[1])] = match[2]
        if len(descriptors) != int(count):
            raise ProbeError("journald descriptor snapshot is incomplete")
        snapshots.append(descriptors)
    if snapshots[0] != snapshots[1]:
        raise ProbeError("journald descriptor snapshot changed during readback")
    return snapshots[0]


def _journal_socket_inodes(descriptors: list[str]) -> set[int]:
    socket_inodes: set[int] = set()
    for value in descriptors:
        match = re.fullmatch(r"socket:\[([0-9]+)\]", value)
        if not match or int(match[1]) <= 0:
            raise ProbeError("journald socket descriptor readback is malformed")
        socket_inodes.add(int(match[1]))
    return socket_inodes


def _journal_boundary_evidence(output: str) -> dict[str, Any]:
    """Parse mandatory process evidence; masked audit dependencies are not open FDs."""
    fields, audit_inodes, endpoints = _journal_readback_fields(output)
    values = {key: fields[key][0] for key in JOURNAL_SINGLE_FIELDS}
    triggered = _verify_journal_unit_fields(fields, values)
    socket_inodes, descriptors, starttime = _verify_journal_process_fields(fields, values, audit_inodes, endpoints)
    return {
        "name": "journald effective process audit boundary",
        "status": "passed",
        "systemdVersion": values["systemd-version"],
        "journalPid": int(values["journal-pid"]),
        "journalStartTime": starttime,
        "journalExecutable": values["journal-exe-before"],
        "fileDescriptors": descriptors,
        "normalUnixEndpoints": endpoints,
        "normalSocketStates": {value.partition(":")[0]: value.rpartition(":")[2] for value in fields["normal-socket"]},
        "networkNamespace": values["journal-netns"],
        "capabilities": {name: values[name] for name in ("CapEff", "CapPrm", "CapBnd")},
        "socketInodes": sorted(socket_inodes),
        "auditInodes": sorted(audit_inodes),
        "triggeredBy": triggered,
    }


def systemd_options(ctx: RuntimeContext) -> tuple[str, ...]:
    """Select only the declared outer backend's guest launch prerequisites."""
    if getattr(ctx, "outer_engine", "podman") == "docker":
        if ctx.name != "docker-29-conformance-rootless" or vars(ctx).get("declared_launcher") != "systemd":
            raise ProbeError("Docker systemd options require the reviewed declared fixture")
        return DOCKER_SYSTEMD_OPTIONS
    return SYSTEMD_OPTIONS


def _verify_docker_runtime(ctx: RuntimeContext) -> None:
    raw = ctx.podman("read selected outer Docker systemd prerequisites", "info", "--format", "{{json .}}")
    info = json.loads(raw)
    runtime = info.get("Runtimes", {}).get("runc", {})
    security = info.get("SecurityOptions")
    executable = shutil.which("runc")
    if (
        info.get("CgroupDriver") != "systemd"
        or info.get("CgroupVersion") != "2"
        or info.get("DefaultRuntime") != "runc"
        or not isinstance(security, list)
        or any("rootless" in str(value) for value in security)
        or not executable
        or not executable.startswith("/")
        or runtime.get("path") not in {"runc", executable}
        or info.get("DockerRootDir") != str(ctx.directory / "root")
    ):
        raise ProbeError("private Docker systemd guest requires rootful cgroup-v2/systemd and the selected runc")
    version = ctx.command("read selected Docker runc version", [*ctx._sudo, executable, "--version"])  # noqa: SLF001
    if len(version) > MAX_VERSION_REPORT or not re.fullmatch(
        r"runc version [0-9]+\.[0-9]+\.[0-9]+(?:[^\n]*)", version.splitlines()[0] if version else ""
    ):
        raise ProbeError("selected Docker runc version report is unavailable or invalid")
    digest = ctx.command("hash selected Docker runc executable", [*ctx._sudo, "sha256sum", executable])  # noqa: SLF001
    if not re.fullmatch(r"[0-9a-f]{64}  /[^\n]+", digest):
        raise ProbeError("selected Docker runc executable hash was unavailable")
    ctx.checks.append(
        {
            "name": "outer Docker runtime prerequisite observation",
            "status": "passed",
            "path": executable,
            "sha256": digest.split()[0],
            "rawVersionReport": version,
            "source": "private daemon default-runtime declaration plus installed executable readback",
            "declaredRuntimePath": runtime["path"],
            "taskExecutableCorrespondence": "unresolved; daemon declaration is not a held task executable identity",
        }
    )


def verify_runtime(ctx: RuntimeContext) -> None:
    """Verify the actual rootful launcher and crun version before starting a guest."""
    uid = ctx.command("systemd outer runtime identity", [*ctx._sudo, "id", "-u"])  # noqa: SLF001
    ctx.assert_equal("systemd requires rootful outer runtime", uid, "0")
    if getattr(ctx, "outer_engine", "podman") == "docker":
        _verify_docker_runtime(ctx)
        return
    raw = ctx.podman(
        "inspect selected systemd OCI runtime", "--runtime", "crun", "info", "--format", "{{json .Host.OCIRuntime}}"
    )
    runtime = json.loads(raw)
    version = str(runtime.get("version", runtime.get("Version", "")))
    name = runtime.get("name", runtime.get("Name"))
    path = runtime.get("path", runtime.get("Path", ""))
    match = re.fullmatch(r"crun version (\d+\.\d+(?:\.\d+)?|UNKNOWN)", version.splitlines()[0] if version else "")
    if name != "crun" or not str(path).startswith("/") or not match or len(version) > MAX_VERSION_REPORT:
        raise ProbeError("selected runtime must report an absolute crun path and bounded actual version report")
    observed = ctx.command("read exact selected crun binary version", [*ctx._sudo, str(path), "--version"])  # noqa: SLF001
    if len(observed) > MAX_VERSION_REPORT or version.splitlines()[0] != observed.splitlines()[0]:
        raise ProbeError("selected crun binary version differs from Podman runtime evidence")
    digest = ctx.command("hash exact selected crun executable", [*ctx._sudo, "sha256sum", str(path)])  # noqa: SLF001
    if not re.fullmatch(r"[0-9a-f]{64}  /[^\n]+", digest):
        raise ProbeError("selected crun executable hash was unavailable")
    ctx.checks.append(
        {
            "name": "selected crun executable provenance",
            "status": "passed",
            "path": str(path),
            "sha256": digest.split()[0],
            "releaseIdentity": "unknown" if match[1] == "UNKNOWN" else match[1],
            "rawVersionReport": observed,
        }
    )


def _exec(
    ctx: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    name: str,
    *args: str,
    timeout: float | None = None,
) -> str:
    budget.checkpoint()
    end = vars(ctx).get("_leaf_protocol_end")
    allowance = timeout
    if end is not None:
        allowance = (
            min(allowance, _leaf_archive_remaining(ctx, end))
            if allowance is not None
            else _leaf_archive_remaining(ctx, end)
        )
    options = {} if allowance is None else {"timeout": allowance}
    result = ctx.exec(name, container, *args, **options)
    budget.checkpoint()
    if end is not None:
        _leaf_archive_remaining(ctx, end)
    return result


def _cgroup_path(path: str, *, allow_root: bool = False) -> str:
    if (
        len(path) > MAX_CGROUP_PATH
        or not re.fullmatch(r"/(?:[A-Za-z0-9_.@:-]+(?:/[A-Za-z0-9_.@:-]+)*)?", path)
        or (path == "/" and not allow_root)
        or any(part in {".", ".."} for part in path.split("/"))
        or len(path.split("/")) - 1 > MAX_CGROUP_DEPTH
    ):
        raise ProbeError("systemd reported an unsafe or unbounded cgroup path")
    return path


def _cgroup_ancestors(path: str) -> list[str]:
    parents = []
    _cgroup_path(path, allow_root=True)
    while path != "/":
        path = path.rsplit("/", 1)[0] or "/"
        parents.append(path)
    return parents


def _hierarchy_snapshot(output: str, phase: str) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"unit": {}, "manager": {}, "group": {}, "process": {}, "scope": {}}
    for line in output.splitlines():
        prefix, separator, value = line.partition("=")
        category, _, observed_phase = prefix.rpartition("-")
        if not separator or category not in snapshot or observed_phase not in {"before", "after"}:
            raise ProbeError("unknown or malformed systemd hierarchy evidence")
        if observed_phase != phase:
            continue
        key, data = _hierarchy_row(category, value)
        if key in snapshot[category]:
            raise ProbeError("duplicate systemd hierarchy evidence")
        snapshot[category][key] = data
    return snapshot


def _hierarchy_row(category: str, value: str) -> tuple[str, Any]:
    if category in {"unit", "manager"}:
        key, delimiter, data = value.partition("=")
        if not delimiter or key not in {"ControlGroup", "MainPID", "Delegate", "ActiveState"}:
            raise ProbeError("malformed systemd manager property evidence")
        return key, data
    if category == "scope":
        return "path", value
    parts = value.split("|")
    if len(parts) != HIERARCHY_ROW_FIELDS:
        raise ProbeError("malformed cgroup or process identity evidence")
    if category == "process":
        role, pid, uids, group, executable, stat = parts
        if not pid.isdecimal() or int(pid) <= 1:
            raise ProbeError("systemd hierarchy process has no live PID")
        return role, [pid, uids, group, executable, _journal_starttime(stat, pid)]
    return parts[0], parts[1:]


def _active_delegation(properties: dict[str, str], required: set[str]) -> None:
    if set(properties) != required or properties["Delegate"] != "yes" or properties["ActiveState"] != "active":
        raise ProbeError("systemd unit is not actively delegated")


def _hierarchy_target(snapshot: dict[str, Any], kind: str, unit: str) -> str:
    properties = snapshot["unit"]
    required_properties = {"ControlGroup", "Delegate", "ActiveState"}
    if kind == "service":
        required_properties.add("MainPID")
    _active_delegation(properties, required_properties)
    target = _cgroup_path(properties["ControlGroup"])
    if target.rsplit("/", 1)[1] != unit:
        raise ProbeError("systemd unit cgroup did not match the exact owned unit")
    return target


def _hierarchy_manager(snapshot: dict[str, Any], mode: str, target: str) -> str | None:
    if mode == "rootful":
        if snapshot["manager"]:
            raise ProbeError("unexpected user manager in rootful hierarchy evidence")
        return None
    manager = snapshot["manager"]
    _active_delegation(manager, {"ControlGroup", "MainPID", "Delegate", "ActiveState"})
    delegated = _cgroup_path(manager["ControlGroup"])
    if not target.startswith(delegated + "/"):
        raise ProbeError("rootless unit escaped the actual user manager delegation")
    processes = snapshot["process"]
    if "manager" not in processes or processes["manager"][0] != manager["MainPID"]:
        raise ProbeError("rootless manager MainPID identity mismatch")
    return delegated


def _hierarchy_roles(snapshot: dict[str, Any], kind: str, unit: str, target: str) -> None:
    processes = snapshot["process"]
    expected_roles = {"main", "daemon"} if kind == "service" else set()
    if snapshot["manager"]:
        expected_roles.add("manager")
    if kind == "scope":
        if not re.fullmatch(r"docker-[a-f0-9]{64}\.scope", unit):
            raise ProbeError("resource scope did not have an exact owned container ID")
        if snapshot["scope"] != {"path": "/sys/fs/cgroup" + target}:
            raise ProbeError("resource scope was missing, ambiguous or mismatched")
        probe_roles = {role for role in processes if re.fullmatch(r"probe-[0-9]+", role)}
        if not probe_roles or len(probe_roles) > MAX_SCOPE_PROCESSES:
            raise ProbeError("resource scope did not have bounded live probe processes")
        expected_roles.update(probe_roles)
    elif snapshot["scope"] or "main" not in processes or processes["main"][0] != snapshot["unit"]["MainPID"]:
        raise ProbeError("Docker service MainPID identity mismatch")
    if set(processes) != expected_roles:
        raise ProbeError("unexpected or missing systemd hierarchy process evidence")


def _verify_hierarchy_process(role: str, values: list[Any], target: str, delegated: str | None, uid: str) -> str:
    pid, uids, group, executable, _starttime = values
    _cgroup_path(group)
    branch = delegated if role == "manager" else target
    if not branch or (group != branch and not group.startswith(branch + "/")):
        raise ProbeError("systemd process escaped its actual delegated unit")
    if uids.split() != [uid] * 4 or not executable.startswith("/"):
        raise ProbeError("systemd process UID or executable identity mismatch")
    if role == "daemon" and executable.rsplit("/", 1)[1] != "dockerd":
        raise ProbeError("Docker service process was not actual dockerd")
    if role == "manager" and executable.rsplit("/", 1)[1] != "systemd":
        raise ProbeError("rootless manager process was not actual systemd")
    if role.startswith("probe-") and (role != "probe-" + pid or group != target):
        raise ProbeError("resource probe process was not in its exact scope")
    if role.startswith("probe-") and executable.rsplit("/", 1)[1] != "docker-resource-probe":
        raise ProbeError("resource scope process was not the stable gated resource probe")
    return group


def _hierarchy_process_groups(
    snapshot: dict[str, Any], target: str, delegated: str | None, uid: str
) -> tuple[set[str], set[str]]:
    groups = snapshot["group"]
    required_groups = {target}
    distributors = set(_cgroup_ancestors(target))
    if delegated:
        required_groups.add(delegated)
        distributors.update(_cgroup_ancestors(delegated))
    for role, values in snapshot["process"].items():
        group = _verify_hierarchy_process(role, values, target, delegated, uid)
        required_groups.add(group)
        distributors.update(_cgroup_ancestors(group))
        if group not in groups or values[0] not in groups[group][4].split():
            raise ProbeError("systemd process cgroup membership disagreed with kernel readback")
    required_groups.update(distributors)
    return required_groups, distributors


def _verify_hierarchy_groups(
    groups: dict[str, list[str]],
    required: set[str],
    distributors: set[str],
    owners: dict[str, str],
    controllers: set[str],
) -> None:
    if set(groups) != required:
        raise ProbeError("missing or unexpected cgroup hierarchy readback")
    for group, (identity, group_type, available, subtree, procs) in groups.items():
        _cgroup_path(group, allow_root=True)
        inode, separator, owner = identity.partition(":")
        if not separator or not inode.isdecimal() or int(inode) <= 0 or not owner.isdecimal() or group_type != "domain":
            raise ProbeError("invalid cgroup directory identity or domain type")
        if group in owners and owner != owners[group]:
            raise ProbeError("systemd unit cgroup UID mismatch")
        if any(not pid.isdecimal() or int(pid) <= 0 for pid in procs.split()):
            raise ProbeError("malformed cgroup process membership")
        if not controllers <= set(available.split()):
            raise ProbeError("required cgroup controller was unavailable")
        if group in distributors and (procs.strip() or not controllers <= set(subtree.split())):
            raise ProbeError("controller distributor was populated or lacked subtree delegation")
        if procs.strip() and "memory" in subtree.split():
            raise ProbeError("populated domain leaf enabled memory subtree distribution")


def _hierarchy_evidence(output: str, *, kind: str, mode: str, unit: str) -> dict[str, Any]:
    if kind not in {"service", "scope"} or mode not in {"rootful", "rootless"}:
        raise ProbeError("unknown systemd hierarchy mode")
    if len(output) > MAX_HIERARCHY_READBACK:
        raise ProbeError("systemd hierarchy evidence exceeded its bounded readback")
    before = _hierarchy_snapshot(output, "before")
    if before != _hierarchy_snapshot(output, "after"):
        raise ProbeError("systemd hierarchy or process identity changed during readback")
    target = _hierarchy_target(before, kind, unit)
    delegated = _hierarchy_manager(before, mode, target)
    _hierarchy_roles(before, kind, unit, target)
    uid = "1000" if mode == "rootless" else "0"
    controllers = {"cpu", "memory", "pids"}
    owners = {"/": "0", **{values[2]: uid for values in before["process"].values()}}
    owners[target] = uid
    if delegated:
        owners[delegated] = uid
    required_groups, distributors = _hierarchy_process_groups(before, target, delegated, uid)
    groups = before["group"]
    _verify_hierarchy_groups(groups, required_groups, distributors, owners, controllers)
    if kind == "scope":
        observed_pids = {values[0] for role, values in before["process"].items() if role.startswith("probe-")}
        if set(groups[target][4].split()) != observed_pids:
            raise ProbeError("resource scope process readback was incomplete")
    return {
        "name": "systemd " + kind + " hierarchy",
        "status": "passed",
        "mode": mode,
        "unit": unit,
        "controlGroup": target,
        "userManagerControlGroup": delegated,
        "distributors": sorted(distributors),
        "groups": groups,
        "processes": before["process"],
    }


def verify_guest(
    ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, mode: str, info: dict[str, Any]
) -> None:
    """Check independent outer PID1, daemon, manager, placement and delegation facts."""
    _exec(
        ctx,
        budget,
        container,
        "verify systemd PID1 and safe exec cgroup placement",
        "sh",
        "-euc",
        PLACEMENT_GUARD + 'test "$(id -u)" = 0; test "$(cat /proc/1/comm)" = systemd; '
        "test \"$(awk '/^Uid:/ {print $2}' /proc/1/status)\" = 0; "
        'printf "pid1=%s\\nexec=%s\\n" "$init" "$current"; '
        "for c in cpu memory pids; do "
        'grep -qw "$c" /sys/fs/cgroup/cgroup.controllers; '
        'grep -qw "$c" /sys/fs/cgroup/cgroup.subtree_control; done',
    )
    expected_root = "/home/docker/.local/share/docker" if mode == "rootless" else "/var/lib/docker"
    boundary = _exec(
        ctx,
        budget,
        container,
        "inspect installed guest boot service boundary",
        "sh",
        "-euc",
        JOURNAL_BOUNDARY_COMMAND,
    )
    ctx.checks.append(_journal_boundary_evidence(boundary))
    ctx.assert_equal("systemd daemon data root", str(info.get("DockerRootDir")), expected_root)
    ctx.assert_equal("systemd daemon cgroup driver", str(info.get("CgroupDriver")), "systemd")
    ctx.assert_equal("systemd daemon cgroup version", str(info.get("CgroupVersion")), "2")
    if mode == "rootless":
        _exec(
            ctx,
            budget,
            container,
            "verify true rootless user manager and bus",
            "sh",
            "-euc",
            "test -S /run/user/1000/bus; test -f /var/lib/systemd/linger/dockertest; "
            'pid=$(systemctl show user@1000.service --property MainPID --value); test "$pid" -gt 1; '
            "test \"$(awk '/^Uid:/ {print $2}' /proc/$pid/status)\" = 1000; "
            'group=$(cut -d: -f3 /proc/$pid/cgroup); test "$group" != /; '
            'test "$(stat -c %u /run/user/1000/bus)" = 1000; '
            'test "$(systemctl show user@1000.service --property Delegate --value)" = yes',
        )
        command = (*USER_MANAGER, "show", "docker.service", "--property", "MainPID", "--value")
    else:
        command = ("systemctl", "show", "docker.service", "--property", "MainPID", "--value")
    pid = _exec(ctx, budget, container, "inspect systemd daemon service main PID", *command)
    if not pid.isdecimal() or int(pid) <= 1:
        raise ProbeError("Docker service did not report a live main PID")
    uid = _exec(
        ctx,
        budget,
        container,
        "read systemd daemon UID",
        "sh",
        "-euc",
        "awk '/^Uid:/ {print $2}' \"/proc/$1/status\"",
        "--",
        pid,
    )
    ctx.assert_equal("systemd daemon service UID", uid, "1000" if mode == "rootless" else "0")
    _exec(
        ctx,
        budget,
        container,
        "verify actual dockerd UID and bounded cgroup",
        "sh",
        "-euc",
        "found=0; for pid in $(pgrep -x dockerd); do "
        'test "$(awk \'/^Uid:/ {print $2}\' /proc/$pid/status)" = "$1"; '
        'group=$(cut -d: -f3 /proc/$pid/cgroup); test "$group" != /; '
        'found=$((found+1)); done; test "$found" = 1',
        "--",
        "1000" if mode == "rootless" else "0",
    )
    hierarchy = _exec(
        ctx,
        budget,
        container,
        "verify Docker service controller delegation",
        "sh",
        "-euc",
        HIERARCHY_READBACK_COMMAND,
        "--",
        "service",
        mode,
        "docker.service",
    )
    ctx.checks.append(_hierarchy_evidence(hierarchy, kind="service", mode=mode, unit="docker.service"))


def _memory_decimal(value: str, *, positive: bool = False) -> int:
    if not re.fullmatch(r"[0-9]{1,20}", value):
        raise ProbeError("memory diagnostic integer was missing or malformed")
    number = int(value)
    if number >= 2**64 or (positive and number == 0):
        raise ProbeError("memory diagnostic integer exceeded its bounded domain")
    return number


def _namespace_inode(value: str, kind: str) -> int:
    match = re.fullmatch(re.escape(kind) + r":\[([0-9]{1,20})\]", value)
    if not match:
        raise ProbeError("memory diagnostic namespace identity was malformed")
    return _memory_decimal(match[1], positive=True)


def _namespace_pids(value: str) -> list[int]:
    parts = value.split()
    if not parts or len(parts) > MAX_CGROUP_DEPTH:
        raise ProbeError("memory diagnostic PID namespace chain was unbounded or missing")
    return [_memory_decimal(part, positive=True) for part in parts]


def _memory_values(fields: dict[str, str]) -> dict[str, Any]:
    if set(fields) != MEMORY_VALUE_FIELDS:
        raise ProbeError("memory diagnostic accounting fields were missing or unknown")
    values: dict[str, Any] = {}
    for key in MEMORY_VALUE_FIELDS - {"memory.events"}:
        value = fields[key]
        values[key] = value if key.endswith(".max") and value == "max" else _memory_decimal(value)
    events = {}
    for row in fields["memory.events"].split(";"):
        parts = row.split()
        if len(parts) != EVENT_ROW_FIELDS or parts[0] in events:
            raise ProbeError("memory diagnostic events were malformed or duplicated")
        events[parts[0]] = _memory_decimal(parts[1])
    required = {"low", "high", "max", "oom", "oom_kill"}
    if not required <= set(events) or set(events) - required - {"oom_group_kill", "sock_throttled"}:
        raise ProbeError("memory diagnostic event fields were missing or unknown")
    values["memory.events"] = events
    return values


def _memory_uid_map(value: str) -> list[list[int]]:
    rows = value.split(";")
    if not rows or len(rows) > MAX_CGROUP_DEPTH:
        raise ProbeError("memory allocator UID mapping was unbounded or missing")
    mappings = []
    for row in rows:
        parts = row.split()
        if len(parts) != UID_MAP_FIELDS:
            raise ProbeError("memory allocator UID mapping was malformed")
        inside, outside, count = [_memory_decimal(part) for part in parts]
        if count == 0 or inside + count > 2**32 - 1 or outside + count > 2**32 - 1:
            raise ProbeError("memory allocator UID mapping exceeded its kernel domain")
        mappings.append([inside, outside, count])
    for column in (0, 1):
        ordered = sorted(mappings, key=lambda row, index=column: row[index])
        for prior, current in pairwise(ordered):
            if prior[column] + prior[2] > current[column]:
                raise ProbeError("memory allocator UID mapping was ambiguous")
    return mappings


def _mapped_root_uid(mappings: list[list[int]]) -> int:
    roots = [outside for inside, outside, _count in mappings if inside == 0]
    if len(roots) != 1:
        raise ProbeError("memory allocator root UID mapping was absent or ambiguous")
    return roots[0]


def _association_process(value: str) -> dict[str, Any]:
    parts = value.split("|")
    if len(parts) != ASSOCIATION_ROW_FIELDS:
        raise ProbeError("memory allocator association row was malformed")
    pid, uids, group, executable, stat, nspid, pidns, cgroupns, userns, uidmap = parts
    if not group.startswith("0::") or not executable.startswith("/"):
        raise ProbeError("memory allocator process view was malformed")
    uid_fields = uids.split()
    if len(uid_fields) != UID_FIELD_COUNT:
        raise ProbeError("memory allocator UID evidence was incomplete")
    return {
        "pid": _memory_decimal(pid, positive=True),
        "uids": [_memory_decimal(uid) for uid in uid_fields],
        "group": _cgroup_path(group.removeprefix("0::")),
        "exe": executable,
        "starttime": _journal_starttime(stat, pid),
        "nspid": _namespace_pids(nspid),
        "pidns": _namespace_inode(pidns, "pid"),
        "cgroupns": _namespace_inode(cgroupns, "cgroup"),
        "userns": _namespace_inode(userns, "user"),
        "uidmap": _memory_uid_map(uidmap),
    }


def _association_records(output: str) -> tuple[dict[str, Any], dict[str, str]]:
    if len(output) > MAX_MEMORY_READBACK:
        raise ProbeError("memory association readback exceeded its source bound")
    snapshots: dict[str, Any] = {"before": {}, "after": {}}
    scope = {}
    required = {"allocator", "daemon", "ancestry", "docker-pid", "scope-inode", "mount-inode", "mount-type"}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if key.startswith("scope-"):
            target, field = scope, key.removeprefix("scope-")
        else:
            match = re.fullmatch(r"association-(before|after)-(.+)", key)
            if not match or match[2] not in required:
                raise ProbeError("unknown memory association record")
            target, field = snapshots[match[1]], match[2]
            if field in {"allocator", "daemon"}:
                value = _association_process(value)
        if not separator or field in target:
            raise ProbeError("memory association record was malformed or duplicated")
        target[field] = value
    if any(set(snapshot) != required for snapshot in snapshots.values()):
        raise ProbeError("memory association identity records were incomplete")
    if snapshots["before"] != snapshots["after"]:
        raise ProbeError("actual memory allocator or daemon identity changed during readback")
    return snapshots["before"], scope


def _scope_allocator(evidence: dict[str, Any]) -> list[Any]:
    probes = [values for role, values in evidence["processes"].items() if role.startswith("probe-")]
    if len(probes) != 1:
        raise ProbeError("actual memory allocator association was ambiguous")
    return probes[0]


def _verify_memory_namespace_mapping(snapshot: dict[str, Any]) -> None:
    allocator, daemon = snapshot["allocator"], snapshot["daemon"]
    a_pids, d_pids = allocator["nspid"], daemon["nspid"]
    ancestry = [_namespace_inode(value, "pid") for value in snapshot["ancestry"].split()]
    if (
        not MIN_PID_ANCESTRY <= len(ancestry) <= MAX_CGROUP_DEPTH
        or len(set(ancestry)) != len(ancestry)
        or ancestry[0] != allocator["pidns"]
        or ancestry[-1] != daemon["pidns"]
        or len(a_pids) - len(d_pids) + 1 != len(ancestry)
        or a_pids[0] != allocator["pid"]
        or d_pids[0] != daemon["pid"]
        or a_pids[-1] != 1
    ):
        raise ProbeError("memory allocator was not a kernel-bound descendant of the actual daemon PID namespace")
    if _memory_decimal(snapshot["docker-pid"], positive=True) != a_pids[len(d_pids) - 1]:
        raise ProbeError("Docker reported a PID unrelated to the actual memory allocator")


def _retained_daemon(daemon: dict[str, Any], service: dict[str, Any], evidence: dict[str, Any]) -> None:
    if service["mode"] != evidence["mode"] or service["userManagerControlGroup"] != evidence["userManagerControlGroup"]:
        raise ProbeError("memory allocator used a different retained daemon mode or manager")
    if service["mode"] == "rootless" and service["processes"]["manager"] != evidence["processes"]["manager"]:
        raise ProbeError("memory allocator user manager changed since service verification")
    pid, uids, group, executable, starttime = service["processes"]["daemon"]
    expected = {
        "pid": int(pid),
        "uids": [int(uid) for uid in uids.split()],
        "group": group,
        "exe": executable,
        "starttime": starttime,
    }
    if any(daemon[key] != value for key, value in expected.items()):
        raise ProbeError("memory allocator daemon changed from its retained service identity")


def _memory_association(output: str, evidence: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    snapshot, scope_fields = _association_records(output)
    allocator, daemon = snapshot["allocator"], snapshot["daemon"]
    _retained_daemon(daemon, service, evidence)
    pid, uids, group, executable, starttime = _scope_allocator(evidence)
    expected = {
        "pid": int(pid),
        "uids": [int(uid) for uid in uids.split()],
        "group": group,
        "exe": executable,
        "starttime": starttime,
    }
    if any(allocator[key] != value for key, value in expected.items()):
        raise ProbeError("actual memory allocator disagreed with the retained scope process identity")
    if allocator["uids"] != [_mapped_root_uid(allocator["uidmap"])] * UID_FIELD_COUNT:
        raise ProbeError("memory allocator inner root UID did not map to its actual guest identity")
    inode = int(evidence["groups"][evidence["controlGroup"]][0].split(":")[0])
    if (
        _memory_decimal(snapshot["scope-inode"], positive=True) != inode
        or _memory_decimal(snapshot["mount-inode"], positive=True) != inode
        or snapshot["mount-type"] != CGROUP2_MAGIC
    ):
        raise ProbeError("actual memory allocator accounting mount did not match its retained cgroup2 scope")
    uid = 1000 if evidence["mode"] == "rootless" else 0
    delegated = evidence["userManagerControlGroup"]
    if (
        daemon["uids"] != [uid] * 4
        or daemon["exe"].rsplit("/", 1)[1] != "dockerd"
        or (delegated and not daemon["group"].startswith(delegated + "/"))
    ):
        raise ProbeError("memory allocator namespace association used an unrelated daemon")
    _verify_memory_namespace_mapping(snapshot)
    values = _memory_values(scope_fields)
    if values["memory.max"] != MEMORY_BYTES:
        raise ProbeError("memory allocator scope changed its exact hard limit")
    return {**snapshot, "scopeMemory": values}


class _AllocatorAfterError(ProbeError):
    def __init__(self, message: str, before: dict[str, Any]) -> None:
        super().__init__(message)
        self.before = before


def _allocator_records(output: str, *, phase: str | None = None) -> dict[str, dict[str, str]]:
    if len(output) > MAX_ALLOCATOR_TELEMETRY:
        raise ProbeError("memory allocator telemetry exceeded its authored source bound")
    snapshots: dict[str, dict[str, str]] = {"before": {}, "after": {}}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if phase is not None and not key.startswith("allocator-" + phase + "-"):
            continue
        match = re.fullmatch(r"allocator-(before|after)-(.+)", key)
        if not separator or not match or match[2] in snapshots[match[1]]:
            raise ProbeError("memory allocator telemetry was malformed, unknown or duplicated")
        snapshots[match[1]][match[2]] = value
    return snapshots


def _allocator_identity(fields: dict[str, str], association: dict[str, Any]) -> dict[str, Any]:
    required = {
        "pid",
        "uids",
        "nspid",
        "starttime",
        "cgroup",
        "exe",
        "pidns",
        "cgroupns",
        "userns",
        "scope-inode",
        "mount-type",
        "complete",
    }
    if set(fields) != required | MEMORY_VALUE_FIELDS or fields["complete"] != "yes":
        raise ProbeError("post-release allocator self-readback was missing, incomplete or unknown")
    allocator = association["allocator"]
    expected = {
        "pid": 1,
        "uids": [0] * 4,
        "nspid": [1],
        "starttime": allocator["starttime"],
        "cgroup": "0::/",
        "exe": allocator["exe"],
        "pidns": allocator["pidns"],
        "cgroupns": allocator["cgroupns"],
        "userns": allocator["userns"],
        "scope-inode": int(association["scope-inode"]),
        "mount-type": CGROUP2_MAGIC,
    }
    observed = {
        **{key: fields[key] for key in ("cgroup", "exe", "mount-type")},
        **{key: _memory_decimal(fields[key], positive=True) for key in ("pid", "starttime", "scope-inode")},
        "uids": [_memory_decimal(uid) for uid in fields["uids"].split()],
        "nspid": _namespace_pids(fields["nspid"]),
        "pidns": _namespace_inode(fields["pidns"], "pid"),
        "cgroupns": _namespace_inode(fields["cgroupns"], "cgroup"),
        "userns": _namespace_inode(fields["userns"], "user"),
    }
    if observed != expected:
        raise ProbeError("post-release allocator identity or namespace accounting association changed")
    return observed


def _allocator_snapshot(fields: dict[str, str], association: dict[str, Any]) -> dict[str, Any]:
    identity = _allocator_identity(fields, association)
    values = _memory_values({key: fields[key] for key in MEMORY_VALUE_FIELDS})
    baseline = association["scopeMemory"]
    if any(values[key] != baseline[key] for key in ("memory.max", "memory.swap.max")):
        raise ProbeError("post-release allocator accounting limits disagreed with the actual scope")
    return {"identity": identity, "memory": values}


def _memory_event_progress(before: dict[str, Any], after: dict[str, Any]) -> None:
    if any(after["memory.events"].get(key, -1) < value for key, value in before["memory.events"].items()):
        raise ProbeError("memory allocator accounting events regressed across stable scope readback")


def _allocator_telemetry(output: str, association: dict[str, Any], *, genuine_oom: bool) -> dict[str, Any]:
    before_records = _allocator_records(output, phase="before")
    before = _allocator_snapshot(before_records["before"], association)
    _memory_event_progress(association["scopeMemory"], before["memory"])
    try:
        snapshots = _allocator_records(output)
        after = None
        if snapshots["after"]:
            after = _allocator_snapshot(snapshots["after"], association)
            _memory_event_progress(before["memory"], after["memory"])
    except ProbeError as error:
        raise _AllocatorAfterError(str(error), before) from error
    if after is None and not genuine_oom:
        raise _AllocatorAfterError("surviving memory allocator omitted its post-allocation readback", before)
    return {"before": before, "after": after}


def _memory_probe_result(
    ctx: RuntimeContext, association: dict[str, Any], output: str, exit_code: str, state: dict[str, Any]
) -> None:
    genuine = exit_code == "137" and state.get("OOMKilled") is True
    try:
        telemetry = _allocator_telemetry(output, association, genuine_oom=genuine)
    except ProbeError as error:
        ctx.checks.append(
            {
                "name": "inner memory allocator diagnostic",
                "status": "failed",
                "association": association,
                "enforcementSatisfied": genuine,
                "error": str(error),
                "verifiedBefore": error.before if isinstance(error, _AllocatorAfterError) else None,
                "beforeStatus": "verified" if isinstance(error, _AllocatorAfterError) else "invalid",
                "afterStatus": "invalid" if isinstance(error, _AllocatorAfterError) else "unverified",
            }
        )
        if not genuine:
            raise ProbeError(
                "inner memory probe lacked genuine Docker OOM-kill evidence; allocator diagnostic failed"
            ) from error
        raise
    no_swap = association["scopeMemory"]["memory.swap.max"] == 0
    ctx.checks.append(
        {
            "name": "inner memory allocator diagnostic",
            "status": "passed" if genuine and no_swap else "failed",
            "association": association,
            "telemetry": telemetry,
            "enforcementSatisfied": genuine,
            "effectiveNoSwap": no_swap,
        }
    )
    if not genuine:
        raise ProbeError("inner memory probe lacked genuine Docker OOM-kill evidence")
    if not no_swap:
        raise ProbeError("inner memory probe had unexpected effective swap allowance")


def _retained_service(ctx: RuntimeContext, mode: str) -> dict[str, Any]:
    services = [
        check
        for check in ctx.checks
        if check.get("name") == "systemd service hierarchy"
        and check.get("mode") == mode
        and check.get("unit") == "docker.service"
        and check.get("status") == "passed"
    ]
    if len(services) != 1:
        raise ProbeError("memory allocator lacked an unambiguous retained service identity")
    return services[0]


def _read_memory_association(
    ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, workload: str, evidence: dict[str, Any]
) -> dict[str, Any]:
    output = _exec(
        ctx,
        budget,
        container,
        "read actual memory allocator swap and namespace association",
        "sh",
        "-euc",
        MEMORY_ASSOCIATION_COMMAND,
        "--",
        evidence["controlGroup"],
        _scope_allocator(evidence)[0],
        workload,
    )
    association = _memory_association(output, evidence, _retained_service(ctx, evidence["mode"]))
    ctx.checks.append(
        {"name": "inner memory allocator scope association", "status": "passed", "association": association}
    )
    return association


def _inner_enforcement_state(
    ctx: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    probe: tuple[str, str],
    *,
    diagnostics: OomDiagnostics | None,
) -> tuple[str, dict[str, Any]]:
    kind, workload = probe
    try:
        exit_code = _exec(
            ctx,
            budget,
            container,
            f"wait bounded inner {kind} enforcement",
            "docker",
            "wait",
            f"docker-native-limit-{kind}",
        )
        state = json.loads(
            _exec(
                ctx,
                budget,
                container,
                f"inspect inner {kind} enforcement state",
                "docker",
                "inspect",
                "--format",
                "{{json .State}}",
                workload,
            )
        )
        return exit_code, state
    finally:
        if kind == "memory" and diagnostics is not None:
            diagnostics.snapshot("after-inner-memory")


# Each mode has its own baseline. These fixed tags never grant admission authority.
LEAF_WITNESS_PURPOSE = "leaf-memory-witness"
LEAF_WITNESS_SECONDS = 10
LEAF_WITNESS_FAILURE_CAPTURE_SECONDS = 2
LEAF_WITNESS_FAILURE_STATE_BYTES = 1024
LEAF_WITNESS_FAILURE_STAGES = frozenset(
    {
        "child-identity",
        "start-gate",
        "before-snapshot",
        "release-child",
        "wait-child",
        "result-write",
        "after-snapshot",
        "after-sentinel",
        "finish-gate",
    }
)
LEAF_WITNESS_FAILURE_STATE_COMMAND = (
    "{ if docker inspect --format '"
    '{"id":{{json .Id}},"name":{{json .Name}},"state":{'
    '"Running":{{json .State.Running}},"OOMKilled":{{json .State.OOMKilled}},'
    '"ExitCode":{{json .State.ExitCode}}}}'
    '\' "$1" 2>/dev/null; then printf "leaf-witness-state-complete=yes\\n"; fi; } | head -c 1025'
)
LEAF_WITNESS_FAILURE_LOG_COMMAND = (
    '{ if docker logs --tail 80 "$1" 2>/dev/null; then '
    'printf "leaf-witness-capture-complete=yes\n"; fi; } | head -c 65537'
)
LEAF_WITNESS_STAGES = frozenset(
    {
        "room-check",
        "launch",
        "bind",
        "root-before",
        "release-await-after",
        "log-read",
        "controller-rebind",
        "retained-hierarchy",
        "root-after",
        "projection-validation",
        "finish-hold",
        "wait-completion",
    }
)
LEAF_WITNESS_NAME = "docker-native-limit-memory-witness"
LEAF_WITNESS_CIDFILE = "/tmp/docker-native-limit-memory-witness.cid"  # noqa: S108 — private owned guest.
LEAF_WITNESS_FIELDS = frozenset(
    {
        "scope-identity",
        "controller-pid",
        "controller-stat",
        "controller-cgroup",
        "controller-pidns",
        "controller-cgroupns",
        "controller-userns",
        "child-pid",
        "child-stat",
        "memory.max",
        "memory.current",
        "memory.swap.max",
        "memory.swap.current",
        "memory.events",
        "memory.events.local",
        "memory.oom.group",
        "pids.max",
        "complete",
    }
)
# Reuse the read-only identity/mount/ancestry reader, adding exactly the controller's direct child.
LEAF_WITNESS_ASSOCIATION_COMMAND = MEMORY_ASSOCIATION_COMMAND.replace(
    "for phase in before after; do",
    'child=$(bounded "/proc/$allocator/task/$allocator/children" 1024)\n'
    'set -- $child; test "$#" -eq 1; child=$1\n'
    "for phase in before after; do",
).replace(
    'identity allocator "$allocator"',
    'identity allocator "$allocator"\n'
    'test "$(awk \'/^PPid:/ {print $2}\' /proc/$child/status)" = "$allocator"\n'
    'test "$(bounded /proc/$allocator/task/$allocator/children 1024 | xargs)" = "$child"\n'
    'identity child "$child"\n'
    'test "$(stat -c %d /sys/fs/cgroup$scope)" = "$(stat -c %d /proc/$allocator/root/sys/fs/cgroup)"\n'
    'printf "witness-%s-scope-device=%s\\n" "$phase" "$(stat -c %d /sys/fs/cgroup$scope)"',
)


def _leaf_witness_require(message: str, *, condition: bool) -> None:
    if not condition:
        raise ProbeError(message)


def _leaf_witness_needed(ctx: RuntimeContext, diagnostics: OomDiagnostics | None) -> bool:
    if diagnostics is None or getattr(ctx, "outer_engine", None) != "docker":
        return False
    candidates = [
        record
        for record in ctx.observations
        if record.get("name") == "owned systemd OOM diagnostic"
        and record.get("phase") == "after-inner-memory"
        and "purpose" not in record
    ]
    if not candidates:
        return False
    record = candidates[-1]
    state = record.get("ociState")
    return (
        type(record.get("schemaVersion")) is int
        and record["schemaVersion"] == 1
        and record.get("authority") == "observation-only"
        and type(state) is dict
        and state.get("OOMKilled") is True
    )


def _leaf_witness_members(hierarchy: dict[str, Any], controller: dict[str, Any], child: dict[str, Any]) -> None:
    expected = {"probe-" + str(process["pid"]): process for process in (controller, child)}
    actual = {role: values for role, values in hierarchy["processes"].items() if role.startswith("probe-")}
    members = set(hierarchy["groups"][hierarchy["controlGroup"]][4].split())
    if len(expected) != 2 or set(actual) != set(expected) or members != {str(controller["pid"]), str(child["pid"])}:  # noqa: PLR2004 — controller plus one child.
        raise ProbeError("witness leaf did not contain exactly two owned processes")
    for role, process in expected.items():
        pid, uids, group, executable, starttime = actual[role]
        if [
            str(process["pid"]),
            " ".join(map(str, process["uids"])),
            process["group"],
            process["exe"],
            process["starttime"],
        ] != [pid, uids, group, executable, starttime]:
            raise ProbeError("witness process disagreed with full leaf membership")


def _leaf_witness_association_records(output: str) -> dict[str, Any]:
    child_records, child_parents, devices, retained = {}, {}, {}, []
    for line in output.splitlines():
        device_match = re.fullmatch(r"witness-(before|after)-scope-device=([0-9]+)", line)
        if device_match:
            if device_match[1] in devices:
                raise ProbeError("duplicate witness mount device")
            devices[device_match[1]] = _memory_decimal(device_match[2])
            continue
        match = re.fullmatch(r"association-(before|after)-child=(.+)", line)
        if match:
            if match[1] in child_records:
                raise ProbeError("duplicate witness child")
            child_records[match[1]] = _association_process(match[2])
            child_parents[match[1]] = _memory_decimal(
                match[2].split("|")[4].rsplit(") ", 1)[1].split()[1], positive=True
            )
        else:
            retained.append(line)
    if set(child_records) != {"before", "after"} or child_records["before"] != child_records["after"]:
        raise ProbeError("changed witness child")
    association, scope_fields = _association_records("\n".join(retained))
    return {
        "association": association,
        "scope": scope_fields,
        "children": child_records,
        "parents": child_parents,
        "devices": devices,
    }


def _leaf_witness_association(output: str, hierarchy: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    records = _leaf_witness_association_records(output)
    association, scope_fields = records["association"], records["scope"]
    child_records, child_parents, devices = records["children"], records["parents"], records["devices"]
    _retained_daemon(association["daemon"], service, hierarchy)
    _verify_memory_namespace_mapping(association)
    controller, child = association["allocator"], child_records["before"]
    if set(devices) != {"before", "after"} or devices["before"] != devices["after"]:
        raise ProbeError("witness accounting device missing or changed")
    if set(child_parents.values()) != {controller["pid"]}:
        raise ProbeError("witness child parent mismatch")
    _leaf_witness_members(hierarchy, controller, child)
    if (
        any(child[key] != controller[key] for key in ("uids", "group", "exe", "pidns", "cgroupns", "userns", "uidmap"))
        or child["nspid"][:-1] == controller["nspid"][:-1]
        or len(child["nspid"]) != len(controller["nspid"])
        or child["nspid"][-1] <= 1
        or controller["uids"] != [_mapped_root_uid(controller["uidmap"])] * UID_FIELD_COUNT
    ):
        raise ProbeError("witness child namespace or ownership mismatch")
    # At each namespace level the child is distinct; both share the same namespaces.
    inode = int(hierarchy["groups"][hierarchy["controlGroup"]][0].split(":")[0])
    if (
        int(association["scope-inode"]) != inode
        or int(association["mount-inode"]) != inode
        or association["mount-type"] != CGROUP2_MAGIC
        or controller["group"] != hierarchy["controlGroup"]
    ):
        raise ProbeError("witness accounting mount or leaf mismatch")
    values = _memory_values(scope_fields)
    if values["memory.max"] != MEMORY_BYTES or values["memory.swap.max"] != 0:
        raise ProbeError("witness hard limits mismatch")
    return {
        **association,
        "child": child,
        "scopeMemory": values,
        "scope-device": devices["before"],
        "hierarchy": hierarchy,
    }


def _leaf_witness_records(output: str) -> dict[str, dict[str, str]]:
    if len(output) > MAX_MEMORY_READBACK:
        raise ProbeError("witness protocol oversized")
    records: dict[str, dict[str, str]] = {"before": {}, "after": {}, "result": {}}
    for line in output.splitlines():
        match = re.fullmatch(r"leaf-witness-(before|after|result)-([^=]+)=(.*)", line)
        if not match or match[2] in records[match[1]]:
            raise ProbeError("witness protocol malformed")
        records[match[1]][match[2]] = match[3]
    if any(
        set(records[phase]) != LEAF_WITNESS_FIELDS or records[phase]["complete"] != "yes"
        for phase in ("before", "after")
    ):
        raise ProbeError("witness before or actual after missing")
    if set(records["result"]) != {"child-reaped", "child-signal", "child-signaled"}:
        raise ProbeError("witness wait status missing")
    return records


def _leaf_witness_snapshot(fields: dict[str, str], association: dict[str, Any]) -> dict[str, Any]:
    controller, child = association["allocator"], association["child"]
    device, separator, inode = fields["scope-identity"].partition(":")
    if (
        not separator
        or not device.isdecimal()
        or not inode.isdecimal()
        or int(device) != association["scope-device"]
        or int(inode) != int(association["scope-inode"])
        or _memory_decimal(fields["controller-pid"], positive=True) != 1
        or _journal_starttime(fields["controller-stat"], "1") != controller["starttime"]
        or fields["controller-cgroup"] != "0::/"
        or _memory_decimal(fields["child-pid"], positive=True) != child["nspid"][-1]
        or _journal_starttime(fields["child-stat"], str(child["nspid"][-1])) != child["starttime"]
        or fields["child-stat"].rsplit(") ", 1)[-1].split()[1] != "1"
        or any(
            _namespace_inode(fields["controller-" + key], kind) != controller[key]
            for key, kind in (("pidns", "pid"), ("cgroupns", "cgroup"), ("userns", "user"))
        )
    ):
        raise ProbeError("witness leaf or process identity changed")
    values = _memory_values({key: fields[key] for key in MEMORY_VALUE_FIELDS})
    local = _memory_values(
        {**{key: fields[key] for key in MEMORY_VALUE_FIELDS}, "memory.events": fields["memory.events.local"]}
    )["memory.events"]
    if (
        values["memory.max"] != MEMORY_BYTES
        or values["memory.swap.max"] != 0
        or values["memory.swap.current"] != 0
        or fields["memory.oom.group"] != "0"
        or fields["pids.max"] != str(INNER_PIDS)
    ):
        raise ProbeError("witness effective limits or group policy invalid")
    return {"identity": fields["scope-identity"], "memory": values, "local": local}


def _leaf_witness_retained_after(output: str, association: dict[str, Any]) -> None:
    before = association["hierarchy"]
    after = _hierarchy_evidence(output, kind="scope", mode=before["mode"], unit=before["unit"])
    if before["groups"].keys() != after["groups"].keys():
        raise ProbeError("witness hierarchy changed")
    if any(old[:4] != after["groups"][group][:4] for group, old in before["groups"].items()):
        raise ProbeError("witness leaf or ancestor identity changed")
    expected = {
        role: values
        for role, values in before["processes"].items()
        if role != "probe-" + str(association["child"]["pid"])
    }
    if after["processes"] != expected:
        raise ProbeError("witness controller after identity or leaf membership changed")
    if after["groups"][after["controlGroup"]][4].split() != [str(association["allocator"]["pid"])]:
        raise ProbeError("witness after leaf was not solely populated by the controller")


def _leaf_witness_counter_pair(old: object, new: object) -> None:
    if not isinstance(old, dict) or not isinstance(new, dict) or old.keys() != new.keys():
        raise ProbeError("witness counter set missing or changed")
    maximum = (1 << 64) - 1
    if any(type(value) is not int or not 0 <= value <= maximum for values in (old, new) for value in values.values()):
        raise ProbeError("witness counter value malformed")
    if any(new[key] < value for key, value in old.items()):
        raise ProbeError("witness counters regressed")


def _leaf_witness_root_pair(roots: list[dict[str, Any]], window: list[int]) -> None:
    if len(roots) != 2:  # noqa: PLR2004 — before and after.
        raise ProbeError("witness root samples missing")
    before, after = roots
    for candidate in [window, *(root.get("sampleWindowMonotonicNs") for root in roots)]:
        if (
            not isinstance(candidate, list)
            or len(candidate) != 2  # noqa: PLR2004 — closed monotonic interval.
            or any(type(value) is not int or value < 0 for value in candidate)
            or candidate[0] > candidate[1]
        ):
            raise ProbeError("witness monotonic window malformed")
    if any(
        root.get("availability") != "observed"
        or root.get("authority") != "observation-only"
        or set(root.get("bindingChecks", {})) != set(DOCKER_CHECKS)
        or not root.get("bindingChecks")
        or not all(value is True for value in root["bindingChecks"].values())
        or root.get("mountSemantics", {}).get("memoryLocalevents") is not False
        or root.get("mountSemantics", {}).get("root") != "full-hierarchy"
        for root in roots
    ):
        raise ProbeError("witness root binding or mount semantics unavailable")
    for name in ("memory.events", "memory.events.local"):
        for root in roots:
            if root.get("counters", {}).get(name, {}).get("availability") != "observed":
                raise ProbeError("witness actual root counters unavailable")
        _leaf_witness_counter_pair(before["counters"][name].get("values"), after["counters"][name].get("values"))
    if before["bindings"] != after["bindings"] or before["mountSemantics"] != after["mountSemantics"]:
        raise ProbeError("witness root identity changed")
    if not (before["sampleWindowMonotonicNs"][1] <= window[0] <= window[1] <= after["sampleWindowMonotonicNs"][0]):
        raise ProbeError("witness root window did not enclose leaf window")


def _leaf_witness_public(
    output: str, association: dict[str, Any], roots: list[dict[str, Any]], window: list[int]
) -> dict[str, Any]:
    records = _leaf_witness_records(output)
    before, after = (_leaf_witness_snapshot(records[phase], association) for phase in ("before", "after"))
    if before["identity"] != after["identity"] or records["before"]["child-stat"] != records["after"]["child-stat"]:
        raise ProbeError("witness retained identity changed")
    _leaf_witness_root_pair(roots, window)
    deltas = {}
    for name, old, new in (
        ("memory.events", before["memory"]["memory.events"], after["memory"]["memory.events"]),
        ("memory.events.local", before["local"], after["local"]),
    ):
        _leaf_witness_counter_pair(old, new)
        deltas[name] = {
            "availability": "observed",
            "before": old,
            "after": new,
            "delta": {key: new[key] - value for key, value in old.items()},
        }
    result = records["result"]
    if result["child-reaped"] != "yes" or result["child-signaled"] not in {"yes", "no"}:
        raise ProbeError("witness child reaping malformed")
    signum = _memory_decimal(result["child-signal"])
    if result["child-signaled"] != "yes" or signum != signals.SIGKILL:
        raise ProbeError("witness child did not terminate by SIGKILL")
    return {
        "availability": "observed",
        "beforeStatus": "observed",
        "afterStatus": "observed",
        "childTermination": "waitpid-signaled-sigkill",
        "childReaped": True,
        "leafWindowMonotonicNs": window,
        "counters": deltas,
        "bindings": {
            "controllerChildAndLeaf": hashlib.sha256(json.dumps(association, sort_keys=True).encode()).hexdigest()
        },
        "effectiveLimits": {"memoryBytes": MEMORY_BYTES, "swapBytes": 0, "pids": INNER_PIDS, "oomGroup": 0},
        "checks": {
            "exactTwoMemberLeaf": True,
            "liveControllerAfter": True,
            "rootEnclosesLeaf": True,
            "stableCounters": True,
        },
        "oomAccountingObserved": deltas["memory.events.local"]["delta"]["oom_kill"] > 0,
    }


def _leaf_witness_snapshot_root(observer: OomDiagnostics, role: str) -> dict[str, Any]:
    first = len(observer.ctx.observations)
    observer.snapshot("before-inner-memory" if role == "root-before" else "after-inner-memory")
    added = observer.ctx.observations[first:]
    for record in added:
        record.update({"purpose": LEAF_WITNESS_PURPOSE, "role": role})
    if len(added) != 1:
        raise ProbeError("witness root sample count invalid")
    return added[0]


def _leaf_witness_room(ctx: RuntimeContext) -> None:
    deadline = getattr(ctx, "runtime_deadline", None)
    if (
        type(deadline) not in {int, float}
        or not math.isfinite(deadline)
        or deadline - time.monotonic() < LEAF_WITNESS_SECONDS
    ):
        raise ProbeError("witness original work deadline insufficient")
    if ctx.backend.command_timeout(LEAF_WITNESS_SECONDS) < LEAF_WITNESS_SECONDS:
        raise ProbeError("witness original cleanup reserve insufficient")


def _leaf_witness_bind(
    collection: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    probe: tuple[str, str],
    service: dict[str, Any],
) -> dict[str, Any]:
    mode, workload = probe
    unit = "docker-" + workload + ".scope"
    hierarchy = _hierarchy_evidence(
        _exec(
            collection,
            budget,
            container,
            "bind complete diagnostic leaf",
            "sh",
            "-euc",
            HIERARCHY_READBACK_COMMAND,
            "--",
            "scope",
            mode,
            unit,
        ),
        kind="scope",
        mode=mode,
        unit=unit,
    )
    candidates = [values for role, values in hierarchy["processes"].items() if role.startswith("probe-")]
    if len(candidates) != 2:  # noqa: PLR2004 — no discarded extra members.
        raise ProbeError("witness full leaf membership unavailable")
    # PID1 is resolved from Docker through the existing namespace map, not guessed by PID order.
    associations = []
    for candidate in candidates:
        try:
            raw = _exec(
                collection,
                budget,
                container,
                "bind diagnostic controller and direct child",
                "sh",
                "-euc",
                'endpoint=$4; docker() { command docker --host "$endpoint" --tls=false "$@"; }; '
                + LEAF_WITNESS_ASSOCIATION_COMMAND,
                "--",
                hierarchy["controlGroup"],
                candidate[0],
                workload,
                vars(collection).get("_leaf_witness_endpoint", "unix:///var/run/docker.sock"),
            )
            associations.append(_leaf_witness_association(raw, hierarchy, service))
        except ProbeError:
            continue
    if len(associations) != 1:
        raise ProbeError("witness controller identity ambiguous")
    return associations[0]


def _leaf_witness_cleanup(collection: RuntimeContext, container: str, workload: str | None) -> None:
    # The cidfile is created by this docker run in the fresh private guest, including partial launches.
    collection.exec(
        "remove and read back exact diagnostic leaf",
        container,
        "sh",
        "-euc",
        "endpoint=$1; nonce=$2; image=$3; mode=$4; shift 4; "
        'docker() { command docker --host "$endpoint" --tls=false "$@"; }; '
        'cid=$(head -c 65 "$1"); test "${#cid}" -eq 64; '
        'case "$cid" in *[!a-f0-9]*) exit 1;; esac; '
        'test -z "$2" || test "$cid" = "$2"; '
        'test "$(docker inspect --format {{.Name}} "$cid")" = "/$3"; '
        'test -z "$nonce" || test "$(docker inspect --format '
        "'{{index .Config.Labels \"org.strukturpiloten.witness\"}}' "
        '"$cid")" = "$nonce"; '
        'test -z "$image" || test "$(docker inspect --format {{.Image}} "$cid")" = "$image"; '
        'test -z "$mode" || test "$(docker inspect --format '
        "'{{index .Config.Labels \"org.strukturpiloten.witness-mode\"}}' "
        '"$cid")" = "$mode"; '
        'docker rm --force "$cid"; ! docker inspect "$cid" >/dev/null 2>&1',
        "--",
        vars(collection).get("_leaf_witness_endpoint", "unix:///var/run/docker.sock"),
        vars(collection).get("_leaf_witness_nonce", ""),
        vars(collection).get("_leaf_witness_image", ""),
        vars(collection).get("_leaf_witness_mode", ""),
        vars(collection).get("_leaf_witness_cidfile", LEAF_WITNESS_CIDFILE),
        workload or "",
        LEAF_WITNESS_NAME,
    )


def _leaf_witness_cleanup_record(
    collection: RuntimeContext, container: str, workload: str | None, record: dict[str, Any]
) -> None:
    try:
        record["cleanupEnteredStage"] = "exact-owned-leaf"
        _leaf_witness_cleanup(collection, container, workload)
        record["cleanupCompletedStage"] = "exact-owned-leaf"
        record["cleanup"] = "verified"
    except Exception:  # noqa: BLE001 — preserve native failure; existing guest cleanup remains mandatory.
        record["cleanup"] = "unavailable"
        record["availability"] = "unavailable"


@contextmanager
def _leaf_witness_stage(record: dict[str, Any], stage: str) -> Iterator[None]:
    if stage not in LEAF_WITNESS_STAGES:
        raise ProbeError("unknown witness collection stage")
    record["enteredStage"] = stage
    yield
    record["completedStage"] = stage


def _leaf_witness_unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("witness duplicate state field")
        result[key] = value
    return result


def _leaf_witness_failure_state(raw: str, workload: str) -> dict[str, Any]:
    if len(raw.encode()) > LEAF_WITNESS_FAILURE_STATE_BYTES or "\r" in raw:
        raise ProbeError("witness state capture oversized or malformed")
    state_raw, separator, receipt = raw.partition("\n")
    if not separator or receipt != "leaf-witness-state-complete=yes":
        raise ProbeError("witness state capture incomplete")
    value = json.loads(state_raw, object_pairs_hook=_leaf_witness_unique_object)
    if (
        not isinstance(value, dict)
        or value.keys() != {"id", "name", "state"}
        or value["id"] != workload
        or value["name"] != "/" + LEAF_WITNESS_NAME
    ):
        raise ProbeError("witness state identity unavailable")
    state = value["state"]
    if (
        not isinstance(state, dict)
        or state.keys() != {"Running", "OOMKilled", "ExitCode"}
        or type(state["Running"]) is not bool
        or type(state["OOMKilled"]) is not bool
        or type(state["ExitCode"]) is not int
        or not 0 <= state["ExitCode"] <= DOCKER_EXIT_MAX
    ):
        raise ProbeError("witness state fields unavailable")
    return {"availability": "observed", **state}


def _leaf_witness_failure_protocol(raw: str) -> dict[str, Any]:
    if len(raw.encode()) > MAX_MEMORY_READBACK or "\r" in raw:
        raise ProbeError("witness failure protocol oversized or malformed")
    lines = raw.split("\n")
    if not lines or lines.pop() != "leaf-witness-capture-complete=yes":
        raise ProbeError("witness failure capture incomplete")
    seen = set()
    failure = {}
    fields = {
        "before": LEAF_WITNESS_FIELDS,
        "after": LEAF_WITNESS_FIELDS,
        "result": {"child-reaped", "child-signal", "child-signaled"},
        "failure": {"stage", "signal"},
    }
    for line in lines:
        match = re.fullmatch(r"leaf-witness-(before|after|result|failure)-([^=]+)=(.+)", line)
        if match is None:
            raise ProbeError("witness failure protocol malformed")
        phase, key, value = match.groups()
        if key not in fields[phase] or (phase, key) in seen:
            raise ProbeError("witness failure field unknown or duplicate")
        seen.add((phase, key))
        if phase == "failure":
            failure[key] = value
    if (
        failure.keys() != {"stage", "signal"}
        or failure["stage"] not in LEAF_WITNESS_FAILURE_STAGES
        or failure["signal"] not in {"none", "sigalrm", "sigterm", "sigint"}
    ):
        raise ProbeError("witness controller failure unavailable")
    return {"availability": "observed", "stage": failure["stage"], "receivedSignal": failure["signal"]}


def _leaf_witness_failure_command(
    collection: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    probe: tuple[str, str],
    deadline: float,
    command: tuple[str, str],
) -> str:
    budget.checkpoint()
    now = time.monotonic()
    remaining = min(deadline - now, collection.timeout, collection.runtime_deadline - now)
    reserved = collection.backend.command_timeout(remaining)
    if type(reserved) not in {int, float} or not math.isfinite(reserved) or reserved <= 0:
        raise ProbeError("witness failure capture reserve unavailable")
    allowance = min(remaining, reserved)
    if not math.isfinite(allowance) or allowance <= 0:
        raise ProbeError("witness failure capture allowance unavailable")
    raw = collection.exec(
        command[0],
        probe[0],
        "sh",
        "-euc",
        'endpoint=$2; docker() { command docker --host "$endpoint" --tls=false "$@"; }; ' + command[1],
        "--",
        probe[1],
        vars(collection).get("_leaf_witness_endpoint", "unix:///var/run/docker.sock"),
        timeout=allowance,
    )
    budget.checkpoint()
    if time.monotonic() > deadline:
        raise ProbeError("witness failure capture returned late")
    return raw


def _leaf_witness_failure_deadline(collection: RuntimeContext) -> float:
    timeout, work_deadline = collection.timeout, collection.runtime_deadline
    if any(type(value) not in {int, float} or not math.isfinite(value) for value in (timeout, work_deadline)):
        raise ProbeError("witness failure capture deadline unavailable")
    now = time.monotonic()
    return min(now + LEAF_WITNESS_FAILURE_CAPTURE_SECONDS, now + timeout, work_deadline)


def _leaf_witness_failure_capture(
    collection: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    workload: str | None,
    record: dict[str, Any],
) -> None:
    if record["enteredStage"] != "release-await-after" or workload is None:
        return
    capture: dict[str, Any] = {
        "availability": "unavailable",
        "enteredStage": None,
        "completedStage": None,
        "ociState": {"availability": "unavailable"},
        "controllerFailure": {"availability": "unavailable"},
    }
    record["failureCapture"] = capture
    try:
        deadline = _leaf_witness_failure_deadline(collection)
        capture["enteredStage"] = "owned-state"
        raw = _leaf_witness_failure_command(
            collection,
            budget,
            (container, workload),
            deadline,
            ("read private diagnostic leaf failure state", LEAF_WITNESS_FAILURE_STATE_COMMAND),
        )
        state = _leaf_witness_failure_state(raw, workload)
        _leaf_witness_require("witness failure state validation returned late", condition=time.monotonic() <= deadline)
        capture["ociState"] = state
        capture["completedStage"] = "owned-state"
        capture["enteredStage"] = "controller-failure"
        raw = _leaf_witness_failure_command(
            collection,
            budget,
            (container, workload),
            deadline,
            ("read private diagnostic leaf failure log", LEAF_WITNESS_FAILURE_LOG_COMMAND),
        )
        failure = _leaf_witness_failure_protocol(raw)
        _leaf_witness_require("witness failure log validation returned late", condition=time.monotonic() <= deadline)
        capture["controllerFailure"] = failure
        capture["completedStage"] = "controller-failure"
        capture["availability"] = "observed"
    except Exception:  # noqa: BLE001 — optional capture never replaces the original diagnostic failure.
        return


# Version-bound, witness-only archive protocol; never used for admission or the legacy probe.
LEAF_WITNESS_START = "/boxferry-leaf-witness-start"
LEAF_WITNESS_HTTP_BYTES = 32768
LEAF_WITNESS_REQUEST_BYTES = 4096
LEAF_WITNESS_API = "1.40"
LEAF_WITNESS_GO_TYPE = 0x8F280000
LEAF_WITNESS_BRIDGE = r"""
umask 077
scratch=$(busybox mktemp -d /tmp/boxferry-witness.XXXXXX) || exit 1
cleanup() {
    busybox rm -f "$scratch/input" "$scratch/decode.err" "$scratch/cli.err" "$scratch/proof" &&
    busybox rmdir "$scratch"
}
trap 'cleanup >/dev/null 2>&1' EXIT
limits() {
    ulimit -Sc 0 && ulimit -Hc 0 && test "$(ulimit -Sc)" = 0 && test "$(ulimit -Hc)" = 0 || return 1
    ulimit -Sf "$1" && ulimit -Hf "$1" && test "$(ulimit -Sf)" = "$1" && test "$(ulimit -Hf)" = "$1"
}
identity() {
    held=$(busybox stat -Lc '%d:%i:%u:%a:%h:%f' "/proc/self/fd/$2") || return 1
    case "$held" in *:0:600:1:8180) ;; *) return 1;; esac
    test "$(busybox stat -c '%d:%i:%u:%a:%h:%f' "$1")" = "$held" || return 1
    test -z "$3" || test "$held" = "$3"
}
empty() { identity "$1" "$2" "$3" && test "$(busybox stat -Lc %s "/proc/self/fd/$2")" = 0; }
fail() { cleanup >/dev/null 2>&1; trap - EXIT; printf '\nBFW1 FAIL %s\n' "$1"; exit 0; }
limits 16 || fail setup
set -C
exec 3>"$scratch/decode.err" 4>"$scratch/cli.err" 5>"$scratch/input" 7>"$scratch/proof" || fail setup
set +C
identity "$scratch/decode.err" 3 '' || fail custody
decode_identity=$held
identity "$scratch/cli.err" 4 '' || fail custody
cli_identity=$held
identity "$scratch/input" 5 '' || fail custody
input_identity=$held
identity "$scratch/proof" 7 '' || fail custody
proof_identity=$held
decode_status=0
( limits 16 && printf %s "$1" | busybox base64 -d >&5 2>&3 ) || decode_status=$?
test "$decode_status" = 0 || fail decode
empty "$scratch/decode.err" 3 "$decode_identity" || fail decode-stderr
identity "$scratch/input" 5 "$input_identity" || fail custody
test "$(busybox stat -Lc %s /proc/self/fd/5)" = "$3" || fail decode
exec 6<"$scratch/input" || fail custody
identity "$scratch/input" 6 "$input_identity" || fail custody
produce() {
    cli_status=0
    ( exec 7>&-; limits 1 || exit 125;
      docker --host "$2" --tls=false system dial-stdio <&6 2>&4 ) || cli_status=$?
    test "$cli_status" = 0 || { printf cli >&7; return 0; }
    empty "$scratch/cli.err" 4 "$cli_identity" || { printf cli-stderr >&7; return 0; }
    empty "$scratch/decode.err" 3 "$decode_identity" || { printf decode-stderr >&7; return 0; }
    identity "$scratch/input" 6 "$input_identity" || { printf custody >&7; return 0; }
    printf complete >&7
}
produce "$@" | busybox head -c 32641
identity "$scratch/proof" 7 "$proof_identity" || fail producer
proof_size=$(busybox stat -Lc %s /proc/self/fd/7) || fail producer
test "$proof_size" -gt 0 && test "$proof_size" -le 32 || fail producer
proof=$(busybox cat "$scratch/proof") || fail producer
identity "$scratch/proof" 7 "$proof_identity" || fail producer
test "$proof_size" = "${#proof}" || fail producer
case "$proof" in complete) ;; cli|cli-stderr|decode-stderr|custody) fail "$proof";; *) fail producer;; esac
cleanup >/dev/null 2>&1 || fail cleanup
trap - EXIT
printf '\nBFW1 OK complete\n'
"""
LEAF_WITNESS_BRIDGE_COMMAND = LEAF_WITNESS_BRIDGE


class _LeafArchiveError(ProbeError):
    def __init__(self, reason: str) -> None:
        super().__init__("witness archive unavailable")
        self.reason = reason


def _leaf_archive_require(reason: str, *, condition: bool) -> None:
    if not condition:
        raise _LeafArchiveError(reason)


def _leaf_archive_endpoint(mode: str) -> str:
    endpoints = {"rootless": "unix:///run/user/1000/docker.sock", "rootful": "unix:///var/run/docker.sock"}
    _leaf_archive_require("mode", condition=mode in endpoints)
    return endpoints[mode]


def _leaf_archive_remaining(ctx: RuntimeContext, end: float) -> float:
    now = time.monotonic()
    remaining = min(end - now, ctx.timeout, ctx.runtime_deadline - now)
    _leaf_archive_require("deadline", condition=math.isfinite(remaining) and remaining > 0)
    try:
        reserved = ctx.backend.command_timeout(remaining)
    except Exception as error:
        raise _LeafArchiveError("deadline") from error
    _leaf_archive_require(
        "deadline", condition=type(reserved) in {int, float} and math.isfinite(reserved) and reserved > 0
    )
    result = min(remaining, reserved)
    _leaf_archive_require("deadline", condition=math.isfinite(result) and result > 0)
    return result


def _leaf_archive_end(ctx: RuntimeContext) -> float:
    _leaf_archive_require(
        "deadline",
        condition=all(type(v) in {int, float} and math.isfinite(v) for v in (ctx.timeout, ctx.runtime_deadline)),
    )
    now = time.monotonic()
    reserved = ctx.backend.command_timeout(ctx.timeout)
    _leaf_archive_require(
        "deadline", condition=type(reserved) in {int, float} and math.isfinite(reserved) and reserved > 0
    )
    return min(now + ctx.timeout, ctx.runtime_deadline, now + reserved)


def _leaf_archive_api(value: object) -> tuple[int, int]:
    _leaf_archive_require(
        "api-version", condition=isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*\.[0-9]+", value) is not None
    )
    major, minor = str(value).split(".")
    return int(major), int(minor)


def _leaf_archive_tar(marker: str) -> bytes:
    _leaf_archive_require("marker", condition=marker in {LEAF_WITNESS_START, LEAF_WITNESS_START + ".finish"})
    info = tarfile.TarInfo(marker[1:])
    info.mode, info.uid, info.gid, info.mtime, info.size = 0o600, 0, 0, 0, 0
    return info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)


def _leaf_archive_request(method: str, target: str, body: bytes = b"") -> bytes:
    _leaf_archive_require(
        "request", condition=method in {"HEAD", "PUT"} and re.fullmatch(r"/[A-Za-z0-9_.%/?=&-]+", target) is not None
    )
    header = f"{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {len(body)}\r\n"
    if method == "PUT":
        header += "Content-Type: application/x-tar\r\n"
    result = (header + "\r\n").encode("ascii") + body
    _leaf_archive_require("request", condition=len(result) <= LEAF_WITNESS_REQUEST_BYTES)
    return result


def _leaf_archive_http(raw: bytes, method: str) -> tuple[int, dict[str, str], bytes]:
    _leaf_archive_require("response-size", condition=len(raw) <= LEAF_WITNESS_HTTP_BYTES)
    response, separator, receipt = raw.rpartition(b"\nBFW1 ")
    failure = re.fullmatch(rb"FAIL (setup|decode|decode-stderr|cli|cli-stderr|custody|cleanup|producer)\n", receipt)
    if separator and failure is not None:
        raise _LeafArchiveError("bridge-" + failure[1].decode("ascii"))
    _leaf_archive_require("bridge", condition=separator != b"" and receipt == b"OK complete\n")
    _leaf_archive_require("response-size", condition=len(response) <= LEAF_WITNESS_HTTP_BYTES - 128)
    header, separator, body = response.partition(b"\r\n\r\n")
    _leaf_archive_require("http-framing", condition=separator != b"" and len(header) <= MAX_ALLOCATOR_TELEMETRY)
    lines = header.split(b"\r\n")
    status = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", lines[0])
    _leaf_archive_require("http-framing", condition=status is not None and len(lines) <= MAX_CGROUP_DEPTH)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        _leaf_archive_require(
            "http-header",
            condition=sep != b""
            and len(line) <= LEAF_WITNESS_FAILURE_STATE_BYTES
            and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) is not None
            and re.fullmatch(rb"[\x20-\x7e]*", value) is not None,
        )
        name = key.decode("ascii").lower()
        _leaf_archive_require("http-header", condition=name not in headers)
        headers[name] = value.decode("ascii").strip()
    _leaf_archive_require(
        "http-framing",
        condition="transfer-encoding" not in headers
        and "trailer" not in headers
        and headers.get("content-encoding", "identity").lower() == "identity",
    )
    length = headers.get("content-length")
    if length is not None:
        _leaf_archive_require("http-framing", condition=re.fullmatch(r"[0-9]{1,20}", length) is not None)
    _leaf_archive_require(
        "http-framing", condition=not body if method == "HEAD" else length is None or int(length) == len(body)
    )
    return int(status[1]), headers, body


def _leaf_archive_timestamp(value: object) -> None:
    _leaf_archive_require(
        "after-stat",
        condition=isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
            r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        is not None,
    )
    try:
        datetime.fromisoformat(value)
    except ValueError as error:
        raise _LeafArchiveError("after-stat") from error


def _leaf_archive_after(headers: dict[str, str]) -> None:
    encoded = headers.get("x-docker-container-path-stat", "")
    _leaf_archive_require("after-stat", condition=0 < len(encoded) <= LEAF_WITNESS_FAILURE_STATE_BYTES)
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw, object_pairs_hook=_leaf_witness_unique_object)
    except (ValueError, UnicodeError, ProbeError) as error:
        raise _LeafArchiveError("after-stat") from error
    _leaf_archive_require(
        "after-stat",
        condition=isinstance(value, dict) and value.keys() == {"name", "size", "mode", "mtime", "linkTarget"},
    )
    _leaf_archive_require(
        "after-stat",
        condition=value["name"] == (LEAF_WITNESS_START + ".after")[1:]
        and type(value["size"]) is int
        and value["size"] == 0
        and type(value["mode"]) is int
        and 0 <= value["mode"] < 2**32
        and value["mode"] & LEAF_WITNESS_GO_TYPE == 0
        and value["mode"] & ~(0xFFF80000 | 0o777) == 0
        and value["linkTarget"] == ""
        and isinstance(value["mtime"], str)
        and re.fullmatch(r"[0-9T:.+Z-]{1,64}", value["mtime"]) is not None,
    )
    _leaf_archive_timestamp(value["mtime"])


class _LeafWitnessArchive:
    def __init__(
        self,
        ctx: RuntimeContext,
        budget: IsolatedStoreDiskBudget,
        probe: tuple[str, str],
        response: BinaryIO,
        record: dict[str, Any],
    ) -> None:
        self.original, self.budget = ctx, budget
        self.ctx = copy.copy(ctx)
        self.ctx.checks = []
        self.guest, self.mode = probe
        self.endpoint = _leaf_archive_endpoint(self.mode)
        vars(self.ctx)["_leaf_witness_endpoint"] = self.endpoint
        self.end = _leaf_archive_end(ctx)
        self.phase_end = self.end
        vars(self.ctx)["_leaf_protocol_end"] = self.end
        self.response, self.record = response, record
        self.nonce, self.image, self.workload = uuid.uuid4().hex, "", None
        self.custody = False
        self.cidfile = LEAF_WITNESS_CIDFILE + "." + self.nonce
        vars(self.ctx).update(
            _leaf_witness_nonce=self.nonce, _leaf_witness_mode=self.mode, _leaf_witness_cidfile=self.cidfile
        )
        record["archive"] = {
            "operation": "initialise",
            "reason": "unavailable",
            "preflight": False,
            "release": "unavailable",
        }

    def remaining(self) -> float:
        return _leaf_archive_remaining(self.ctx, min(self.end, self.phase_end))

    def command(self, name: str, *args: str) -> str:
        return _exec(
            self.ctx,
            self.budget,
            self.guest,
            name,
            "docker",
            "--host",
            self.endpoint,
            "--tls=false",
            *args,
            timeout=self.remaining(),
        )

    def rpc(self, method: str, marker: str, body: bytes = b"") -> tuple[int, dict[str, str]]:
        _leaf_archive_require(
            "identity",
            condition=isinstance(self.workload, str) and re.fullmatch(r"[a-f0-9]{64}", self.workload) is not None,
        )
        _leaf_archive_require(
            "identity",
            condition=self.guest in self.ctx.containers and re.fullmatch(r"[a-f0-9]{64}", self.guest) is not None,
        )
        target = f"/v{LEAF_WITNESS_API}/containers/{self.workload}/archive?path=" + quote(marker, safe="")
        if method == "PUT":
            target += "&noOverwriteDirNonDir=1"
        self.remaining()
        request = _leaf_archive_request(method, target, body)
        self.record["archive"].pop("httpStatus", None)
        self.record["archive"]["request"] = method.lower()
        self.ctx.reset_witness_response(self.response)
        self.budget.checkpoint()
        self.ctx.podman(
            "private diagnostic archive exchange",
            "exec",
            self.guest,
            *getattr(self.ctx, "exec_guard", ()),
            "/bin/dash",
            "-eu",
            "-c",
            LEAF_WITNESS_BRIDGE_COMMAND,
            "--",
            base64.b64encode(request).decode("ascii"),
            self.endpoint,
            str(len(request)),
            timeout=self.remaining(),
            stdout=self.response,
        )
        self.budget.checkpoint()
        self.remaining()
        raw = self.ctx.read_witness_response(self.response, LEAF_WITNESS_HTTP_BYTES)
        status, headers, response_body = _leaf_archive_http(raw, method)
        self.remaining()
        self.record["archive"]["httpStatus"] = status
        _leaf_archive_require("http-status", condition=status in {200, 404})
        _leaf_archive_require("http-framing", condition=not response_body)
        return status, headers

    def inspect(self, *, running: bool) -> None:
        raw = self.command("bind diagnostic archive identity", "inspect", "--format", "{{json .}}", str(self.workload))
        _leaf_archive_require("inspect-size", condition=len(raw.encode()) <= MAX_MEMORY_READBACK)
        value = json.loads(raw, object_pairs_hook=_leaf_witness_unique_object)
        _leaf_archive_require(
            "identity",
            condition=isinstance(value, dict)
            and all(isinstance(value.get(key), dict) for key in ("Config", "State", "HostConfig")),
        )
        labels = value["Config"].get("Labels")
        _leaf_archive_require("identity", condition=isinstance(labels, dict))
        _leaf_archive_require(
            "identity",
            condition=value.get("Id") == self.workload
            and value.get("Name") == "/" + LEAF_WITNESS_NAME
            and value.get("Image") == self.image
            and labels.get("org.strukturpiloten.witness") == self.nonce
            and labels.get("org.strukturpiloten.witness-mode") == self.mode
            and value.get("State", {}).get("Running") is running
            and value.get("Config", {}).get("Cmd")
            == ["docker-resource-probe", "memory-witness", "--wait-for-start", LEAF_WITNESS_START],
        )
        config = value.get("HostConfig", {})
        _leaf_archive_require("rootfs", condition=config.get("ReadonlyRootfs") is False and "Mounts" in value)
        mounts, tmpfs = value["Mounts"], config.get("Tmpfs", {})
        _leaf_archive_require(
            "mounts",
            condition=(mounts is None or isinstance(mounts, list)) and (tmpfs is None or isinstance(tmpfs, dict)),
        )
        destinations = [entry["Destination"] for entry in (mounts or [])] + list(tmpfs or {})
        for destination in destinations:
            _leaf_archive_require(
                "mounts",
                condition=isinstance(destination, str)
                and destination.startswith("/")
                and "//" not in destination
                and ".." not in destination.split("/")
                and "." not in destination.split("/"),
            )
            _leaf_archive_require(
                "mounts",
                condition=all(
                    not (
                        destination == "/"
                        or marker == destination.rstrip("/")
                        or marker.startswith(destination.rstrip("/") + "/")
                    )
                    for marker in (LEAF_WITNESS_START, LEAF_WITNESS_START + ".after", LEAF_WITNESS_START + ".finish")
                ),
            )
        if not running:
            _leaf_archive_require("identity", condition=value.get("State", {}).get("Status") == "created")
        self.remaining()

    def create(self) -> str:
        self.record["archive"]["operation"] = "image"
        version = json.loads(
            self.command("read diagnostic archive API range", "version", "--format", "{{json .Server}}")
        )
        _leaf_archive_require(
            "api-version",
            condition=_leaf_archive_api(version.get("MinAPIVersion"))
            <= _leaf_archive_api(LEAF_WITNESS_API)
            <= _leaf_archive_api(version.get("ApiVersion")),
        )
        self.image = self.command(
            "pin actual diagnostic witness image", "image", "inspect", "--format", "{{.Id}}", self.ctx.image_ref
        )
        _leaf_archive_require("image", condition=re.fullmatch(r"sha256:[a-f0-9]{64}", self.image) is not None)
        vars(self.ctx)["_leaf_witness_image"] = self.image
        self.record["archive"]["operation"] = "create-custody"
        _exec(
            self.ctx,
            self.budget,
            self.guest,
            "verify fresh diagnostic CID file",
            "sh",
            "-euc",
            'test ! -e "$1"; test ! -L "$1"',
            "--",
            self.cidfile,
        )
        self.record["archive"]["operation"] = "create"
        self.custody = True
        workload = self.command(
            "create diagnostic-only leaf memory witness",
            "create",
            "--name",
            LEAF_WITNESS_NAME,
            "--cidfile",
            self.cidfile,
            "--label",
            "org.strukturpiloten.witness=" + self.nonce,
            "--label",
            "org.strukturpiloten.witness-mode=" + self.mode,
            "--memory",
            str(MEMORY_BYTES),
            "--memory-swap",
            str(MEMORY_BYTES),
            "--pids-limit",
            str(INNER_PIDS),
            self.image,
            "docker-resource-probe",
            "memory-witness",
            "--wait-for-start",
            LEAF_WITNESS_START,
        )
        _leaf_archive_require("create-cid", condition=re.fullmatch(r"[a-f0-9]{64}", workload) is not None)
        self.workload = workload
        self.record["archive"]["operation"] = "preflight"
        self.inspect(running=False)
        for marker in (LEAF_WITNESS_START, LEAF_WITNESS_START + ".after", LEAF_WITNESS_START + ".finish"):
            status, _ = self.rpc("HEAD", marker)
            _leaf_archive_require("marker-exists", condition=status == HTTPStatus.NOT_FOUND)
        self.inspect(running=False)
        self.record["archive"]["preflight"] = True
        self.record["archive"]["operation"] = "start"
        _leaf_witness_room(self.original)
        _leaf_archive_require("start-room", condition=self.remaining() >= LEAF_WITNESS_SECONDS)
        result = self.command("start diagnostic-only leaf memory witness", "start", workload)
        _leaf_archive_require("start-uncertain", condition=result == workload)
        self.inspect(running=True)
        return workload

    def put(self, marker: str) -> None:
        status, _ = self.rpc("PUT", "/", _leaf_archive_tar(marker))
        _leaf_archive_require("put-uncertain", condition=status == HTTPStatus.OK)

    def await_after(self) -> None:
        self.phase_end = min(self.end, time.monotonic() + 8)
        self.record["archive"]["operation"] = "release"
        self.put(LEAF_WITNESS_START)
        self.record["archive"]["release"] = "extracted"
        self.record["archive"]["operation"] = "await-after"
        await_end = self.phase_end
        for _ in range(80):
            self.remaining()
            _leaf_archive_require("await-deadline", condition=time.monotonic() < await_end)
            self.inspect(running=True)
            status, headers = self.rpc("HEAD", LEAF_WITNESS_START + ".after")
            self.inspect(running=True)
            _leaf_archive_require("await-deadline", condition=time.monotonic() <= await_end)
            if status == HTTPStatus.OK:
                _leaf_archive_after(headers)
                self.remaining()
                self.record["awaitResult"] = "after-observed"
                self.phase_end = self.end
                return
            time.sleep(min(0.1, self.remaining(), max(0, await_end - time.monotonic())))
        self.record["awaitResult"] = "poll-exhausted"
        raise _LeafArchiveError("await-deadline")

    def finish(self) -> None:
        self.record["archive"]["operation"] = "finish"
        self.put(LEAF_WITNESS_START + ".finish")
        self.record["archive"]["reason"] = "complete"


def _leaf_witness_observe(archive: _LeafWitnessArchive) -> None:
    ctx, collection, budget, container, mode, record = (
        archive.original,
        archive.ctx,
        archive.budget,
        archive.guest,
        archive.mode,
        archive.record,
    )
    with _leaf_witness_stage(record, "launch"):
        workload = archive.create()
    with _leaf_witness_stage(record, "bind"):
        association = _leaf_witness_bind(collection, budget, container, (mode, workload), _retained_service(ctx, mode))
        controller = str(association["allocator"]["pid"])
    with _leaf_witness_stage(record, "root-before"):
        observer_ctx = copy.copy(collection)
        observer_ctx.runtime_deadline = min(observer_ctx.runtime_deadline, archive.end)
        observer_ctx.timeout = archive.remaining()
        observer = OomDiagnostics(observer_ctx, container)
        roots = [_leaf_witness_snapshot_root(observer, "root-before")]
    with _leaf_witness_stage(record, "release-await-after"):
        window = [time.monotonic_ns()]
        archive.await_after()
    with _leaf_witness_stage(record, "log-read"):
        output = archive.command("read private leaf witness protocol", "logs", workload)
    with _leaf_witness_stage(record, "controller-rebind"):
        after_raw = _exec(
            collection,
            budget,
            container,
            "rebind live diagnostic controller",
            "sh",
            "-euc",
            'endpoint=$4; docker() { command docker --host "$endpoint" --tls=false "$@"; }; '
            + MEMORY_ASSOCIATION_COMMAND,
            "--",
            association["allocator"]["group"],
            controller,
            workload,
            archive.endpoint,
        )
        after_association, _ = _association_records(after_raw)
        if any(after_association[key] != association[key] for key in after_association):
            _leaf_witness_require("witness controller or mount changed after child reap", condition=False)
    with _leaf_witness_stage(record, "retained-hierarchy"):
        after_hierarchy = _exec(
            collection,
            budget,
            container,
            "verify diagnostic leaf retained only controller",
            "sh",
            "-euc",
            HIERARCHY_READBACK_COMMAND,
            "--",
            "scope",
            mode,
            "docker-" + workload + ".scope",
        )
        _leaf_witness_retained_after(after_hierarchy, association)
    with _leaf_witness_stage(record, "root-after"):
        window.append(time.monotonic_ns())
        observer_ctx.timeout = archive.remaining()
        roots.append(_leaf_witness_snapshot_root(observer, "root-after"))
        archive.remaining()
    with _leaf_witness_stage(record, "projection-validation"):
        public = _leaf_witness_public(output, association, roots, window)
        archive.remaining()
        record.update(public)
    with _leaf_witness_stage(record, "finish-hold"):
        archive.finish()
    with _leaf_witness_stage(record, "wait-completion"):
        completion = archive.command("wait diagnostic controller completion", "wait", workload)
        record["controllerCompletion"] = "observation-complete" if completion == "0" else "failed"
        if completion != "0":
            record["availability"] = "unavailable"


def _leaf_witness_close_response(stack: ExitStack, record: dict[str, Any]) -> None:
    try:
        stack.close()
    except Exception:  # noqa: BLE001 — keep the original failure/cancellation and close-status refusal.
        record["availability"] = "unavailable"


def _collect_leaf_memory_witness(
    ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, mode: str
) -> None:
    """Observe a second leaf only after the existing outer marker has already refused admission."""
    record: dict[str, Any] = {
        "name": "inner leaf memory witness",
        "schemaVersion": 1,
        "purpose": LEAF_WITNESS_PURPOSE,
        "availability": "unavailable",
        "attribution": "unresolved",
        "authority": "observation-only",
        "controllerCompletion": "unavailable",
        "awaitResult": "unavailable",
        "enteredStage": None,
        "completedStage": None,
        "cleanupEnteredStage": None,
        "cleanupCompletedStage": None,
        "childTermination": "unavailable",
        "beforeStatus": "unavailable",
        "afterStatus": "unavailable",
        "bindings": {},
        "counters": {name: {"availability": "unavailable"} for name in ("memory.events", "memory.events.local")},
        "leafWindowMonotonicNs": None,
        "cleanup": "not-created",
        "limits": "separate non-atomic observation; no victim-cause or native qualification authority",
    }
    archive = None
    stack = ExitStack()
    try:
        with _leaf_witness_stage(record, "room-check"):
            _leaf_witness_room(ctx)
        response = stack.enter_context(ctx.private_witness_response())
        archive = _LeafWitnessArchive(ctx, budget, (container, mode), response, record)
        _leaf_witness_observe(archive)
    except Exception as error:  # noqa: BLE001 — optional diagnostics never replace the original native failure.
        record["availability"] = "unavailable"
        record.setdefault("archive", {"operation": "initialise"})["reason"] = (
            error.reason if isinstance(error, _LeafArchiveError) else "unavailable"
        )
        if archive is not None:
            _leaf_witness_failure_capture(archive.ctx, budget, container, archive.workload, record)
    finally:
        if archive is not None and archive.custody:
            _leaf_witness_cleanup_record(archive.ctx, container, archive.workload, record)
        _leaf_witness_close_response(stack, record)
        ctx.observations.append(record)


def verify_inner_limits(
    ctx: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    *,
    mode: str = "rootful",
    diagnostics: OomDiagnostics | None = None,
) -> None:
    """Read hard limits and require actual bounded OOM and PID refusal evidence."""
    for kind in ("memory", "pids"):
        name = f"docker-native-limit-{kind}"
        try:
            workload = _exec(
                ctx,
                budget,
                container,
                f"start bounded inner {kind} probe",
                "docker",
                "run",
                "--detach",
                "--name",
                name,
                "--memory",
                str(MEMORY_BYTES),
                "--memory-swap",
                str(MEMORY_BYTES),
                "--pids-limit",
                str(INNER_PIDS),
                ctx.image_ref,
                "docker-resource-probe",
                kind,
                "--wait-for-start",
                RESOURCE_START_FILE,
                *(("--memory-evidence",) if kind == "memory" else ()),
            )
            if not re.fullmatch(r"[a-f0-9]{64}", workload):
                raise ProbeError("inner resource probe did not return an exact owned container ID")
            scope_unit = "docker-" + workload + ".scope"
            hierarchy = _exec(
                ctx,
                budget,
                container,
                f"verify inner {kind} scope placement and ownership",
                "sh",
                "-euc",
                HIERARCHY_READBACK_COMMAND,
                "--",
                "scope",
                mode,
                scope_unit,
            )
            evidence = _hierarchy_evidence(hierarchy, kind="scope", mode=mode, unit=scope_unit)
            ctx.checks.append(evidence)
            _exec(
                ctx,
                budget,
                container,
                f"verify inner {kind} scope hard limits",
                "sh",
                "-euc",
                "scope=/sys/fs/cgroup$1; "
                'test "$(stat -c %i:%u "$scope")" = "$2"; '
                'test "$(cat "$scope/memory.max")" = "$3"; '
                'test "$(cat "$scope/pids.max")" = "$4"; printf "%s\\n" "$scope"',
                "--",
                evidence["controlGroup"],
                evidence["groups"][evidence["controlGroup"]][0],
                str(MEMORY_BYTES),
                str(INNER_PIDS),
            )
            association = (
                _read_memory_association(ctx, budget, container, workload, evidence) if kind == "memory" else {}
            )
            if kind == "memory" and diagnostics is not None:
                diagnostics.snapshot(
                    "before-inner-memory",
                    scope=association["allocator"]["group"],
                    scope_inode=int(association["scope-inode"]),
                )
            try:
                readback = _exec(
                    ctx,
                    budget,
                    container,
                    f"read exact inner {kind} cgroup limits",
                    "docker",
                    "exec",
                    name,
                    "sh",
                    "-euc",
                    "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max; touch /tmp/resource-start",
                )
                ctx.assert_equal(f"inner {kind} hard limit values", readback, f"{MEMORY_BYTES}\n{INNER_PIDS}")
            except BaseException:
                # Release can have reached the allocator even if exec/readback
                # failed. Preserve that failure and sample before owned removal.
                if kind == "memory" and diagnostics is not None:
                    diagnostics.snapshot("after-inner-memory")
                raise
            exit_code, state = _inner_enforcement_state(
                ctx, budget, container, (kind, workload), diagnostics=diagnostics
            )
            if kind == "memory":
                output = _exec(
                    ctx, budget, container, "read actual memory allocator self telemetry", "docker", "logs", workload
                )
                _memory_probe_result(ctx, association, output, exit_code, state)
                if _leaf_witness_needed(ctx, diagnostics):
                    _collect_leaf_memory_witness(ctx, budget, container, mode)
            else:
                output = _exec(ctx, budget, container, "read bounded inner PID refusal", "docker", "logs", name)
                event = re.fullmatch(r"bounded-pid-refusal events-before=(\d+) events-after=(\d+)", output)
                if exit_code != "0" or not event or int(event[2]) <= int(event[1]):
                    raise ProbeError("inner PID probe did not observe bounded EAGAIN refusal")
            _exec(ctx, budget, container, f"daemon responsive after inner {kind} enforcement", "docker", "info")
            verify_outer_container_limits(ctx, container)
        finally:
            ctx.exec(
                f"remove owned inner {kind} probe",
                container,
                "sh",
                "-euc",
                'docker info >/dev/null; if docker inspect "$1" >/dev/null 2>&1; then docker rm --force "$1"; fi',
                "--",
                name,
            )
            ctx.exec(
                f"read back owned inner {kind} absence",
                container,
                "sh",
                "-euc",
                'docker info >/dev/null; ! docker inspect "$1" >/dev/null 2>&1',
                "--",
                name,
            )


def _guest_state(ctx: RuntimeContext, container: str) -> dict[str, Any]:
    raw = ctx.podman("read owned systemd lifecycle state", "inspect", "--format", "{{json .State}}", container)
    try:
        state = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ProbeError("owned systemd lifecycle state is malformed") from error
    if not isinstance(state, dict) or type(state.get("Running")) is not bool:
        raise ProbeError("owned systemd lifecycle running state is missing or malformed")
    return state


def _assert_orderly_state(ctx: RuntimeContext, state: dict[str, Any]) -> None:
    expected: dict[str, Any] = {
        "Running": False,
        "Status": "exited",
        "ExitCode": 0,
        "OOMKilled": False,
        "Error": "",
        "Pid": 0,
        "Paused": False,
        "Restarting": False,
        "Dead": False,
    }
    if any(type(state.get(key)) is not type(value) or state[key] != value for key, value in expected.items()):
        ctx.checks.append({"name": "owned systemd orderly lifecycle state", "status": "failed", "actual": state})
        raise ProbeError("owned systemd guest must stop without OOM or OCI error and exit exactly zero")
    ctx.checks.append({"name": "owned systemd orderly lifecycle state", "status": "passed", "actual": state})


def _observe_before_stop(ctx: RuntimeContext, observer: Callable[[], None] | None) -> None:
    if observer is None:
        return
    try:
        observer()
    except Exception as error:  # noqa: BLE001 — evidence cannot alter the native shutdown result.
        ctx.observations.append(
            {
                "name": "owned systemd OOM custody",
                "phase": "before-stop-request",
                "availability": "error",
                "attribution": "unresolved",
                "reason": type(error).__name__,
            }
        )


def stop_guest(
    ctx: RuntimeContext,
    container: str,
    *,
    on_exit: Callable[[str, dict[str, Any]], None] | None = None,
    before_stop: Callable[[], None] | None = None,
) -> None:
    """Request exit.target without force; verify zero exit, never admit emergency halt."""
    if container not in ctx.containers:
        raise ProbeError("systemd shutdown target is not an owned guest")
    exact = ctx.podman("resolve owned systemd guest ID", "inspect", "--format", "{{.Id}}", container)
    if not re.fullmatch(r"[0-9a-f]{64}", exact) or (re.fullmatch(r"[0-9a-f]{64}", container) and exact != container):
        raise ProbeError("owned systemd guest identity is missing or inconsistent")
    exit_sampled = False

    def observe_exit(state: dict[str, Any]) -> None:
        nonlocal exit_sampled
        if on_exit is None or exit_sampled or state["Running"] is not False:
            return
        exit_sampled = True
        try:
            on_exit(exact, copy.deepcopy(state))
        except Exception as error:  # noqa: BLE001 — diagnostics cannot alter mandatory shutdown checks.
            ctx.observations.append(
                {
                    "name": "owned systemd OOM diagnostic",
                    "phase": "after-exit",
                    "availability": "error",
                    "attribution": "unresolved",
                    "reason": f"{type(error).__name__}: {error}",
                }
            )

    state = _guest_state(ctx, exact)
    if state["Running"] is False:
        observe_exit(state)
        _assert_orderly_state(ctx, state)
        return
    stop_signal = ctx.podman(
        "read owned systemd emergency stop signal", "inspect", "--format", "{{.Config.StopSignal}}", exact
    )
    normalized = "RTMIN+3" if stop_signal == str(int(signals.SIGRTMIN) + 3) else stop_signal.upper().removeprefix("SIG")
    ctx.assert_equal("owned systemd emergency stop signal", normalized, "RTMIN+3")
    # Deliberate lifecycle transition: prove placement before the request, not
    # after PID1 and its cgroups disappear. This is self-contained even when a
    # cancelled startup has not yet assigned ctx.exec_guard. No guest helper is
    # launched after this request; only exact-ID host readback establishes exit.
    request = PLACEMENT_GUARD + 'test "$(id -u)" = 0; test "$(cat /proc/1/comm)" = systemd; exec "$@"'
    try:
        _observe_before_stop(ctx, before_stop)
        ctx.podman(
            "request owned systemd exit.target with pre-shutdown placement guard",
            "exec",
            exact,
            "sh",
            "-euc",
            request,
            "--",
            "systemctl",
            "exit",
            "0",
            timeout=10,
        )
        result = ctx.podman("wait for owned systemd orderly exit", "wait", exact, timeout=30)
        ctx.assert_equal("owned systemd orderly exit", result, "0")
        state = _guest_state(ctx, exact)
        observe_exit(state)
        _assert_orderly_state(ctx, state)
    except ProbeError as error:
        # Cleanup may halt or force-remove this exact guest, but that fallback
        # must never turn a failed request, unsafe placement or timeout into
        # native admission, even if it happens to produce exit zero.
        try:
            ctx.stop(exact, seconds=30)
            observe_exit(_guest_state(ctx, exact))
        except ProbeError:
            pass
        raise ProbeError("owned systemd orderly shutdown failed; emergency halt is not native admission") from error
