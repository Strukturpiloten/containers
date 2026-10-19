"""Fail-closed guest systemd contract for dedicated Docker conformance images."""

# Fixed guest paths/argv and explicit failures are intentional evidence.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import json
import math
import re
import signal as signals
import time
from itertools import pairwise
from typing import TYPE_CHECKING, Any

from scripts.runtime_errors import ProbeError
from scripts.runtime_resource_budgets import verify_outer_container_limits

if TYPE_CHECKING:
    from scripts.runtime_oom_diagnostics import OomDiagnostics
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
USER_MANAGER = (
    "runuser",
    "-u",
    "dockertest",
    "--",
    "env",
    "HOME=/home/docker",
    "XDG_RUNTIME_DIR=/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    "systemctl",
    "--user",
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


PLACEMENT_GUARD = (
    "init=$(cut -d: -f3 /proc/1/cgroup); current=$(cut -d: -f3 /proc/self/cgroup); "
    'printf "%s\\n" "$init" | LC_ALL=C grep -Eq "^(/[A-Za-z0-9_.@:-]+)+$"; '
    'case "$init/" in */./*|*/../*) exit 90 ;; esac; '
    'test "$init" = "$current"; '
    'root_procs=$(cat /sys/fs/cgroup/cgroup.procs); test -z "$root_procs"; '
    'leaf_controllers=$(cat "/sys/fs/cgroup$current/cgroup.subtree_control"); test -z "$leaf_controllers"; '
)

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


def guarded_command(*args: str) -> tuple[str, ...]:
    """Refuse guest helpers in a distributor or outside the delegated parent."""
    script = PLACEMENT_GUARD + 'set +e; "$@"; result=$?; set -e; ' + PLACEMENT_GUARD + 'exit "$result"'
    return ("sh", "-euc", script, "--", *args)


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


def verify_runtime(ctx: RuntimeContext) -> None:
    """Verify the actual rootful launcher and crun version before starting a guest."""
    uid = ctx.command("systemd outer runtime identity", [*ctx._sudo, "id", "-u"])  # noqa: SLF001
    ctx.assert_equal("systemd requires rootful outer Podman", uid, "0")
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


def _exec(ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, name: str, *args: str) -> str:
    budget.checkpoint()
    result = ctx.exec(name, container, *args)
    budget.checkpoint()
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
            exit_code, state = _inner_enforcement_state(
                ctx, budget, container, (kind, workload), diagnostics=diagnostics
            )
            if kind == "memory":
                output = _exec(
                    ctx, budget, container, "read actual memory allocator self telemetry", "docker", "logs", workload
                )
                _memory_probe_result(ctx, association, output, exit_code, state)
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


def stop_guest(ctx: RuntimeContext, container: str) -> None:
    """Request exit.target without force; verify zero exit, never admit emergency halt."""
    if container not in ctx.containers:
        raise ProbeError("systemd shutdown target is not an owned guest")
    exact = ctx.podman("resolve owned systemd guest ID", "inspect", "--format", "{{.Id}}", container)
    if not re.fullmatch(r"[0-9a-f]{64}", exact) or (re.fullmatch(r"[0-9a-f]{64}", container) and exact != container):
        raise ProbeError("owned systemd guest identity is missing or inconsistent")
    state = _guest_state(ctx, exact)
    if state["Running"] is False:
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
        _assert_orderly_state(ctx, _guest_state(ctx, exact))
    except ProbeError as error:
        # Cleanup may halt or force-remove this exact guest, but that fallback
        # must never turn a failed request, unsafe placement or timeout into
        # native admission, even if it happens to produce exit zero.
        try:
            ctx.stop(exact, seconds=30)
            _guest_state(ctx, exact)
        except ProbeError:
            pass
        raise ProbeError("owned systemd orderly shutdown failed; emergency halt is not native admission") from error
