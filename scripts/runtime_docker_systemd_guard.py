"""Fixed stdlib-only guest placement guard and rootless fixture user contract."""

from __future__ import annotations

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


PLACEMENT_GUARD = (
    "init=$(cut -d: -f3 /proc/1/cgroup); current=$(cut -d: -f3 /proc/self/cgroup); "
    'printf "%s\\n" "$init" | LC_ALL=C grep -Eq "^(/[A-Za-z0-9_.@:-]+)+$"; '
    'case "$init/" in */./*|*/../*) exit 90 ;; esac; '
    'test "$init" = "$current"; '
    'root_procs=$(cat /sys/fs/cgroup/cgroup.procs); test -z "$root_procs"; '
    'leaf_controllers=$(cat "/sys/fs/cgroup$current/cgroup.subtree_control"); test -z "$leaf_controllers"; '
)


def guarded_command(*args: str) -> tuple[str, ...]:
    """Refuse guest helpers in a distributor or outside the delegated parent."""
    script = PLACEMENT_GUARD + 'set +e; "$@"; result=$?; set -e; ' + PLACEMENT_GUARD + 'exit "$result"'
    return ("sh", "-euc", script, "--", *args)
