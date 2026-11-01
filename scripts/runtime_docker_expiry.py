"""Stop one inode-bound private runtime slice at its original monotonic deadline.

Executed only inside the backend's root-owned transient expiry service. This is
not a reusable supervisor: it accepts one closed slice name, inode and deadline.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import time
from pathlib import Path

AGGREGATE_SECONDS = 1800
CLEANUP_RESERVE_SECONDS = 60


def expire(slice_name: str, identity: str, deadline_ns: int, ready_file: Path | None = None) -> None:
    """Wait without renewing authority, then request an exact owned-slice stop."""
    if os.geteuid() != 0 or re.fullmatch(r"strukturpiloten[0-9a-f]{32}\.slice", slice_name) is None:
        msg = "expiry service requires root and a closed private slice name"
        raise ValueError(msg)
    if re.fullmatch(r"[0-9]+:[0-9]+", identity) is None:
        msg = "expiry service requires an exact cgroup device/inode"
        raise ValueError(msg)
    remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if not -CLEANUP_RESERVE_SECONDS <= remaining <= AGGREGATE_SECONDS:
        msg = "expiry deadline is invalid or stale"
        raise ValueError(msg)
    cgroup = Path("/sys/fs/cgroup") / slice_name
    observed = cgroup.stat()
    if f"{observed.st_dev}:{observed.st_ino}" != identity:
        msg = "private runtime cgroup was replaced before expiry was armed"
        raise ValueError(msg)
    if ready_file is not None:
        descriptor = os.open(ready_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as ready:
            ready.write(f"{identity}|{deadline_ns}\n")
    while (remaining := (deadline_ns - time.monotonic_ns()) / 1_000_000_000) > 0:
        time.sleep(min(remaining, 1))
    try:
        observed = cgroup.stat()
    except FileNotFoundError:
        return
    if f"{observed.st_dev}:{observed.st_ino}" != identity:
        msg = "private runtime cgroup was replaced; expiry will not stop another slice"
        raise ValueError(msg)
    # This process already runs as root under the bounded expiry service. The
    # no-block request cannot wait behind stopping the slice being controlled.
    subprocess.run(  # noqa: S603 - closed argv after exact slice/inode validation.
        ["/usr/bin/systemctl", "stop", "--no-block", slice_name],
        check=True,
        capture_output=True,
        timeout=5,
    )


def main() -> None:
    """Parse the three immutable values passed by the owned Docker backend."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slice", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--deadline-ns", required=True, type=int)
    parser.add_argument("--ready-file", required=True, type=Path)
    args = parser.parse_args()
    expire(args.slice, args.identity, args.deadline_ns, args.ready_file)


if __name__ == "__main__":
    main()
