"""Independent process evidence and offline execution of the real journal readback."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import signal as signals
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.runtime_docker_systemd import (
    HIERARCHY_READBACK_COMMAND,
    JOURNAL_BOUNDARY_COMMAND,
    LEAF_WITNESS_STAGES,
    MEMORY_ASSOCIATION_COMMAND,
    MEMORY_BYTES,
    _allocator_records,
    _allocator_telemetry,
    _cgroup_ancestors,
    _cgroup_path,
    _collect_leaf_memory_witness,
    _hierarchy_evidence,
    _journal_boundary_evidence,
    _leaf_witness_association,
    _leaf_witness_needed,
    _leaf_witness_public,
    _leaf_witness_records,
    _leaf_witness_retained_after,
    _memory_association,
    _memory_probe_result,
    _memory_values,
    verify_inner_limits,
)
from scripts.runtime_tests import ProbeError

READBACK = """masked-unit=systemd-sysctl.service:masked:inactive
masked-unit=systemd-timesyncd.service:masked:inactive
masked-unit=systemd-journald-audit.socket:masked:inactive
masked-unit=systemd-tmpfiles-setup.service:masked:inactive
masked-unit=systemd-tmpfiles-clean.service:masked:inactive
normal-socket=systemd-journald.socket:active:listening
normal-socket=systemd-journald-dev-log.socket:active:listening
triggered-by=systemd-journald.socket systemd-journald-dev-log.socket systemd-journald-audit.socket
drop-in=verified
unit-capabilities=cap_chown cap_audit_read
journal-pid=42
journal-pid-after=42
journal-exe-before=/lib/systemd/systemd-journald
journal-exe-after=/lib/systemd/systemd-journald
journal-stat-before=42 (systemd-journal) S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 100 1
journal-stat-after=42 (systemd-journal) S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 100 1
journal-netns=net:[1234]
init-netns=net:[1234]
journal-netns-after=net:[1234]
init-netns-after=net:[1234]
CapEff=00000025002800cf
CapPrm=00000025002800cf
CapBnd=00000025002800cf
fd-before=0:socket:[100]
fd-before=1:socket:[101]
fd-before=2:socket:[102]
fd-before=3:/dev/null
fd-after=0:socket:[100]
fd-after=1:socket:[101]
fd-after=2:socket:[102]
fd-after=3:/dev/null
fd-count-before=4
fd-count-after=4
netlink-table-begin
sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
00000000 9 0 00000000 0 0 0 2 0 90
00000001 0 42 00000000 0 0 0 2 0 500
netlink-table-end
unix-table-begin
Num RefCount Protocol Flags Type St Inode Path
00000000: 00000002 00000000 00000000 0002 01 100 /run/systemd/journal/socket
00000001: 00000002 00000000 00000000 0002 01 101 /run/systemd/journal/dev-log
00000002: 00000002 00000000 00010000 0001 01 102 /run/systemd/journal/stdout
00000003: 00000002 00000000 00000000 0001 03 103 /run/systemd/journal/stdout
unix-table-end
systemd-version=247.3-7+deb11u8
"""

SYSTEMCTL = """
systemctl() {
    case "$*" in
        is-enabled*) printf '%s\\n' masked; return 1;;
        *systemd-journald.service*TriggeredBy*)
            printf '%s\\n' 'systemd-journald.socket systemd-journald-dev-log.socket systemd-journald-audit.socket';;
        *DropInPaths*) printf '%s\\n' "$BOUNDARY_FILE";;
        *CapabilityBoundingSet*) printf '%s\\n' 'cap_chown cap_audit_read';;
        *MainPID*)
            if [ -f "$PID_MARK" ]; then printf '%s\\n' "${PID_AFTER:-42}";
            else touch "$PID_MARK"; printf '%s\\n' 42; fi;;
        *systemd-journald.socket*ActiveState*|*systemd-journald-dev-log.socket*ActiveState*)
            printf '%s\\n' "${NORMAL_ACTIVE:-active}";;
        *SubState*) printf '%s\\n' "${SOCKET_SUBSTATE:-listening}";;
        *ActiveState*) printf '%s\\n' inactive;;
        *) return 2;;
    esac
}
readlink() {
    if [ "$1" = "$JOURNAL_EXE" ]; then
        if [ -f "$EXE_MARK" ] && [ -n "${EXE_AFTER:-}" ]; then printf '%s\\n' "$EXE_AFTER";
        else touch "$EXE_MARK"; /usr/bin/readlink "$@"; fi
    else /usr/bin/readlink "$@"; fi
}
cat() {
    if [ "$1" = "$JOURNAL_STAT" ]; then
        if [ -f "$STAT_MARK" ] && [ -n "${STAT_AFTER:-}" ]; then printf '%s\\n' "$STAT_AFTER";
        else touch "$STAT_MARK"; /bin/cat "$@"; fi
    else /bin/cat "$@"; fi
}
"""

DPKG_QUERY = "#!/bin/sh\nprintf %s '247.3-7+deb11u8'\n"


def _fixture_roles(kind: str, mode: str) -> dict[str, tuple[int, str]]:
    roles = {
        "main": (55, "rootlesskit" if mode == "rootless" else "dockerd"),
        "daemon": (89 if mode == "rootless" else 55, "dockerd"),
    }
    if kind == "scope":
        roles = {"probe-101": (101, "docker-resource-probe")}
    if mode == "rootless":
        roles["manager"] = (44, "systemd")
    return roles


def _fixture_parent_paths(paths: set[str]) -> set[str]:
    # Explicit parent graph construction for fixture data only.
    paths = paths.copy()
    for path in list(paths):
        parent = path
        while parent != "/":
            parent = parent.rsplit("/", 1)[0] or "/"
            paths.add(parent)
    return paths


def hierarchy_fixture(*, kind: str = "service", mode: str = "rootful", service_child: bool = False) -> str:
    """Independent sibling-scope layouts, not inferred from daemon service ancestry."""
    uid = "1000" if mode == "rootless" else "0"
    manager = "/user.slice/user-1000.slice/user@1000.service"
    dispatcher = manager + "/different.slice" if mode == "rootless" else "/system.slice"
    unit = "docker.service" if kind == "service" else "docker-" + "a" * 64 + ".scope"
    target = dispatcher + "/" + unit
    leaves = {target: "55 89" if kind == "service" else "101"}
    if service_child:
        leaves = {target + "/daemon": "55 89"}
    paths = set(leaves) | {target}
    if mode == "rootless":
        leaves[manager + "/init.scope"] = "44"
        paths.update({manager, manager + "/init.scope"})
    paths = _fixture_parent_paths(paths)
    lines = []
    for phase in ("before", "after"):
        lines.extend(
            f"unit-{phase}={key}={value}"
            for key, value in {"ControlGroup": target, "Delegate": "yes", "ActiveState": "active"}.items()
        )
        if kind == "service":
            lines.append(f"unit-{phase}=MainPID=55")
        if mode == "rootless":
            lines.extend(
                f"manager-{phase}={key}={value}"
                for key, value in {
                    "ControlGroup": manager,
                    "Delegate": "yes",
                    "ActiveState": "active",
                    "MainPID": "44",
                }.items()
            )
        for inode, path in enumerate(sorted(paths), 10):
            subtree = "" if path in leaves else "cpuset cpu io memory pids"
            owner = uid if path == target or path.startswith(manager) else "0"
            lines.append(
                f"group-{phase}={path}|{inode}:{owner}|domain|cpuset cpu io memory pids|"
                f"{subtree}|{leaves.get(path, '')}"
            )
        if kind == "scope":
            lines.append(f"scope-{phase}=/sys/fs/cgroup{target}")
        for role, (pid, executable) in _fixture_roles(kind, mode).items():
            group = manager + "/init.scope" if role == "manager" else target + ("/daemon" if service_child else "")
            stat = f"{pid} ({executable}) S " + "1 " * 18 + "100 1"
            lines.append(f"process-{phase}={role}|{pid}|{uid} {uid} {uid} {uid}|{group}|/usr/bin/{executable}|{stat}")
    return "\n".join(lines)


def _memory_fixture_scope(mode: str) -> tuple[str, str]:
    output = hierarchy_fixture(kind="scope", mode=mode)
    line = next(line for line in output.splitlines() if line.startswith("group-before=") and "docker-" in line)
    fields = line.removeprefix("group-before=").split("|")
    return fields[0], fields[1].split(":")[0]


def _memory_fixture_process(mode: str, role: str) -> list[str]:
    kind = "scope" if role == "allocator" else "service"
    prefix = "process-before=probe-101|" if kind == "scope" else "process-before=daemon|"
    output = hierarchy_fixture(kind=kind, mode=mode)
    line = next(line for line in output.splitlines() if line.startswith(prefix))
    _role, pid, uids, group, exe, stat = line.partition("=")[2].split("|")
    rootless = mode == "rootless"
    if role == "allocator":
        nspid, pidns, cgroupns = (
            ("101 201 1", "pid:[702]", "cgroup:[802]") if rootless else ("101 1", "pid:[701]", "cgroup:[801]")
        )
    else:
        nspid, pidns, cgroupns = (
            ("89 7", "pid:[701]", "cgroup:[800]") if rootless else ("55", "pid:[700]", "cgroup:[800]")
        )
    userns = "user:[902]" if rootless else "user:[900]"
    uidmap = "0 1000 1;1 231072 65536" if rootless else "0 0 4294967295"
    return [pid, uids, "0::" + group, exe, stat, nspid, pidns, cgroupns, userns, uidmap]


def memory_association_fixture(*, mode: str = "rootful", swap_max: str = "0") -> str:
    """Kernel namespace ancestry plus mapped outer identities, independent expected data."""
    _target, inode = _memory_fixture_scope(mode)
    rootless = mode == "rootless"
    lines = []
    for phase in ("before", "after"):
        lines.extend(
            f"association-{phase}-{role}=" + "|".join(_memory_fixture_process(mode, role))
            for role in ("allocator", "daemon")
        )
        for key, value in {
            "ancestry": "pid:[702] pid:[701]" if rootless else "pid:[701] pid:[700]",
            "docker-pid": "201" if rootless else "101",
            "scope-inode": inode,
            "mount-inode": inode,
            "mount-type": "63677270",
        }.items():
            lines.append(f"association-{phase}-{key}={value}")
    for key, value in {
        "memory.max": str(MEMORY_BYTES),
        "memory.current": "4096",
        "memory.swap.max": swap_max,
        "memory.swap.current": "0",
        "memory.events": "low 0;high 0;max 0;oom 0;oom_kill 0",
    }.items():
        lines.append(f"scope-{key}={value}")
    return "\n".join(lines)


def allocator_telemetry_fixture(*, mode: str = "rootful", after: bool = False, swap_max: str = "0") -> str:
    """Inner PID1/UID0 and relative root view correlate via kernel namespace/inode identity."""
    _target, inode = _memory_fixture_scope(mode)
    rootless = mode == "rootless"
    identity = {
        "pid": "1",
        "uids": "0 0 0 0",
        "nspid": "1",
        "starttime": "100",
        "cgroup": "0::/",
        "exe": "/usr/bin/docker-resource-probe",
        "pidns": "pid:[702]" if rootless else "pid:[701]",
        "cgroupns": "cgroup:[802]" if rootless else "cgroup:[801]",
        "userns": "user:[902]" if rootless else "user:[900]",
        "scope-inode": inode,
        "mount-type": "63677270",
        "memory.max": str(MEMORY_BYTES),
        "memory.swap.max": swap_max,
        "memory.swap.current": "0",
        "memory.events": "low 0;high 0;max 0;oom 0;oom_kill 0",
        "complete": "yes",
    }
    lines = []
    for phase in ("before", "after") if after else ("before",):
        fields = {**identity, "memory.current": "134217728" if phase == "after" else "4096"}
        lines.extend(f"allocator-{phase}-{key}={value}" for key, value in fields.items())
    return "\n".join(lines)


def _write_hierarchy_fixture(directory: Path, output: str) -> tuple[str, str]:
    unit_properties, manager_properties = [], []
    for line in output.splitlines():
        prefix, _, value = line.partition("=")
        if prefix == "group-before":
            group, identity, group_type, controllers, subtree, procs = value.split("|")
            path = directory / "cgroup" / group.removeprefix("/")
            path.mkdir(parents=True, exist_ok=True)
            for name, content in {
                "identity": identity,
                "cgroup.type": group_type,
                "cgroup.controllers": controllers,
                "cgroup.subtree_control": subtree,
                "cgroup.procs": "\n".join(procs.split()),
            }.items():
                (path / name).write_text(content)
        elif prefix == "process-before":
            _role, pid, uids, group, executable, stat = value.split("|")
            path = directory / "proc" / pid
            path.mkdir(parents=True, exist_ok=True)
            (path / "cgroup").write_text("0::" + group)
            (path / "status").write_text("Uid:\t" + uids + "\n")
            (path / "stat").write_text(stat)
            if not (path / "exe").is_symlink():
                (path / "exe").symlink_to(executable)
        elif prefix == "unit-before":
            unit_properties.append(value)
        elif prefix == "manager-before":
            manager_properties.append(value)
    (directory / "unit-properties").write_text("\n".join(unit_properties))
    (directory / "manager-properties").write_text("\n".join(manager_properties))
    target = next(
        property_.removeprefix("ControlGroup=")
        for property_ in unit_properties
        if property_.startswith("ControlGroup=")
    )
    return target, target.rsplit("/", 1)[1]


def _alter_hierarchy_fixture(directory: Path, target: str, unit: str, kind: str, failure: str | None) -> None:
    parent = directory / "cgroup" / target.rsplit("/", 1)[0].removeprefix("/")
    if failure == "missing-controller":
        (parent / "cgroup.subtree_control").write_text("cpu pids")
    elif failure == "populated-parent":
        (parent / "cgroup.procs").write_text("77")
    elif failure == "scope-collision" and kind == "scope":
        (directory / "cgroup/another.slice" / unit).mkdir(parents=True)
    elif failure == "missing-root-file":
        (directory / "cgroup/cgroup.procs").unlink()
    elif failure == "missing-root-controller":
        (directory / "cgroup/cgroup.controllers").write_text("cpu pids")
    elif failure == "populated-root":
        (directory / "cgroup/cgroup.procs").write_text("77")


HIERARCHY_READERS = r"""
systemctl() {
    case "$*" in *user@1000.service*) file=$FIXTURE/manager-properties;; *) file=$FIXTURE/unit-properties;; esac
    case "$*" in *--value*) sed -n 's/^MainPID=//p' "$file";; *) /bin/cat "$file";; esac
}
runuser() {
    while [ "$1" != systemctl ]; do shift; done
    shift; systemctl "$@"
}
stat() { test "$2" = '%i:%u'; /bin/cat "$3/identity"; }
pgrep() { if [ "$MODE" = rootless ]; then printf 89; else printf 55; fi; }
"""


class MemoryDiagnosticTests(unittest.TestCase):
    def evidence(self, mode: str = "rootful") -> tuple[dict[str, object], dict[str, object]]:
        scope = _hierarchy_evidence(
            hierarchy_fixture(mode=mode, kind="scope"), kind="scope", mode=mode, unit="docker-" + "a" * 64 + ".scope"
        )
        service = _hierarchy_evidence(hierarchy_fixture(mode=mode), kind="service", mode=mode, unit="docker.service")
        return scope, service

    def association(self, mode: str = "rootful", swap_max: str = "0") -> dict[str, object]:
        scope, service = self.evidence(mode)
        return _memory_association(memory_association_fixture(mode=mode, swap_max=swap_max), scope, service)

    def test_kernel_event_versions_retain_optional_socket_and_group_counters(self) -> None:
        # Independent Linux v7.2 memory.events schema, also observed by candidate 802e427.
        required = "low 0;high 0;max 0;oom 0;oom_kill 0"
        for optional in ("", ";oom_group_kill 0", ";sock_throttled 0", ";oom_group_kill 0;sock_throttled 0"):
            with self.subTest(optional=optional):
                fields = {
                    "memory.max": "33554432",
                    "memory.current": "2510848",
                    "memory.swap.max": "max",
                    "memory.swap.current": "0",
                    "memory.events": required + optional,
                }
                expected = {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0}
                if "oom_group_kill" in optional:
                    expected["oom_group_kill"] = 0
                if "sock_throttled" in optional:
                    expected["sock_throttled"] = 0
                self.assertEqual(_memory_values(fields)["memory.events"], expected)
                for value in ("0", "18446744073709551615"):
                    fields["memory.events"] = required + ";sock_throttled " + value
                    self.assertEqual(_memory_values(fields)["memory.events"]["sock_throttled"], int(value))

    def test_optional_socket_counter_rejects_invalid_values_duplicates_unknowns_and_missing_required(self) -> None:
        required = "low 0;high 0;max 0;oom 0;oom_kill 0"
        scope, service = self.evidence()
        original = memory_association_fixture()
        malformed = [
            required + ";sock_throttled " + value
            for value in ("-1", "max", "1.5", "", "+1", "x", "18446744073709551616")
        ]
        malformed.extend(
            (
                required + ";sock_throttled 0;sock_throttled 1",
                required + ";sock_throttled 0;future_event 0",
            )
        )
        malformed.extend(
            ";".join(row for row in required.split(";") if row.split()[0] != key) + ";sock_throttled 0"
            for key in ("low", "high", "max", "oom", "oom_kill")
        )
        for events in malformed:
            with self.subTest(events=events), self.assertRaises(ProbeError):
                _memory_association(original.replace(required, events), scope, service)
            with self.subTest(telemetry=events), self.assertRaises(ProbeError):
                _allocator_telemetry(
                    allocator_telemetry_fixture().replace(required, events), self.association(), genuine_oom=True
                )

    def test_socket_counter_progression_is_retained_and_regression_or_disappearance_fails(self) -> None:
        required = "low 0;high 0;max 0;oom 0;oom_kill 0"
        for mode in ("rootful", "rootless"):
            scope, service = self.evidence(mode)
            association = _memory_association(
                memory_association_fixture(mode=mode).replace(required, required + ";sock_throttled 5"),
                scope,
                service,
            )
            original = allocator_telemetry_fixture(mode=mode, after=True)
            output = original.replace(
                "allocator-before-memory.events=" + required,
                "allocator-before-memory.events=" + required + ";sock_throttled 6",
            ).replace(
                "allocator-after-memory.events=" + required,
                "allocator-after-memory.events=" + required + ";sock_throttled 7",
            )
            with self.subTest(mode=mode):
                result = _allocator_telemetry(output, association, genuine_oom=False)
                self.assertEqual(result["before"]["memory"]["memory.events"]["sock_throttled"], 6)
                self.assertEqual(result["after"]["memory"]["memory.events"]["sock_throttled"], 7)
                ctx = MagicMock(checks=[])
                _memory_probe_result(ctx, association, output, "137", {"OOMKilled": True})
                self.assertEqual(ctx.checks[-1]["status"], "passed")
            for changed in (
                output.replace(";sock_throttled 6", ";sock_throttled 4"),
                output.replace(";sock_throttled 6", ""),
                output.replace(";sock_throttled 7", ";sock_throttled 5"),
                output.replace(";sock_throttled 7", ""),
            ):
                with self.subTest(mode=mode, changed=changed[-100:]), self.assertRaisesRegex(ProbeError, "regressed"):
                    _allocator_telemetry(changed, association, genuine_oom=True)

    def test_native_socket_counter_does_not_admit_unlimited_swap_even_with_real_oom(self) -> None:
        required = "low 0;high 0;max 0;oom 0;oom_kill 0"
        scope, service = self.evidence()
        association = _memory_association(
            memory_association_fixture(swap_max="max").replace(
                required, required + ";oom_group_kill 0;sock_throttled 0"
            ),
            scope,
            service,
        )
        output = allocator_telemetry_fixture(swap_max="max").replace(
            required, required + ";oom_group_kill 0;sock_throttled 0"
        )
        ctx = MagicMock(checks=[])
        with self.assertRaisesRegex(ProbeError, "unexpected effective swap"):
            _memory_probe_result(ctx, association, output, "137", {"OOMKilled": True})
        self.assertEqual(ctx.checks[-1]["status"], "failed")
        self.assertFalse(ctx.checks[-1]["effectiveNoSwap"])
        self.assertEqual(ctx.checks[-1]["telemetry"]["before"]["memory"]["memory.events"]["sock_throttled"], 0)

    def test_allocator_self_pid1_and_uid0_are_bound_to_mapped_guest_process_in_both_modes(self) -> None:
        for mode in ("rootful", "rootless"):
            with self.subTest(mode=mode):
                association = self.association(mode)
                result = _allocator_telemetry(allocator_telemetry_fixture(mode=mode), association, genuine_oom=True)
                self.assertEqual(association["allocator"]["pid"], 101)
                self.assertEqual(result["before"]["identity"]["pid"], 1)
                self.assertEqual(result["before"]["identity"]["uids"], [0] * 4)
                self.assertEqual(association["allocator"]["uids"], [1000 if mode == "rootless" else 0] * 4)
                self.assertEqual(result["before"]["identity"]["scope-inode"], int(association["scope-inode"]))
                self.assertIsNone(result["after"])
                ctx = MagicMock(checks=[])
                _memory_probe_result(
                    ctx, association, allocator_telemetry_fixture(mode=mode), "137", {"OOMKilled": True}
                )
                self.assertTrue(ctx.checks[-1]["enforcementSatisfied"])

    def test_surviving_allocator_reports_swap_without_admitting_exit4_or_conflating_no_swap_with_oom(self) -> None:
        for swap_max in ("0", "67108864", "max"):
            with self.subTest(swap_max=swap_max):
                association = self.association(swap_max=swap_max)
                output = allocator_telemetry_fixture(after=True, swap_max=swap_max)
                if swap_max != "0":
                    output = output.replace(
                        "allocator-after-memory.swap.current=0", "allocator-after-memory.swap.current=83886080"
                    )
                ctx = MagicMock(checks=[])
                with self.assertRaisesRegex(ProbeError, "lacked genuine Docker OOM"):
                    _memory_probe_result(ctx, association, output, "4", {"OOMKilled": False})
                diagnostic = ctx.checks[-1]
                self.assertFalse(diagnostic["enforcementSatisfied"])
                self.assertEqual(diagnostic["telemetry"]["after"]["memory"]["memory.current"], 134217728)
                self.assertEqual(diagnostic["effectiveNoSwap"], swap_max == "0")

    def test_real_oom_does_not_require_post_allocation_record_but_requires_actual_before_and_zero_swap(self) -> None:
        association = self.association()
        for output in ("", allocator_telemetry_fixture().replace("allocator-before-memory.swap.max=0\n", "")):
            with self.subTest(output=output[:80]), self.assertRaises(ProbeError):
                _memory_probe_result(MagicMock(checks=[]), association, output, "137", {"OOMKilled": True})
        swapped = self.association(swap_max="max")
        with self.assertRaisesRegex(ProbeError, "unexpected effective swap"):
            _memory_probe_result(
                MagicMock(checks=[]), swapped, allocator_telemetry_fixture(swap_max="max"), "137", {"OOMKilled": True}
            )
        with self.assertRaisesRegex(ProbeError, "omitted its post-allocation"):
            _allocator_telemetry(allocator_telemetry_fixture(), association, genuine_oom=False)

    def test_wrong_exit_or_oom_state_stays_rejected_with_valid_diagnostic(self) -> None:
        for exit_code, state in (("0", True), ("137", False), ("4", False), ("137", "true")):
            with (
                self.subTest(exit_code=exit_code, state=state),
                self.assertRaisesRegex(ProbeError, "lacked genuine Docker OOM"),
            ):
                _memory_probe_result(
                    MagicMock(checks=[]),
                    self.association(),
                    allocator_telemetry_fixture(after=True),
                    exit_code,
                    {"OOMKilled": state},
                )

    def test_changed_mapped_allocator_daemon_mount_and_namespace_ancestry_fail_closed(self) -> None:
        for mode in ("rootful", "rootless"):
            original = memory_association_fixture(mode=mode)
            scope, service = self.evidence(mode)
            allocator = "|".join(_memory_fixture_process(mode, "allocator"))
            daemon = "|".join(_memory_fixture_process(mode, "daemon"))
            for changed in (
                original.replace(allocator, allocator.replace("|100 1", "|200 1")),
                original.replace(allocator, allocator.replace("100 1|", "200 1|")),
                original.replace(allocator, allocator.replace("/usr/bin/docker-resource-probe", "/usr/bin/other")),
                original.replace(daemon, daemon.replace("100 1|", "200 1|")),
                original.replace(daemon, daemon.replace("docker.service", "other.service")),
                original.replace(daemon, daemon.replace("/usr/bin/dockerd", "/usr/bin/other")),
                original.replace("mount-type=63677270", "mount-type=01021994"),
                original.replace(
                    "mount-inode=" + scope["groups"][scope["controlGroup"]][0].split(":")[0], "mount-inode=999"
                ),
                original.replace(
                    "ancestry=pid:[702] pid:[701]" if mode == "rootless" else "ancestry=pid:[701] pid:[700]",
                    "ancestry=pid:[702] pid:[999]" if mode == "rootless" else "ancestry=pid:[701] pid:[999]",
                ),
                original.replace("docker-pid=201" if mode == "rootless" else "docker-pid=101", "docker-pid=999"),
                original.replace("scope-memory.swap.max=0", "scope-memory.swap.max=invalid"),
            ):
                if changed == original:
                    continue
                with self.subTest(mode=mode, prefix=changed[:100]), self.assertRaises(ProbeError):
                    _memory_association(changed, scope, service)
            sibling = (
                original.replace(allocator, allocator.replace("101 201 1", "101 1"))
                if mode == "rootless"
                else original.replace(daemon, daemon.replace("pid:[700]", "pid:[999]"))
            )
            with self.assertRaisesRegex(ProbeError, "kernel-bound descendant"):
                _memory_association(sibling, scope, service)

    def test_mapping_and_source_records_reject_malformed_duplicate_unknown_and_oversized_data(self) -> None:
        original = memory_association_fixture(mode="rootless")
        scope, service = self.evidence("rootless")
        for changed in (
            original + "\n" + original.splitlines()[0],
            original + "\nunknown=value",
            "\n".join(original.splitlines()[1:]),
            original + "x" * 65537,
            original.replace("0 1000 1;1 231072 65536", "0 1001 1;1 231072 65536"),
            original.replace("0 1000 1;1 231072 65536", "1 231072 65536"),
            original.replace("0 1000 1;1 231072 65536", "0 1000 2;1 231072 65536"),
            original.replace("0 1000 1;1 231072 65536", "0 1000 1;1 1000 1"),
            original.replace("101 201 1", "101 0 1"),
            original.replace("scope-memory.swap.current=0", "scope-memory.swap.current=-1"),
            original.replace("scope-memory.events=low 0", "scope-memory.events=unknown 0"),
            original.replace("oom_kill 0", "oom_kill 0;oom_kill 0"),
        ):
            with self.subTest(prefix=changed[:100]), self.assertRaises(ProbeError):
                _memory_association(changed, scope, service)

    def test_allocator_records_reject_missing_changed_or_unrelated_self_readbacks(self) -> None:
        original = allocator_telemetry_fixture(after=True)
        for before, after in (
            ("starttime=100", "starttime=200"),
            ("pid=1\n", "pid=101\n"),
            ("uids=0 0 0 0", "uids=1000 1000 1000 1000"),
            ("cgroup=0::/", "cgroup=0::/other"),
            ("exe=/usr/bin/docker-resource-probe", "exe=/usr/bin/other"),
            ("pidns=pid:[701]", "pidns=pid:[999]"),
            ("cgroupns=cgroup:[801]", "cgroupns=cgroup:[999]"),
            ("userns=user:[900]", "userns=user:[999]"),
            ("mount-type=63677270", "mount-type=01021994"),
            ("memory.max=33554432", "memory.max=67108864"),
            ("memory.swap.max=0", "memory.swap.max=1"),
            ("memory.swap.current=0", "memory.swap.current=max"),
            ("complete=yes", "complete=no"),
        ):
            with self.subTest(change=after), self.assertRaises(ProbeError):
                _allocator_telemetry(original.replace(before, after), self.association(), genuine_oom=True)
        for changed in (
            original + "\n" + original.splitlines()[0],
            original + "\ntrailing=data",
            original + "\nallocator-before-unknown=value",
            original + "x" * 8193,
            original.replace("allocator-after-complete=yes\n", ""),
            original.replace("allocator-before-memory.swap.max=0\n", ""),
        ):
            with self.subTest(prefix=changed[:80]), self.assertRaises(ProbeError):
                _allocator_telemetry(changed, self.association(), genuine_oom=True)

    def test_bounded_reader_checks_raw_bytes_before_trailing_newline_trimming(self) -> None:
        reader = MEMORY_ASSOCIATION_COMMAND.split("identity() {", 1)[0] + '\nbounded "$4" 4'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value"
            for contents, accepted in ((b"1234", True), (b"123\n", True), (b"1234\n", False), (b"12345", False)):
                path.write_bytes(contents)
                result = subprocess.run(  # noqa: S603 — bounded task-local reader only.
                    ["/bin/sh", "-euc", reader, "--", "scope", "101", "owned", str(path)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_retained_service_restart_and_rootless_manager_drift_are_rejected(self) -> None:
        for mode in ("rootful", "rootless"):
            scope, service = self.evidence(mode)
            original = memory_association_fixture(mode=mode)
            daemon = "|".join(_memory_fixture_process(mode, "daemon"))
            replacement = daemon.split("|")
            old_pid = replacement[0]
            replacement[4] = "999" + replacement[4][len(old_pid) :]
            replacement[5] = "999" + replacement[5][len(old_pid) :]
            replacement[0] = "999"
            changed = original.replace(daemon, "|".join(replacement))
            with self.subTest(mode=mode), self.assertRaisesRegex(ProbeError, "retained service identity"):
                _memory_association(changed, scope, service)
        scope, service = self.evidence("rootless")
        scope["processes"]["manager"] = list(scope["processes"]["manager"])
        scope["processes"]["manager"][0] = "45"
        with self.assertRaisesRegex(ProbeError, "user manager changed"):
            _memory_association(memory_association_fixture(mode="rootless"), scope, service)

    def test_counter_regression_overflow_and_changed_inode_fail_while_current_over_max_is_diagnostic(self) -> None:
        association = self.association()
        original = allocator_telemetry_fixture(after=True)
        for changed in (
            original.replace("memory.current=4096", "memory.current=18446744073709551616"),
            original.replace("memory.events=low 0", "memory.events=low -1"),
            original.replace(
                "allocator-before-memory.events=low 0;high 0;max 0;oom 0",
                "allocator-before-memory.events=low 0;high 0;max 0;oom 1",
            ),
            original.replace("scope-inode=" + association["scope-inode"], "scope-inode=999"),
        ):
            with self.subTest(prefix=changed[:100]), self.assertRaises(ProbeError):
                _allocator_telemetry(changed, association, genuine_oom=True)
        result = _allocator_telemetry(original, association, genuine_oom=True)
        self.assertGreater(result["after"]["memory"]["memory.current"], MEMORY_BYTES)

    def test_verified_before_survives_near_bound_partial_after_without_any_admission(self) -> None:
        before = allocator_telemetry_fixture()
        output = before + "\nallocator-after-exe=" + "x" * (7900 - len(before))
        ctx = MagicMock(checks=[])
        with self.assertRaisesRegex(ProbeError, "lacked genuine Docker OOM"):
            _memory_probe_result(ctx, self.association(), output, "4", {"OOMKilled": False})
        diagnostic = ctx.checks[-1]
        self.assertEqual(diagnostic["status"], "failed")
        self.assertEqual(diagnostic["beforeStatus"], "verified")
        self.assertEqual(diagnostic["afterStatus"], "invalid")
        self.assertEqual(diagnostic["verifiedBefore"]["identity"]["pid"], 1)
        self.assertEqual(diagnostic["verifiedBefore"]["memory"]["memory.swap.max"], 0)
        self.assertFalse(diagnostic["enforcementSatisfied"])
        self.assertNotIn("rawOutput", diagnostic)
        absent = MagicMock(checks=[])
        with self.assertRaises(ProbeError):
            _memory_probe_result(absent, self.association(), "", "4", {"OOMKilled": False})
        self.assertEqual(absent.checks[-1]["afterStatus"], "unverified")


class HierarchyBoundaryTests(unittest.TestCase):
    def evidence(self, output: str, *, kind: str = "service", mode: str = "rootful") -> dict[str, object]:
        unit = "docker.service" if kind == "service" else "docker-" + "a" * 64 + ".scope"
        return _hierarchy_evidence(output, kind=kind, mode=mode, unit=unit)

    def test_populated_daemon_leaves_do_not_need_subtree_controllers(self) -> None:
        for mode in ("rootful", "rootless"):
            for service_child in (False, True):
                with self.subTest(mode=mode, service_child=service_child):
                    evidence = self.evidence(hierarchy_fixture(mode=mode, service_child=service_child), mode=mode)
                    self.assertEqual(evidence["status"], "passed")
                    self.assertIn("/", evidence["distributors"])

    def test_namespace_root_is_only_a_root_owned_empty_controller_distributor(self) -> None:
        for mode in ("rootful", "rootless"):
            for kind in ("service", "scope"):
                original = hierarchy_fixture(mode=mode, kind=kind)
                rows = original.splitlines()
                root = next(row for row in rows if row.startswith("group-before=/|"))
                self.assertEqual(sum(row.startswith("group-before=/|") for row in rows), 1)
                self.assertEqual(sum(row.startswith("group-after=/|") for row in rows), 1)
                fields = root.split("|", maxsplit=1)[1].split("|")
                changes = [None, [fields[0].replace(":0", ":1000"), *fields[1:]], [*fields[:-1], "77"]]
                for position in (2, 3):
                    for controller in ("cpu", "memory", "pids"):
                        missing = fields.copy()
                        missing[position] = " ".join(
                            value for value in missing[position].split() if value != controller
                        )
                        changes.append(missing)
                for replacement in changes:
                    with self.subTest(mode=mode, kind=kind, root=replacement):
                        changed = "\n".join(
                            row
                            if not row.startswith(("group-before=/|", "group-after=/|"))
                            else row.split("|", maxsplit=1)[0] + "|" + "|".join(replacement)
                            for row in rows
                            if replacement is not None or not row.startswith(("group-before=/|", "group-after=/|"))
                        )
                        with self.assertRaises(ProbeError):
                            self.evidence(changed, mode=mode, kind=kind)

    def test_root_paths_terminate_and_never_admit_units_managers_or_processes(self) -> None:
        self.assertEqual(_cgroup_ancestors("/"), [])
        self.assertEqual(_cgroup_ancestors("/one"), ["/"])
        self.assertEqual(_cgroup_ancestors("/one/two"), ["/one", "/"])
        self.assertEqual(_cgroup_path("/", allow_root=True), "/")
        for unsafe in ("/", "", "relative", "//one", "/one/", "/./one", "/one/../two", "/" + "x/" * 33 + "leaf"):
            with self.subTest(path=unsafe), self.assertRaises(ProbeError):
                _cgroup_path(unsafe)
        for mode in ("rootful", "rootless"):
            for kind in ("service", "scope"):
                original = hierarchy_fixture(mode=mode, kind=kind)
                changes = []
                for row in original.splitlines():
                    if row.startswith(("unit-before=ControlGroup=", "manager-before=ControlGroup=")):
                        prefix, _, _group = row.rpartition("=")
                        changes.append(
                            original.replace(
                                prefix.replace("-before", "-after") + "=" + _group,
                                prefix.replace("-before", "-after") + "=/",
                            ).replace(row, prefix + "=/")
                        )
                    elif row.startswith("process-before="):
                        group = row.split("|")[3]
                        changes.append(original.replace("|" + group + "|/usr/bin/", "|/|/usr/bin/"))
                for changed in changes:
                    with self.subTest(mode=mode, kind=kind, changed=changed[:100]), self.assertRaises(ProbeError):
                        self.evidence(changed, mode=mode, kind=kind)

    def test_actual_scope_dispatcher_is_not_assumed_to_be_daemon_service(self) -> None:
        for mode in ("rootful", "rootless"):
            with self.subTest(mode=mode):
                evidence = self.evidence(hierarchy_fixture(mode=mode, kind="scope"), mode=mode, kind="scope")
                self.assertNotIn("docker.service", evidence["controlGroup"])
                self.assertEqual(evidence["status"], "passed")
                if mode == "rootless":
                    self.assertIn("different.slice", evidence["controlGroup"])
                    self.assertEqual(
                        evidence["userManagerControlGroup"], "/user.slice/user-1000.slice/user@1000.service"
                    )

    def test_controller_and_no_internal_process_requirements_apply_to_distributors(self) -> None:
        for kind in ("service", "scope"):
            for mode in ("rootful", "rootless"):
                original = hierarchy_fixture(mode=mode, kind=kind)
                for before, after in (
                    ("|domain|cpuset cpu io memory pids|", "|domain|cpuset cpu io pids|"),
                    ("|domain|cpuset cpu io memory pids|", "|domain|cpuset io memory pids|"),
                    ("|cpuset cpu io memory pids|\n", "|cpuset cpu io pids|\n"),
                    ("|cpuset cpu io memory pids|\n", "|cpuset io memory pids|\n"),
                    ("|cpuset cpu io memory pids|\n", "|cpuset cpu io memory pids|77\n"),
                    ("|domain|", "|domain threaded|"),
                    ("Delegate=yes", "Delegate=no"),
                ):
                    with self.subTest(kind=kind, mode=mode, change=after), self.assertRaises(ProbeError):
                        self.evidence(original.replace(before, after), mode=mode, kind=kind)

    def test_stable_scope_and_manager_uid_lineage_and_membership_mismatches_fail(self) -> None:
        original = hierarchy_fixture(kind="scope", mode="rootless")
        unit = "docker-" + "a" * 64 + ".scope"
        for changed in (
            original.replace(":1000|", ":999|"),
            original.replace("|1000 1000 1000 1000|", "|0 0 0 0|"),
            original.replace("MainPID=44", "MainPID=45"),
            original.replace("|cpuset cpu io memory pids|", "|cpuset io memory pids|"),
            original.replace("|101\n", "|999\n"),
            original.replace("/different.slice/" + unit, "/outside.slice/" + unit),
            original.replace("/usr/bin/docker-resource-probe", "/usr/bin/not-the-probe"),
        ):
            with self.subTest(change=changed[:100]), self.assertRaises(ProbeError):
                self.evidence(changed, kind="scope", mode="rootless")
        target = "/user.slice/user-1000.slice/user@1000.service/different.slice/" + unit
        escaped = original.replace(target, "/outside.slice/" + unit)
        with self.assertRaisesRegex(ProbeError, "escaped the actual user manager"):
            self.evidence(escaped, kind="scope", mode="rootless")

    def test_scope_uid_manager_membership_collision_and_process_identity_fail_closed(self) -> None:
        for mode in ("rootful", "rootless"):
            original = hierarchy_fixture(mode=mode, kind="scope")
            lines = original.splitlines()
            group = next(
                line for line in lines if line.startswith("group-before=") and ".scope|" in line and "docker-" in line
            )
            pid = next(line for line in lines if line.startswith("process-before=probe-101|"))
            scope = next(line for line in lines if line.startswith("scope-before="))
            manager = next((line for line in lines if line.startswith("manager-before=ControlGroup=")), "")
            changes = [
                original.replace(group, group.replace(":1000|" if mode == "rootless" else ":0|", ":999|")),
                original.replace(pid, pid.replace("|101|", "|102|")),
                original.replace(pid, pid.replace("100 1", "200 1")),
                original.replace(pid, pid.replace("/usr/bin/docker-resource-probe", "/usr/bin/other")),
                original.replace(scope, scope + "\n" + scope),
                original.replace(scope, scope.replace("/sys/fs/cgroup/", "/sys/fs/cgroup/outside/")),
                original.replace("a" * 64 + ".scope", "b" * 64 + ".scope"),
                original.replace("|101|", "|999 101|"),
                original.replace("|domain|", "|threaded|"),
            ]
            if manager:
                changes.append(original.replace("user@1000.service", "user@2000.service", 1))
                changes.append(original.replace(manager, manager.replace("user@1000.service", "user@2000.service")))
            for number, changed in enumerate(changes):
                with self.subTest(mode=mode, scenario=number), self.assertRaises(ProbeError):
                    self.evidence(changed, mode=mode, kind="scope")

    def test_missing_malformed_duplicate_unknown_and_unbounded_evidence_fail_closed(self) -> None:
        original = hierarchy_fixture()
        lines = original.splitlines()
        for changed in (
            "",
            "\n".join(lines[1:]),
            original + "\n" + lines[0],
            original + "\nunknown-before=value",
            original.replace("/system.slice", "/../system.slice"),
            original.replace("/system.slice", "/" + "deep/" * 33 + "system.slice"),
            original.replace("/system.slice", "/" + "x" * 4096),
            original + "x" * (256 * 1024),
            original.replace("process-after=daemon|55|", "process-after=daemon|99|"),
            original.replace("|/usr/bin/dockerd|", "|/usr/bin/not-dockerd|"),
            original.replace("|0 0 0 0|", "|1000 1000 1000 1000|"),
        ):
            with self.subTest(prefix=changed[:100]), self.assertRaises(ProbeError):
                self.evidence(changed)

    def test_real_reader_on_synthetic_hierarchies_without_runtime_or_cgroup_writes(self) -> None:
        for mode in ("rootful", "rootless"):
            for kind in ("service", "scope"):
                for failure in (
                    None,
                    "missing-controller",
                    "populated-parent",
                    "scope-collision",
                    "missing-root-file",
                    "missing-root-controller",
                    "populated-root",
                ):
                    with (
                        self.subTest(mode=mode, kind=kind, failure=failure),
                        tempfile.TemporaryDirectory() as temporary,
                    ):
                        directory = Path(temporary)
                        target, unit = _write_hierarchy_fixture(directory, hierarchy_fixture(kind=kind, mode=mode))
                        _alter_hierarchy_fixture(directory, target, unit, kind, failure)
                        script = HIERARCHY_READERS + HIERARCHY_READBACK_COMMAND.replace(
                            "/sys/fs/cgroup", str(directory / "cgroup")
                        ).replace("/proc/", str(directory / "proc") + "/")
                        completed = subprocess.run(  # noqa: S603 — offline synthetic files, no runtime.
                            ["/bin/sh", "-euc", script, "--", kind, mode, unit],
                            env={**os.environ, "FIXTURE": str(directory), "MODE": mode},
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=10,
                        )
                        collision = failure == "scope-collision" and kind == "scope"
                        if collision or failure == "missing-root-file":
                            self.assertNotEqual(completed.returncode, 0)
                            continue
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        readback = completed.stdout.replace(str(directory / "cgroup"), "/sys/fs/cgroup")
                        if failure in {
                            "missing-controller",
                            "populated-parent",
                            "missing-root-controller",
                            "populated-root",
                        }:
                            with self.assertRaises(ProbeError):
                                self.evidence(readback, kind=kind, mode=mode)
                        else:
                            self.assertEqual(self.evidence(readback, kind=kind, mode=mode)["status"], "passed")


ACCOUNTING_SHIM = r"""
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
pid_t __real_getpid(void);
pid_t __wrap_getpid(void) { return getenv("TEST_WITNESS_PID1") ? 1 : __real_getpid(); }
FILE *__real_fopen(const char *, const char *);
int __real_stat(const char *, struct stat *);
int __real_statfs(const char *, struct statfs *);
FILE *__wrap_fopen(const char *path, const char *mode) {
    const char *prefix = "/sys/fs/cgroup/";
    if (strncmp(path, prefix, strlen(prefix)) == 0) {
        char mapped[4096];
        const char *root = getenv("TEST_ACCOUNTING");
        if (!root) { errno = ENOENT; return NULL; }
        int count = snprintf(mapped, sizeof(mapped), "%s/%s", root, path + strlen(prefix));
        if (count < 0 || (size_t)count >= sizeof(mapped)) { errno = ENAMETOOLONG; return NULL; }
        return __real_fopen(mapped, mode);
    }
    return __real_fopen(path, mode);
}
int __wrap_stat(const char *path, struct stat *status) {
    if (strcmp(path, "/sys/fs/cgroup") == 0) {
        memset(status, 0, sizeof(*status)); status->st_ino = 42; return 0;
    }
    return __real_stat(path, status);
}
int __wrap_statfs(const char *path, struct statfs *status) {
    if (strcmp(path, "/sys/fs/cgroup") == 0) {
        memset(status, 0, sizeof(*status)); status->f_type = CGROUP2_SUPER_MAGIC; return 0;
    }
    return __real_statfs(path, status);
}
"""


@unittest.skipUnless(Path("/proc/self/stat").is_file(), "Linux process identity regression requires procfs")
class CompiledResourceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            message = "bounded authored-C regression requires a local C compiler"
            raise unittest.SkipTest(message)
        temporary = tempfile.TemporaryDirectory(prefix="containers-resource-gate-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "docker-resource-probe"
        source = Path(__file__).resolve().parents[1] / "images/docker/conformance/resource-probe.c"
        subprocess.run(  # noqa: S603 — local compiler, authored source, task-owned temporary output.
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(cls.binary)],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        shim = cls.directory / "accounting-shim.c"
        shim.write_text(ACCOUNTING_SHIM)
        cls.instrumented = cls.directory / "instrumented-probe"
        subprocess.run(  # noqa: S603 — deterministic test-only syscall substitutions, no cgroup writes.
            [
                compiler,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                str(shim),
                "-Wl,--wrap=fopen,--wrap=stat,--wrap=statfs,--wrap=getpid",
                "-o",
                str(cls.instrumented),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def accounting(self, root: Path) -> None:
        root.mkdir()
        for key, value in {
            "memory.max": str(MEMORY_BYTES),
            "memory.current": "4096",
            "memory.swap.max": "0",
            "memory.swap.current": "0",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
        }.items():
            (root / key).write_text(value)

    def identity(self, pid: int) -> tuple[str, str, str, str, str]:
        process = Path("/proc") / str(pid)
        starttime = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
        uids = next(line for line in (process / "status").read_text().splitlines() if line.startswith("Uid:"))
        return (
            str((process / "exe").readlink()),
            starttime,
            uids,
            (process / "cgroup").read_text(),
            (process / "task" / str(pid) / "children").read_text(),
        )

    def test_real_c_gate_stays_one_child_free_stable_process_across_multiple_sleep_periods(self) -> None:
        trigger = self.directory / "release"
        with subprocess.Popen(  # noqa: S603 — bounded authored probe, no runtime/cgroup writes.
            [str(self.binary), "memory", "--wait-for-start", str(trigger)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as probe:
            try:
                before = self.identity(probe.pid)
                self.assertEqual(before[0], str(self.binary))
                self.assertEqual(before[4], "")
                for _ in range(3):
                    time.sleep(0.15)
                    self.assertIsNone(probe.poll())
                    self.assertEqual(self.identity(probe.pid), before)
                trigger.touch()
                stdout, stderr = probe.communicate(timeout=12)
                # No host limit is imposed: reaching bounded 128 MiB returns 4,
                # not native OOM admission. Gate release preserves the resource action.
                self.assertEqual(probe.returncode, 4, stderr)
                self.assertEqual(stdout, "")
            finally:
                if probe.poll() is None:
                    probe.kill()
                probe.wait(timeout=3)

    def test_missing_gate_times_out_without_starting_resource_action(self) -> None:
        started = time.monotonic()
        result = subprocess.run(  # noqa: S603 — bounded missing-file gate only.
            [str(self.binary), "memory", "--wait-for-start", str(self.directory / "never-created")],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertGreaterEqual(elapsed, 9.9)
        self.assertLess(elapsed, 14)

    def test_cancelled_gate_exits_without_children_or_resource_action(self) -> None:
        with subprocess.Popen(  # noqa: S603 — child-free, bounded authored gate, no container runtime.
            [str(self.binary), "memory", "--wait-for-start", str(self.directory / "cancelled")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as probe:
            try:
                self.assertEqual(self.identity(probe.pid)[4], "")
                probe.terminate()
                stdout, stderr = probe.communicate(timeout=3)
                self.assertEqual(probe.returncode, -signals.SIGTERM, stderr)
                self.assertEqual(stdout, "")
            finally:
                if probe.poll() is None:
                    probe.kill()
                probe.wait(timeout=3)

    def test_opt_in_c_producer_emits_complete_real_self_identity_and_substituted_accounting(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            root = Path(temporary)
            accounting = root / "accounting"
            self.accounting(accounting)
            trigger = root / "release"
            with subprocess.Popen(  # noqa: S603 — bounded authored probe with test-only accounting substitutes.
                [str(self.instrumented), "memory", "--wait-for-start", str(trigger), "--memory-evidence"],
                env={**os.environ, "TEST_ACCOUNTING": str(accounting)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as probe:
                try:
                    actual = self.identity(probe.pid)
                    trigger.touch()
                    stdout, stderr = probe.communicate(timeout=12)
                    self.assertEqual(probe.returncode, 4, stderr)
                    self.assertLessEqual(len(stdout), 8192)
                    snapshots = _allocator_records(stdout)
                    for phase in ("before", "after"):
                        fields = snapshots[phase]
                        self.assertEqual(fields["pid"], str(probe.pid))
                        self.assertEqual(fields["starttime"], actual[1])
                        self.assertEqual(fields["exe"], str(self.instrumented))
                        self.assertEqual(fields["scope-inode"], "42")
                        self.assertEqual(fields["mount-type"], "63677270")
                        self.assertEqual(fields["memory.max"], str(MEMORY_BYTES))
                        self.assertEqual(fields["memory.swap.max"], "0")
                        self.assertEqual(fields["complete"], "yes")
                    self.assertEqual(snapshots["before"], snapshots["after"])
                finally:
                    if probe.poll() is None:
                        probe.kill()
                    probe.wait(timeout=3)
        # These substituted scalar reads do not impose host limits or prove OOM.

    def test_opt_in_c_missing_or_oversized_evidence_fails_before_emission(self) -> None:
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                root = Path(temporary)
                accounting = root / "accounting"
                self.accounting(accounting)
                if missing:
                    (accounting / "memory.swap.max").unlink()
                else:
                    (accounting / "memory.swap.max").write_text("0" * 1024 + "\n")
                trigger = root / "release"
                trigger.touch()
                result = subprocess.run(  # noqa: S603 — test-only fixture failure, no resource action/cgroup writes.
                    [str(self.instrumented), "memory", "--wait-for-start", str(trigger), "--memory-evidence"],
                    env={**os.environ, "TEST_ACCOUNTING": str(accounting)},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3,
                )
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("memory.swap.max", result.stderr)

    def test_namespace_ancestry_rejects_malformed_arguments_and_same_namespace_without_entry(self) -> None:
        for target, ancestor in (
            ("0", str(os.getpid())),
            ("invalid", "1"),
            ("9" * 30, "1"),
            (str(os.getpid()), str(os.getpid())),
        ):
            with self.subTest(target=target, ancestor=ancestor):
                result = subprocess.run(  # noqa: S603 — namespace FDs inspected read-only, no setns/unshare.
                    [str(self.binary), "--pid-ancestry", target, ancestor],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=3,
                )
                self.assertEqual(result.returncode, 11, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_normal_mode_and_invalid_gate_arguments_retain_failure_codes(self) -> None:
        for arguments, expected in (
            (["memory"], 4),
            (["unknown"], 2),
            (["unknown", "--wait-for-start", str(self.directory / "absent")], 2),
            (["memory", "--unknown", str(self.directory)], 2),
            (["memory", "--wait-for-start", str(self.directory)], 9),
            (["memory", "--wait-for-start", "relative"], 9),
            (["memory", "--wait-for-start", "/" + "x" * 4096], 9),
            (["pids", "--wait-for-start", str(self.directory), "--memory-evidence"], 2),
            (["memory", "--wait-for-start", str(self.directory), "--unknown"], 2),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(  # noqa: S603 — bounded authored probe, invalid/normal local argv.
                    [str(self.binary), *arguments], capture_output=True, text=True, check=False, timeout=12
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def witness_accounting(self, root: Path) -> None:
        self.accounting(root)
        for name, value in {
            "memory.events.local": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            "memory.oom.group": "0",
            "pids.max": "16",
        }.items():
            (root / name).write_text(value)

    def witness_child(self, probe: subprocess.Popen) -> int:
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            children = (Path("/proc") / str(probe.pid) / "task" / str(probe.pid) / "children").read_text().split()
            if children:
                self.assertEqual(len(children), 1)
                return int(children[0])
            time.sleep(0.01)
        message = "authored controller did not create its one bounded child"
        raise AssertionError(message)

    def test_witness_controller_survives_reaps_and_retains_actual_after_for_manual_sigkill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.witness_accounting(root / "accounting")
            start = root / "start"
            with subprocess.Popen(  # noqa: S603 — bounded authored controller and synthetic read-only accounting.
                [str(self.instrumented), "memory-witness", "--wait-for-start", str(start)],
                env={**os.environ, "TEST_ACCOUNTING": str(root / "accounting"), "TEST_WITNESS_PID1": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as probe:
                try:
                    child = self.witness_child(probe)
                    os.kill(child, signals.SIGSTOP)
                    start.touch()
                    # Child is stopped, so the owned pipe remains open while controller writes release.
                    time.sleep(0.05)
                    os.kill(child, signals.SIGKILL)
                    deadline = time.monotonic() + 2
                    while not Path(str(start) + ".after").exists() and time.monotonic() < deadline:
                        self.assertIsNone(probe.poll())
                        time.sleep(0.01)
                    self.assertTrue(Path(str(start) + ".after").is_file())
                    self.assertIsNone(probe.poll())
                    self.assertEqual(self.identity(probe.pid)[4], "")
                    self.assertFalse((Path("/proc") / str(child)).exists())
                    Path(str(start) + ".finish").touch()
                    stdout, stderr = probe.communicate(timeout=2)
                    self.assertEqual(probe.returncode, 0, stderr)
                    records = _leaf_witness_records(stdout)
                    self.assertEqual(
                        records["result"], {"child-reaped": "yes", "child-signal": "9", "child-signaled": "yes"}
                    )
                    self.assertEqual(records["before"]["scope-identity"], records["after"]["scope-identity"])
                    self.assertEqual(records["after"]["memory.events.local"], "low 0;high 0;max 0;oom 0;oom_kill 0")
                    self.assertNotIn("allocator-before-", stdout)
                finally:
                    if probe.poll() is None:
                        probe.terminate()
                        probe.communicate(timeout=2)

    def test_witness_cancellation_and_timeout_reap_only_owned_unreaped_child(self) -> None:
        for cancellation in (signals.SIGTERM, signals.SIGALRM):
            with self.subTest(signal=cancellation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.witness_accounting(root / "accounting")
                with subprocess.Popen(  # noqa: S603 — synthetic accounting, no allocation gate release.
                    [str(self.instrumented), "memory-witness", "--wait-for-start", str(root / "never")],
                    env={**os.environ, "TEST_ACCOUNTING": str(root / "accounting"), "TEST_WITNESS_PID1": "1"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ) as probe:
                    child = self.witness_child(probe)
                    probe.send_signal(cancellation)
                    stdout, _ = probe.communicate(timeout=2)
                    self.assertEqual(probe.returncode, 12)
                    self.assertFalse((Path("/proc") / str(child)).exists())
                    self.assertNotIn("leaf-witness-after-", stdout)


class JournalBoundaryTests(unittest.TestCase):
    def alter_fixture(self, process: Path, scenario: str | None, unix: str) -> None:
        if scenario == "fd":
            for descriptor in (process / "fd").iterdir():
                descriptor.unlink()
        elif scenario in {"status", "net/netlink", "net/unix", "stat", "exe"}:
            (process / scenario).unlink()
        elif scenario == "unrelated-fd":
            (process / "fd/1").unlink()
            (process / "fd/1").symlink_to("socket:[999]")
        elif scenario == "bad-unix":
            (process / "net/unix").write_text("malformed table\n")
        elif scenario == "missing-stdout":
            (process / "net/unix").write_text(unix.replace("/run/systemd/journal/stdout", "/run/other"))
        elif scenario == "connected-datagram":
            (process / "net/unix").write_text(unix.replace("0002 01 100", "0002 03 100"))

    def test_masked_audit_dependency_is_not_an_open_audit_descriptor(self) -> None:
        for version in ("247.3-7+deb11u8", "257.13-1~deb13u1"):
            for audit_reference in (" systemd-journald-audit.socket", ""):
                with self.subTest(version=version, audit_reference=audit_reference):
                    readback = READBACK.replace("247.3-7+deb11u8", version).replace(
                        "systemd-journald-dev-log.socket systemd-journald-audit.socket",
                        "systemd-journald-dev-log.socket" + audit_reference,
                    )
                    evidence = _journal_boundary_evidence(readback)
                    self.assertEqual(evidence["status"], "passed")
                    self.assertEqual(evidence["socketInodes"], [100, 101, 102])
                    self.assertEqual(evidence["auditInodes"], [90])
                    self.assertEqual(evidence["systemdVersion"], version)
                    self.assertEqual(evidence["journalStartTime"], 100)
                    self.assertEqual(set(evidence["normalUnixEndpoints"].values()), {100, 101, 102})

    def test_any_actual_audit_capability_or_audit_descriptor_is_rejected(self) -> None:
        for capability in ("CapEff", "CapPrm", "CapBnd"):
            with self.subTest(capability=capability):
                changed = READBACK.replace(f"{capability}=00000025002800cf", f"{capability}=00000025402800cf")
                with self.assertRaisesRegex(ProbeError, "CAP_AUDIT_CONTROL"):
                    _journal_boundary_evidence(changed)
        with self.assertRaisesRegex(ProbeError, "NETLINK_AUDIT"):
            _journal_boundary_evidence(READBACK.replace("socket:[101]", "socket:[90]"))

    def test_active_socket_units_accept_listening_or_running_without_replacing_fd_proof(self) -> None:
        for journal_state in ("listening", "running"):
            for devlog_state in ("listening", "running"):
                with self.subTest(journal=journal_state, devlog=devlog_state):
                    readback = READBACK.replace(
                        "normal-socket=systemd-journald.socket:active:listening",
                        f"normal-socket=systemd-journald.socket:active:{journal_state}",
                    ).replace(
                        "normal-socket=systemd-journald-dev-log.socket:active:listening",
                        f"normal-socket=systemd-journald-dev-log.socket:active:{devlog_state}",
                    )
                    evidence = _journal_boundary_evidence(readback)
                    self.assertEqual(
                        evidence["normalSocketStates"],
                        {"systemd-journald.socket": journal_state, "systemd-journald-dev-log.socket": devlog_state},
                    )
                    self.assertEqual(evidence["socketInodes"], [100, 101, 102])
                    with self.assertRaisesRegex(ProbeError, "all three normal UNIX endpoints"):
                        _journal_boundary_evidence(readback.replace("socket:[102]", "socket:[999]"))
        running = READBACK.replace(":active:listening", ":active:running")
        with self.assertRaisesRegex(ProbeError, "CAP_AUDIT_CONTROL"):
            _journal_boundary_evidence(running.replace("CapEff=00000025002800cf", "CapEff=00000025402800cf"))
        with self.assertRaisesRegex(ProbeError, "NETLINK_AUDIT"):
            _journal_boundary_evidence(running.replace("socket:[101]", "socket:[90]"))

    def test_unknown_inactive_or_duplicate_normal_socket_states_fail(self) -> None:
        for state in ("active:unknown", "active:dead", "active:", "inactive:running", "failed:listening"):
            with self.subTest(state=state), self.assertRaisesRegex(ProbeError, "socket units must be active"):
                _journal_boundary_evidence(
                    READBACK.replace("systemd-journald.socket:active:listening", f"systemd-journald.socket:{state}")
                )
        duplicated = READBACK.replace(
            "normal-socket=systemd-journald-dev-log.socket:active:listening",
            "normal-socket=systemd-journald.socket:active:running",
        )
        with self.assertRaisesRegex(ProbeError, "socket units must be active"):
            _journal_boundary_evidence(duplicated)

    @unittest.skipUnless(Path("/proc/net/unix").is_file(), "Linux UNIX socket state observation requires procfs")
    def test_connected_datagram_client_marks_its_bound_receiver_connected(self) -> None:
        # Independent Linux behavior, using only task-local unprivileged sockets;
        # no container runtime, guest/host service or external endpoint is used.
        with (
            tempfile.TemporaryDirectory() as temporary,
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver,
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client,
        ):
            address = str(Path(temporary) / "journal.sock")
            receiver.bind(address)
            inode = os.fstat(receiver.fileno()).st_ino

            def row() -> list[str]:
                matches = [
                    line.split()
                    for line in Path("/proc/net/unix").read_text().splitlines()[1:]
                    if line.split()[6] == str(inode)
                ]
                self.assertEqual(len(matches), 1)
                return matches[0]

            self.assertEqual([int(value, 16) for value in row()[3:6]], [0, 2, 1])
            client.connect(address)
            self.assertEqual([int(value, 16) for value in row()[3:6]], [0, 2, 3])

    def test_both_owned_datagram_endpoints_accept_only_unconnected_or_connected_states(self) -> None:
        for native_state in ("01", "03"):
            for devlog_state in ("01", "03"):
                with self.subTest(native=native_state, devlog=devlog_state):
                    readback = READBACK.replace(
                        "0002 01 100 /run/systemd/journal/socket",
                        f"0002 {native_state} 100 /run/systemd/journal/socket",
                    ).replace(
                        "0002 01 101 /run/systemd/journal/dev-log",
                        f"0002 {devlog_state} 101 /run/systemd/journal/dev-log",
                    )
                    self.assertEqual(_journal_boundary_evidence(readback)["socketInodes"], [100, 101, 102])
        for state in ("00", "02", "04", "FF"):
            with self.subTest(state=state), self.assertRaises(ProbeError):
                _journal_boundary_evidence(READBACK.replace("0002 01 100", f"0002 {state} 100"))
        with self.assertRaises(ProbeError):
            _journal_boundary_evidence(READBACK.replace("00010000 0001 01 102", "00010000 0001 03 102"))

    def test_connected_datagram_state_never_bypasses_type_flags_fd_audit_or_identity_proof(self) -> None:
        connected = READBACK.replace("0002 01 100", "0002 03 100").replace("0002 01 101", "0002 03 101")
        replacements = (
            ("00000000 0002 03 100", "00010000 0002 03 100"),
            ("00000000 0002 03 100", "00000000 0001 03 100"),
            ("socket:[100]", "socket:[999]"),
            ("socket:[101]", "socket:[90]"),
            ("CapEff=00000025002800cf", "CapEff=00000025402800cf"),
            ("CapPrm=00000025002800cf", "CapPrm=00000025402800cf"),
            ("CapBnd=00000025002800cf", "CapBnd=00000025402800cf"),
            ("journal-pid-after=42", "journal-pid-after=43"),
            ("fd-after=3:/dev/null", "fd-after=3:/dev/kmsg"),
        )
        for before, after in replacements:
            with self.subTest(before=before), self.assertRaises(ProbeError):
                _journal_boundary_evidence(connected.replace(before, after))

    def test_missing_duplicate_and_malformed_mandatory_evidence_fails_closed(self) -> None:
        replacements = (
            ("CapEff=00000025002800cf\n", ""),
            ("CapPrm=00000025002800cf", "CapPrm=not-hex"),
            ("CapBnd=00000025002800cf", "CapBnd=0000"),
            ("CapEff=00000025002800cf", "CapEff=00000025002800cf\nCapEff=00000025002800cf"),
            ("journal-netns=net:[1234]", "journal-netns=net:[9999]"),
            ("journal-netns=net:[1234]", "journal-netns="),
            ("journal-pid=42", "journal-pid=1"),
            ("journal-pid=42", "journal-pid=../../1"),
            ("unit-capabilities=cap_chown cap_audit_read", "unit-capabilities="),
            ("unit-capabilities=cap_chown cap_audit_read", "unit-capabilities=cap_audit_control"),
            ("drop-in=verified", "drop-in=missing"),
            ("systemd-sysctl.service:masked:inactive", "systemd-sysctl.service:enabled:active"),
            ("systemd-journald.socket:active:listening", "systemd-journald.socket:inactive:dead"),
            ("triggered-by=systemd-journald.socket ", "triggered-by="),
            ("triggered-by=", "triggered-by=other.socket "),
            ("socket:[101]", "socket:[not-an-inode]"),
            ("socket:[101]", "socket:[0]"),
            ("fd-before=0:socket:[100]\nfd-before=1:socket:[101]\n", ""),
            ("fd-count-before=4", "fd-count-before=1"),
            ("fd-count-after=4", "fd-count-after=0"),
            ("netlink-table-begin\n", ""),
            ("netlink-table-end", "netlink-table-end\nnetlink-table-end"),
            ("sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode", "bad header"),
            ("00000000 9 0 00000000 0 0 0 2 0 90", "00000000 9 0 00000000 0 0 0 2 0"),
            ("00000000 9 0 00000000 0 0 0 2 0 90", "00000000 x 0 00000000 0 0 0 2 0 90"),
            ("systemd-version=247.3-7+deb11u8", "systemd-version="),
            ("journal-pid-after=42", "journal-pid-after=43"),
            ("journal-stat-after=42", "journal-stat-after=43"),
            ("100 1\njournal-netns=", "101 1\njournal-netns="),
            ("journal-stat-after=42 (systemd-journal) S", "journal-stat-after=malformed"),
            ("journal-exe-after=/lib/systemd/systemd-journald", "journal-exe-after=/bin/other"),
            ("journal-netns-after=net:[1234]", "journal-netns-after=net:[9999]"),
            ("fd-after=1:socket:[101]", "fd-after=1:socket:[999]"),
            ("fd-after=3:/dev/null", "fd-after=3:/dev/kmsg"),
            ("fd-after=3:/dev/null", "fd-after=3:/dev/null\nfd-after=3:/dev/null"),
            ("unix-table-begin\n", ""),
            ("unix-table-end", "unix-table-end\nunix-table-end"),
            ("Num RefCount Protocol Flags Type St Inode Path", "broken UNIX header"),
            ("00000000 00010000 0001 01 102", "00000000 00000000 0001 01 102"),
            ("00000000 00000000 0002 01 101", "00000000 00000000 0001 01 101"),
            ("00000000 00000000 0002 01 101", "00000000 00000000 0002 01 invalid"),
            ("/run/systemd/journal/dev-log", "/run/other"),
            ("01 101 /run/systemd/journal/dev-log", "01 100 /run/systemd/journal/dev-log"),
            (
                "unix-table-end",
                "00000004: 00000002 00000000 00000000 0002 01 104 /run/systemd/journal/dev-log\nunix-table-end",
            ),
        )
        for before, after in replacements:
            with self.subTest(before=before, after=after), self.assertRaises(ProbeError):
                _journal_boundary_evidence(READBACK.replace(before, after))
        with self.assertRaises(ProbeError):
            _journal_boundary_evidence(READBACK + "unknown-data=value\n")

    def test_readback_shell_fixture_functions_use_posix_identifiers(self) -> None:
        names = re.findall(r"^(\S+)\(\)\s*\{", SYSTEMCTL, re.MULTILINE)
        self.assertTrue(names)
        for name in names:
            with self.subTest(name=name):
                self.assertRegex(name, r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

    def test_real_readback_command_uses_process_namespace_and_fails_missing_proc_data(self) -> None:
        scenarios = (
            None,
            "status",
            "net/netlink",
            "net/unix",
            "stat",
            "exe",
            "fd",
            "unrelated-fd",
            "bad-unix",
            "changed-pid",
            "changed-stat",
            "changed-exe",
            "missing-stdout",
            "running",
            "unknown-substate",
            "inactive-unit",
            "connected-datagram",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for pid in (1, 42):
                    (root / f"proc/{pid}/ns").mkdir(parents=True)
                    (root / f"proc/{pid}/ns/net").symlink_to("net:[1234]")
                process = root / "proc/42"
                (process / "net").mkdir()
                (process / "fd").mkdir()
                (process / "exe").symlink_to("/lib/systemd/systemd-journald")
                stat = READBACK.split("journal-stat-before=")[1].splitlines()[0]
                (process / "stat").write_text(stat + "\n")
                for index, inode in enumerate((100, 101, 102)):
                    (process / f"fd/{index}").symlink_to(f"socket:[{inode}]")
                (process / "status").write_text(
                    "CapEff:\t00000025002800cf\nCapPrm:\t00000025002800cf\nCapBnd:\t00000025002800cf\n"
                )
                (process / "net/netlink").write_text(
                    READBACK.split("netlink-table-begin\n")[1].split("netlink-table-end", maxsplit=1)[0]
                )
                boundary = root / "etc/systemd/system/systemd-journald.service.d/boundary.conf"
                unix = READBACK.split("unix-table-begin\n")[1].split("unix-table-end", maxsplit=1)[0]
                (process / "net/unix").write_text(unix)
                boundary.parent.mkdir(parents=True)
                boundary.write_text("[Service]\nCapabilityBoundingSet=~CAP_AUDIT_CONTROL\n")
                provenance = root / "usr/share/strukturpiloten/docker"
                provenance.mkdir(parents=True)
                (provenance / "journal-boundary").write_text(boundary.read_text())
                (provenance / "conformance-packages").write_text("systemd=247.3-7+deb11u8\n")
                binaries = root / "bin"
                binaries.mkdir()
                package_query = binaries / "dpkg-query"
                package_query.write_text(DPKG_QUERY)
                package_query.chmod(0o700)
                self.alter_fixture(process, scenario, unix)
                command = JOURNAL_BOUNDARY_COMMAND.replace("/proc/", f"{root}/proc/")
                command = command.replace("/etc/", f"{root}/etc/").replace("/usr/share/", f"{root}/usr/share/")
                result = subprocess.run(  # noqa: S603 - fixed read-only command against task-local proc fixtures.
                    ["/bin/sh", "-euc", SYSTEMCTL + command],
                    env={
                        **os.environ,
                        "PATH": os.pathsep.join((str(binaries), os.environ["PATH"])),
                        "BOUNDARY_FILE": str(boundary),
                        "PID_MARK": str(root / "pid-read"),
                        "EXE_MARK": str(root / "exe-read"),
                        "STAT_MARK": str(root / "stat-read"),
                        "JOURNAL_STAT": str(process / "stat"),
                        "JOURNAL_EXE": str(process / "exe"),
                        "PID_AFTER": "43" if scenario == "changed-pid" else "42",
                        "EXE_AFTER": "/bin/other" if scenario == "changed-exe" else "",
                        "STAT_AFTER": stat.replace("100 1", "101 1") if scenario == "changed-stat" else "",
                        "SOCKET_SUBSTATE": {
                            "running": "running",
                            "unknown-substate": "unknown",
                        }.get(scenario, "listening"),
                        "NORMAL_ACTIVE": "inactive" if scenario == "inactive-unit" else "active",
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                expect_failure = scenario not in {None, "running", "connected-datagram"}
                if expect_failure and result.returncode == 0:
                    with self.assertRaises(ProbeError):
                        _journal_boundary_evidence(result.stdout)
                elif expect_failure:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(_journal_boundary_evidence(result.stdout)["socketInodes"], [100, 101, 102])


class LeafWitnessProtocolTests(unittest.TestCase):
    def association(self) -> dict:
        hierarchy = _hierarchy_evidence(
            hierarchy_fixture(kind="scope"), kind="scope", mode="rootful", unit="docker-" + "a" * 64 + ".scope"
        )
        service = _hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")
        association = _memory_association(memory_association_fixture(), hierarchy, service)
        association["scope-device"] = 4
        association["child"] = {**association["allocator"], "pid": 102, "starttime": 200, "nspid": [102, 2]}
        return association

    def full_binding(self, mode: str = "rootful") -> tuple[str, dict, dict]:
        source = hierarchy_fixture(kind="scope", mode=mode)
        fields = _memory_fixture_process(mode, "allocator")
        fields[0] = "102"
        fields[4] = "102 (/usr/bin/docker-resource-probe) S " + "101 " + "1 " * 17 + "200 1"
        fields[5] = "102 202 2" if mode == "rootless" else "102 2"
        lines = [
            line + " 102" if line.startswith("group-") and line.endswith("|101") else line
            for line in source.splitlines()
        ]
        raw = memory_association_fixture(mode=mode)
        for phase in ("before", "after"):
            lines.append(f"process-{phase}=probe-102|102|{fields[1]}|{fields[2][3:]}|{fields[3]}|{fields[4]}")
            raw += f"\nassociation-{phase}-child=" + "|".join(fields)
            raw += f"\nwitness-{phase}-scope-device=4"
        hierarchy = _hierarchy_evidence("\n".join(lines), kind="scope", mode=mode, unit="docker-" + "a" * 64 + ".scope")
        service = _hierarchy_evidence(hierarchy_fixture(mode=mode), kind="service", mode=mode, unit="docker.service")
        return raw, hierarchy, service

    def test_full_membership_child_parent_namespace_and_device_bindings(self) -> None:
        for mode in ("rootful", "rootless"):
            raw, hierarchy, service = self.full_binding(mode)
            association = _leaf_witness_association(raw, hierarchy, service)
            self.assertEqual(association["child"]["pid"], 102)
            self.assertEqual(association["allocator"]["pid"], 101)
            self.assertEqual(
                {role for role in hierarchy["processes"] if role.startswith("probe-")}, {"probe-101", "probe-102"}
            )
            _leaf_witness_retained_after(hierarchy_fixture(kind="scope", mode=mode), association)
            for changed in (
                raw.replace(") S 101 ", ") S 103 "),
                raw.replace("association-after-child=102", "association-after-child=103"),
                raw.replace("witness-after-scope-device=4", "witness-after-scope-device=5"),
                raw.replace("association-after-child=", "unknown-child="),
            ):
                with self.subTest(mode=mode, changed=changed[-60:]), self.assertRaises(ProbeError):
                    _leaf_witness_association(changed, hierarchy, service)
            extra = copy.deepcopy(hierarchy)
            extra["groups"][extra["controlGroup"]][4] += " 103"
            with self.assertRaises(ProbeError):
                _leaf_witness_association(raw, extra, service)
            with self.assertRaises(ProbeError):
                _leaf_witness_retained_after(
                    "\n".join(
                        line.replace("|101", "|101 102") if line.startswith("group-") else line
                        for line in hierarchy_fixture(kind="scope", mode=mode).splitlines()
                    ),
                    association,
                )

    def protocol(self) -> str:
        association = self.association()
        fields = {
            "scope-identity": "4:" + association["scope-inode"],
            "controller-pid": "1",
            "controller-stat": "1 (resource-probe) S " + " ".join(["0"] * 18 + ["100"] + ["0"] * 5),
            "controller-cgroup": "0::/",
            "controller-pidns": "pid:[701]",
            "controller-cgroupns": "cgroup:[801]",
            "controller-userns": "user:[900]",
            "child-pid": "2",
            "child-stat": "2 (resource-probe) S " + " ".join(["1"] + ["0"] * 17 + ["200"] + ["0"] * 5),
            "memory.max": str(MEMORY_BYTES),
            "memory.current": "8192",
            "memory.swap.max": "0",
            "memory.swap.current": "0",
            "memory.events": "low 0;high 0;max 0;oom 0;oom_kill 0;oom_group_kill 0",
            "memory.events.local": "low 0;high 0;max 0;oom 0;oom_kill 0;oom_group_kill 0",
            "memory.oom.group": "0",
            "pids.max": "16",
            "complete": "yes",
        }
        lines = [
            f"leaf-witness-{phase}-{key}={value}" for phase in ("before", "after") for key, value in fields.items()
        ]
        lines.extend(
            [
                "leaf-witness-result-child-reaped=yes",
                "leaf-witness-result-child-signal=9",
                "leaf-witness-result-child-signaled=yes",
            ]
        )
        return "\n".join(lines)

    def roots(self) -> list[dict]:
        events = {"availability": "observed", "values": {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0}}
        return [
            {
                "availability": "observed",
                "authority": "observation-only",
                "bindingChecks": dict.fromkeys(
                    (
                        "ownedContainer",
                        "containerIncarnation",
                        "ownedSlice",
                        "hostProcess",
                        "cgroup2Mount",
                        "outerCgroup",
                        "stableRead",
                    ),
                    True,
                ),
                "bindings": {"scope": "private-hash"},
                "mountSemantics": {"root": "full-hierarchy", "memoryLocalevents": False},
                "sampleWindowMonotonicNs": window,
                "counters": {"memory.events": copy.deepcopy(events), "memory.events.local": copy.deepcopy(events)},
            }
            for window in ([1, 2], [5, 6])
        ]

    def observe(self, output: str | None = None, roots: list[dict] | None = None) -> dict:
        return _leaf_witness_public(output or self.protocol(), self.association(), roots or self.roots(), [3, 4])

    def test_actual_after_and_waitpid_sigkill_are_separate_observation_without_cause_authority(self) -> None:
        result = self.observe()
        self.assertEqual(result["availability"], "observed")
        self.assertEqual(result["childTermination"], "waitpid-signaled-sigkill")
        self.assertFalse(result["oomAccountingObserved"])
        self.assertTrue(result["childReaped"])
        self.assertNotIn("enforcementSatisfied", result)
        self.assertNotIn("controller-stat", json.dumps(result))
        self.assertNotIn("pid:[701]", json.dumps(result))
        self.assertNotIn("scope-inode", json.dumps(result))

    def test_missing_after_identity_policy_status_and_non_sigkill_fail_closed(self) -> None:
        original = self.protocol()
        for changed in (
            "\n".join(line for line in original.splitlines() if not line.startswith("leaf-witness-after-")),
            original.replace("leaf-witness-after-scope-identity=4:", "leaf-witness-after-scope-identity=5:"),
            original.replace("leaf-witness-after-child-pid=2", "leaf-witness-after-child-pid=3"),
            original.replace("leaf-witness-after-child-stat=2", "leaf-witness-after-child-stat=3"),
            original.replace("memory.oom.group=0", "memory.oom.group=1"),
            original.replace("memory.swap.max=0", "memory.swap.max=max"),
            original.replace("child-reaped=yes", "child-reaped=no"),
            original.replace("child-signal=9", "child-signal=15"),
            original.replace("child-signaled=yes", "child-signaled=no"),
            original + "\nleaf-witness-after-unknown=1",
            original + "\n" + original.splitlines()[0],
        ):
            with self.subTest(change=changed[-80:]), self.assertRaises(ProbeError):
                self.observe(changed)

    def test_counter_sets_are_actual_optional_and_never_defaulted_to_zero(self) -> None:
        original = self.protocol()
        sock = original.replace("oom_group_kill 0", "oom_group_kill 0;sock_throttled 2")
        result = self.observe(sock)
        self.assertEqual(result["counters"]["memory.events.local"]["delta"]["sock_throttled"], 0)
        for changed in (
            "\n".join(
                line.replace("sock_throttled 2", "sock_throttled 1") if line.startswith("leaf-witness-after-") else line
                for line in sock.splitlines()
            ),
            original.replace("leaf-witness-before-memory.events=low 0", "leaf-witness-before-memory.events=low 1"),
            sock.replace(";sock_throttled 2", "", 1),
        ):
            with self.subTest(change=changed[-80:]), self.assertRaises(ProbeError):
                self.observe(changed)

    def test_unknown_mount_or_root_ordering_is_unavailable(self) -> None:
        for value in (None, True, "false"):
            roots = self.roots()
            roots[0]["mountSemantics"]["memoryLocalevents"] = value
            with self.subTest(mount=value), self.assertRaises(ProbeError):
                self.observe(roots=roots)
        roots = self.roots()
        roots[0]["sampleWindowMonotonicNs"] = [1, 4]
        with self.assertRaises(ProbeError):
            self.observe(roots=roots)
        roots = self.roots()
        roots[1]["bindings"]["scope"] = "changed"
        with self.assertRaises(ProbeError):
            self.observe(roots=roots)

    def test_root_missing_counters_and_regression_are_unavailable(self) -> None:
        roots = self.roots()
        roots[0]["counters"]["memory.events"]["values"]["low"] = 1
        with self.assertRaises(ProbeError):
            self.observe(roots=roots)
        roots = self.roots()
        roots[1]["counters"]["memory.events.local"] = {"availability": "missing"}
        with self.assertRaises(ProbeError):
            self.observe(roots=roots)
        roots = self.roots()
        del roots[0]["bindingChecks"]["ownedSlice"]
        with self.assertRaises(ProbeError):
            self.observe(roots=roots)

    def test_trigger_requires_existing_typed_outer_marker_and_keeps_other_backends_out(self) -> None:
        for marker in (False, None, "true", 1, True):
            ctx = MagicMock(
                outer_engine="docker",
                observations=[
                    {
                        "name": "owned systemd OOM diagnostic",
                        "phase": "after-inner-memory",
                        "schemaVersion": 1,
                        "authority": "observation-only",
                        "ociState": {"OOMKilled": marker},
                    }
                ],
            )
            self.assertEqual(_leaf_witness_needed(ctx, MagicMock()), marker is True)
            ctx.outer_engine = "podman"
            self.assertFalse(_leaf_witness_needed(ctx, MagicMock()))
        self.assertFalse(_leaf_witness_needed(MagicMock(outer_engine="docker", observations=[]), MagicMock()))

    def test_driver_preserves_original_deadline_private_checks_and_exact_cleanup(self) -> None:
        ctx = MagicMock(runtime_deadline=time.monotonic() + 100, observations=[], checks=[], image_ref="private-image")
        ctx.backend.command_timeout.return_value = 10
        service = _hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")
        ctx.checks.append(service)
        original_checks = copy.deepcopy(ctx.checks)
        deadline = ctx.runtime_deadline
        outputs = {
            "start diagnostic-only leaf memory witness": "a" * 64,
            "read private leaf witness protocol": self.protocol(),
            "rebind live diagnostic controller": memory_association_fixture(),
            "wait diagnostic controller completion": "0",
        }
        ctx.exec.side_effect = lambda name, *_args: outputs.get(name, "")
        with (
            patch("scripts.runtime_docker_systemd._leaf_witness_bind", return_value=self.association()),
            patch("scripts.runtime_docker_systemd._leaf_witness_retained_after"),
            patch("scripts.runtime_docker_systemd._leaf_witness_snapshot_root", side_effect=self.roots()),
            patch("scripts.runtime_docker_systemd.time.monotonic_ns", side_effect=[3, 4]),
        ):
            _collect_leaf_memory_witness(ctx, MagicMock(), "owned", "rootful")
        self.assertEqual(ctx.runtime_deadline, deadline)
        self.assertEqual(ctx.checks, original_checks)
        result = ctx.observations[-1]
        self.assertEqual(result["availability"], "observed")
        self.assertEqual(result["authority"], "observation-only")
        self.assertEqual(result["controllerCompletion"], "observation-complete")
        self.assertEqual(result["cleanup"], "verified")
        names = [call.args[0] for call in ctx.exec.call_args_list]
        self.assertLess(names.index("rebind live diagnostic controller"), names.index("finish diagnostic leaf hold"))
        cleanup = next(
            call.args
            for call in ctx.exec.call_args_list
            if call.args[0] == "remove and read back exact diagnostic leaf"
        )
        self.assertIn("a" * 64, cleanup)
        self.assertIn('docker rm --force "$cid"', cleanup[4])
        self.assertNotIn("prune", cleanup[4])

    def test_primary_result_only_triggers_extra_actor_for_already_known_outer_marker_true(self) -> None:
        for marker in (False, None, True):
            ctx = MagicMock(unsafe=True, outer_engine="docker", observations=[], checks=[], image_ref="private-image")
            ctx.checks.append(
                _hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")
            )

            def execute(name: str, *_args: str) -> str:
                if name.startswith("start bounded inner"):
                    return "a" * 64
                if name.startswith("wait bounded inner"):
                    return "137" if "memory" in name else "0"
                return {
                    "inspect inner memory enforcement state": '{"OOMKilled":true}',
                    "inspect inner pids enforcement state": "{}",
                    "verify inner memory scope placement and ownership": hierarchy_fixture(kind="scope"),
                    "verify inner pids scope placement and ownership": hierarchy_fixture(kind="scope"),
                    "read actual memory allocator swap and namespace association": memory_association_fixture(),
                    "read actual memory allocator self telemetry": allocator_telemetry_fixture(),
                    "read exact inner memory cgroup limits": f"{MEMORY_BYTES}\n16",
                    "read exact inner pids cgroup limits": f"{MEMORY_BYTES}\n16",
                    "read bounded inner PID refusal": "bounded-pid-refusal events-before=0 events-after=1",
                }.get(name, "")

            ctx.exec.side_effect = execute

            def snapshot(
                phase: str, *, _context: MagicMock = ctx, _marker: bool | None = marker, **_kwargs: object
            ) -> None:
                _context.observations.append(
                    {
                        "name": "owned systemd OOM diagnostic",
                        "phase": phase,
                        "schemaVersion": 1,
                        "authority": "observation-only",
                        "ociState": {"OOMKilled": _marker},
                    }
                )

            diagnostics = MagicMock()
            diagnostics.snapshot.side_effect = snapshot
            with (
                patch("scripts.runtime_docker_systemd._collect_leaf_memory_witness") as witness,
                patch("scripts.runtime_docker_systemd.verify_outer_container_limits"),
            ):
                verify_inner_limits(ctx, MagicMock(), "owned", diagnostics=diagnostics)
            self.assertEqual(witness.call_count, int(marker is True))
            legacy = next(check for check in ctx.checks if check["name"] == "inner memory allocator diagnostic")
            self.assertTrue(legacy["enforcementSatisfied"])
            self.assertIsNone(legacy["telemetry"]["after"])

    def test_deadline_shortage_launches_no_actor_and_private_exception_operands_do_not_escape(self) -> None:
        ctx = MagicMock(runtime_deadline=time.monotonic() - 1, observations=[], checks=[])
        _collect_leaf_memory_witness(ctx, MagicMock(), "owned", "rootful")
        ctx.exec.assert_not_called()
        self.assertEqual(ctx.observations[-1]["availability"], "unavailable")
        self.assertEqual(ctx.observations[-1]["cleanup"], "not-created")
        ctx.runtime_deadline = time.monotonic() + 100
        ctx.backend.command_timeout.return_value = 10
        ctx.exec.side_effect = ProbeError("PRIVATE-PROC-PATH-PID-OPERAND")
        _collect_leaf_memory_witness(ctx, MagicMock(), "owned", "rootful")
        self.assertNotIn("PRIVATE-PROC-PATH-PID-OPERAND", json.dumps(ctx.observations))
        self.assertEqual(ctx.checks, [])
        self.assertEqual(ctx.observations[-1]["cleanup"], "unavailable")

    def driver_context(self) -> MagicMock:
        ctx = MagicMock(runtime_deadline=time.monotonic() + 100, observations=[], checks=[], image_ref="private-image")
        ctx.backend.command_timeout.return_value = 10
        ctx.checks.append(
            _hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")
        )
        return ctx

    def collect_driver(
        self,
        *,
        fail_at: str | tuple[str, ...] | None = None,
        completion: str = "0",
        launch_output: str = "a" * 64,
        ctx: MagicMock | None = None,
        failure: BaseException | None = None,
    ) -> MagicMock:
        ctx = ctx if ctx is not None else self.driver_context()
        private_failure = failure if failure is not None else ProbeError("PRIVATE /proc/4789/root/secret operand")

        def operation(name: str, value: object = None) -> object:
            if name == fail_at or (isinstance(fail_at, tuple) and name in fail_at):
                raise private_failure
            return value

        commands = {
            "start diagnostic-only leaf memory witness": ("launch", launch_output),
            "release diagnostic leaf and await actual after": ("release-await-after", ""),
            "read private leaf witness protocol": ("log-read", self.protocol()),
            "rebind live diagnostic controller": ("controller-rebind", memory_association_fixture()),
            "verify diagnostic leaf retained only controller": ("retained-hierarchy", "private-hierarchy"),
            "finish diagnostic leaf hold": ("finish-hold", ""),
            "wait diagnostic controller completion": ("wait-completion", completion),
            "remove and read back exact diagnostic leaf": ("cleanup", ""),
        }
        ctx.exec.side_effect = lambda name, *_args: operation(*commands[name])
        roots = iter(self.roots())

        def project(*args: object) -> dict:
            operation("projection-validation")
            return _leaf_witness_public(*args)

        with (
            patch(
                "scripts.runtime_docker_systemd._leaf_witness_room", side_effect=lambda _ctx: operation("room-check")
            ),
            patch(
                "scripts.runtime_docker_systemd._leaf_witness_bind",
                side_effect=lambda *_args: operation("bind", self.association()),
            ),
            patch(
                "scripts.runtime_docker_systemd._leaf_witness_retained_after",
                side_effect=lambda *_args: operation("retained-hierarchy-validation"),
            ),
            patch(
                "scripts.runtime_docker_systemd._leaf_witness_snapshot_root",
                side_effect=lambda _observer, role: operation(role, next(roots)),
            ),
            patch("scripts.runtime_docker_systemd._leaf_witness_public", side_effect=project),
            patch("scripts.runtime_docker_systemd.time.monotonic_ns", side_effect=[3, 4]),
        ):
            _collect_leaf_memory_witness(ctx, MagicMock(), "owned", "rootful")
        return ctx

    def test_collection_failure_identifies_each_operation_without_cleanup_overwriting_it(self) -> None:
        # Independently specified public protocol: no command-derived or exception-derived labels.
        stages = (
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
        )
        self.assertEqual(LEAF_WITNESS_STAGES, frozenset(stages))
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                ctx = self.collect_driver(fail_at=stage)
                result = ctx.observations[-1]
                self.assertEqual(result["enteredStage"], stage)
                self.assertEqual(result["completedStage"], stages[index - 1] if index else None)
                self.assertEqual(result["availability"], "unavailable")
                self.assertEqual(result["controllerCompletion"], "unavailable")
                self.assertEqual(result["cleanup"], "not-created" if index == 0 else "verified")
                cleanup_stage = None if index == 0 else "exact-owned-leaf"
                self.assertEqual(result["cleanupEnteredStage"], cleanup_stage)
                self.assertEqual(result["cleanupCompletedStage"], cleanup_stage)
                self.assertEqual(
                    ctx.checks,
                    [_hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")],
                )
                public = json.dumps(result)
                for private in ("/proc/4789", "secret", "PRIVATE", "private-hierarchy", "private-image", "a" * 64):
                    self.assertNotIn(private, public)

    def test_success_and_controller_failure_have_completed_wait_without_invented_completion(self) -> None:
        for completion, expected, availability in (
            ("0", "observation-complete", "observed"),
            ("1", "failed", "unavailable"),
        ):
            with self.subTest(completion=completion):
                result = self.collect_driver(completion=completion).observations[-1]
                self.assertEqual(result["enteredStage"], "wait-completion")
                self.assertEqual(result["completedStage"], "wait-completion")
                self.assertEqual(result["controllerCompletion"], expected)
                self.assertEqual(result["availability"], availability)
                self.assertEqual(result["cleanupEnteredStage"], "exact-owned-leaf")
                self.assertEqual(result["cleanupCompletedStage"], "exact-owned-leaf")
                self.assertEqual(result["cleanup"], "verified")

    def test_cleanup_failure_keeps_collection_location_and_actual_controller_completion(self) -> None:
        for fail_at, entered, completed, controller in (
            ("release-await-after", "release-await-after", "root-before", "unavailable"),
            (None, "wait-completion", "wait-completion", "observation-complete"),
        ):
            with self.subTest(fail_at=fail_at):
                failures = (fail_at, "cleanup") if fail_at else "cleanup"
                result = self.collect_driver(fail_at=failures).observations[-1]
                self.assertEqual(result["enteredStage"], entered)
                self.assertEqual(result["completedStage"], completed)
                self.assertEqual(result["controllerCompletion"], controller)
                self.assertEqual(result["cleanupEnteredStage"], "exact-owned-leaf")
                self.assertIsNone(result["cleanupCompletedStage"])
                self.assertEqual(result["cleanup"], "unavailable")
                self.assertEqual(result["availability"], "unavailable")
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_invalid_launch_identity_is_not_forwarded_as_owned_cleanup_identity(self) -> None:
        ctx = self.collect_driver(launch_output="PRIVATE invalid container identity")
        result = ctx.observations[-1]
        self.assertEqual(result["enteredStage"], "launch")
        self.assertEqual(result["completedStage"], "room-check")
        self.assertEqual(result["availability"], "unavailable")
        self.assertEqual(result["cleanup"], "verified")
        cleanup = ctx.exec.call_args_list[-1].args
        self.assertEqual(cleanup[-2], "")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_retained_hierarchy_validation_failure_is_not_a_completed_read(self) -> None:
        result = self.collect_driver(fail_at="retained-hierarchy-validation").observations[-1]
        self.assertEqual(result["enteredStage"], "retained-hierarchy")
        self.assertEqual(result["completedStage"], "controller-rebind")
        self.assertEqual(result["cleanup"], "verified")
        self.assertEqual(result["availability"], "unavailable")

    def test_cancellation_propagates_after_exact_cleanup_and_retains_interrupted_stage(self) -> None:
        ctx = self.driver_context()
        cancellation = KeyboardInterrupt("PRIVATE cancellation operand")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.collect_driver(ctx=ctx, fail_at="root-after", failure=cancellation)
        self.assertIs(caught.exception, cancellation)
        result = ctx.observations[-1]
        self.assertEqual(result["enteredStage"], "root-after")
        self.assertEqual(result["completedStage"], "retained-hierarchy")
        self.assertEqual(result["cleanup"], "verified")
        cleanup = ctx.exec.call_args_list[-1].args
        self.assertEqual(cleanup[0], "remove and read back exact diagnostic leaf")
        self.assertIn("a" * 64, cleanup)
        self.assertNotIn("PRIVATE", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
