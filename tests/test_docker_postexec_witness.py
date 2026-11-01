"""Hermetic held-task witnesses; never inspect host tasks or invoke a runtime."""

from __future__ import annotations

import copy
import errno
import hashlib
import io
import stat
import unittest
from contextlib import ExitStack, nullcontext
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from scripts import docker_direct_startup_observations as observations
from scripts import docker_userns_active as active
from scripts import docker_userns_qualification as qualification
from scripts import runtime_docker
from scripts.docker_userns_active_client import ActiveClient
from scripts.evidence_gate import EvidenceError, require_ordinary_runtime_authority
from tests.test_docker_userns_callers import caller_case, caller_record
from tests.test_docker_userns_qualification import binding, scoped_receipt


class ClosedWitness(unittest.TestCase):
    def test_complete_partial_and_legacy_are_distinct(self) -> None:
        scoped = scoped_receipt()
        complete = scoped["postExecWitness"]
        self.assertTrue(qualification.postexec_witness_valid(complete, scoped, complete=True))
        partial = copy.deepcopy(complete)
        partial["samples"].pop()
        self.assertTrue(qualification.postexec_witness_valid(partial, scoped))
        self.assertFalse(qualification.postexec_witness_valid(partial, scoped, complete=True))
        self.assertTrue(qualification.postexec_witness_valid(None, scoped))
        self.assertFalse(qualification.postexec_witness_valid(None, scoped, complete=True))

    def test_closed_envelope_source_order_and_checkpoint_stability(self) -> None:
        scoped = scoped_receipt()
        original = scoped["postExecWitness"]
        mutations = [
            {"bindingSha256": "0" * 64},
            {"sourceManifestSha256": "0" * 64},
            {"leaseSha256": "0" * 64},
            {"schemaVersion": True},
            {"samples": []},
            {"samples": original["samples"][::-1]},
            {"rawPid": 100},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                value.update(mutation)
                self.assertFalse(qualification.postexec_witness_valid(value, scoped, complete=True))
        for key, wrong in (
            ("labelSha256", "0" * 64),
            ("parentTaskSha256", "c" * 64),
            ("parentNamespaceSha256", "e" * 64),
            ("identityMatched", 1),
            ("parentChildMatched", False),
            ("namespaceSeparated", False),
            ("executableBytes", True),
            ("executableBytes", 0),
            ("executableBytes", 32 * 1024 * 1024 + 1),
            ("executableSha256", "A" * 64),
            ("unknown", True),
        ):
            with self.subTest(key=key, wrong=wrong):
                value = copy.deepcopy(original)
                value["samples"][0][key] = wrong
                self.assertFalse(qualification.postexec_witness_valid(value, scoped, complete=True))
        value = copy.deepcopy(original)
        value["samples"][1]["executableSha256"] = "0" * 64
        self.assertFalse(qualification.postexec_witness_valid(value, scoped, complete=True))


class RootWitness(unittest.TestCase):
    def port(self) -> active.RootPort:
        port = active.RootPort.__new__(active.RootPort)
        port.record = {
            "state": "attached",
            "retained": False,
            "bindingSha256": "a" * 64,
            "profileName": "fixture",
            "subject": {"container": "a" * 64},
        }
        port.cleanup = False
        port.work_until = 100_000_000_000
        port.binding = SimpleNamespace(runtime_slice="owned.slice", slice_identity="1:2")
        port.modules = SimpleNamespace(qualification=qualification)
        port.store = SimpleNamespace(path=Path("/run/fixed/" + "f" * 32))
        port.commit = Mock()
        port.guard = Mock()
        port.point = Mock()
        return port

    def test_checkpoint_order_clamp_restore_and_no_lifecycle_change(self) -> None:
        port = self.port()
        scoped = scoped_receipt()
        scoped.update(bindingSha256="a" * 64, profileName="fixture", sourceManifestSha256=active.SOURCE_MANIFEST_SHA256)
        samples = copy.deepcopy(scoped["postExecWitness"]["samples"])
        for sample in samples:
            sample["labelSha256"] = hashlib.sha256(b"fixture (enforce)\n").hexdigest()
        deadlines = []

        def sample(checkpoint: str) -> dict:
            deadlines.append(port.work_until)
            return samples[0 if checkpoint == "ready" else 1]

        port.witness_sample = Mock(side_effect=sample)
        with (
            patch.object(active, "receipt", return_value=scoped),
            patch.object(active.time, "monotonic_ns", return_value=1),
        ):
            with self.assertRaises(active.RefusedError):
                port.collect_postexec_witness("pre-close")
            port.collect_postexec_witness("ready")
            port.collect_postexec_witness("pre-close")
            with self.assertRaises(active.RefusedError):
                port.collect_postexec_witness("pre-close")
        self.assertEqual(deadlines, [5_000_000_001] * 2)
        self.assertEqual(port.work_until, 100_000_000_000)
        self.assertEqual(port.record["state"], "attached")
        self.assertFalse(port.record["retained"])
        self.assertEqual(port.commit.call_count, 2)

    def test_failure_restores_deadline_without_committing_or_cleanup_authority(self) -> None:
        port = self.port()
        port.witness_sample = Mock(side_effect=active.RefusedError)
        with (
            patch.object(active, "receipt", return_value=scoped_receipt()),
            self.assertRaises(active.RefusedError),
        ):
            port.collect_postexec_witness("ready")
        self.assertEqual(port.work_until, 100_000_000_000)
        self.assertNotIn("postExecWitness", port.record)
        port.commit.assert_not_called()
        self.assertFalse(port.cleanup)
        for key in ("readerPending", "childPending", "durabilityUnknown", "retained"):
            port = self.port()
            port.record[key] = True
            with self.subTest(key=key), self.assertRaises(active.RefusedError):
                port.witness_budget()

    def test_parent_mapping_and_unique_immediate_namespace_child(self) -> None:
        port = self.port()
        parent = {"pid": 10, "uid": 1000, "before": {"namespaces": (1, 2, 3)}}
        child = {"pid": 20, "exe": 20, "before": {"parent": 10, "namespacePid": 7, "namespaces": (4, 5, 3)}}
        other = {"pid": 30, "exe": 30, "before": {"parent": 99, "namespacePid": 8, "namespaces": (6, 7, 3)}}
        tasks = {20: child, 30: other}
        port.witness_task = lambda pid: nullcontext(tasks[pid])
        with ExitStack() as stack, patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)):
            self.assertIs(port.witness_parent(stack, parent, {10, 20}, None), parent)
            self.assertIs(port.witness_parent(stack, parent, {20, 30}, 7), child)
            self.assertIs(port.witness_child(stack, parent, {10, 20, 30}, (1, 2), {20}), child)
            for mutation in ({"parent": 11}, {"namespaces": (1, 5, 3)}, {"namespaces": (4, 2, 3)}):
                before = child["before"].copy()
                child["before"].update(mutation)
                with self.subTest(mutation=mutation), self.assertRaises(active.RefusedError):
                    port.witness_child(stack, parent, {10, 20, 30}, (1, 2), {20})
                child["before"] = before
            other["before"]["parent"] = 10
            with self.assertRaises(active.RefusedError):
                port.witness_child(stack, parent, {10, 20, 30}, (1, 2), {20})
            with self.assertRaises(active.RefusedError):
                port.witness_child(stack, parent, {10, 20}, (1, 999), {20})

    def test_status_requires_exact_uid_pid_and_namespace_mapping(self) -> None:
        port = self.port()
        raw = b"Pid:\t20\nTgid:\t20\nUid:\t1000 1000 1000 1000\nPPid:\t10\nNSpid:\t20 7\n"
        port.witness_read = Mock(return_value=raw)
        self.assertEqual(port.witness_status(1, 20, 1000), {"parent": 10, "namespacePid": 7})
        for invalid in (raw.replace(b"1000", b"0"), raw.replace(b"20 7", b"21 7"), raw + b"PPid: 11\n"):
            port.witness_read.return_value = invalid
            with self.subTest(invalid=invalid), self.assertRaises(active.RefusedError):
                port.witness_status(1, 20, 1000)

    def test_proc_and_executable_aggregate_limits(self) -> None:
        port = self.port()
        port.witness_counts = {"procBytes": 512 * 1024, "exeBytes": 96 * 1024 * 1024}
        with (
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active, "proc_bytes", return_value=b"x"),
        ):
            with self.assertRaises(active.RefusedError):
                port.witness_read(1, "status")
            with self.assertRaises(active.RefusedError):
                port.witness_executable_bytes(1)

    def sampled_port(self, *, direct: bool) -> tuple[active.RootPort, dict]:
        port = self.port()
        port.binding = binding()
        if direct:
            port.binding = qualification.MaintainedDirectBinding(
                **(
                    asdict(port.binding)
                    | {
                        "image": "docker-20.10-rootless",
                        "phase": "ordinary-direct",
                        "purpose": "maintained-prerequisite",
                    }
                )
            )
        tasks = {}
        for pid, uid, parent, guest, namespaces in (
            (10, 1000 if direct else 0, 1, 1, (1, 2, 3)),
            (20, 1000, 10, 7, (1, 2, 3)),
            (30, 1000, 10 if direct else 20, 8, (4, 5, 3)),
        ):
            tasks[pid] = {
                "pid": pid,
                "uid": uid,
                "directory": pid,
                "exe": pid,
                "pidfd": pid,
                "before": {
                    "startTicks": pid,
                    "cgroup": "owned",
                    "namespacePid": guest,
                    "parent": parent,
                    "namespaces": namespaces,
                },
            }
        port.record["subject"].update(pid=10, startTicks=10, cgroup="owned", startedAt="fixed")
        port.inspect = Mock(return_value={"State": {"Running": True, "Pid": 10, "StartedAt": "fixed"}})
        port.witness_task = Mock(side_effect=lambda pid, _uid=1000: nullcontext(tasks[pid]))
        port.witness_systemd_pid = Mock(return_value=7)
        port.witness_scope_pids = Mock(return_value={10, 30} if direct else {10, 20, 30})
        port.witness_task_state = Mock(side_effect=lambda task: task["before"])
        port.witness_parent_children = Mock(return_value={30})
        port.modules.observations = SimpleNamespace(
            held_rootlesskit=Mock(side_effect=lambda *_args: nullcontext({"descriptor": 99, "identity": (1, 2)})),
            held_executable_hash=Mock(return_value=("a" * 64, 128)),
        )
        return port, tasks

    def test_complete_direct_and_systemd_samples_and_drift_refusals(self) -> None:
        for direct in (True, False):
            for wrong in ("none", "hash", "task", "scope", "engine", "unit"):
                if direct and wrong == "unit":
                    continue
                port, tasks = self.sampled_port(direct=direct)
                if wrong == "hash":
                    port.modules.observations.held_executable_hash.side_effect = [
                        ("a" * 64, 128),
                        ("b" * 64, 128),
                        ("a" * 64, 128),
                    ]
                elif wrong == "task":
                    port.witness_task_state.side_effect = lambda task: task["before"] | {"startTicks": 99}
                elif wrong == "scope":
                    port.witness_scope_pids.side_effect = [{10, 20, 30}, {10, 20}]
                elif wrong == "engine":
                    port.inspect.side_effect = [port.inspect.return_value, {"State": {"Running": False}}]
                elif wrong == "unit":
                    port.witness_systemd_pid.side_effect = [7, 8]
                with (
                    self.subTest(direct=direct, wrong=wrong),
                    patch.object(active.time, "monotonic_ns", return_value=1),
                    patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    if wrong == "none":
                        result = port.witness_sample("ready")
                        self.assertEqual(result["executableSha256"], "a" * 64)
                        self.assertEqual(
                            result["parentTaskSha256"],
                            active.digest(active.encoded(tasks[10 if direct else 20]["before"])),
                        )
                        self.assertEqual(port.modules.observations.held_executable_hash.call_count, 3)
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.witness_sample("ready")

    def test_complete_sample_rechecks_child_universe_after_hashing(self) -> None:
        for direct in (True, False):
            port, _tasks = self.sampled_port(direct=direct)
            port.witness_parent_children.side_effect = [{30}, {30, 40}]
            with (
                self.subTest(direct=direct),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                patch.object(active.select, "select", return_value=([], [], [])),
                self.assertRaises(active.RefusedError),
            ):
                port.witness_sample("ready")
            self.assertEqual(port.modules.observations.held_executable_hash.call_count, 3)

    def test_scope_walk_rejects_symlinks_aliases_duplicates_and_pid_overflow(self) -> None:
        port = self.port()
        entry = SimpleNamespace(name="child", is_symlink=lambda: False, is_dir=lambda **_kw: True)
        for raw, children, child_identity in (
            (b"10\n", [], (1, 3)),
            (b"10\n10\n", [], (1, 3)),
            (b"10\n", [SimpleNamespace(is_symlink=lambda: True)], (1, 3)),
            (b"10\n", [entry], (1, 3)),
            (b"10\n", [entry], (1, 4)),
            (b"".join(str(pid).encode() + b"\n" for pid in range(1, 66)), [], (1, 3)),
        ):
            port.witness_counts = {"procBytes": 0, "pids": set()}

            def info(fd: int, identity: tuple = child_identity) -> SimpleNamespace:
                return SimpleNamespace(st_dev=1, st_ino=3 if fd == 1 else identity[1])

            with (
                self.subTest(raw=raw, children=len(children), identity=child_identity),
                ExitStack() as stack,
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", side_effect=info),
                patch.object(active.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=child_identity[1])),
                patch.object(active.os, "open", return_value=2),
                patch.object(active.os, "close"),
                patch.object(active.os, "read", return_value=raw),
                patch.object(
                    active.os, "scandir", side_effect=lambda _fd, entries=children: nullcontext(iter(entries))
                ),
            ):
                if raw == b"10\n" and not children:
                    self.assertEqual(port.witness_scope_walk(stack, 1), ({10}, {(): (1, 3)}))
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_scope_walk(stack, 1)

    def test_scope_identity_and_named_directory_drift_are_refused(self) -> None:
        port = self.port()

        def info(fd: int) -> SimpleNamespace:
            return SimpleNamespace(st_dev=1, st_ino=fd)

        for changed in ("none", "runtime", "scope", "subtree"):
            port.witness_counts = {"procBytes": 0, "pids": set()}
            opens = [1, 2, 3, 1, 2, 3]
            named = [SimpleNamespace(st_dev=1, st_ino=2), SimpleNamespace(st_dev=1, st_ino=3)] * 2
            if changed == "runtime":
                named[2] = SimpleNamespace(st_dev=1, st_ino=99)
            if changed == "scope":
                named[3] = SimpleNamespace(st_dev=1, st_ino=99)
            trees = [({10}, {(): (1, 3)}), ({10}, {(): (1, 3)})]
            if changed == "subtree":
                trees[1] = ({10}, {(): (1, 3), ("new",): (1, 99)})
            with (
                self.subTest(changed=changed),
                ExitStack() as stack,
                patch.object(active.os, "open", side_effect=opens),
                patch.object(active.os, "close"),
                patch.object(active.os, "fstat", side_effect=info),
                patch.object(active.os, "stat", side_effect=named),
                patch.object(active, "filesystem_magic"),
                patch.object(port, "witness_scope_walk", side_effect=trees),
            ):
                self.assertEqual(port.witness_scope_pids(stack), {10})
                if changed == "none":
                    self.assertEqual(port.witness_scope_pids(stack), {10})
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_scope_pids(stack)

    def test_held_task_rejects_label_cgroup_executable_and_dead_task(self) -> None:
        port = self.port()
        state = {"cgroup": "0::/owned.slice/docker-" + "a" * 64 + ".scope\n"}
        task = {"directory": 1, "pid": 10, "uid": 1000, "pidfd": 2, "exe": 3}
        original = SimpleNamespace(st_dev=1, st_ino=2)
        for wrong in ("none", "label", "cgroup", "executable", "dead"):
            snapshot = dict(state)
            if wrong == "cgroup":
                snapshot["cgroup"] += "0::/foreign.scope\n"
            with (
                self.subTest(wrong=wrong),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active, "task_snapshot", return_value=snapshot),
                patch.object(port, "witness_status", return_value={"parent": 1}),
                patch.object(port, "witness_namespaces", return_value=(1, 2, 3)),
                patch.object(
                    port,
                    "witness_read",
                    return_value=b"foreign (enforce)\n" if wrong == "label" else b"fixture (enforce)\n",
                ),
                patch.object(active.select, "select", return_value=([2] if wrong == "dead" else [], [], [])),
                patch.object(active.os, "fstat", return_value=original),
                patch.object(
                    active.os,
                    "stat",
                    return_value=SimpleNamespace(st_dev=1, st_ino=99) if wrong == "executable" else original,
                ),
                patch.object(active, "mark", side_effect=vars),
            ):
                if wrong == "none":
                    self.assertEqual(port.witness_task_state(task)["cgroup"], state["cgroup"])
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_task_state(task)


class CompleteParentChildren(unittest.TestCase):
    def port(self) -> active.RootPort:
        port = RootWitness().port()
        port.witness_counts = {"procBytes": 0, "exeBytes": 0, "pids": set()}
        return port

    def test_nonleader_children_union_and_stable_held_threads(self) -> None:
        for wrong in ("none", "extra", "missing", "duplicate", "thread-set", "thread-identity", "named-inode"):
            port = self.port()
            with ExitStack() as stack:
                parent = {"pid": 10, "uid": 1000, "directory": 10, "stack": stack}
                current = {110: b"", 111: b"30 "}

                def opened(name: str, _flags: int, *, dir_fd: int) -> int:
                    self.assertIn((dir_fd, name), {(10, "task"), (100, "10"), (100, "11")})
                    return 100 if name == "task" else 100 + int(name)

                def named(name: str, *, dir_fd: int, follow_symlinks: bool) -> SimpleNamespace:
                    self.assertFalse(follow_symlinks)
                    self.assertIn(dir_fd, {10, 100})
                    return SimpleNamespace(st_dev=1, st_ino=100 if name == "task" else 100 + int(name))

                with (
                    self.subTest(wrong=wrong),
                    patch.object(active.time, "monotonic_ns", return_value=1),
                    patch.object(active.os, "open", side_effect=opened),
                    patch.object(active.os, "close"),
                    patch.object(active.os, "fstat", side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd)),
                    patch.object(active.os, "stat", side_effect=named) as named_stat,
                    patch.object(active, "filesystem_magic"),
                    patch.object(port, "witness_thread_ids", return_value={10, 11}) as ids,
                    patch.object(
                        port, "witness_thread_state", side_effect=lambda _fd, tid, _parent: (tid, tid * 10)
                    ) as state,
                    patch.object(
                        port,
                        "witness_read",
                        side_effect=lambda fd, leaf, values=current: values[fd] if leaf == "children" else b"",
                    ),
                ):
                    self.assertEqual(port.witness_parent_children(parent), {30})
                    self.assertEqual(port.witness_parent_children(parent), {30})
                    self.assertEqual(set(parent["threads"]), {10, 11})
                    self.assertEqual(port.witness_counts["pids"], {30})
                    if wrong == "none":
                        continue
                    if wrong == "extra":
                        current[111] = b"30 40 "
                    elif wrong == "missing":
                        current[111] = b""
                    elif wrong == "duplicate":
                        current[110] = b"30 "
                    elif wrong == "thread-set":
                        ids.return_value = {10}
                    elif wrong == "thread-identity":
                        state.side_effect = lambda _fd, tid, _parent: (tid, 999)
                    else:
                        named_stat.side_effect = None
                        named_stat.return_value = SimpleNamespace(st_dev=1, st_ino=999)
                    with self.assertRaises(active.RefusedError):
                        port.witness_parent_children(parent)

    def test_thread_census_changing_during_first_scan_refuses(self) -> None:
        port = self.port()
        with (
            ExitStack() as stack,
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active.os, "open", return_value=100),
            patch.object(active.os, "close"),
            patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=100)),
            patch.object(active.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=100)),
            patch.object(active, "filesystem_magic"),
            patch.object(port, "witness_thread_ids", side_effect=[{10}, {10, 11}]),
            patch.object(port, "witness_thread_state", return_value=(10, 100)),
            patch.object(port, "witness_read", return_value=b"30 "),
            self.assertRaises(active.RefusedError),
        ):
            port.witness_parent_children({"pid": 10, "uid": 1000, "directory": 10, "stack": stack})

    def test_missing_escaped_extra_ambiguous_or_unreadable_children_refuse_without_recovery(self) -> None:
        parent = {"pid": 10, "uid": 1000, "before": {"namespaces": (1, 2, 3)}}
        for candidates, children, relation, inaccessible in (
            ({10, 30}, {30}, {30: 10}, False),
            ({10, 30}, {30, 40}, {30: 10}, False),
            ({10}, {30}, {}, False),
            ({10, 30, 40}, {30}, {30: 10, 40: 10}, False),
            ({10, 30, 40}, {30, 40}, {30: 10, 40: 10}, False),
            ({10, 30}, {30}, {30: 99}, False),
            ({10, 30}, {30}, {30: 10}, True),
        ):
            port = self.port()
            tasks = {
                pid: {"pid": pid, "exe": pid, "before": {"parent": ppid, "namespaces": (4, 5, 3)}}
                for pid, ppid in relation.items()
            }
            port.witness_task = Mock(
                side_effect=active.RefusedError if inaccessible else lambda pid, values=tasks: nullcontext(values[pid])
            )
            with (
                self.subTest(candidates=candidates, children=children, relation=relation, inaccessible=inaccessible),
                ExitStack() as stack,
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
            ):
                if candidates == {10, 30} and children == {30} and relation == {30: 10} and not inaccessible:
                    self.assertIs(port.witness_child(stack, parent, candidates, (1, 2), children), tasks[30])
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_child(stack, parent, candidates, (1, 2), children)
                if not children <= candidates:
                    port.witness_task.assert_not_called()

    def test_thread_ids_share_original_64_id_cap_and_reject_foreign_names(self) -> None:
        for wrong in ("none", "65", "symlink", "nondirectory", "foreign-name"):
            port = self.port()
            names = [str(value) for value in range(1, 66)] if wrong == "65" else ["10", "11"]
            if wrong == "foreign-name":
                names.append("../12")
            entries = [
                SimpleNamespace(
                    name=name,
                    is_symlink=lambda value=wrong: value == "symlink",
                    is_dir=lambda value=wrong, **_kw: value != "nondirectory",
                )
                for name in names
            ]
            with (
                self.subTest(wrong=wrong),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "scandir", side_effect=lambda _fd, values=entries: nullcontext(iter(values))),
            ):
                if wrong == "none":
                    self.assertEqual(port.witness_thread_ids(1), {10, 11})
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_thread_ids(1)

    def test_thread_status_and_children_read_keep_original_proc_and_read_caps(self) -> None:
        port = self.port()
        parent = {"pid": 10, "uid": 1000}
        fields = [b"S"] + [b"0"] * 18 + [b"123"]
        raw_stat = b"11 (thread) " + b" ".join(fields)
        raw_status = b"Pid: 11\nTgid: 10\nUid: 1000 1000 1000 1000\n"
        for wrong in ("none", "tgid", "uid", "dead"):
            status = raw_status.replace(b"Tgid: 10", b"Tgid: 99") if wrong == "tgid" else raw_status
            if wrong == "uid":
                status = status.replace(b"1000", b"0")
            current_stat = raw_stat.replace(b") S", b") Z") if wrong == "dead" else raw_stat
            port.witness_read = Mock(
                side_effect=lambda _fd, leaf, raw=current_stat, fields=status: raw if leaf == "stat" else fields
            )
            with self.subTest(wrong=wrong):
                if wrong == "none":
                    self.assertEqual(port.witness_thread_state(1, 11, parent), (11, 123))
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_thread_state(1, 11, parent)
        del port.witness_read
        for wrong in ("aggregate", "per-read"):
            port.witness_counts["procBytes"] = active.WITNESS_PROC_LIMIT if wrong == "aggregate" else 0
            with (
                self.subTest(wrong=wrong),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "open", return_value=2),
                patch.object(active.os, "close"),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o444)),
                patch.object(active.os, "read", return_value=b"30 " if wrong == "aggregate" else b"x" * 8193) as read,
                self.assertRaises(active.RefusedError),
            ):
                port.witness_read(1, "children")
            read.assert_called_once_with(2, 8193)


class HeldExecutable(unittest.TestCase):
    def test_elf_hash_capability_size_metadata_and_machine_guards(self) -> None:
        raw = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(20)
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1, st_size=len(raw))
        api = SimpleNamespace(require=active.require, check=Mock(), mark=lambda value: vars(value).copy())
        consume = Mock()
        with (
            patch.object(observations.os, "fstat", return_value=info),
            patch.object(observations.os, "getxattr", side_effect=OSError(errno.ENODATA, "absent")) as capability,
            patch.object(observations.os, "read", side_effect=[raw, b""]) as read,
        ):
            self.assertEqual(
                observations.held_executable_hash(api, 3, "amd64", 123, consume),
                (hashlib.sha256(raw).hexdigest(), len(raw)),
            )
            consume.assert_called_once_with(len(raw))
            for key, wrong in (("st_uid", 1000), ("st_nlink", 2), ("st_size", 0), ("st_mode", stat.S_IFREG | 0o777)):
                original = getattr(info, key)
                setattr(info, key, wrong)
                with self.subTest(key=key), self.assertRaises(active.RefusedError):
                    observations.held_executable_hash(api, 3, "amd64", 123, consume)
                setattr(info, key, original)
            capability.side_effect = None
            capability.return_value = b"capability"
            with self.assertRaises(active.RefusedError):
                observations.held_executable_hash(api, 3, "amd64", 123, consume)
            capability.side_effect = OSError(errno.ENODATA, "absent")
            read.side_effect = [raw, b""]
            with self.assertRaises(active.RefusedError):
                observations.held_executable_hash(api, 3, "arm64", 123, consume)

    def test_runtime_hook_has_fixed_checkpoint_and_propagates_failure(self) -> None:
        profile = SimpleNamespace(witness=Mock(side_effect=ValueError("unavailable")))
        ctx = SimpleNamespace(backend=SimpleNamespace(scoped_profile=profile))
        with self.assertRaises(ValueError):
            runtime_docker._postexec_checkpoint(ctx, "ready")
        profile.witness.assert_called_once_with("ready")
        runtime_docker._postexec_checkpoint(SimpleNamespace(), "pre-close")


class WitnessIntegration(unittest.TestCase):
    def test_client_sends_no_subject_selectors_and_rejects_bad_checkpoint(self) -> None:
        client = ActiveClient.__new__(ActiveClient)
        client.binding = SimpleNamespace(digest=lambda: "a" * 64)
        client.evidence = {"original": True}
        scoped = scoped_receipt()
        scoped["state"] = "attached"
        client.rpc = Mock(return_value=scoped)
        client.refuse_response = Mock(side_effect=ValueError("unavailable"))
        client.witness("pre-close")
        client.rpc.assert_called_once_with("witness", {"bindingSha256": "a" * 64, "checkpoint": "pre-close"})
        self.assertIs(client.evidence, scoped)
        for wrong in ("post-create", "ready", "/proc/1"):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                client.witness(wrong)
        scoped["postExecWitness"] = None
        with self.assertRaises(ValueError):
            client.witness("pre-close")

    def test_gate_refuses_old_missing_reordered_and_unbound_components(self) -> None:
        context = caller_case("ci-pr", "amd64")[2]
        record = caller_record(context)
        require_ordinary_runtime_authority(record, "docker", {"launcher": "systemd", "mode": "rootless"})
        for wrong in ("missing", "legacy", "partial", "reordered", "binding"):
            changed = copy.deepcopy(record)
            scoped = changed["phases"][0]["scopedProfile"]
            if wrong == "missing":
                del scoped["postExecWitness"]
            elif wrong == "legacy":
                scoped["postExecWitness"] = scoped["profileObservation"]
            elif wrong == "partial":
                scoped["postExecWitness"]["samples"].pop()
            elif wrong == "reordered":
                scoped["postExecWitness"]["samples"].reverse()
            else:
                scoped["postExecWitness"]["bindingSha256"] = "0" * 64
            with self.subTest(wrong=wrong), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(changed, "docker", {"launcher": "systemd", "mode": "rootless"})

    def test_root_rpc_accepts_only_bound_checkpoint_while_attached(self) -> None:
        record = {"bindingSha256": "a" * 64, "state": "attached"}
        port, store = Mock(), Mock()
        store.read.return_value = record
        store.locked.side_effect = nullcontext
        route = SimpleNamespace(operation="witness", name="f" * 32, request=Path("/inert"))
        modules = SimpleNamespace(
            qualification=SimpleNamespace(ProfileLease=Mock(return_value=SimpleNamespace()), State=qualification.State)
        )
        for extra in (None, "pid", "container", "path", "profile", "command"):
            request = {"bindingSha256": "a" * 64, "checkpoint": "ready"}
            if extra is not None:
                request[extra] = "caller-selected"
            with (
                self.subTest(extra=extra),
                patch.object(active, "request_value", return_value=request),
                patch.object(active, "Store", return_value=store),
                patch.object(active, "RootPort", return_value=port),
                patch.object(active, "receipt", return_value={}),
            ):
                if extra is None:
                    self.assertEqual(active.root_rpc(Path("/inert"), {}, modules, route), {})
                    port.collect_postexec_witness.assert_called_once_with("ready")
                else:
                    with self.assertRaises(active.RefusedError):
                        active.root_rpc(Path("/inert"), {}, modules, route)
        record["state"] = "prepared"
        with (
            patch.object(active, "request_value", return_value={"bindingSha256": "a" * 64, "checkpoint": "ready"}),
            patch.object(active, "Store", return_value=store),
            patch.object(active, "RootPort", return_value=port),
            self.assertRaises(active.RefusedError),
        ):
            active.root_rpc(Path("/inert"), {}, modules, route)

    def test_both_witness_failures_preserve_original_finally_cleanup(self) -> None:
        for failed in ("ready", "pre-close"):
            events = []
            ctx = MagicMock(directory=Path("/unused"), image_ref="inert")
            ctx.start.return_value = "owned"
            ctx.assert_equal = Mock()
            ctx.load_fixture_archive.side_effect = lambda *_args, captured=events: captured.append("work")
            ctx.exec.side_effect = lambda name, *_args, captured=events: captured.append(name)

            def witness(checkpoint: str, failing: str = failed, captured: list = events) -> None:
                captured.append(checkpoint)
                if checkpoint == failing:
                    reason = "witness unavailable"
                    raise ValueError(reason)

            def docker(_ctx: object, _budget: object, _container: str, name: str, *_args: str) -> str:
                if name == "read Docker API versions":
                    return '{"Version":"29.0"}'
                if name == "inspect Docker storage and security":
                    return '{"SecurityOptions":["rootless"]}'
                return "unless-stopped wget"

            ctx.backend.scoped_profile.witness.side_effect = witness
            with (
                self.subTest(failed=failed),
                patch.object(runtime_docker, "_outer_options", return_value=()),
                patch.object(runtime_docker, "_prepare_started_daemon"),
                patch.object(runtime_docker, "_verify_daemon_user"),
                patch.object(runtime_docker, "_docker", side_effect=docker),
                patch.object(runtime_docker, "_checked_exec", return_value="29.0"),
                patch.object(runtime_docker, "_require_api_range"),
                patch.object(runtime_docker, "_require_storage_driver"),
                patch.object(runtime_docker, "_wait_http"),
                patch.object(runtime_docker, "verify_outer_container_limits"),
                patch.object(runtime_docker, "_diagnose_failed_start"),
                patch.object(
                    runtime_docker,
                    "_shutdown_docker_phase",
                    side_effect=lambda *_a, captured=events, **_kw: captured.append("shutdown"),
                ),
                self.assertRaisesRegex(ValueError, "witness unavailable"),
            ):
                runtime_docker._run_nested_docker_with_archive(
                    ctx,
                    {"mode": "rootless"},
                    ("1000", runtime_docker.DockerProbePhase.ENFORCEMENT),
                    Mock(),
                    io.BytesIO(),
                )
            self.assertEqual(events[-1], "shutdown")
            self.assertEqual(events[0], "ready")
            if failed == "ready":
                ctx.load_fixture_archive.assert_not_called()
            else:
                self.assertLess(events.index("ready"), events.index("work"))
                self.assertLess(events.index("verify nested Docker cleanup readback"), events.index("pre-close"))
