"""Hermetic held-task witnesses; never inspect host tasks or invoke a runtime."""

from __future__ import annotations

import copy
import errno
import hashlib
import io
import json
import stat
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
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
from tests.test_docker_userns_qualification import binding, current_scoped_receipt, postexec_v2_fixture, scoped_receipt


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
        port._witness_proc = SimpleNamespace(
            open=lambda directory, leaf, flags: active.os.open(leaf, flags | active.os.O_CLOEXEC, dir_fd=directory)
        )
        return port

    def test_checkpoint_order_clamp_restore_and_no_lifecycle_change(self) -> None:
        port = self.port()
        scoped = scoped_receipt()
        scoped.update(bindingSha256="a" * 64, profileName="fixture", sourceManifestSha256=active.SOURCE_MANIFEST_SHA256)
        samples = copy.deepcopy(postexec_v2_fixture(scoped)["samples"])
        for sample in samples:
            sample["labelSha256"] = hashlib.sha256(b"fixture (enforce)\n").hexdigest()
        deadlines = []

        def sample(checkpoint: str) -> dict:
            deadlines.append(port.work_until)
            port._witness_scope = (object(), ())
            port._witness_anchor = {"fixture": True}
            return samples[0 if checkpoint == "ready" else 1]

        port.witness_sample = Mock(side_effect=sample)
        with (
            patch.object(active, "receipt", return_value=scoped),
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active, "write_leaf"),
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
        self.assertIsNone(port._witness_scope)

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
            patch.object(active.os, "open", return_value=1),
            patch.object(active.os, "read", return_value=b"x"),
            patch.object(active.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)),
            patch.object(active.os, "close"),
            patch.object(active, "filesystem_magic"),
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
                    "pid": pid,
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
        private = {}

        def write(_directory: Path, name: str, raw: bytes) -> None:
            self.assertEqual(name, active.WITNESS_ANCHOR)
            if name in private:
                raise FileExistsError
            private[name] = raw

        def read(path: Path, **kwargs: object) -> bytes:
            self.assertEqual(path.name, active.WITNESS_ANCHOR)
            self.assertEqual(kwargs, {"immutable": True})
            return private[path.name]

        for target, options in (
            ("ProcView", {"return_value": port._witness_proc}),
            ("write_leaf", {"side_effect": write}),
            ("root_bytes", {"side_effect": read}),
        ):
            replacement = patch.object(active, target, **options)
            replacement.start()
            self.addCleanup(replacement.stop)

        def realm(_stack: ExitStack) -> tuple:
            port._witness_owner_pidfd = 99
            return (1, 3, 0x20000000)

        port.witness_realm = Mock(side_effect=realm)
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

    def test_sample_rejects_missing_outer_candidate_or_stale_incarnation(self) -> None:
        for direct in (True, False):
            for candidates, start in (({20, 30}, 10), ({10, 20, 30}, 99)):
                port, tasks = self.sampled_port(direct=direct)
                port.witness_scope_pids.return_value = candidates
                tasks[10]["before"]["startTicks"] = start
                with (
                    self.subTest(direct=direct, candidates=candidates, start=start),
                    patch.object(active.time, "monotonic_ns", return_value=1),
                    self.assertRaises(active.RefusedError),
                ):
                    port.witness_sample("ready")
                port.modules.observations.held_rootlesskit.assert_not_called()

    def readback_port(self, stack: ExitStack) -> active.RootPort:
        port = self.port()
        port.witness_counts = {"procBytes": 0, "pids": {10, 20, 30, 40}}
        port._witness_child_readback = False
        port._witness_scope = (stack, ((1, (1, 1)), (2, (1, 2))))
        port.witness_task = Mock(side_effect=AssertionError("no task lookup after original refusal"))
        return port

    def test_missing_child_readback_reports_all_none_or_partial_without_repair_or_retry(self) -> None:
        all_ids = b"".join(str(pid).encode() + b"\n" for pid in range(1, 65))
        for bodies, expected, starting_bytes in (
            ([b"30\n20\n30\n", b"40\n"], 2, 0),
            ([b"20\n", b""], 0, 0),
            ([b"30\n", b"30\n"], 1, 0),
            ([all_ids, b"30\n40\n"], 2, active.WITNESS_PROC_LIMIT - len(all_ids) - len(b"30\n40\n")),
        ):
            with ExitStack() as stack:
                port = self.readback_port(stack)
                port.witness_counts["procBytes"] = starting_bytes
                candidates, children = {10, 20}, {20, 30, 40}
                with (
                    self.subTest(bodies=bodies),
                    patch.object(active.time, "monotonic_ns", return_value=1),
                    patch.object(active.os, "fstat", side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd)),
                    patch.object(active.os, "open", side_effect=[101, 102]) as opened,
                    patch.object(active.os, "read", side_effect=bodies) as read,
                    patch.object(active.os, "close") as closed,
                    patch.object(active.os, "scandir", side_effect=AssertionError("no rescan")),
                ):
                    for _attempt in range(2):
                        with self.assertRaises(active.RefusedError) as refused:
                            port.witness_child(stack, {"pid": 10}, candidates, (1, 2), children)
                        self.assertEqual(refused.exception.args, ("active-scoped-profile-refused",))
                    self.assertEqual([call.kwargs["dir_fd"] for call in opened.call_args_list], [1, 2])
                    self.assertTrue(
                        all(
                            call.args
                            == ("cgroup.procs", active.os.O_RDONLY | active.os.O_NOFOLLOW | active.os.O_CLOEXEC)
                            for call in opened.call_args_list
                        )
                    )
                    self.assertEqual(
                        [call.args for call in read.call_args_list],
                        [(101, active.WITNESS_READ_LIMIT + 1), (102, active.WITNESS_READ_LIMIT + 1)],
                    )
                    self.assertEqual([call.args for call in closed.call_args_list], [(101,), (102,)])
                self.assertEqual(
                    port.record["diagnostic"]["ownedScopeReadback"],
                    {
                        "kind": "owned-scope-missing-child-readback-v1",
                        "missingCount": 2,
                        "complete": True,
                        "reobservedMissingCount": expected,
                    },
                )
                self.assertEqual(port.witness_counts["procBytes"], starting_bytes + sum(map(len, bodies)))
                self.assertEqual(port._witness_failure, "children-scope-initial-universe")
                self.assertEqual(candidates, {10, 20})
                self.assertEqual(children, {20, 30, 40})
                port.witness_task.assert_not_called()
                self.assertFalse(port.cleanup)

    def test_missing_child_readback_keeps_primary_exception_when_diagnostic_is_incomplete(self) -> None:
        cases = (
            ("identity-before", {"identities": [SimpleNamespace(st_dev=1, st_ino=99)], "reads": 0}),
            (
                "identity-after",
                {"identities": [SimpleNamespace(st_dev=1, st_ino=1), SimpleNamespace(st_dev=1, st_ino=99)]},
            ),
            ("malformed", {"raw": b"30"}),
            ("oversized", {"raw": b"x" * (active.WITNESS_READ_LIMIT + 1)}),
            ("aggregate", {"procBytes": active.WITNESS_PROC_LIMIT}),
            ("pid-cap", {"pids": set(range(1, 65)), "raw": b"99\n"}),
            ("deadline-before", {"reads": 0}),
            ("deadline-after", {}),
            (
                "deadline-final",
                {"identities": [SimpleNamespace(st_dev=1, st_ino=fd) for fd in (1, 1, 2, 2)], "reads": 2},
            ),
            ("io", {"error": OSError(errno.EIO, "PRIVATE_READBACK_CANARY")}),
            ("interrupt", {"error": KeyboardInterrupt()}),
            ("system-exit", {"error": SystemExit(1)}),
            ("directory-cap", {"directories": tuple((fd, (1, fd)) for fd in range(65)), "reads": 0}),
            ("wrong-owner", {"directories": ((1, (1, 1)),), "owner": None, "reads": 0}),
        )
        for fault, options in cases:
            with ExitStack() as stack:
                port = self.readback_port(stack)
                raw = options.get("raw", b"30\n")
                port.witness_counts.update({key: options[key] for key in ("procBytes", "pids") if key in options})
                if "directories" in options:
                    port._witness_scope = (options.get("owner", stack), options["directories"])
                identities = options.get(
                    "identities", [SimpleNamespace(st_dev=1, st_ino=1), SimpleNamespace(st_dev=1, st_ino=1)]
                )
                clock = {
                    "deadline-before": [port.work_until],
                    "deadline-after": [1, port.work_until],
                    "deadline-final": [1, 1, 1, 1, port.work_until],
                }.get(fault)
                error = options.get("error")
                primaries = []
                original_require = port.witness_require

                def require(
                    code: str, value: object, original: object = original_require, caught: list = primaries
                ) -> None:
                    try:
                        original(code, value)
                    except active.RefusedError as primary:
                        if code == "children-scope-initial-universe":
                            caught.append(primary)
                        raise

                port.witness_require = require
                original_bytes = port.witness_counts["procBytes"]
                with (
                    self.subTest(fault=fault),
                    patch.object(active.time, "monotonic_ns", side_effect=clock, return_value=1),
                    patch.object(active.os, "fstat", side_effect=identities),
                    patch.object(active.os, "open", return_value=101) as opened,
                    patch.object(active.os, "read", side_effect=error, return_value=raw) as read,
                    patch.object(active.os, "close") as closed,
                    self.assertRaises(active.RefusedError) as refused,
                ):
                    port.witness_child(stack, {"pid": 10}, {10, 20}, (1, 2), {20, 30})
                self.assertIs(refused.exception, primaries[0])
                self.assertEqual(port._witness_failure, "children-scope-initial-universe")
                self.assertEqual(
                    port.record["diagnostic"]["ownedScopeReadback"],
                    {
                        "kind": "owned-scope-missing-child-readback-v1",
                        "missingCount": 1,
                        "complete": False,
                        "reobservedMissingCount": None,
                    },
                )
                expected_reads = options.get("reads", 1)
                self.assertEqual(read.call_count, expected_reads)
                self.assertEqual(opened.call_count, read.call_count)
                self.assertEqual(closed.call_count, read.call_count)
                self.assertEqual(
                    port.witness_counts["procBytes"],
                    original_bytes + (len(raw) * expected_reads if error is None else 0),
                )
                self.assertFalse(port.cleanup)

    def test_scope_readback_never_runs_for_success_later_guard_or_original_interrupt(self) -> None:
        for readback, candidates, children in (
            (False, {10, 20}, {20}),
            (True, {10}, {20}),
            (None, {10}, {20}),
            (False, {10, 20}, {10}),
        ):
            with ExitStack() as stack:
                port = self.readback_port(stack)
                port._witness_child_readback = readback
                parent = {"pid": 10, "before": {"namespaces": (1, 2, 3)}}
                child = {"pid": 20, "exe": 20, "before": {"parent": 10, "namespaces": (4, 5, 3)}}
                port.witness_task = Mock(return_value=nullcontext(child))
                with (
                    self.subTest(readback=readback, candidates=candidates, children=children),
                    patch.object(
                        port, "witness_missing_child_readback", side_effect=AssertionError("no diagnostic")
                    ) as observe,
                    patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                    patch.object(active.os, "open") as opened,
                ):
                    if children == {child["pid"]} and child["pid"] in candidates:
                        self.assertIs(port.witness_child(stack, parent, candidates, (1, 2), children), child)
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.witness_child(stack, parent, candidates, (1, 2), children)
                observe.assert_not_called()
                opened.assert_not_called()
                self.assertNotIn("ownedScopeReadback", port.record.get("diagnostic", {}))
        port = self.port()
        interrupt = KeyboardInterrupt()
        with (
            ExitStack() as stack,
            patch.object(port, "witness_require", side_effect=interrupt),
            patch.object(port, "witness_missing_child_readback") as observe,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                port.witness_child(stack, {"pid": 10}, {10}, (1, 2), {20})
            self.assertIs(raised.exception, interrupt)
        observe.assert_not_called()

    def test_readback_uses_only_authenticated_scope_walk_handles_in_original_stack(self) -> None:
        port = self.port()
        port.witness_counts = {"procBytes": 0, "pids": set()}
        port._witness_child_readback = False
        entry = SimpleNamespace(name="child", is_symlink=lambda: False, is_dir=lambda **_kw: True)
        scope_fd = 3
        leaves = {scope_fd: iter((4, 7)), 5: iter((6, 8))}

        def opened(name: str, _flags: int, *, dir_fd: int | None = None) -> int:
            if name == "cgroup.procs":
                return next(leaves[dir_fd])
            return {"/sys/fs/cgroup": 1, "owned.slice": 2, "docker-" + "a" * 64 + ".scope": 3, "child": 5}[name]

        def named(name: str, *, dir_fd: int, follow_symlinks: bool) -> SimpleNamespace:
            self.assertFalse(follow_symlinks)
            self.assertEqual(dir_fd, 3 if name == "child" else 1 if name == "owned.slice" else 2)
            return SimpleNamespace(st_dev=1, st_ino=5 if name == "child" else 2 if name == "owned.slice" else 3)

        with (
            ExitStack() as stack,
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active, "filesystem_magic"),
            patch.object(active.os, "fstat", side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd)),
            patch.object(active.os, "stat", side_effect=named) as statted,
            patch.object(active.os, "open", side_effect=opened) as open_file,
            patch.object(active.os, "close"),
            patch.object(
                active.os, "read", side_effect=lambda fd, _cap: {4: b"10\n20\n", 6: b"", 7: b"30\n", 8: b""}[fd]
            ) as read,
            patch.object(
                active.os, "scandir", side_effect=lambda fd: nullcontext(iter([entry] if fd == scope_fd else []))
            ) as scanned,
        ):
            candidates = port.witness_scope_pids(stack)
            self.assertEqual(candidates, {10, 20})
            self.assertEqual(port._witness_scope, (stack, ((3, (1, 3)), (5, (1, 5)))))
            port.witness_counts["pids"].add(30)  # Already charged by the real parent-children census.
            with self.assertRaises(active.RefusedError):
                port.witness_child(stack, {"pid": 10}, candidates, (1, 2), {20, 30})
            self.assertEqual(port.record["diagnostic"]["ownedScopeReadback"]["reobservedMissingCount"], 1)
            self.assertEqual([call.args[0] for call in read.call_args_list], [4, 6, 7, 8])
            self.assertEqual(scanned.call_count, 2)
            self.assertEqual(statted.call_count, 3)
            self.assertEqual(
                [call.kwargs["dir_fd"] for call in open_file.call_args_list if call.args[0] == "cgroup.procs"],
                [3, 5, 3, 5],
            )

    def test_scope_walk_unions_unordered_and_repeated_pid_locators(self) -> None:
        port = self.port()
        entry = SimpleNamespace(name="child", is_symlink=lambda: False, is_dir=lambda **_kw: True)
        all_pids = b"".join(str(pid).encode() + b"\n" for pid in range(64, 0, -1))
        for root_raw, child_raw, expected in (
            (b"30\n10\n20\n", b"", {10, 20, 30}),
            (b"30\n10\n30\n20\n10\n", b"", {10, 20, 30}),
            (b"30\n10\n", b"20\n10\n30\n", {10, 20, 30}),
            (all_pids + b"64\n1\n", all_pids, set(range(1, 65))),
        ):
            port.witness_counts = {"procBytes": 0, "pids": set()}
            with (
                self.subTest(root_raw=root_raw, child_raw=child_raw),
                ExitStack() as stack,
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd + 2)),
                patch.object(active.os, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=4)),
                patch.object(active.os, "open", side_effect=[3, 2, 4]) as opened,
                patch.object(active.os, "close"),
                patch.object(active.os, "read", side_effect=[root_raw, child_raw]) as read,
                patch.object(
                    active.os, "scandir", side_effect=lambda fd: nullcontext(iter([entry] if fd == 1 else []))
                ) as scanned,
                patch.object(port, "witness_budget", wraps=port.witness_budget) as budget,
            ):
                self.assertEqual(port.witness_scope_walk(stack, 1), (expected, {(): (1, 3), ("child",): (1, 4)}))
                self.assertEqual(port.witness_counts, {"procBytes": len(root_raw) + len(child_raw), "pids": expected})
                self.assertEqual(
                    [call.args for call in read.call_args_list],
                    [(3, active.WITNESS_READ_LIMIT + 1), (4, active.WITNESS_READ_LIMIT + 1)],
                )
                self.assertEqual([call.args for call in scanned.call_args_list], [(1,), (2,)])
                self.assertEqual(opened.call_count, 3)
                self.assertEqual(budget.call_count, 2)

    def test_scope_walk_rejects_malformed_symlinks_aliases_and_pid_overflow(self) -> None:
        port = self.port()
        entry = SimpleNamespace(name="child", is_symlink=lambda: False, is_dir=lambda **_kw: True)
        for raw, children, child_identity in (
            (b"10\n", [], (1, 3)),
            *((raw, [], (1, 3)) for raw in (b"10", b"0\n", b"01\n", b"-1\n", b"10 \n", b"10\n\n", b"12345678901\n")),
            (b"10\n" * (active.WITNESS_READ_LIMIT // 3 + 1), [], (1, 3)),
            (b"10\n", [SimpleNamespace(is_symlink=lambda: True)], (1, 3)),
            (b"10\n", [entry], (1, 3)),
            (b"10\n", [SimpleNamespace(name="../child", is_symlink=lambda: False, is_dir=lambda **_kw: True)], (1, 4)),
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

    def test_scope_walk_duplicate_bytes_still_consume_aggregate_budget(self) -> None:
        port = self.port()
        raw = b"10\n10\n"
        for excess in (0, 1):
            port.witness_counts = {"procBytes": active.WITNESS_PROC_LIMIT - len(raw) + excess, "pids": set()}
            with (
                self.subTest(excess=excess),
                ExitStack() as stack,
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=3)),
                patch.object(active.os, "open", return_value=2),
                patch.object(active.os, "close"),
                patch.object(active.os, "read", return_value=raw) as read,
                patch.object(active.os, "scandir", side_effect=lambda _fd: nullcontext(iter([]))),
            ):
                if excess:
                    with self.assertRaises(active.RefusedError):
                        port.witness_scope_walk(stack, 1)
                else:
                    self.assertEqual(port.witness_scope_walk(stack, 1), ({10}, {(): (1, 3)}))
                self.assertEqual(port.witness_counts["procBytes"], active.WITNESS_PROC_LIMIT + excess)
                read.assert_called_once_with(2, active.WITNESS_READ_LIMIT + 1)

    def test_scope_walk_read_errors_cannot_become_empty_candidates(self) -> None:
        port = self.port()
        for code in (errno.EIO, errno.EOPNOTSUPP):
            port.witness_counts = {"procBytes": 0, "pids": set()}
            with (
                self.subTest(code=code),
                ExitStack() as stack,
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=3)),
                patch.object(active.os, "open", return_value=2),
                patch.object(active.os, "close") as closed,
                patch.object(active.os, "read", side_effect=OSError(code, "unavailable")) as read,
                self.assertRaises(OSError),
            ):
                port.witness_scope_walk(stack, 1)
            read.assert_called_once_with(2, active.WITNESS_READ_LIMIT + 1)
            closed.assert_called_once_with(2)

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
                    if changed == "subtree":
                        self.assertEqual(port._witness_failure, "scope-directory-stability")

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
                    self.assertEqual(
                        port._witness_failure,
                        {
                            "label": "label",
                            "cgroup": "cgroup",
                            "executable": "executable-identity",
                            "dead": "task-alive",
                        }[wrong],
                    )


class ScopeCensusSiteDiagnostics(unittest.TestCase):
    port = RootWitness.port
    sampled_port = RootWitness.sampled_port

    def test_actual_read_sites_and_escaping_walk_preserve_error_privacy_and_single_read(self) -> None:
        for checkpoint in ("ready", "pre-close"):
            for site, expected in (
                ("walk-grammar", "scope-pid-grammar"),
                ("walk-io", "scope-walk"),
                ("readback-grammar", "scope-readback-pid-grammar"),
            ):
                with ExitStack() as stack:
                    port = self.port()
                    raw = b"PRIVATE_SCOPE_CANARY\n"
                    original_error = PermissionError(errno.EACCES, "PRIVATE_SCOPE_CANARY")

                    def sample(
                        _checkpoint: str,
                        *,
                        selected_site: str = site,
                        owner: active.RootPort = port,
                        owner_stack: ExitStack = stack,
                    ) -> dict:
                        if selected_site == "readback-grammar":
                            owner._witness_scope = (owner_stack, ((1, (1, 1)),))
                            owner.witness_missing_child_readback(owner_stack, {30})
                        else:
                            owner.witness_scope_walk(owner_stack, 1)
                        self.fail("the original failing site must refuse")

                    port.witness_sample = Mock(side_effect=sample)
                    view = scoped_receipt() | {"bindingSha256": "a" * 64, "profileName": "fixture"}
                    if checkpoint == "pre-close":
                        port.record["postExecWitness"] = postexec_v2_fixture(view) | {
                            "samples": [postexec_v2_fixture(view)["samples"][0]]
                        }
                    original_witness = copy.deepcopy(port.record.get("postExecWitness"))
                    with (
                        self.subTest(checkpoint=checkpoint, site=site),
                        patch.object(active, "receipt", return_value=view),
                        patch.object(active.time, "monotonic_ns", return_value=1),
                        patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=1)),
                        patch.object(active.os, "open", return_value=2) as opened,
                        patch.object(active.os, "close") as closed,
                        patch.object(
                            active.os,
                            "read",
                            side_effect=original_error if site == "walk-io" else None,
                            return_value=raw,
                        ) as read,
                        patch.object(active.os, "scandir", side_effect=AssertionError("no further enumeration")),
                        self.assertRaises(PermissionError if site == "walk-io" else active.RefusedError) as refused,
                    ):
                        port.collect_postexec_witness(checkpoint)
                    if site == "walk-io":
                        self.assertIs(refused.exception, original_error)
                    else:
                        self.assertEqual(refused.exception.args, ("active-scoped-profile-refused",))
                    phase = "witness-" + checkpoint + "-" + expected
                    self.assertEqual(port.record["diagnostic"]["phase"], phase)
                    self.assertFalse(port.record["diagnostic"]["comparisons"][phase])
                    self.assertEqual(port.record.get("postExecWitness"), original_witness)
                    self.assertEqual(port.witness_counts["procBytes"], 0 if site == "walk-io" else len(raw))
                    read.assert_called_once_with(2, active.WITNESS_READ_LIMIT + 1)
                    opened.assert_called_once()
                    closed.assert_called_once_with(2)
                    port.commit.assert_not_called()
                    self.assertEqual(port.work_until, 100_000_000_000)
                    self.assertFalse(port.cleanup)
                    failure = active.failure_receipt(
                        {"actor": "root", "operation": "witness", "record": port.record}, refused.exception
                    )
                    self.assertEqual(failure["phase"], phase)
                    self.assertFalse(failure["cleanupAuthority"])
                    self.assertNotIn("PRIVATE_SCOPE_CANARY", json.dumps(failure))

    def test_readback_grammar_failure_cannot_replace_original_missing_child_refusal(self) -> None:
        with ExitStack() as stack:
            port = self.port()

            def sample(_checkpoint: str) -> dict:
                port._witness_scope = (stack, ((1, (1, 1)),))
                port._witness_child_readback = False
                return port.witness_child(stack, {"pid": 10}, {10, 20}, (1, 2), {20, 30})

            port.witness_sample = Mock(side_effect=sample)
            with (
                patch.object(active, "receipt", return_value=scoped_receipt()),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=1)),
                patch.object(active.os, "open", return_value=2),
                patch.object(active.os, "close"),
                patch.object(active.os, "read", return_value=b"PRIVATE_READBACK_CANARY") as read,
                self.assertRaises(active.RefusedError) as refused,
            ):
                port.collect_postexec_witness("ready")
            phase = "witness-ready-children-scope-initial-universe"
            self.assertEqual(port.record["diagnostic"]["phase"], phase)
            self.assertFalse(port.record["diagnostic"]["ownedScopeReadback"]["complete"])
            read.assert_called_once_with(2, active.WITNESS_READ_LIMIT + 1)
            failure = active.failure_receipt(
                {"actor": "root", "operation": "witness", "record": port.record}, refused.exception
            )
            self.assertEqual(failure["phase"], phase)
            self.assertNotIn("PRIVATE_READBACK_CANARY", json.dumps(failure))
            self.assertFalse(failure["cleanupAuthority"])
            port.commit.assert_not_called()

    def test_required_outer_membership_has_its_own_actual_guard_in_each_checkpoint(self) -> None:
        for direct in (False, True):
            for checkpoint in ("ready", "pre-close"):
                port, _tasks = self.sampled_port(direct=direct)
                with (
                    self.subTest(direct=direct, checkpoint=checkpoint),
                    patch.object(active, "receipt", return_value=WitnessFailureDiagnostics.view(self, port)),
                    patch.object(active.time, "monotonic_ns", return_value=1),
                    patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    if checkpoint == "pre-close":
                        port.collect_postexec_witness("ready")
                    original = copy.deepcopy(port.record.get("postExecWitness"))
                    port.witness_scope_pids.return_value = {20, 30}
                    port.witness_parent_children.reset_mock()
                    with self.assertRaises(active.RefusedError):
                        port.collect_postexec_witness(checkpoint)
                    self.assertEqual(
                        port.record["diagnostic"]["phase"], "witness-" + checkpoint + "-scope-outer-membership"
                    )
                    self.assertEqual(port.record.get("postExecWitness"), original)
                    port.witness_parent_children.assert_not_called()

    def test_legacy_coarse_scope_failure_keeps_its_historical_closed_shape(self) -> None:
        for checkpoint in ("ready", "pre-close"):
            phase = "witness-" + checkpoint + "-scope-census"
            self.assertIn("scope-census", active.WITNESS_FAILURE_CODES)
            self.assertIn(phase, active.FAILURE_PHASES)
            failure = active.failure_receipt(
                {"actor": "root", "operation": "witness", "record": {"diagnostic": {"phase": phase}}},
                active.RefusedError("private legacy refusal"),
            )
            self.assertEqual(failure["phase"], phase)
            self.assertEqual(failure["schemaVersion"], 1)
            self.assertFalse(failure["cleanupAuthority"])
            self.assertNotIn("private legacy refusal", json.dumps(failure))


class WitnessFailureDiagnostics(unittest.TestCase):
    port = RootWitness.port
    sampled_port = RootWitness.sampled_port

    def view(self, port: active.RootPort) -> dict:
        return scoped_receipt() | {
            "bindingSha256": port.record["bindingSha256"],
            "profileName": port.record["profileName"],
            "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
        }

    def test_pre_close_guard_code_preserves_ready_proof_and_original_refusal(self) -> None:
        for wrong, code in (
            ("hash", "executable-hash"),
            ("task", "task-readback"),
            ("scope", "scope-readback"),
            ("children", "children-readback"),
            ("engine", "subject-readback"),
            ("checkpoint", "checkpoint-stability"),
        ):
            port, _tasks = self.sampled_port(direct=True)
            with (
                self.subTest(wrong=wrong),
                patch.object(active, "receipt", return_value=self.view(port)),
                patch.object(active.time, "monotonic_ns", return_value=1),
                patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                patch.object(active.select, "select", return_value=([], [], [])),
            ):
                port.collect_postexec_witness("ready")
                ready = copy.deepcopy(port.record["postExecWitness"])
                if wrong == "hash":
                    port.modules.observations.held_executable_hash.side_effect = [
                        ("a" * 64, 128),
                        ("b" * 64, 128),
                        ("a" * 64, 128),
                    ]
                elif wrong == "task":
                    port.witness_task_state.side_effect = lambda task: task["before"] | {"startTicks": 99}
                elif wrong == "scope":
                    port.witness_scope_pids.side_effect = [{10, 30}, {10}]
                elif wrong == "children":
                    port.witness_parent_children.side_effect = [{30}, {30, 40}]
                elif wrong == "checkpoint":
                    port.modules.observations.held_executable_hash.return_value = ("b" * 64, 128)
                else:
                    port.inspect.side_effect = [port.inspect.return_value, {"State": {"Running": False}}]
                with self.assertRaises(active.RefusedError) as raised:
                    port.collect_postexec_witness("pre-close")
                self.assertEqual(raised.exception.args, ("active-scoped-profile-refused",))
                phase = "witness-pre-close-" + code
                self.assertEqual(port.record["diagnostic"], {"phase": phase, "comparisons": {phase: False}})
                self.assertEqual(port.record["postExecWitness"], ready)
                self.assertEqual(port.work_until, 100_000_000_000)
                self.assertFalse(port.cleanup)
                self.assertFalse(port.record["retained"])
                self.assertEqual(port.commit.call_count, 1)

    def test_existing_budget_clock_distinguishes_original_and_checkpoint_cutoffs(self) -> None:
        for original, expected in ((3, "inherited-budget"), (100_000_000_000, "checkpoint-budget")):
            port = self.port()
            port.work_until = original
            port.witness_sample = Mock(side_effect=lambda _checkpoint, owner=port: owner.witness_budget())
            with (
                self.subTest(original=original),
                patch.object(active, "receipt", return_value=self.view(port)),
                patch.object(active.time, "monotonic_ns", side_effect=[1, 5_000_000_001]) as clock,
                self.assertRaises(active.RefusedError),
            ):
                port.collect_postexec_witness("ready")
            self.assertEqual(clock.call_count, 2)
            self.assertEqual(port.record["diagnostic"]["phase"], "witness-ready-" + expected)
            self.assertEqual(port.work_until, original)
            port.commit.assert_not_called()

    def test_read_exception_keeps_type_errno_and_private_operands_out_of_failure(self) -> None:
        port = self.port()
        error = PermissionError(errno.EACCES, "/private/pid/label/canary")
        port.witness_sample = Mock(side_effect=lambda _checkpoint: port.witness_read(1, "status"))
        with (
            patch.object(active, "receipt", return_value=self.view(port)),
            patch.object(active.time, "monotonic_ns", return_value=1) as clock,
            patch.object(port._witness_proc, "open", side_effect=error) as reader,
            self.assertRaises(PermissionError) as raised,
        ):
            port.collect_postexec_witness("ready")
        self.assertIs(raised.exception, error)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(clock.call_count, 2)
        result = active.failure_receipt({"actor": "root", "operation": "witness", "record": port.record}, error)
        self.assertEqual(result["phase"], "witness-ready-proc-read")
        self.assertEqual(result["reason"], "permission-denied")
        self.assertFalse(result["cleanupAuthority"])
        self.assertNotIn("canary", active.encoded(result).decode())
        self.assertTrue(active.valid_failure(result))

    def test_optional_diagnostic_damage_cannot_replace_the_original_exception(self) -> None:
        port = self.port()
        port.record["diagnostic"] = []
        error = PermissionError(errno.EACCES, "/private/original-canary")
        port.witness_sample = Mock(side_effect=lambda _checkpoint: port.witness_read(1, "status"))
        with (
            patch.object(active, "receipt", return_value=self.view(port)),
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(port._witness_proc, "open", side_effect=error),
            self.assertRaises(PermissionError) as raised,
        ):
            port.collect_postexec_witness("ready")
        self.assertIs(raised.exception, error)
        port.commit.assert_not_called()
        self.assertFalse(port.cleanup)
        self.assertEqual(port.work_until, 100_000_000_000)

    def test_successful_parent_search_discards_expected_candidate_refusal(self) -> None:
        port = self.port()
        parent = {"pid": 30, "before": {"namespacePid": 7, "namespaces": (1, 2, 3)}}

        skipped_pid = 20

        def task(pid: int) -> object:
            if pid == skipped_pid:
                port.witness_failure("task-status")
                reason = "private-candidate"
                raise active.RefusedError(reason)
            return nullcontext(parent)

        port.witness_task = Mock(side_effect=task)
        with ExitStack() as stack, patch.object(active.time, "monotonic_ns", return_value=1):
            self.assertIs(port.witness_parent(stack, {"before": {"namespaces": (1, 2, 3)}}, {20, 30}, 7), parent)
        self.assertIsNone(port._witness_failure)
        self.assertNotIn("diagnostic", port.record)
        port.witness_require("subject-readback", value=True)
        self.assertIsNone(port._witness_failure)

    def test_validator_names_only_existing_failed_branch_and_preserves_result(self) -> None:
        scoped = scoped_receipt()
        original = scoped["postExecWitness"]
        for wrong, code in (
            ("envelope", "checkpoint-envelope"),
            ("sample", "checkpoint-sample"),
            ("stable", "checkpoint-stability"),
        ):
            value = copy.deepcopy(original)
            if wrong == "envelope":
                value["rawPrivate"] = "/private/canary"
            elif wrong == "sample":
                value["samples"][0]["labelSha256"] = "0" * 64
            else:
                value["samples"][1]["executableSha256"] = "0" * 64
            report = Mock()
            with self.subTest(wrong=wrong):
                self.assertFalse(qualification.postexec_witness_valid(value, scoped, diagnostic=report))
                report.assert_called_once_with(code)
                self.assertFalse(qualification.postexec_witness_valid(value, scoped))
        report = Mock()
        self.assertTrue(qualification.postexec_witness_valid(original, scoped, complete=True, diagnostic=report))
        self.assertTrue(qualification.postexec_witness_valid(None, scoped, diagnostic=report))
        report.assert_not_called()
        self.assertEqual(scoped["postExecWitness"], original)

    def test_predicate_truthiness_is_not_evaluated_twice(self) -> None:
        class Predicate:
            def __init__(self, *, matched: bool) -> None:
                self.matched = matched
                self.calls = 0

            def __bool__(self) -> bool:
                self.calls += 1
                return self.matched

        for matched in (True, False):
            port = self.port()
            predicate = Predicate(matched=matched)
            with self.subTest(matched=matched):
                if matched:
                    port.witness_require("cgroup", predicate)
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_require("cgroup", predicate)
                self.assertEqual(predicate.calls, 1)


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
                    self.assertEqual(
                        port._witness_failure,
                        {
                            "extra": "thread-children-readback",
                            "missing": "thread-children-readback",
                            "duplicate": "thread-children-readback",
                            "thread-set": "thread-census",
                            "thread-identity": "thread-children-readback",
                            "named-inode": "thread-identity",
                        }[wrong],
                    )

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
                patch.object(active, "filesystem_magic"),
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
        with (
            patch("scripts.runtime_docker_dead_nonactor_controls.require_controls") as controls,
            self.assertRaises(ValueError),
        ):
            runtime_docker._postexec_checkpoint(ctx, "ready")
        controls.assert_called_once_with(ctx)
        profile.witness.assert_called_once_with("ready")
        runtime_docker._postexec_checkpoint(SimpleNamespace(), "pre-close")


class ChildScopeSiteDiagnostics(unittest.TestCase):
    port = RootWitness.port
    sampled_port = RootWitness.sampled_port
    view = WitnessFailureDiagnostics.view

    def setUp(self) -> None:
        effects = ExitStack()
        self.addCleanup(effects.close)
        for target in (
            "subprocess.run",
            "subprocess.Popen",
            "scripts.docker_userns_active.main",
            "scripts.runtime_docker_backend.DockerBackend.prepare",
            "scripts.runtime_docker_backend.DockerBackend.cleanup",
        ):
            effects.enter_context(patch(target, side_effect=AssertionError("native boundary forbidden")))

    def test_all_three_original_guards_have_literal_initial_readback_ready_and_preclose_codes(self) -> None:
        for direct in (False, True):
            for checkpoint in ("ready", "pre-close"):
                for readback in (False, True):
                    for site in ("universe", "unreadable-required-child", "unlisted-immediate-child"):
                        with self.subTest(direct=direct, checkpoint=checkpoint, readback=readback, site=site):
                            self.selection_case(direct=direct, checkpoint=checkpoint, readback=readback, site=site)

    def test_unavailable_or_damaged_private_pass_keeps_legacy_refusal_without_source_work(self) -> None:
        for private_pass in (None, 0, "private pass", object()):
            port = self.port()
            port._witness_child_readback = private_pass
            port.witness_task = Mock(side_effect=AssertionError("task acquisition forbidden"))
            with ExitStack() as stack, self.assertRaises(active.RefusedError) as refused:
                port.witness_child(stack, {"pid": 10}, {10}, (1, 2), {30})
            self.assertEqual(refused.exception.args, ("active-scoped-profile-refused",))
            self.assertEqual(port._witness_failure, "children-scope")
            port.witness_task.assert_not_called()

    def selection_case(self, *, direct: bool, checkpoint: str, readback: bool, site: str) -> None:
        port, _tasks = self.sampled_port(direct=direct)
        with (
            patch.object(active, "receipt", return_value=self.view(port)),
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
            patch.object(active.select, "select", return_value=([], [], [])),
        ):
            if checkpoint == "pre-close":
                port.collect_postexec_witness("ready")
            original = copy.deepcopy(port.record.get("postExecWitness"))
            for mock in (
                port.witness_task,
                port.witness_scope_pids,
                port.witness_parent_children,
                port.modules.observations.held_executable_hash,
            ):
                mock.reset_mock()
            reader = port.witness_task.side_effect
            passes = []
            child_pid = 30
            private = "private required child"

            def selected(
                stack: ExitStack,
                parent: dict,
                candidates: set,
                identity: tuple,
                children: set,
            ) -> dict:
                passes.append(port._witness_child_readback)
                if port._witness_child_readback != readback:
                    return active.RootPort.witness_child(port, stack, parent, candidates, identity, children)
                children = {"universe": children | {99}, "unlisted-immediate-child": set()}.get(site, children)

                def task(pid: int, *args: object) -> object:
                    if site == "unreadable-required-child" and pid == child_pid:
                        raise active.RefusedError(private)
                    return reader(pid, *args)

                with patch.object(port.witness_task, "side_effect", task):
                    return active.RootPort.witness_child(port, stack, parent, candidates, identity, children)

            port.witness_child = Mock(side_effect=selected)
            with self.assertRaises(active.RefusedError) as refused:
                port.collect_postexec_witness(checkpoint)
            self.assertEqual(refused.exception.args, ("active-scoped-profile-refused",))
            pass_name = "readback" if readback else "initial"
            code = "children-scope-" + pass_name + "-" + site
            phase = "witness-" + checkpoint + "-" + code
            self.assertIn(code, active.WITNESS_FAILURE_CODES)
            expected_diagnostic = {"phase": phase, "comparisons": {phase: False}}
            if not readback and site == "universe":
                expected_diagnostic["ownedScopeReadback"] = {
                    "kind": "owned-scope-missing-child-readback-v1",
                    "missingCount": 1,
                    "complete": False,
                    "reobservedMissingCount": None,
                }
            self.assertEqual(port.record["diagnostic"], expected_diagnostic)
            self.assertEqual(port.record.get("postExecWitness"), original)
            self.assertEqual(
                passes,
                [False, True] if readback else [False],
            )
            self.assertEqual(port.witness_scope_pids.call_count, 2 if readback else 1)
            self.assertEqual(port.witness_parent_children.call_count, 2 if readback else 1)
            self.assertEqual(port.modules.observations.held_executable_hash.call_count, 3 if readback else 0)
            task_calls = [(10, 1000)] if direct else [(10, 0), (10,), (20,), (30,)]
            child_calls = [(30,)] if direct else [(10,), (30,)]
            task_calls += child_calls * (int(readback) + int(site != "universe"))
            self.assertEqual([item.args for item in port.witness_task.call_args_list], task_calls)
            self.assertEqual(port.work_until, 100_000_000_000)
            self.assertFalse(port.cleanup)
            self.assertFalse(port.record["retained"])
            failure = active.failure_receipt(
                {"actor": "root", "operation": "witness", "binding": binding(), "record": port.record},
                refused.exception,
            )
            self.assertEqual(failure["schemaVersion"], 1)
            self.assertTrue(active.valid_failure(failure))
            self.assertFalse(failure["cleanupAuthority"])
            self.assertNotIn("private required child", active.encoded(failure).decode())


FIXTURE_PROC_BASE = 1000
FIXTURE_PIDFD_BASE = 100
FIXTURE_OWNER_FD = 99


class DeadNonactorV2(unittest.TestCase):
    """Run the production proof/ordering bodies with every native boundary replaced."""

    port = RootWitness.port
    sampled_port = RootWitness.sampled_port
    view = WitnessFailureDiagnostics.view

    def setUp(self) -> None:
        self.effects = ExitStack()
        self.addCleanup(self.effects.close)
        for target in (
            "subprocess.run",
            "subprocess.Popen",
            "scripts.docker_userns_active.os.open",
            "scripts.docker_userns_active.os.scandir",
        ):
            self.effects.enter_context(patch(target, side_effect=AssertionError("native boundary forbidden")))

    @staticmethod
    def bodies(pid: int, parent: int = 20) -> dict[str, bytes]:
        """Build independent kernel-shaped observations, including a nested numeric PID view."""
        fields = [b"Z", str(parent).encode()] + [b"0"] * 17 + [str(pid * 10).encode()]
        return {
            "stat": str(pid).encode() + b" (dead (child)) " + b" ".join(fields) + b"\n",
            "status": (
                f"State: Z (zombie)\nPid: {pid}\nTgid: {pid}\nPPid: {parent}\n"
                f"Uid: 1000 1000 1000 1000\nNSpid: {pid} {pid - 20}\n"
            ).encode(),
            "fdinfo": f"pos: 0\nflags: 02000002\nPid: {pid}\nNSpid: {pid} {pid - 20}\n".encode(),
        }

    def io(self, port: active.RootPort, proc: object, bodies: dict[int, dict], *, ready: bool = True) -> dict:
        """Replace only kernel calls; retain the production parser, byte charging and proof loops."""
        opened, reads = {}, []
        serial = [2000]

        def acquire(pid: int) -> int:
            port.witness_pid(pid)
            return pid + 1000

        def open_leaf(directory: int, leaf: str, _flags: int) -> int:
            serial[0] += 1
            opened[serial[0]] = (directory, leaf)
            return serial[0]

        def read_leaf(descriptor: int, limit: int) -> bytes:
            directory, leaf = opened[descriptor]
            self.assertEqual(limit, 8193)
            pid = int(leaf.split("/")[1]) - 100 if leaf.startswith("fdinfo/") else directory - 1000
            kind = "fdinfo" if leaf.startswith("fdinfo/") else leaf
            reads.append((pid, kind))
            raw = bodies[pid][kind]
            return raw() if callable(raw) else raw

        proc.pid = Mock(side_effect=acquire)
        proc.open = Mock(side_effect=open_leaf)
        port._witness_proc = proc
        port._witness_observer = 900
        self.effects.enter_context(patch.object(active.time, "monotonic_ns", return_value=1))
        self.effects.enter_context(patch.object(active, "filesystem_magic"))
        self.effects.enter_context(patch.object(active.os, "read", side_effect=read_leaf))
        closed = self.effects.enter_context(patch.object(active.os, "close"))
        pidfds = self.effects.enter_context(
            patch.object(active.os, "pidfd_open", side_effect=lambda pid, _flags: pid + 100)
        )
        self.effects.enter_context(
            patch.object(
                active.os,
                "fstat",
                side_effect=lambda fd: SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o444, st_dev=1, st_ino=fd if fd >= FIXTURE_PROC_BASE else 2
                ),
            )
        )
        self.effects.enter_context(
            patch.object(
                active.select,
                "select",
                side_effect=lambda fds, *_args: (list(fds) if ready and fds[0] >= FIXTURE_PIDFD_BASE else [], [], []),
            )
        )
        return {"reads": reads, "opened": opened, "closed": closed, "pidfds": pidfds}

    def test_positive_proof_and_every_identity_unknown_refuses(self) -> None:
        original = self.bodies(40)
        cases = [
            None,
            ("stat", b") Z", b") S"),
            ("stat", b" 400\n", b" 401\n"),
            ("status", b"Tgid: 40", b"Tgid: 41"),
            ("status", b"PPid: 20", b"PPid: 21"),
            ("status", b"1000 1000 1000 1000", b"1000 1000 1000 0"),
            ("status", b"State: Z", b"State: S"),
            ("fdinfo", b"Pid: 40", b"Pid: -1"),
            ("fdinfo", b"Pid: 40", b"Pid: 0"),
            ("fdinfo", b"NSpid: 40 20", b"NSpid: 40 21"),
            ("fdinfo", b"NSpid: 40 20", b"NSpid: 40 -1"),
            ("fdinfo", b"NSpid: 40 20", b"NSpid: 40 0"),
            ("fdinfo", b"NSpid: 40 20", b"Other: 40 20"),
        ]
        for mutation in cases:
            with self.subTest(mutation=mutation), ExitStack() as held:
                port = self.port()
                port.witness_counts = {"procBytes": 0, "pids": set()}
                bodies = original.copy()
                if mutation is not None:
                    key, before, after = mutation
                    bodies[key] = bodies[key].replace(before, after)
                    if mutation == ("stat", b" 400\n", b" 401\n"):
                        bodies[key] = Mock(side_effect=[original[key], bodies[key]])
                io = self.io(port, SimpleNamespace(), {40: bodies})
                task = {"pid": 40, "directory": 1040, "pidfd": 140}
                if mutation is None:
                    state = port.witness_dead_state(task, {"pid": 20, "uid": 1000})
                    self.assertEqual(state["startTicks"], 400)
                    self.assertEqual(len(io["reads"]), 6)
                else:
                    with self.assertRaises(active.RefusedError):
                        port.witness_dead_state(task, {"pid": 20, "uid": 1000})
                if mutation is None:
                    self.assertEqual(
                        port.witness_counts["procBytes"], sum(len(original[key]) for _pid, key in io["reads"])
                    )
                held.close()

    def test_zombie_leader_with_live_threads_is_not_a_dead_process(self) -> None:
        port = self.port()
        port.witness_counts = {"procBytes": 0, "pids": set()}
        io = self.io(port, SimpleNamespace(), {40: self.bodies(40)}, ready=False)
        with self.assertRaises(active.RefusedError):
            port.witness_dead_state({"pid": 40, "directory": 1040, "pidfd": 140}, {"pid": 20, "uid": 1000})
        self.assertNotIn((40, "fdinfo"), io["reads"])

    def test_reserved_original_locators_refuse_before_any_missing_lookup(self) -> None:
        for reserved in (10, 20, 30):
            port = self.port()
            proc = SimpleNamespace(pid=Mock(side_effect=AssertionError("reserved locator lookup")))
            port._witness_proc = proc
            anchor = {"roles": {role: {"pid": pid} for role, pid in (("outer", 10), ("parent", 20), ("child", 30))}}
            with self.subTest(reserved=reserved), ExitStack() as held, self.assertRaises(active.RefusedError):
                port.witness_dead(held, {40, reserved}, {"pid": 20}, anchor)
            proc.pid.assert_not_called()

    def test_dead_acquisition_io_and_interruption_release_every_acquired_handle(self) -> None:
        for fault in ("pidfd", "read", "interrupt"):
            port = self.port()
            port.witness_counts = {"procBytes": 0, "pids": set()}
            io = self.io(port, SimpleNamespace(), {40: self.bodies(40)})
            expected = OSError
            if fault == "pidfd":
                io["pidfds"].side_effect = OSError(errno.ESRCH, "private")
            else:
                expected = KeyboardInterrupt if fault == "interrupt" else OSError
                port.witness_read = Mock(side_effect=expected)
            anchor = {"roles": {"outer": {"pid": 10}, "parent": {"pid": 20}, "child": {"pid": 30}}}
            with self.subTest(fault=fault), ExitStack() as held, self.assertRaises(expected):
                port.witness_dead(held, {40}, {"pid": 20, "uid": 1000}, anchor)
            closed = [call.args[0] for call in io["closed"].call_args_list]
            self.assertEqual(closed.count(1040), 1)
            self.assertEqual(closed.count(140), int(fault != "pidfd"))

    def test_six_groups_complete_initial_before_selection_and_final_after_all_readbacks(self) -> None:
        for direct in (False, True):
            with self.subTest(direct=direct):
                port, _tasks = self.sampled_port(direct=direct)
                proc = port._witness_proc
                bodies = {pid: self.bodies(pid, 10 if direct else 20) for pid in range(40, 46)}
                io = self.io(port, proc, bodies)
                original_realm = port.witness_realm.side_effect
                port.witness_realm.side_effect = lambda held, owner=port, original=original_realm: (
                    setattr(owner, "_witness_observer", 900),
                    original(held),
                )[1]
                with patch.object(active, "receipt", return_value=self.view(port)):
                    port.collect_postexec_witness("ready")
                    port.witness_parent_children.return_value = {30, *bodies}
                    original_child = port.witness_child
                    selection_reads = []
                    image_exits = []

                    @contextmanager
                    def image(*_args: object, kernel: dict = io, exits: list = image_exits) -> object:
                        yield {"descriptor": 99, "identity": (1, 2)}
                        exits.append(len(kernel["reads"]))

                    port.modules.observations.held_rootlesskit.side_effect = image

                    def selected(
                        *args: object,
                        captured: list = selection_reads,
                        kernel: dict = io,
                        original: object = original_child,
                    ) -> dict:
                        captured.append(len(kernel["reads"]))
                        return original(*args)

                    port.witness_child = selected
                    port.collect_postexec_witness("pre-close")
                self.assertEqual(selection_reads, [36, 36])
                self.assertEqual(image_exits, [36])
                self.assertEqual(len(io["reads"]), 72)
                self.assertEqual(port.record["postExecWitness"]["samples"][-1]["deadNonactorCount"], 6)
                self.assertEqual(
                    port.witness_counts["procBytes"],
                    4 * sum(len(raw) for body in bodies.values() for raw in body.values()),
                )
                self.assertEqual(port.commit.call_count, 2)
                self.assertTrue(
                    qualification.postexec_witness_valid(
                        port.record["postExecWitness"], self.view(port), complete=True, current=True
                    )
                )
                self.assertEqual([call.args for call in io["pidfds"].call_args_list], [(pid, 0) for pid in bodies])
                closed = [call.args[0] for call in io["closed"].call_args_list]
                for descriptor in [*io["opened"], *(pid + 100 for pid in bodies), *(pid + 1000 for pid in bodies)]:
                    self.assertEqual(closed.count(descriptor), 1)

    def test_final_reap_or_reuse_refuses_without_committing_preclose(self) -> None:
        for fault in ("reaped", "reused", "owner-dead"):
            port, _tasks = self.sampled_port(direct=False)
            proc = port._witness_proc
            body = self.bodies(40)
            original = body["fdinfo"]
            body["fdinfo"] = (
                Mock(side_effect=[original, original, original.replace(b"Pid: 40", b"Pid: -1")])
                if fault == "reaped"
                else original
            )
            if fault == "reused":
                body["stat"] = Mock(
                    side_effect=[body["stat"], body["stat"], *[body["stat"].replace(b" 400\n", b" 401\n")] * 2]
                )
            self.io(port, proc, {40: body})
            original_realm = port.witness_realm.side_effect
            port.witness_realm.side_effect = lambda held, owner=port, original=original_realm: (
                setattr(owner, "_witness_observer", 900),
                original(held),
            )[1]
            with patch.object(active, "receipt", return_value=self.view(port)):
                port.collect_postexec_witness("ready")
                ready = copy.deepcopy(port.record["postExecWitness"])
                port.witness_parent_children.return_value = {30, 40}
                if fault == "owner-dead":
                    self.effects.enter_context(
                        patch.object(
                            active.select,
                            "select",
                            side_effect=lambda fds, *_: (list(fds) if fds[0] >= FIXTURE_OWNER_FD else [], [], []),
                        )
                    )
                with self.subTest(fault=fault), self.assertRaises(active.RefusedError):
                    port.collect_postexec_witness("pre-close")
                self.assertEqual(port.record["postExecWitness"], ready)
                self.assertEqual(port.commit.call_count, 1)
                self.assertFalse(port.cleanup)

    def test_actual_byte_caps_and_id_ledger_refuse_without_enlargement(self) -> None:
        for boundary in ("aggregate", "per-read", "pid"):
            port = self.port()
            port.witness_counts = {"procBytes": 0, "pids": set(range(1, 65)) if boundary == "pid" else set()}
            bodies = self.bodies(100)
            if boundary != "pid":
                for key, raw in bodies.items():
                    bodies[key] = raw + b" " * (8192 - len(raw) + int(boundary == "per-read"))
                if boundary == "aggregate":
                    port.witness_counts["procBytes"] = active.WITNESS_PROC_LIMIT - 8192
            io = self.io(port, SimpleNamespace(), {100: bodies})
            anchor = {"roles": {"outer": {"pid": 10}, "parent": {"pid": 20}, "child": {"pid": 30}}}
            with self.subTest(boundary=boundary), ExitStack() as held, self.assertRaises(active.RefusedError):
                port.witness_dead(held, {100}, {"pid": 20, "uid": 1000}, anchor)
            self.assertFalse(port.cleanup)
            if boundary == "pid":
                io["pidfds"].assert_not_called()

    def test_current_validation_never_upgrades_historical_v1(self) -> None:
        historical = scoped_receipt()
        self.assertTrue(qualification.postexec_witness_valid(historical["postExecWitness"], historical, complete=True))
        self.assertFalse(
            qualification.postexec_witness_valid(historical["postExecWitness"], historical, complete=True, current=True)
        )
        current = current_scoped_receipt()
        value = current["postExecWitness"]
        self.assertTrue(qualification.postexec_witness_valid(value, current, complete=True, current=True))
        for key, invalid in (
            ("deadNonactorCount", True),
            ("deadNonactorCount", -1),
            ("deadNonactorCount", 65),
            ("coverageComplete", False),
            ("deadNonactorSha256", "0" * 64),
            ("realmSha256", "0" * 64),
        ):
            wrong = copy.deepcopy(value)
            wrong["samples"][1][key] = invalid
            with self.subTest(key=key, invalid=invalid):
                self.assertFalse(qualification.postexec_witness_valid(wrong, current, complete=True, current=True))

    def test_partial_ready_publication_cannot_commit_or_be_retried_into_success(self) -> None:
        port, _tasks = self.sampled_port(direct=True)
        self.io(port, port._witness_proc, {})
        writer = active.write_leaf
        original_write = writer.side_effect

        def partial(*args: object) -> None:
            original_write(*args)
            raise OSError(errno.EIO, "private durable-publication canary")

        writer.side_effect = partial
        with patch.object(active, "receipt", return_value=self.view(port)):
            with self.assertRaises(OSError):
                port.collect_postexec_witness("ready")
            writer.side_effect = original_write
            with self.assertRaises(FileExistsError):
                port.collect_postexec_witness("ready")
        port.commit.assert_not_called()
        self.assertNotIn("postExecWitness", port.record)
        self.assertFalse(port.cleanup)

    def test_anchor_integrity_and_binding_are_required_before_dead_lookup(self) -> None:
        port, _tasks = self.sampled_port(direct=True)
        proc = port._witness_proc
        self.io(port, proc, {})
        with patch.object(active, "receipt", return_value=self.view(port)):
            port.collect_postexec_witness("ready")
            self.assertEqual(port.witness_ready_anchor()["roles"]["child"]["pid"], 30)
            with patch.object(active, "root_bytes", return_value=b"{}\n"), self.assertRaises(active.RefusedError):
                port.witness_ready_anchor()
            port.record["postExecWitness"]["leaseSha256"] = "0" * 64
            with self.assertRaises(active.RefusedError):
                port.witness_ready_anchor()
        proc.pid.assert_not_called()

    def test_private_state_and_public_envelopes_fit_without_increasing_caps(self) -> None:
        port, _tasks = self.sampled_port(direct=False)
        self.io(port, port._witness_proc, {})
        with patch.object(active, "receipt", return_value=self.view(port)):
            port.collect_postexec_witness("ready")
            raw = active.write_leaf.call_args.args[2]
            anchor = active.json.loads(raw)
        for task in anchor["roles"].values():
            task["state"].update(
                cgroup="0::/" + "x" * (8192 - 5) + "\n",
                startTicks=2**64 - 1,
                executable=[2**64 - 1] * 9,
                namespaces=[[2**64 - 1] * 2] * 3,
            )
        bounded = active.encoded(anchor)
        self.assertLess(len(bounded), active.MAX_STATE)
        current = current_scoped_receipt()
        self.assertLess(len(active.encoded(current)), active.MAX_STATE)
        with self.assertRaises(active.RefusedError):
            active.encoded({"unbounded": "x" * active.MAX_STATE})
        self.assertEqual(
            (
                active.MAX_STATE,
                active.MAX_SOURCE,
                active.WITNESS_PROC_LIMIT,
                active.WITNESS_READ_LIMIT,
                active.WITNESS_EXEC_LIMIT,
                active.WITNESS_PID_LIMIT,
            ),
            (32768, 262144, 524288, 8192, 100663296, 64),
        )

    def test_complete_six_group_production_envelope(self) -> None:
        """Measure the full sampler/census/hash/owner bodies against a finite virtual kernel."""
        port, _tasks = self.sampled_port(direct=False)
        proc = port._witness_proc
        group = "0::/" + port.binding.runtime_slice + "/docker-" + "a" * 64 + ".scope\n"
        port.record["subject"]["cgroup"] = group
        namespace = (1, 41, active.CLONE_NEWPID)
        port.record.update(
            owners={
                "owner": {
                    "schemaVersion": 2,
                    "pid": 200,
                    "startTicks": 200,
                    "pgid": 200,
                    "cgroup": "owner\n",
                    "namespace": {"user": 1, "mnt": 2, "cgroup": 3},
                    "pidNamespace": list(namespace),
                    "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                    "leaseSha256": active.digest(b"f" * 32),
                }
            },
            ownerIntents={"owner": {"argv": ["fixed", "owner"]}},
            coordinatorPid=201,
            coordinatorPgid=201,
        )
        for name in (
            "witness_task",
            "witness_task_state",
            "witness_scope_pids",
            "witness_parent_children",
            "witness_realm",
        ):
            setattr(port, name, getattr(active.RootPort, name).__get__(port))
        port.modules.observations = observations
        kernel = WitnessKernel(self, port, proc, group)
        proc.pid, proc.pid_namespace, proc.self_pid = kernel.pid, kernel.pid_namespace, kernel.self_pid
        proc.open = lambda directory, leaf, flags: kernel.opened(leaf, flags, dir_fd=directory)
        active.ProcView.side_effect = kernel.factory
        with (
            patch.object(active, "receipt", return_value=self.view(port)),
            patch.object(active, "filesystem_magic"),
            patch.object(active.time, "monotonic_ns", return_value=1),
            patch.object(active.os, "open", side_effect=kernel.opened),
            patch.object(active.os, "read", side_effect=kernel.read),
            patch.object(active.os, "close", side_effect=kernel.close),
            patch.object(active.os, "fstat", side_effect=lambda fd: kernel.info(kernel.live[fd])),
            patch.object(active.os, "stat", side_effect=kernel.named),
            patch.object(active.os, "scandir", side_effect=kernel.scan),
            patch.object(active.os, "getpgid", return_value=200),
            patch.object(active.os, "pidfd_open", side_effect=lambda number, _flags: kernel.acquire(("pidfd", number))),
            patch.object(active.os, "getxattr", side_effect=OSError(errno.ENODATA, "none")),
            patch.object(
                active.select,
                "select",
                side_effect=lambda fds, *_args: (fds if kernel.live[fds[0]][1] in range(40, 46) else [], [], []),
            ),
        ):
            port.collect_postexec_witness("ready")
            self.assertFalse(kernel.live)
            kernel.phase = "pre-close"
            kernel.peak = 0
            port.collect_postexec_witness("pre-close")
            self.assertFalse(kernel.live)
        self.assertEqual(sum(name == "pre-close" for name, _size in kernel.reads), 141)
        self.assertEqual(port.witness_counts["exeBytes"], 384)
        self.assertLess(port.witness_counts["procBytes"], active.WITNESS_PROC_LIMIT)
        self.assertLessEqual(kernel.peak, 68)
        self.assertEqual(len(port.witness_counts["pids"]), 12)
        self.assertEqual(port.commit.call_count, 2)


class WitnessKernel:
    """Supply finite independent syscall observations to the complete production sampler."""

    def __init__(self, case: unittest.TestCase, port: active.RootPort, proc: object, group: str) -> None:
        """Keep all virtual descriptors and byte observations local to one hermetic test."""
        self.case, self.port, self.proc, self.group = case, port, proc, group
        self.live, self.offsets, self.reads = {}, {}, []
        self.serial, self.peak, self.phase = 3000, 0, "ready"

    def acquire(self, node: tuple) -> int:
        self.serial += 1
        self.live[self.serial] = node
        self.peak = max(self.peak, len(self.live))
        return self.serial

    def close(self, fd: int) -> None:
        self.case.assertIn(fd, self.live)
        del self.live[fd]

    def pid(self, number: int) -> int:
        self.port.witness_pid(number)
        return self.acquire(("proc", number))

    def pid_namespace(self, held: ExitStack, directory: int) -> tuple:
        number = self.live[directory][1]
        ino = 41 if number in {1, 100, 200} else 3
        descriptor = self.acquire(("namespace", ino))
        held.callback(active.os.close, descriptor)
        self.port.witness_proc_bytes(len(f"pid:[{ino}]"))
        return (1, ino, active.CLONE_NEWPID)

    def self_pid(self) -> int:
        self.port.witness_proc_bytes(3)
        return 100

    def factory(self, held: ExitStack, _charge: object, _seen: object) -> object:
        root = self.acquire(("proc-root",))
        held.callback(active.os.close, root)
        return self.proc

    def proc_leaf(self, number: int, leaf: str) -> tuple:
        """Model only the fixed leaves needed by the admitted actor paths."""
        if leaf.startswith("ns/"):
            identity = {30: {"user": 4, "mnt": 5}, 200: {"user": 1, "mnt": 2, "cgroup": 3}}.get(
                number, {"user": 1, "mnt": 2}
            )
            return "namespace", identity[leaf[3:]]
        fixed = {"exe": ("exe", number), "root": ("image", "root"), "task": ("task", number)}
        return fixed.get(leaf, ("leaf", number, leaf))

    def resolved(self, node: tuple, leaf: str) -> tuple:
        """Resolve finite virtual directory entries without consulting the host."""
        if node[0] == "proc":
            return self.proc_leaf(node[1], leaf)
        if node[0] == "task":
            self.case.assertEqual(leaf, str(node[1]))
            return "proc", node[1]
        if node[0] == "image":
            return ("exe", "image") if leaf == "rootlesskit" else ("image", leaf)
        expected = {"cgroup-root": self.port.binding.runtime_slice, "scope": "cgroup.procs"}
        if node[0] in expected:
            self.case.assertEqual(leaf, expected[node[0]])
        return {"cgroup-root": ("runtime",), "runtime": ("scope",), "scope": ("members",)}[node[0]]

    def opened(self, leaf: str, _flags: int, *, dir_fd: int | None = None) -> int:
        """Allocate one independently tracked virtual descriptor."""
        if dir_fd is None:
            self.case.assertEqual(leaf, "/sys/fs/cgroup")
            node = ("cgroup-root",)
        else:
            node = self.resolved(self.live[dir_fd], leaf)
        return self.acquire(node)

    def info(self, node: tuple) -> object:
        kind = node[0]
        inode = 2 if kind in {"runtime", "exe"} else node[1] if kind == "namespace" else hash(node) % 1_000_000 + 100
        return SimpleNamespace(
            st_dev=1,
            st_ino=inode,
            st_uid=0,
            st_gid=0,
            st_mode=(stat.S_IFREG if kind in {"leaf", "members", "exe"} else stat.S_IFDIR) | 0o555,
            st_nlink=1,
            st_size=128 if kind == "exe" else 0,
            st_mtime_ns=0,
            st_ctime_ns=0,
        )

    def named(self, leaf: str, *, dir_fd: int, **_kwargs: object) -> object:
        descriptor = self.opened(leaf, 0, dir_fd=dir_fd)
        result = self.info(self.live[descriptor])
        self.close(descriptor)
        return result

    def leaf_bytes(self, number: int, leaf: str) -> bytes:
        """Provide independent live/dead process fields and the original parent census."""
        if leaf.startswith("fdinfo/"):
            dead_pid = self.live[int(leaf.split("/")[1])][1]
            return self.case.bodies(dead_pid)["fdinfo"]
        if number in range(40, 46):
            return self.case.bodies(number)[leaf]
        parent, guest = {20: (10, 7), 30: (20, 8)}.get(number, (1, 1))
        uid = 1000 if number in {20, 30} else 0
        contents = {
            "stat": f"{number} (live) S {parent} ".encode() + b"0 " * 17 + str(number).encode() + b"\n",
            "status": (
                f"Pid: {number}\nTgid: {number}\nUid: {uid} {uid} {uid} {uid}\nPPid: {parent}\n"
                f"NSpid: {number} {guest}\n"
            ).encode(),
            "cgroup": {200: b"owner\n"}.get(number, self.group.encode()),
            "attr/apparmor/current": {200: b"unconfined\n"}.get(number, b"fixture (enforce)\n"),
            "cmdline": b"fixed\0owner\0",
            "children": b"30 " if self.phase == "ready" else b"30 40 41 42 43 44 45 ",
        }
        return contents[leaf]

    def read(self, fd: int, limit: int) -> bytes:
        """Count actual byte reads, including the three original executable hash streams."""
        node = self.live[fd]
        if node[0] == "exe":
            raw = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(108)
            result = b"" if self.offsets.get(fd) else raw
            self.offsets[fd] = True
            return result
        raw = b"10\n20\n30\n" if node[0] == "members" else self.leaf_bytes(node[1], node[2])
        self.reads.append((self.phase, len(raw)))
        return raw[:limit]

    def scan(self, directory: int) -> object:
        node = self.live[directory]
        entries = (
            []
            if node[0] == "scope"
            else [SimpleNamespace(name=str(node[1]), is_symlink=lambda: False, is_dir=lambda **_kwargs: True)]
        )
        return nullcontext(iter(entries))


class CertifiedProcView(unittest.TestCase):
    port = RootWitness.port

    def test_anchor_reader_requires_exact_immutable_mode(self) -> None:
        for mode in (0o400, 0o600):
            info = SimpleNamespace(
                st_dev=1,
                st_ino=11,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFREG | mode,
                st_nlink=1,
                st_size=3,
                st_mtime_ns=0,
                st_ctime_ns=0,
            )
            path = Mock()
            path.lstat.return_value = info
            with (
                self.subTest(mode=mode),
                patch.object(active.os, "open", return_value=11),
                patch.object(active.os, "fstat", return_value=info),
                patch.object(active.os, "read", side_effect=[b"{}\n", b""]),
                patch.object(active.os, "close") as closed,
            ):
                if mode == active.IMMUTABLE_FILE:
                    self.assertEqual(active.root_bytes(path, immutable=True), b"{}\n")
                else:
                    with self.assertRaises(active.RefusedError):
                        active.root_bytes(path, immutable=True)
            closed.assert_called_once_with(11)

    def test_authenticated_terminal_disposal_accepts_only_the_fixed_orphan_leaf(self) -> None:
        port = self.port()
        port.record.update(
            state="closed",
            readerPending=False,
            childPending=False,
            guestAbsenceVerified=True,
            profileAbsenceVerified=True,
        )
        port.finish_owner = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "lease"
            root.mkdir()
            for name in (
                "lock",
                "state.json",
                "policy",
                "probe-ready.json",
                "probe-close",
                "probe-release",
                "probe-closed.json",
                "owner-ready.json",
                "owner-release",
                "owner-closed.json",
                active.WITNESS_ANCHOR,
            ):
                (root / name).write_bytes(b"partial")
            (root / "cli").mkdir()
            (root / "cli/config.json").write_bytes(b"{}\n")
            port.store = SimpleNamespace(path=root)
            with patch.object(active, "root_bytes", side_effect=lambda path: path.read_bytes()):
                port.dispose()
            self.assertFalse(root.exists())
        self.assertTrue(port.record["custodyDisposed"])
        port.finish_owner.assert_called_once_with("owner")

    def test_openat2_uses_all_restrictions_and_errors_never_fall_back(self) -> None:
        for result in (21, -1):
            calls = []

            def syscall(*args: object, state: tuple = (calls, result)) -> int:
                number, directory, name, how, size = args
                state[0].append((number, directory, name.value, tuple(how._obj), size))
                return state[1]

            with (
                self.subTest(result=result),
                patch.object(active.ctypes, "CDLL", return_value=SimpleNamespace(syscall=syscall)),
                patch.object(active.ctypes, "get_errno", return_value=errno.ENOSYS),
                patch.object(active.os, "open", side_effect=AssertionError("no resolver fallback")),
            ):
                if result < 0:
                    with self.assertRaises(OSError) as refused:
                        active.ProcView.open(11, "40/status", active.os.O_RDONLY | active.os.O_NOFOLLOW)
                    self.assertEqual(refused.exception.errno, errno.ENOSYS)
                else:
                    self.assertEqual(
                        active.ProcView.open(11, "40/status", active.os.O_RDONLY | active.os.O_NOFOLLOW), 21
                    )
            self.assertEqual(
                calls,
                [(437, 11, b"40/status", (active.os.O_RDONLY | active.os.O_NOFOLLOW | active.os.O_CLOEXEC, 0, 11), 24)],
            )
        for name in ("/proc/40", "../40", "40/../status", "40//stat", ".", ""):
            with self.subTest(name=name), self.assertRaises(active.RefusedError):
                active.ProcView.open(11, name, active.os.O_RDONLY)

    def test_namespace_jump_is_only_literal_pid_after_an_authenticated_link(self) -> None:
        for fault in (None, "target", "kind", "filesystem", "open"):
            view = active.ProcView.__new__(active.ProcView)
            view.open = Mock(return_value=11)
            view.link = Mock(return_value="pid:[41]")
            with (
                self.subTest(fault=fault),
                ExitStack() as held,
                patch.object(
                    active.os,
                    "open",
                    side_effect=OSError(errno.EXDEV, "private") if fault == "open" else None,
                    return_value=21,
                ) as opened,
                patch.object(active.os, "close") as closed,
                patch.object(
                    active.os, "fstat", return_value=SimpleNamespace(st_dev=5, st_ino=42 if fault == "target" else 41)
                ),
                patch.object(active.fcntl, "ioctl", return_value=0 if fault == "kind" else active.CLONE_NEWPID),
                patch.object(
                    active, "filesystem_magic", side_effect=active.RefusedError if fault == "filesystem" else None
                ),
            ):
                if fault is None:
                    self.assertEqual(view.pid_namespace(held, 7), (5, 41, active.CLONE_NEWPID))
                else:
                    with self.assertRaises((active.RefusedError, OSError)):
                        view.pid_namespace(held, 7)
                view.open.assert_called_once_with(
                    7, "ns", active.os.O_RDONLY | active.os.O_DIRECTORY | active.os.O_NOFOLLOW
                )
                view.link.assert_called_once_with(11, "pid")
                opened.assert_called_once_with("pid", active.os.O_RDONLY | active.os.O_CLOEXEC, dir_fd=11)
                self.assertIn(unittest.mock.call(11), closed.call_args_list)
                held.close()
                if fault != "open":
                    self.assertEqual(closed.call_args_list.count(unittest.mock.call(21)), 1)

    def test_link_is_held_without_following_and_charges_actual_bytes(self) -> None:
        view = active.ProcView.__new__(active.ProcView)
        view.open = Mock(return_value=11)
        view.charge = Mock()
        with (
            patch.object(active.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK)),
            patch.object(active, "filesystem_magic"),
            patch.object(active.os, "readlink", return_value="pid:[41]") as link,
            patch.object(active.os, "close") as closed,
        ):
            self.assertEqual(view.link(7, "pid"), "pid:[41]")
        view.open.assert_called_once_with(7, "pid", active.os.O_PATH | active.os.O_NOFOLLOW)
        link.assert_called_once_with("", dir_fd=11)
        view.charge.assert_called_once_with(8)
        closed.assert_called_once_with(11)


class OwnerPidRealm(unittest.TestCase):
    def test_owner_pins_own_namespace_before_ready_until_terminal_close_on_every_path(self) -> None:
        for fault in (None, "ready", "terminal"):
            closed, publication = [], []
            namespace = (5, 41, active.CLONE_NEWPID)
            store = Mock(path=Path("/inert/" + "f" * 32))
            record = {
                "bindingSha256": "a" * 64,
                "coordinatorPid": 100,
                "coordinatorPgid": 101,
                "coordinatorTask": {"pid": 100},
                "namespace": {"user": 1},
            }
            store.read.return_value = record
            port = SimpleNamespace(
                binding=SimpleNamespace(digest=lambda: "a" * 64, deadline_ns=1000),
                owner_unit=lambda _kind: "fixed.service",
                admission={},
            )
            proc = Mock()
            proc.self_pid.return_value = 200
            proc.pid.return_value = 302

            def pin(held: ExitStack, directory: int, expected: object = namespace) -> tuple:
                self.assertEqual(directory, 302)
                held.callback(active.os.close, 303)
                return expected

            proc.pid_namespace.side_effect = pin

            def publish(_directory: Path, _name: str, raw: bytes, state: tuple = (closed, publication, fault)) -> None:
                self.assertNotIn(303, state[0])
                state[1].append(active.json.loads(raw))
                if state[2] == "ready":
                    raise OSError(errno.EIO, "private")

            def terminal(*_args: object, state: tuple = (closed, publication, namespace, fault)) -> int:
                self.assertNotIn(303, state[0])
                self.assertEqual(state[1][0]["pidNamespace"], list(state[2]))
                self.assertEqual(state[1][0]["schemaVersion"], 2)
                if state[3] == "terminal":
                    raise RuntimeError
                return 0

            with (
                self.subTest(fault=fault),
                patch.object(active, "Store", return_value=store),
                patch.object(active, "RootPort", return_value=port),
                patch.object(active, "ProcView", return_value=proc),
                patch.object(active.os, "open", return_value=401),
                patch.object(active.os, "pidfd_open", return_value=501),
                patch.object(active.os, "close", side_effect=closed.append),
                patch.object(active.os, "getpid", return_value=200),
                patch.object(active.os, "getpgid", return_value=201),
                patch.object(
                    active,
                    "task_snapshot",
                    side_effect=[
                        {"cgroup": "0::/system.slice/fixed.service\n", "startTicks": 1},
                        record["coordinatorTask"],
                    ],
                ),
                patch.object(active, "namespace_snapshot", return_value=record["namespace"]),
                patch.object(active.select, "select", return_value=([], [], [])),
                patch.object(active, "write_leaf", side_effect=publish),
                patch.object(active, "owner_loop", side_effect=terminal),
                patch.object(active.signal, "signal"),
                patch("subprocess.run", side_effect=AssertionError("no runtime")),
            ):
                if fault is None:
                    self.assertEqual(
                        active.owner_main(Path("/inert"), {"deadlineNs": 2000, "uid": 1000}, None, "f" * 32, "owner"), 0
                    )
                else:
                    with self.assertRaises((OSError, RuntimeError)):
                        active.owner_main(Path("/inert"), {"deadlineNs": 2000, "uid": 1000}, None, "f" * 32, "owner")
            self.assertEqual(sorted(closed), [302, 303, 401, 501])
            store.close.assert_called_once_with()

    def test_callback_opens_actual_owner_namespace_inside_original_proc_pidfd_bracket(self) -> None:
        for legacy in (False, True):
            port = RootWitness.port(self)
            namespace = (5, 41, active.CLONE_NEWPID)
            ready = {
                "schemaVersion": 1 if legacy else 2,
                "pid": 200,
                "startTicks": 1,
                "cgroup": "owned",
                "pgid": 201,
                "namespace": {"user": 1, "mnt": 2, "cgroup": 3},
                "pidNamespace": list(namespace),
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                "leaseSha256": active.digest(b"f" * 32),
            }
            port.record.update(
                owners={"owner": ready},
                ownerIntents={"owner": {"argv": ["fixed", "owner"]}},
                coordinatorPid=100,
                coordinatorPgid=101,
            )
            proc = Mock()
            proc.pid.return_value = 401
            closed = []

            def pin(held: ExitStack, directory: int, state: tuple = (closed, namespace)) -> tuple:
                self.assertEqual(directory, 401)
                self.assertNotIn(401, state[0])
                self.assertNotIn(501, state[0])
                held.callback(active.os.close, 303)
                return state[1]

            proc.pid_namespace.side_effect = pin
            with (
                self.subTest(legacy=legacy),
                ExitStack() as held,
                patch.object(active.os, "pidfd_open", return_value=501),
                patch.object(active.os, "close", side_effect=closed.append),
                patch.object(active.os, "getpgid", return_value=201),
                patch.object(active.os, "stat", side_effect=[SimpleNamespace(st_ino=index) for index in (1, 2, 3)]),
                patch.object(active.select, "select", return_value=([], [], [])),
                patch.object(active, "task_snapshot", return_value={"startTicks": 1, "cgroup": "owned"}),
            ):

                def reader(_directory: int, leaf: str) -> bytes:
                    return b"unconfined\n" if leaf == "attr/apparmor/current" else b"fixed\0owner\0"

                if legacy:
                    with self.assertRaises(active.RefusedError):
                        port.owner_handle("owner", realm_stack=held, proc=proc, reader=reader)
                    proc.pid_namespace.assert_not_called()
                    self.assertIn(501, closed)
                else:
                    self.assertEqual(port.owner_handle("owner", realm_stack=held, proc=proc, reader=reader), 501)
                    self.assertNotIn(303, closed)
                    self.assertNotIn(501, closed)
                self.assertIn(401, closed)
                held.close()
                if not legacy:
                    self.assertIn(303, closed)


class WitnessIntegration(unittest.TestCase):
    def test_client_sends_no_subject_selectors_and_rejects_bad_checkpoint(self) -> None:
        client = ActiveClient.__new__(ActiveClient)
        client._bootstrap_anchor, client._close_receipt = None, None
        client.binding = SimpleNamespace(digest=lambda: "a" * 64)
        client.evidence = {"original": True}
        scoped = current_scoped_receipt()
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
        for phase in record["phases"]:
            scoped = phase["scopedProfile"]
            scoped["postExecWitness"] = postexec_v2_fixture(scoped)
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
        for failed in ("controls", "ready", "pre-close"):
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
                patch(
                    "scripts.runtime_docker_dead_nonactor_controls.require_controls",
                    side_effect=lambda _ctx, call=witness: call("controls"),
                ),
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
            self.assertEqual(events[0], "controls")
            if failed in {"controls", "ready"}:
                ctx.load_fixture_archive.assert_not_called()
            else:
                self.assertLess(events.index("ready"), events.index("work"))
                self.assertLess(events.index("verify nested Docker cleanup readback"), events.index("pre-close"))
