"""Independent lifecycle-accounting expectations; no runtime or privileged call."""

from __future__ import annotations

import argparse
import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from unittest.mock import MagicMock, patch

from scripts import maintenance, release_evidence, runtime_docker_systemd, runtime_tests
from scripts import runtime_oom_diagnostics as oom
from scripts.evidence_gate import EvidenceError, _read, require_ordinary_runtime_authority
from scripts.runtime_docker import DockerProbePhase
from scripts.runtime_docker_backend import DockerBackend, DockerBackendError
from scripts.runtime_errors import ProbeError
from tests.test_docker_userns_qualification import scoped_receipt, stage_disposal

OWNER = "c" * 32
SERVER = {"Version": "29.4.2", "GitCommit": "d329809"}
CONTAINERD = "containerd containerd v2.4.2 b7a25261e029d68978bbf290df0a62fc819b3c51"
EVENT_FILES = ("memory.events", "memory.events.local")
COUNTER = {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0, "oom_group_kill": 0}


def parent(purpose: str = "baseline", *, kills: int = 0) -> dict:
    """Build the closed parent record independently of collector constructors."""
    values = {name: dict(COUNTER) for name in EVENT_FILES}
    values["memory.events"].update(oom=kills, oom_kill=kills)
    return {
        "schemaVersion": 1,
        "kind": "owned-parent-oom-lifecycle",
        "purpose": purpose,
        "availability": "observed",
        "bindingChecks": dict.fromkeys(
            ("ownedParent", "fullHierarchy", "outsideCollector", "stableRead", "quiescent"), True
        ),
        "bindings": {
            "parent": "a" * 64,
            "mount": "b" * 64,
            "namespace": "c" * 64,
            "memory.events": "d" * 64,
            "memory.events.local": "e" * 64,
        },
        "mountSemantics": {"root": "full-hierarchy", "memoryLocalevents": False},
        "populated": [0, 0],
        "counters": values,
        "sampleWindowMonotonicNs": [1, 2] if purpose == "baseline" else [90, 91],
    }


def root(phase: str, *, kills: int = 0, window: tuple[int, int] = (10, 11)) -> dict:
    """Build bound original-root snapshots without implementation helpers."""
    values = {name: {"availability": "observed", "values": dict(COUNTER)} for name in EVENT_FILES}
    values["memory.events"]["values"].update(oom=kills, oom_kill=kills)
    return {
        "schemaVersion": 1,
        "availability": "observed",
        "attribution": "unresolved",
        "authority": "observation-only",
        "bindingChecks": dict.fromkeys(
            (
                "ownedContainer",
                "containerIncarnation",
                "hostProcess",
                "cgroup2Mount",
                "ownedSlice",
                "outerCgroup",
                "stableRead",
            ),
            True,
        ),
        "bindings": {
            "containerIncarnation": "a" * 64,
            "hostProcess": "c" * 64,
            "outerCgroup": "d" * 64,
            "mount": "b" * 64,
        },
        "mountSemantics": {"root": "full-hierarchy", "memoryLocalevents": False},
        "counters": values,
        "sampleWindowMonotonicNs": list(window),
        "phase": phase,
        "ociState": {"Running": True, "OOMKilled": False},
    }


def state(*, killed: bool = False) -> dict:
    """Original strict zero-exit lifecycle fields, retaining actual sticky flag."""
    return {
        "Running": False,
        "Status": "exited",
        "ExitCode": 0,
        "OOMKilled": killed,
        "Error": "",
        "Pid": 0,
        "Paused": False,
        "Restarting": False,
        "Dead": False,
    }


class LedgerTests(unittest.TestCase):
    def ledger(self, *, mode: str = "qualification") -> oom.DockerOomLedger:
        ledger = oom.DockerOomLedger(parent(), mode)
        ledger.bind_server(dict(SERVER), CONTAINERD)
        ledger.bind_image({"configDigest": "sha256:" + "f" * 64, "architecture": "amd64"})
        ledger.root_snapshot("lifecycle-start", root("lifecycle-start"))
        ledger.defer_state({"actual": state(), "status": "passed"})
        return ledger

    def original(
        self, ledger: oom.DockerOomLedger, *, cardinality: int = 1, wait: str = "137", bracket: bool = True
    ) -> None:
        if bracket:
            ledger.root_snapshot("before-inner-memory", root("before-inner-memory", window=(20, 21)))
            ledger.root_snapshot("after-inner-memory", root("after-inner-memory", kills=1, window=(30, 31)))
        identity = {
            "pid": 123,
            "starttime": 456,
            "pidns": 789,
            "group": "/owned/allocator",
            "exe": "/usr/local/bin/docker-resource-probe",
        }
        processes = [["123", "0 0 0 0", "/owned/allocator", "/usr/local/bin/docker-resource-probe", 456]] * cardinality
        telemetry = {"before": {"identity": {"pid": 1, "nspid": [1], "starttime": 456}}, "after": None}
        ledger.admit_original(
            identity,
            processes,
            telemetry,
            {
                "wait": wait,
                "state": {"OOMKilled": True, "ExitCode": 137},
                "effectiveNoSwap": True,
                "workload": "a" * 64,
                "command": [
                    "docker-resource-probe",
                    "memory",
                    "--wait-for-start",
                    "/tmp/resource-start",  # noqa: S108 - in-guest barrier, never a host operand.
                    "--memory-evidence",
                ],
                "executable": "/usr/local/bin/docker-resource-probe",
                "sourceSha256": "43b1c7d6affa6a226a4547203f3b2b0b0fdc6930cae40f6c91a2ffda5ffe6bc6",
            },
        )

    def test_original_single_process_null_after_and_true_flag_remain_pending_until_full_cleanup(self) -> None:
        ledger = self.ledger()
        self.original(ledger)
        ctx = SimpleNamespace(
            outer_engine="docker",
            oom_accounting_mode="qualification",
            backend=SimpleNamespace(oom_ledger=ledger),
            checks=[],
        )
        runtime_docker_systemd._assert_orderly_state(ctx, state(killed=True))
        self.assertEqual(ctx.checks[-1]["status"], "pending")
        ledger.reconcile(parent("terminal", kills=1))
        self.assertFalse(ledger.finalized)
        self.assertEqual(ctx.checks[-1]["status"], "pending")
        ledger.finalize(ctx)
        self.assertTrue(ledger.finalized)
        self.assertTrue(all(check["status"] == "passed" for check in ctx.checks))
        self.assertEqual(ctx.checks[0]["actual"]["OOMKilled"], True)
        self.assertEqual(ledger.entries[0]["killedProcesses"], 1)

    def test_false_flag_and_zero_kill_control_still_require_complete_parent_lifetime(self) -> None:
        ledger = self.ledger()
        check = {"actual": state(), "status": "passed"}
        ledger.defer_state(check)
        with self.assertRaises(ValueError):
            ledger.finalize(SimpleNamespace(checks=[]))
        self.assertEqual(check["status"], "pending")
        with self.assertRaises(ValueError):
            ledger.reconcile(parent("terminal", kills=1))
        self.assertEqual(check["status"], "pending")
        ledger.reconcile(parent("terminal"))
        ledger.finalize(SimpleNamespace(checks=[]))
        self.assertEqual(check["status"], "passed")

    def test_extra_sibling_late_local_group_reset_identity_and_bool_counters_fail(self) -> None:
        mutations = []
        extra = parent("terminal", kills=2)
        mutations.append(extra)
        for filename, key in (
            ("memory.events.local", "oom"),
            ("memory.events.local", "oom_kill"),
            ("memory.events.local", "oom_group_kill"),
            ("memory.events", "oom_group_kill"),
        ):
            value = parent("terminal", kills=1)
            value["counters"][filename][key] = 1
            mutations.append(value)
        for value in (True, -1, "1"):
            malformed = parent("terminal", kills=1)
            malformed["counters"]["memory.events"]["oom_kill"] = value
            mutations.append(malformed)
        changed = parent("terminal", kills=1)
        changed["bindings"]["parent"] = "f" * 64
        mutations.append(changed)
        overlap = parent("terminal", kills=1)
        overlap["sampleWindowMonotonicNs"] = [25, 26]
        mutations.append(overlap)
        for terminal in mutations:
            with self.subTest(terminal=terminal):
                ledger = self.ledger()
                self.original(ledger)
                with self.assertRaises(ValueError):
                    ledger.reconcile(terminal)
                self.assertFalse(ledger.reconciled)

    def test_nonzero_or_incomplete_baseline_quiescence_mount_and_namespace_refuse(self) -> None:
        for field in ("oom", "oom_kill", "oom_group_kill"):
            for name in EVENT_FILES:
                value = parent()
                value["counters"][name][field] = 1
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    oom.DockerOomLedger(value, "qualification")
        for field, replacement in (
            ("populated", [0, 1]),
            ("populated", [False, 0]),
            ("bindingChecks", {}),
            ("counters", {}),
            ("mountSemantics", {"root": "full-hierarchy", "memoryLocalevents": True}),
        ):
            value = parent()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                oom.DockerOomLedger(value, "qualification")

    def test_no_authority_wrong_cardinality_diagnostic_and_overlapping_brackets_cannot_debit(self) -> None:
        for mode, cardinality, wait in (
            ("qualification", 2, "137"),
            ("qualification", 1, "0"),
            ("diagnostic", 1, "137"),
        ):
            ledger = self.ledger(mode=mode)
            with self.subTest(mode=mode, cardinality=cardinality, wait=wait), self.assertRaises(ValueError):
                self.original(ledger, cardinality=cardinality, wait=wait)
            self.assertEqual(ledger.entries, [])
        ledger = self.ledger()
        with self.assertRaises(ValueError):
            ledger.reconcile(parent("terminal", kills=1))
        ledger.root_snapshot("before-inner-memory", root("before-inner-memory", window=(20, 25)))
        with self.assertRaises(ValueError):
            ledger.root_snapshot("after-inner-memory", root("after-inner-memory", kills=1, window=(24, 26)))

    def test_observed_root_local_group_resets_and_flag_initialization_are_strict(self) -> None:
        for filename, key in (
            ("memory.events.local", "oom"),
            ("memory.events.local", "oom_kill"),
            ("memory.events", "oom_group_kill"),
        ):
            value = root("before-inner-memory", window=(20, 21))
            value["counters"][filename]["values"][key] = 1
            with self.subTest(filename=filename, key=key), self.assertRaises(ValueError):
                self.ledger().root_snapshot("before-inner-memory", value)
        ledger = self.ledger()
        self.original(ledger)
        with self.assertRaises(ValueError):
            ledger.root_snapshot("before-inner-memory", root("before-inner-memory", window=(40, 41)))
        initial = root("lifecycle-start")
        initial["ociState"]["OOMKilled"] = True
        with self.assertRaises(ValueError):
            oom.DockerOomLedger(parent(), "qualification").root_snapshot("lifecycle-start", initial)

    def test_unknown_reported_runtime_semantics_refuse_without_inventing_binary_attestation(self) -> None:
        for server, containerd in (
            ({"Version": "29.4.3", "GitCommit": "d329809"}, CONTAINERD),
            ({"Version": "29.4.2", "GitCommit": "055a478"}, CONTAINERD),
            (SERVER, "containerd containerd v2.4.3 unknown"),
        ):
            with self.subTest(server=server, containerd=containerd), self.assertRaises(ValueError):
                oom.DockerOomLedger(parent(), "qualification").bind_server(server, containerd)

    def test_duplicate_original_identity_and_missing_pending_authority_cannot_reconcile(self) -> None:
        ledger = self.ledger()
        self.original(ledger)
        ledger.root_snapshot("before-inner-memory", root("before-inner-memory", kills=1, window=(40, 41)))
        ledger.root_snapshot("after-inner-memory", root("after-inner-memory", kills=2, window=(50, 51)))
        with self.assertRaises(ValueError):
            self.original(ledger, bracket=False)
        self.assertEqual(len(ledger.entries), 1)
        with self.assertRaises(ValueError):
            ledger.reconcile(parent("terminal", kills=2))
        diagnostic = self.ledger(mode="diagnostic")
        with self.assertRaises(ValueError):
            diagnostic.reconcile(parent("terminal"))

    def test_missing_ledger_does_not_create_false_flag_fast_path(self) -> None:
        ctx = SimpleNamespace(
            outer_engine="docker", declared_launcher="systemd", backend=SimpleNamespace(oom_ledger=None), checks=[]
        )
        with self.assertRaises(ProbeError):
            runtime_docker_systemd._assert_orderly_state(ctx, state())

    def test_every_nonflag_lifecycle_field_remains_strict_and_podman_gets_no_waiver(self) -> None:
        ledger = self.ledger()
        ctx = SimpleNamespace(
            outer_engine="docker",
            oom_accounting_mode="qualification",
            backend=SimpleNamespace(oom_ledger=ledger),
            checks=[],
        )
        for key, value in (
            ("Running", True),
            ("ExitCode", 137),
            ("Error", "failure"),
            ("Pid", 9),
            ("Paused", True),
            ("Restarting", True),
            ("Dead", True),
            ("OOMKilled", 1),
        ):
            observed = state(killed=True)
            observed[key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError):
                runtime_docker_systemd._assert_orderly_state(ctx, observed)
        ctx.outer_engine = "podman"
        with self.assertRaises(ProbeError):
            runtime_docker_systemd._assert_orderly_state(ctx, state(killed=True))


class ParentCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.proc, self.cgroups = self.directory / "proc", self.directory / "cgroups"
        self.proc.mkdir()
        self.cgroups.mkdir()
        self.parent = self.cgroups / ("strukturpiloten" + OWNER + ".slice")
        self.parent.mkdir()
        self.collector = self.proc / str(os.getpid())
        for process in (self.collector, self.proc / "1"):
            (process / "ns").mkdir(parents=True)
            (process / "ns" / "cgroup").symlink_to("cgroup:[1234]")
        (self.collector / "stat").write_text(f"{os.getpid()} (collector) S " + "0 " * 18 + "1234")
        (self.collector / "cgroup").write_text("0::/user.slice/session.scope\n")
        device = self.cgroups.stat().st_dev
        (self.collector / "mountinfo").write_text(
            f"29 22 {os.major(device)}:{os.minor(device)} / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        )
        (self.parent / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        for name in EVENT_FILES:
            (self.parent / name).write_text("".join(f"{key} {value}\n" for key, value in COUNTER.items()))
        self.request = {
            "owner": OWNER,
            "purpose": "baseline",
            "sliceIdentity": f"{self.parent.stat().st_dev}:{self.parent.stat().st_ino}",
            "deadline": time.monotonic() + 5,
        }
        original = oom._DockerOuterRead.directory

        def directory(reader: oom._DockerOuterRead, path: str, *, parent: int | None = None) -> int:
            mapped = {"/proc": str(self.proc), "/sys/fs/cgroup": str(self.cgroups)}.get(path, path)
            return original(reader, mapped, parent=parent)

        self.patch_directory = patch.object(oom._DockerOuterRead, "directory", new=directory)
        self.patch_directory.start()
        self.addCleanup(self.patch_directory.stop)
        filesystem = patch.object(oom, "_docker_filesystem")
        filesystem.start()
        self.addCleanup(filesystem.stop)

    def test_parent_reads_without_live_guest_or_daemon_and_bookends_empty_hierarchy(self) -> None:
        result = oom._collect_docker_parent(self.request)
        self.assertEqual(result["availability"], "observed")
        self.assertEqual(result["populated"], [0, 0])
        self.assertTrue(all(result["bindingChecks"].values()))
        oom._parent_validate(result, "baseline")
        self.request["purpose"] = "terminal"
        self.assertEqual(oom._collect_docker_parent(self.request)["availability"], "observed")

    def test_charged_collector_namespace_mismatch_missing_controller_and_populated_fail(self) -> None:
        for group in ("/strukturpiloten" + OWNER + ".slice", "/strukturpiloten" + OWNER + ".slice/child"):
            (self.collector / "cgroup").write_text("0::" + group + "\n")
            self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        (self.collector / "cgroup").write_text("0::/user.slice/session.scope\n")
        namespace = self.proc / "1/ns/cgroup"
        namespace.unlink()
        namespace.symlink_to("cgroup:[5678]")
        self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        namespace.unlink()
        namespace.symlink_to("cgroup:[1234]")
        (self.parent / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        (self.parent / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        (self.parent / "memory.events").unlink()
        self.assertEqual(oom._collect_docker_parent(self.request)["availability"], "missing")

    def test_closed_request_deadline_and_fixed_counter_identity_are_enforced(self) -> None:
        for change in (
            {"deadline": True},
            {"deadline": time.monotonic() - 1},
            {"deadline": float("inf")},
            {"owner": "foreign"},
            {"purpose": "arbitrary"},
            {"purpose": []},
            {"pid": 1},
            {"path": "/"},
        ):
            request = {**self.request, **change}
            with self.subTest(change=change):
                result = oom._collect_docker_parent(request)
                self.assertNotEqual(result["availability"], "observed")
                self.assertIn(result["purpose"], {"baseline", "terminal"})
        original = oom._parent_counters

        def replace_file(reads: oom._DockerOuterRead, descriptor: int) -> tuple:
            result = original(reads, descriptor)
            path = self.parent / "memory.events"
            path.rename(self.parent / "old.events")
            path.write_text("".join(f"{key} {value}\n" for key, value in COUNTER.items()))
            return result

        with patch.object(oom, "_parent_counters", new=replace_file):
            self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")

    def test_late_population_identity_drift_symlink_and_arbitrary_request_fail(self) -> None:
        original = oom._parent_counters

        def populate(reads: oom._DockerOuterRead, descriptor: int) -> tuple:
            result = original(reads, descriptor)
            (self.parent / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            return result

        with patch.object(oom, "_parent_counters", new=populate):
            self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        (self.parent / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        self.request["sliceIdentity"] = "0:1"
        self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        self.request["sliceIdentity"] = f"{self.parent.stat().st_dev}:{self.parent.stat().st_ino}"
        (self.parent / "memory.events").unlink()
        (self.parent / "memory.events").symlink_to(self.directory / "foreign")
        self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")
        self.request["path"] = "/"
        self.assertNotEqual(oom._collect_docker_parent(self.request)["availability"], "observed")


class BackendOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.backend = DockerBackend(Path(temporary.name), ())
        self.ctx = SimpleNamespace(
            declared_launcher="systemd", oom_accounting_mode="qualification", timeout=10, checks=[]
        )

    def test_parent_request_uses_original_watchdog_and_refuses_late_validation(self) -> None:
        backend = self.backend
        backend.sudo = ("sudo", "-n")
        backend.deadline = 100
        backend._gnu_timeout_provider = ("/usr/bin/timeout", "9.1", "0" * 64)
        backend.slice_creation_intent = True
        backend.slice_identity = "12:34"
        backend._slice_identity = MagicMock(return_value="12:34")
        response = parent()
        response["bindings"]["parent"] = oom._docker_hash(["/" + backend.slice, [12, 34]])
        response["sampleWindowMonotonicNs"] = [100, 100]
        self.ctx.command = MagicMock(return_value=json.dumps(response))
        nanoseconds = patch("scripts.runtime_docker_backend.time.monotonic_ns", return_value=100)
        nanoseconds.start()
        self.addCleanup(nanoseconds.stop)
        with patch("scripts.runtime_docker_backend.time.monotonic", return_value=20):
            result = backend.parent_oom_snapshot(self.ctx, "baseline")
        self.assertEqual(result["purpose"], "baseline")
        command = self.ctx.command.call_args.args[1]
        self.assertEqual(command[:4], ["sudo", "-n", "/usr/bin/timeout", "--signal=TERM"])
        self.assertIn("--docker-parent", command)
        request = json.loads(command[-1])
        self.assertEqual(set(request), {"owner", "purpose", "sliceIdentity", "deadline"})
        self.assertEqual(request["owner"], backend.owner)
        self.assertLessEqual(request["deadline"], backend.deadline)
        self.assertNotIn("pid", request)
        wrong = copy.deepcopy(response)
        wrong["bindings"]["parent"] = "0" * 64
        self.ctx.command.return_value = json.dumps(wrong)
        with (
            patch("scripts.runtime_docker_backend.time.monotonic", return_value=20),
            self.assertRaises(DockerBackendError),
        ):
            backend.parent_oom_snapshot(self.ctx, "baseline")
        self.ctx.command.return_value = json.dumps(response)
        clock = [20]
        original = oom._parent_validate

        def late(value: object, purpose: str) -> dict:
            result = original(value, purpose)
            clock[0] = 40
            return result

        with (
            patch("scripts.runtime_docker_backend.time.monotonic", side_effect=lambda: clock[0]),
            patch("scripts.runtime_docker_backend._parent_validate", side_effect=late),
            self.assertRaises(DockerBackendError),
        ):
            backend.parent_oom_snapshot(self.ctx, "baseline")
        backend.deadline = 80
        self.ctx.command.reset_mock()
        with (
            patch("scripts.runtime_docker_backend.time.monotonic", return_value=20),
            self.assertRaises(DockerBackendError),
        ):
            backend.parent_oom_snapshot(self.ctx, "baseline")
        self.ctx.command.assert_not_called()

    def test_creation_timeout_before_first_service_still_cleans_exact_intended_slice(self) -> None:
        backend = self.backend
        backend._call = MagicMock(side_effect=TimeoutError)
        with self.assertRaises(TimeoutError):
            backend._prepare_oom_accounting(self.ctx)
        self.assertTrue(backend.slice_creation_intent)
        self.assertEqual(backend.units, {})
        backend._stop_slice = MagicMock()
        backend.stop_services(self.ctx)
        backend._stop_slice.assert_called_once_with(self.ctx)

    def test_creation_timeout_recovers_custody_and_executes_original_slice_stop(self) -> None:
        backend = self.backend
        backend.slice_creation_intent = True
        backend.slice_identity = None
        active = [True]
        calls = []
        backend._read_state = lambda _ctx, _unit: {
            "LoadState": "loaded",
            "ControlGroup": "/" + backend.slice if active[0] else "",
            "ActiveState": "active" if active[0] else "inactive",
        }
        backend._slice_identity = lambda _ctx: "12:34"

        def call(_ctx: object, _name: str, arguments: list[str], **_kwargs: object) -> str:
            calls.append(arguments)
            if arguments == ["systemctl", "stop", backend.slice]:
                active[0] = False
            return ""

        backend._call = call
        backend.stop_services(self.ctx)
        self.assertEqual(backend.slice_identity, "12:34")
        self.assertEqual(
            calls, [["systemctl", "stop", backend.slice], ["test", "!", "-e", "/sys/fs/cgroup/" + backend.slice]]
        )

    def test_creation_intent_without_bound_inode_still_requires_cgroup_absence(self) -> None:
        backend = self.backend
        backend.slice_creation_intent = True
        backend._read_state = lambda _ctx, _unit: {"LoadState": "not-found"}
        backend._call = MagicMock(side_effect=DockerBackendError("cgroup remains"))
        with self.assertRaises(DockerBackendError):
            backend.stop_services(self.ctx)
        self.assertEqual(backend._call.call_args.args[2], ["test", "!", "-e", "/sys/fs/cgroup/" + backend.slice])

    def test_bad_baseline_prevents_any_daemon_and_keeps_independent_slice_custody(self) -> None:
        backend = self.backend
        backend._call = MagicMock()
        backend._slice_identity = MagicMock(return_value="12:34")
        bad = parent()
        bad["counters"]["memory.events"]["oom_kill"] = 1
        backend.parent_oom_snapshot = MagicMock(return_value=bad)
        with self.assertRaises(ValueError):
            backend._prepare_oom_accounting(self.ctx)
        self.assertTrue(backend.slice_creation_intent)
        self.assertEqual(backend.slice_identity, "12:34")
        self.assertEqual(backend.units, {})
        backend._stop_slice = MagicMock()
        backend.stop_services(self.ctx)
        backend._stop_slice.assert_called_once()

    def test_terminal_is_after_all_units_before_slice_stop_and_remains_pending(self) -> None:
        backend = self.backend
        ledger = LedgerTests().ledger()
        ledger.defer_state({"actual": state(), "status": "passed"})
        backend.oom_ledger = ledger
        backend.resources_drained = True
        backend.slice_creation_intent = True
        backend.units = {"containerd": (), "dockerd": ()}
        events = []
        backend._stop_unit = lambda _ctx, unit: events.append(unit)
        backend.parent_oom_snapshot = lambda _ctx, purpose: events.append(purpose) or parent("terminal")
        backend._stop_slice = lambda _ctx: events.append("slice-stop")
        backend.stop_services(self.ctx)
        self.assertEqual(events, ["dockerd", "containerd", "terminal", "slice-stop"])
        self.assertTrue(ledger.reconciled)
        self.assertFalse(ledger.finalized)
        with self.assertRaises(DockerBackendError):
            backend._start(self.ctx, "late", ())
        with self.assertRaises(DockerBackendError):
            backend.run_options(())

    def test_cleanup_absence_and_retained_failures_control_finalization(self) -> None:
        backend = self.backend
        ledger = LedgerTests().ledger()
        ledger.defer_state({"actual": state(), "status": "passed"})
        backend.oom_ledger = ledger
        backend.slice_creation_intent = True
        backend._cleanup_resources = lambda _ctx: []
        backend.parent_oom_snapshot = lambda _ctx, _purpose: parent("terminal")
        backend._stop_slice = MagicMock()
        self.ctx._owned_mounts = list
        self.ctx.containers = []
        self.ctx.run_containers = set()
        backend.lifecycle_failures.append("earlier abnormal shutdown")
        with self.assertRaises(DockerBackendError):
            backend.cleanup(self.ctx)
        backend._stop_slice.assert_called_once()
        self.assertTrue(ledger.reconciled)
        self.assertFalse(ledger.finalized)

    def test_unproved_resource_drain_skips_terminal_but_still_stops_slice(self) -> None:
        backend = self.backend
        backend.oom_ledger = LedgerTests().ledger()
        backend.slice_creation_intent = True
        backend.resources_drained = False
        backend.parent_oom_snapshot = MagicMock()
        backend._stop_slice = MagicMock()
        with self.assertRaises(DockerBackendError):
            backend.stop_services(self.ctx)
        backend.parent_oom_snapshot.assert_not_called()
        backend._stop_slice.assert_called_once()

    def test_terminal_accounting_failure_never_skips_existing_slice_cleanup(self) -> None:
        backend = self.backend
        backend.oom_ledger = LedgerTests().ledger()
        backend.resources_drained = True
        backend.slice_creation_intent = True
        backend.parent_oom_snapshot = MagicMock(return_value=parent("terminal", kills=1))
        backend._stop_slice = MagicMock()
        with self.assertRaises(DockerBackendError):
            backend.stop_services(self.ctx)
        backend._stop_slice.assert_called_once()
        self.assertFalse(backend.oom_ledger.finalized)
        self.assertFalse(backend.oom_ledger.reconciled)


class _PhaseBudget:
    def __init__(self, checks: unittest.TestCase, events: list[str]) -> None:
        self.checks, self.events = checks, events
        self.active = False
        self.exits = 0

    def __enter__(self) -> Self:
        self.checks.assertFalse(self.active)
        self.active = True
        self.events.append("budget.enter")
        return self

    def __exit__(self, *_args: object) -> None:
        self.checks.assertTrue(self.active)
        self.active = False
        self.exits += 1
        self.events.append("budget.exit")

    def bind_source_archive(self, identity: tuple[int, ...]) -> None:
        self.checks.assertEqual(identity, (11, 22, 4096))

    def checkpoint(self) -> None:
        self.checks.assertTrue(self.active, "checkpoint ran outside live budget")


class _PhaseArchive:
    def __init__(self, budget: _PhaseBudget) -> None:
        self.budget = budget
        self.path = Path("owned-image.tar")
        self.identity = (11, 22, 4096)
        self.verified = 0

    def prepare(self, _ctx: object, _args: object) -> None:
        self.budget.checkpoint()

    def load_path(self) -> Path:
        self.budget.checkpoint()
        return self.path

    def verify(self) -> None:
        self.budget.checkpoint()
        self.verified += 1


class _PhaseLedger:
    def __init__(self, budget: _PhaseBudget) -> None:
        self.budget = budget
        self.images: list[dict[str, str]] = []
        self.finalized = False

    def bind_image(self, identity: dict[str, str]) -> None:
        self.budget.checkpoint()
        self.images.append(copy.deepcopy(identity))


@dataclass(frozen=True)
class _PhaseCase:
    engine: str = "podman"
    ledger: bool = False
    launcher: str = "systemd"
    phase: DockerProbePhase = DockerProbePhase.ENFORCEMENT
    architecture: str = "amd64"
    loaded_arch: str | None = None
    expected: dict[str, str] | None = None
    stage: str | None = None
    probe_failure: bool = False
    cleanup_failure: bool = False
    mode: str = "qualification"
    focused: str = "none"
    late: str | None = None
    scope_missing: bool = False
    scoped_receipt: dict | None = None


def experimental_receipt() -> dict:
    """Build actual experimental authority and cleanup labels without a normal grant."""
    return scoped_receipt(phase="enforcement")


class _PhaseScopedReceipt:
    def __init__(self, receipt: dict, *, fail: bool, late: str | None, events: list[str]) -> None:
        self.receipt, self.fail, self.late, self.events = receipt, fail, late, events

    @property
    def evidence(self) -> dict:
        if self.fail:
            message = "late scoped export sentinel"
            raise ProbeError(message)
        return copy.deepcopy(self.receipt)

    def dispose_stage(self) -> dict:
        self.events.append("stage.dispose")
        if self.late == "disposal":
            message = "stage disposal sentinel"
            raise ProbeError(message)
        if self.late == "disposal-cancel":
            raise KeyboardInterrupt
        return stage_disposal(self.receipt)


def _phase_scope(context: SimpleNamespace, budget: _PhaseBudget, case: _PhaseCase) -> None:
    """Model only scoped prerequisite preparation, inside the independent live budget."""
    budget.checkpoint()
    context.scoped_calls += 1
    if not case.scope_missing:
        receipt = (
            scoped_receipt(phase=case.phase.value, architecture=case.architecture)
            if case.scoped_receipt is None
            else case.scoped_receipt
        )
        context.backend.scoped_profile = _PhaseScopedReceipt(
            receipt, fail=case.late == "export", late=case.late, events=budget.events
        )


def _phase_cleanup(
    context: SimpleNamespace,
    budget: _PhaseBudget,
    case: _PhaseCase,
    progress: tuple[list[float], list[str], _PhaseLedger | None],
) -> None:
    """Model late cleanup/export inputs without performing any runtime operation."""
    clock, events, accounting = progress
    context.cleanup_calls += 1
    budget.checks.assertFalse(budget.active, "cleanup ran before budget exit")
    budget.checks.assertIsNone(context.runtime_disk_budget)
    events.append("cleanup")
    if case.cleanup_failure:
        message = "cleanup failure sentinel"
        raise ProbeError(message)
    if accounting is not None:
        accounting.finalized = True
    if accounting is not None:
        context.checks.append(
            {
                "name": "owned parent OOM lifecycle accounting",
                "status": "passed",
                "mode": case.mode,
                "property": "no-additional-oom-killed-process-in-bound-lifetime",
            }
        )
    if case.late == "deadline":
        clock[0] += 61
    if case.late == "check":
        context.checks.append({"name": "late admission sentinel", "status": "failed"})


class PhaseExecutionTests(unittest.TestCase):
    """Run the actual phase executor/work wrapper with only external effects mocked."""

    def execute(self, case: _PhaseCase) -> tuple[dict, SimpleNamespace, _PhaseBudget, _PhaseArchive, list[str]]:
        engine, ledger, launcher, phase, loaded_arch, expected, stage, probe_failure = (
            case.engine,
            case.ledger,
            case.launcher,
            case.phase,
            case.loaded_arch or case.architecture,
            case.expected,
            case.stage,
            case.probe_failure,
        )
        events: list[str] = []
        clock = [time.monotonic()]
        budget = _PhaseBudget(self, events)
        archive = _PhaseArchive(budget)
        accounting = _PhaseLedger(budget) if ledger else None
        identity = {
            "architecture": loaded_arch,
            "configDigest": "sha256:" + "d" * 64,
            "manifestDigest": "sha256:" + "c" * 64,
            "archiveSha256": "b" * 64,
            "sourceRevision": "a" * 40,
        }
        context = SimpleNamespace(
            outer_engine=engine,
            backend=SimpleNamespace(oom_ledger=accounting, scoped_profile=None),
            checks=[],
            observations=[],
            runtime_disk_budget=None,
            cleanup_calls=0,
            probe_calls=0,
            scoped_calls=0,
        )

        def prepare() -> dict[str, str]:
            context.checks.append({"name": "prepare fixture", "status": "passed"})
            return {
                "engine": engine,
                "clientVersion": "Docker version 29.8.2" if engine == "docker" else "podman version 5.4.2",
                "serverVersion": "29.8.2",
                "containerdVersion": "containerd 2.2.0",
                "systemdVersion": "systemd 259",
                "rootMode": "rootful",
                "endpoint": "private-unix",
                "storage": "invocation-owned",
            }

        def load(path: Path) -> dict[str, str]:
            self.assertEqual(path, archive.path)
            self.assertTrue(budget.active, "archive load ran outside live budget")
            context.checks.append({"name": "load fixture", "status": "passed"})
            return copy.deepcopy(identity)

        def probe(actual: object, _profile: object, *positional: object, **keywords: object) -> None:
            self.assertIs(actual, context)
            self.assertTrue(budget.active, "phase probe ran outside live budget")
            self.assertIs(context.runtime_disk_budget, budget)
            context.probe_calls += 1
            events.append("probe")
            if phase is DockerProbePhase.CLEAN_CONTROL:
                self.assertEqual(positional, (phase,))
            else:
                self.assertEqual(keywords["archive"], archive.path)
            self.assertTrue(keywords["allow_privileged"])
            self.assertFalse(keywords["skip_nested"])
            if probe_failure:
                message = "probe failure sentinel"
                raise ProbeError(message)
            context.checks.append({"name": "required fixture probe", "status": "passed"})

        context.prepare, context.load_archive = prepare, load
        context.cleanup = lambda: _phase_cleanup(context, budget, case, (clock, events, accounting))
        context.bind_guest_profile = lambda _profile: None
        context.backend.prepare_scoped_profile = lambda *_args: _phase_scope(context, budget, case)
        plan = runtime_tests._DockerPhasePlan(
            args=argparse.Namespace(
                outer_engine=engine,
                timeout=45,
                oom_accounting_mode=case.mode,
                focused_runtime=case.focused,
                allow_privileged=True,
                active_userns_stage=stage,
                evidence="fixture-evidence.json",
            ),
            metadata={
                "name": "docker-29-conformance-rootless",
                "tests": {"docker": {"launcher": launcher, "mode": "rootless", "outerPrivilege": "privileged"}},
            },
            architecture=case.architecture,
            use_sudo=False,
            archive=archive,
            phase=phase,
            deadline=clock[0] + 60,
            cancellation=runtime_tests._PairCancellation(),
            expected_identity=expected,
        )
        fixture_context = (case.scoped_receipt or {}).get("workflowContext")
        if fixture_context is None:
            fixture_context = scoped_receipt(phase=case.phase.value, architecture=case.architecture)["workflowContext"]
        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_REPOSITORY": fixture_context["repository"],
                    "GITHUB_EVENT_NAME": fixture_context["event"],
                    "GITHUB_REF": fixture_context["ref"],
                    "GITHUB_WORKFLOW_REF": fixture_context["workflowRef"],
                    "GITHUB_WORKFLOW_SHA": fixture_context["workflow"],
                    "GITHUB_JOB": fixture_context["job"],
                    "GITHUB_RUN_ID": fixture_context["run"],
                    "GITHUB_RUN_ATTEMPT": fixture_context["attempt"],
                    "GITHUB_SHA": fixture_context["candidate"],
                    "ImageOS": fixture_context["imageOS"],
                    "ImageVersion": fixture_context["imageVersion"],
                },
                clear=True,
            ),
            patch("scripts.runtime_tests.time.monotonic", side_effect=lambda: clock[0]),
            patch("scripts.evidence_gate._active_validation_request", return_value="docker-rootless-diagnostic"),
            patch.object(runtime_tests, "RuntimeContext", return_value=context),
            patch.object(runtime_tests, "IsolatedStoreDiskBudget", return_value=budget),
            patch("scripts.runtime_docker._run_docker_phase", side_effect=probe) as control,
            patch.object(runtime_tests, "_docker", side_effect=probe) as enforcement,
        ):
            result = runtime_tests._execute_docker_phase(plan)
        self.assertEqual(control.call_count + enforcement.call_count, context.probe_calls)
        return result, context, budget, archive, events

    def test_authored_experimental_fixtures_bind_their_own_context_under_hosted_ci(self) -> None:
        ambient = {
            "GITHUB_SHA": "f" * 40,
            "GITHUB_WORKFLOW_SHA": "f" * 40,
            "GITHUB_RUN_ID": "999",
            "GITHUB_RUN_ATTEMPT": "9",
            "GITHUB_JOB": "validate",
            "ImageVersion": "20270101.999.9",
        }
        with patch.dict(os.environ, ambient):
            for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
                result, *_rest = self.execute(
                    _PhaseCase(engine="docker", ledger=True, stage="owned-stage", phase=phase)
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["qualification"], "none")
                self.assertEqual(result["scopedProfile"]["binding"]["candidate"], "a" * 40)
            self.assertEqual(os.environ["GITHUB_SHA"], ambient["GITHUB_SHA"])
            self.assertEqual(dict(os.environ)["ImageVersion"], ambient["ImageVersion"])
            pair, _events = PairAuthorityTests().pair()
            self.assertEqual(pair["status"], "passed")
            self.assertEqual(pair["qualification"], "none")

    def test_nonledger_podman_and_direct_routes_execute_exactly_once_inside_budget(self) -> None:
        for engine, launcher, phase in (
            ("podman", "systemd", DockerProbePhase.CLEAN_CONTROL),
            ("podman", "systemd", DockerProbePhase.ENFORCEMENT),
            ("podman", "direct", DockerProbePhase.ENFORCEMENT),
            ("docker", "direct", DockerProbePhase.ENFORCEMENT),
        ):
            with self.subTest(engine=engine, launcher=launcher, phase=phase):
                result, context, budget, archive, events = self.execute(
                    _PhaseCase(engine=engine, launcher=launcher, phase=phase)
                )
                self.assertEqual(context.probe_calls, 1)
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["qualification"], "complete")
                self.assertTrue(result["cleanupVerified"])
                self.assertEqual(context.cleanup_calls, 1)
                self.assertEqual(archive.verified, 1)
                self.assertEqual(budget.exits, 1)
                self.assertEqual(events, ["budget.enter", "probe", "budget.exit", "cleanup"])

    def test_ledger_bind_and_both_probe_routes_keep_budget_live_until_return(self) -> None:
        for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
            with self.subTest(phase=phase):
                result, context, budget, _archive, events = self.execute(
                    _PhaseCase(engine="docker", ledger=True, phase=phase, stage="owned-stage")
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["qualification"], "none")
                self.assertEqual(result["oomAccountingStatus"], "complete")
                self.assertEqual(context.probe_calls, 1)
                self.assertEqual(context.backend.oom_ledger.images, [result["imageIdentity"]])
                self.assertTrue(context.backend.oom_ledger.finalized)
                self.assertEqual(budget.exits, 1)
                self.assertEqual(events, ["budget.enter", "probe", "budget.exit", "cleanup"])

    def test_wrong_architecture_fails_before_probe_or_qualification_on_every_route(self) -> None:
        for engine, ledger, launcher in (
            ("podman", False, "systemd"),
            ("docker", False, "direct"),
            ("docker", True, "systemd"),
        ):
            with self.subTest(engine=engine, ledger=ledger):
                result, context, budget, _archive, _events = self.execute(
                    _PhaseCase(engine=engine, ledger=ledger, launcher=launcher, loaded_arch="arm64")
                )
                self.assertEqual(result["status"], "failed")
                self.assertIn("archive architecture differs", result["error"])
                self.assertNotEqual(result["qualification"], "complete")
                self.assertEqual(context.probe_calls, 0)
                self.assertEqual(context.cleanup_calls, 1)
                self.assertFalse(budget.active)

    def test_control_identity_mismatch_fails_before_probe_or_false_qualification(self) -> None:
        for engine, ledger, launcher in (
            ("podman", False, "systemd"),
            ("docker", False, "direct"),
            ("docker", True, "systemd"),
        ):
            with self.subTest(engine=engine, ledger=ledger):
                expected = {"architecture": "amd64", "configDigest": "sha256:" + "b" * 64}
                result, context, budget, _archive, _events = self.execute(
                    _PhaseCase(engine=engine, ledger=ledger, launcher=launcher, expected=expected)
                )
                self.assertEqual(result["status"], "failed")
                self.assertIn("archive identities differ", result["error"])
                self.assertNotEqual(result["qualification"], "complete")
                self.assertEqual(context.probe_calls, 0)
                self.assertEqual(context.cleanup_calls, 1)
                self.assertFalse(budget.active)

    def test_inapplicable_podman_stage_cannot_skip_validation_or_qualify(self) -> None:
        result, context, budget, _archive, _events = self.execute(_PhaseCase(stage="unusable-stage"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("requires the explicit Docker backend", result["error"])
        self.assertNotEqual(result["qualification"], "complete")
        self.assertEqual(context.probe_calls, 0)
        self.assertEqual(context.scoped_calls, 0)
        self.assertEqual(context.cleanup_calls, 1)
        self.assertFalse(budget.active)

    def test_applicable_docker_stage_is_prepared_while_budget_is_active(self) -> None:
        result, context, _budget, _archive, _events = self.execute(
            _PhaseCase(engine="docker", ledger=True, stage="owned-stage")
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(context.scoped_calls, 1)
        self.assertEqual(context.probe_calls, 1)

    def test_work_and_cleanup_failures_are_both_retained_after_budget_exit(self) -> None:
        for ledger in (False, True):
            for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
                with self.subTest(ledger=ledger, phase=phase):
                    result, context, budget, _archive, events = self.execute(
                        _PhaseCase(
                            engine="docker",
                            ledger=ledger,
                            phase=phase,
                            stage="owned-stage",
                            probe_failure=True,
                            cleanup_failure=True,
                        )
                    )
                    self.assertEqual(result["status"], "failed")
                    self.assertIn("probe failure sentinel", result["error"])
                    self.assertIn("cleanup failure sentinel", result["cleanupError"])
                    self.assertNotEqual(result["qualification"], "complete")
                    self.assertFalse(result["cleanupVerified"])
                    self.assertEqual(context.probe_calls, 1)
                    self.assertEqual(context.cleanup_calls, 1)
                    self.assertFalse(budget.active)
                    self.assertEqual(events, ["budget.enter", "probe", "budget.exit", "cleanup"])

    def test_cleanup_failure_cannot_finalize_valid_ledger_or_nonledger_work(self) -> None:
        for ledger in (False, True):
            with self.subTest(ledger=ledger):
                result, context, budget, _archive, _events = self.execute(
                    _PhaseCase(engine="docker", ledger=ledger, stage="owned-stage", cleanup_failure=True)
                )
                self.assertEqual(context.probe_calls, 1)
                self.assertEqual(result["status"], "failed")
                self.assertIn("cleanup failure sentinel", result["cleanupError"])
                self.assertNotEqual(result["qualification"], "complete")
                self.assertFalse(result["cleanupVerified"])
                self.assertFalse(budget.active)
                if ledger:
                    self.assertFalse(context.backend.oom_ledger.finalized)


class ProducerAuthorityTests(unittest.TestCase):
    """Late actual producer outcomes cannot be promoted by workload mode."""

    execute = PhaseExecutionTests.execute

    def test_experimental_accounting_success_retains_none_at_phase_boundary(self) -> None:
        result, context, _budget, _archive, _events = self.execute(
            _PhaseCase(engine="docker", ledger=True, stage="owned-stage", focused="mandatory-accounting")
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["oomAccountingMode"], "qualification")
        self.assertEqual(result["oomAccountingStatus"], "complete")
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(result["scopedProfile"], experimental_receipt())
        self.assertEqual(context.oom_accounting_mode, "qualification")

    def test_missing_normal_prerequisite_does_not_become_authority_without_stage(self) -> None:
        result, _context, _budget, _archive, _events = self.execute(_PhaseCase(engine="docker", ledger=True))
        self.assertEqual(result["status"], "failed")
        self.assertNotEqual(result["oomAccountingStatus"], "complete")
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(result["prerequisiteAuthority"], "unavailable")

    def test_actual_late_export_deadline_and_check_failures_cannot_complete(self) -> None:
        for late in ("export", "deadline", "check"):
            with self.subTest(late=late):
                result, _context, _budget, _archive, _events = self.execute(
                    _PhaseCase(engine="docker", ledger=True, stage="owned-stage", late=late)
                )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertNotEqual(result["oomAccountingStatus"], "complete")
                if late == "export":
                    self.assertIn("late scoped export sentinel", result["cleanupError"])

    def test_missing_or_unknown_requested_prerequisite_cannot_pass_focused_work(self) -> None:
        for change in (
            {"scope_missing": True},
            {"scoped_receipt": {}},
            {"scoped_receipt": {"qualification": "complete"}},
        ):
            with self.subTest(change=change):
                result, _context, _budget, _archive, _events = self.execute(
                    _PhaseCase(
                        engine="docker", ledger=True, stage="owned-stage", focused="mandatory-accounting", **change
                    )
                )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertNotEqual(result["oomAccountingStatus"], "complete")

    def test_focused_selector_never_infers_or_changes_workload_from_stage(self) -> None:
        result, context, _budget, _archive, _events = self.execute(
            _PhaseCase(
                engine="docker", ledger=True, stage="owned-stage", focused="mandatory-accounting", mode="diagnostic"
            )
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(context.oom_accounting_mode, "diagnostic")
        self.assertEqual(context.probe_calls, 0)

    def test_actual_maintained_phases_validate_root_facts_and_dispose_after_cleanup(self) -> None:
        for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
            with self.subTest(phase=phase):
                result, _context, _budget, _archive, events = self.execute(
                    _PhaseCase(
                        engine="docker",
                        ledger=True,
                        stage="owned-stage",
                        phase=phase,
                        scoped_receipt=scoped_receipt(purpose="maintained-prerequisite", phase=phase.value),
                    )
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["qualification"], "complete")
                self.assertEqual(result["oomAccountingStatus"], "complete")
                self.assertEqual(result["prerequisiteAuthority"], "maintained-prerequisite")
                if phase is DockerProbePhase.ENFORCEMENT:
                    self.assertEqual(events[-2:], ["cleanup", "stage.dispose"])
                    self.assertTrue(result["stageDisposal"]["stageDisposed"])
                else:
                    self.assertNotIn("stageDisposal", result)
                    self.assertNotIn("stage.dispose", events)

    def test_maintained_late_failures_never_publish_completion(self) -> None:
        for late in ("export", "deadline", "check", "disposal", "disposal-cancel"):
            with self.subTest(late=late):
                result, _context, _budget, _archive, _events = self.execute(
                    _PhaseCase(
                        engine="docker",
                        ledger=True,
                        stage="owned-stage",
                        late=late,
                        scoped_receipt=scoped_receipt(purpose="maintained-prerequisite", phase="enforcement"),
                    )
                )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertNotEqual(result["oomAccountingStatus"], "complete")


class _PairArchiveFixture:
    def __init__(self, path: Path, late: str | None, clock: list[float], events: list[str]) -> None:
        self.path, self.late, self.clock, self.events = path, late, clock, events
        self.identity = (11, 22, 4096)

    def verify(self) -> None:
        self.events.append("verify")
        if self.late == "verify":
            message = "late archive verification sentinel"
            raise ProbeError(message)

    def close(self) -> None:
        self.events.append("close")
        if self.late == "deadline":
            self.clock[0] += runtime_tests.SYSTEMD_PAIR_SECONDS + 1
        if self.late == "close":
            message = "late archive close sentinel"
            raise ProbeError(message)


class _LatePairWriter:
    def __init__(self, stream: object, clock: list[float]) -> None:
        self.stream, self.clock = stream, clock
        self.delayed = False

    def __enter__(self) -> Self:
        self.stream.__enter__()
        return self

    def __exit__(self, *exception: object) -> object:
        return self.stream.__exit__(*exception)

    def __getattr__(self, name: str) -> object:
        return getattr(self.stream, name)

    def write(self, body: bytes) -> int:
        result = self.stream.write(body)
        if not self.delayed:
            self.clock[0] += runtime_tests.SYSTEMD_PAIR_SECONDS + 1
            self.delayed = True
        return result


class _PairOpenFixture:
    def __init__(self, target: Path, clock: list[float], *, late: bool) -> None:
        self.original, self.target, self.clock, self.late = Path.open, target, clock, late

    def __call__(self, path: Path, *arguments: object, **keywords: object) -> object:
        stream = self.original(path, *arguments, **keywords)
        candidate = path.name == "record" and path.parent.name.startswith(".runtime-evidence-")
        return _LatePairWriter(stream, self.clock) if self.late and candidate else stream


class PairAuthorityTests(unittest.TestCase):
    execute = PhaseExecutionTests.execute

    def pair(
        self,
        *,
        engine: str = "docker",
        late: str | None = None,
        mixed: bool = False,
        maintained: bool = False,
        architecture: str = "amd64",
    ) -> tuple[dict, list[str]]:
        actual = []
        for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
            result, _ctx, _budget, _archive, _events = self.execute(
                _PhaseCase(
                    engine=engine,
                    architecture=architecture,
                    ledger=engine == "docker",
                    phase=phase,
                    stage="owned-stage" if engine == "docker" else None,
                    focused="mandatory-accounting" if engine == "docker" and not maintained else "none",
                    scoped_receipt=scoped_receipt(
                        purpose="maintained-prerequisite", phase=phase.value, architecture=architecture
                    )
                    if maintained
                    else None,
                )
            )
            actual.append(result)
        if mixed:
            actual[-1]["qualification"] = "none"
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root_path = Path(directory)
            clock = [1000.0]
            archive = _PairArchiveFixture(root_path / "image.tar", late, clock, events)
            args = argparse.Namespace(
                oom_accounting_mode="qualification",
                outer_engine=engine,
                focused_runtime="mandatory-accounting" if engine == "docker" and not maintained else "none",
                active_userns_stage="owned-stage" if engine == "docker" else None,
                skip_nested=False,
                allow_privileged=True,
                archive="caller.tar",
                timeout=45,
                evidence=str(root_path / "evidence.json"),
            )
            metadata = {
                "name": "docker-29-conformance-rootless",
                "tests": {"docker": {"launcher": "systemd", "mode": "rootless"}},
            }
            evidence = {
                "image": "docker-29-conformance-rootless",
                "runId": "1",
                "runAttempt": "2",
                "producingJob": actual[0]["producingJob"],
                "status": "failed",
                "checks": [],
                "host": {"outerEngineSelection": "profile"},
                "architecture": architecture,
            }
            open_record = _PairOpenFixture(Path(args.evidence), clock, late=late == "write")

            def bound_open(path: Path, *arguments: object, **keywords: object) -> object:
                return open_record(path, *arguments, **keywords)

            with (
                patch.object(Path, "open", new=bound_open),
                patch.object(runtime_tests, "_ArchiveSnapshot", return_value=archive),
                patch.object(runtime_tests, "_execute_docker_phase", side_effect=actual),
                patch("scripts.runtime_tests.time.monotonic", side_effect=lambda: clock[0]),
            ):
                result = runtime_tests._run_systemd_pair(args, metadata, evidence, use_sudo=False)
            self.assertEqual(json.loads(Path(args.evidence).read_text()), result)
        return result, events

    def test_actual_pair_aggregates_complete_experimental_accounting_without_native_authority(self) -> None:
        result, _events = self.pair()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["oomAccountingMode"], "qualification")
        self.assertEqual(result["oomAccountingStatus"], "complete")
        self.assertEqual(result["qualification"], "none")
        self.assertTrue(all(phase["qualification"] == "none" for phase in result["phases"]))
        self.assertTrue(
            all(phase["scopedProfile"] == scoped_receipt(phase=phase["phase"]) for phase in result["phases"])
        )

    def test_actual_pair_late_archive_and_deadline_failures_clear_all_completion_labels(self) -> None:
        for late in ("verify", "close", "deadline"):
            with self.subTest(late=late):
                result, events = self.pair(late=late)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertNotEqual(result["oomAccountingStatus"], "complete")
                self.assertTrue(all(phase["qualification"] == "none" for phase in result["phases"]))
                self.assertTrue(all(phase["oomAccountingStatus"] != "complete" for phase in result["phases"]))
                self.assertIn("close", events)

    def test_supported_podman_pair_retains_normal_authority_but_mixed_pair_cannot_complete(self) -> None:
        result, _events = self.pair(engine="podman")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["qualification"], "complete")
        self.assertFalse(result["oomAccountingRequired"])
        mixed, _events = self.pair(engine="podman", mixed=True)
        self.assertEqual(mixed["qualification"], "none")
        self.assertTrue(all(phase["qualification"] == "none" for phase in mixed["phases"]))

    def test_actual_maintained_pair_reaches_canonical_authority_after_both_phases(self) -> None:
        result, _events = self.pair(maintained=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["qualification"], "complete")
        self.assertEqual(result["oomAccountingStatus"], "complete")
        with patch.dict(os.environ, {}, clear=True):
            require_ordinary_runtime_authority(result, "docker", {"launcher": "systemd", "mode": "rootless"})

    def test_actual_maintained_pair_late_archive_deadline_and_writer_failures_revoke_authority(self) -> None:
        for late in ("verify", "close", "deadline", "write"):
            with self.subTest(late=late):
                result, _events = self.pair(maintained=True, late=late)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertTrue(all(phase["qualification"] == "none" for phase in result["phases"]))


class LatePairEvidenceTests(unittest.TestCase):
    execute = PhaseExecutionTests.execute
    pair = PairAuthorityTests.pair

    def test_actual_final_evidence_write_cannot_leave_complete_authority_after_deadline(self) -> None:
        for engine in ("docker", "podman"):
            with self.subTest(engine=engine):
                result, _events = self.pair(engine=engine, late="write")
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["qualification"], "none")
                self.assertTrue(all(phase["qualification"] == "none" for phase in result["phases"]))
                self.assertNotEqual(result.get("oomAccountingStatus"), "complete")


class _PairPublicationFault:
    def __init__(self, target: Path, clock: list[float], fault: str) -> None:
        self.target, self.clock, self.fault = target, clock, fault
        self.original_open, self.original_link = Path.open, os.link
        self.events: list[str] = []
        self.retired_descriptor: int | None = None
        self.reused_descriptor: int | None = None

    def open(self, path: Path, *arguments: object, **keywords: object) -> object:
        stream = self.original_open(path, *arguments, **keywords)
        if (
            path.name == "record"
            and path.parent.name.startswith(".runtime-evidence-")
            and arguments
            and arguments[0] == "xb"
        ):
            return _PairPublicationWriter(stream, self)
        return stream

    def link(self, source: Path, target: Path, **keywords: object) -> None:
        if not self.events or self.events[-1] != "data-closed":
            message = "publication preceded final data descriptor close"
            raise AssertionError(message)
        self.closed_data_descriptors(source)
        if self.fault == "publication-before-error":
            message = "publication error before creating a name"
            raise OSError(message)
        self.original_link(source, target, **keywords)
        self.events.append("published")
        self.after_publication(source, target)

    def closed_data_descriptors(self, source: Path) -> None:
        identity = source.stat()
        for descriptor in Path("/proc/self/fd").iterdir():
            try:
                live = os.fstat(int(descriptor.name))
            except OSError:
                continue
            if (live.st_dev, live.st_ino) == (identity.st_dev, identity.st_ino):
                message = "publication retained an open data descriptor"
                raise AssertionError(message)

    def after_publication(self, source: Path, target: Path) -> None:
        if self.fault == "publication-replacement":
            target.unlink()
            target.write_bytes(b"replacement sentinel\n")
        elif self.fault in {"anchor-replacement", "anchor-symlink"}:
            source.unlink()
            if self.fault == "anchor-symlink":
                source.symlink_to(target.parent / "sentinel")
            else:
                source.write_bytes(b"private replacement sentinel\n")
        if self.fault in {
            "publication-deadline",
            "publication-replacement",
            "recovery-close",
            "recovery-write",
            "anchor-replacement",
            "anchor-symlink",
        }:
            self.clock[0] = 11.0
        elif self.fault == "publication-error":
            message = "publication returned an error after creating the name"
            raise OSError(message)
        elif self.fault == "publication-cancel":
            raise KeyboardInterrupt


class _PairPublicationWriter:
    def __init__(self, stream: object, fixture: _PairPublicationFault) -> None:
        self.stream, self.fixture = stream, fixture

    def __enter__(self) -> Self:
        self.stream.__enter__()
        return self

    def __getattr__(self, name: str) -> object:
        return getattr(self.stream, name)

    def write(self, body: bytes) -> int:
        return self.stream.write(body[:-1] if self.fixture.fault == "partial-write" else body)

    def flush(self) -> None:
        self.stream.flush()
        if self.fixture.fault == "flush":
            message = "evidence flush failure"
            raise OSError(message)

    def __exit__(self, *exception: object) -> object:
        retired = self.stream.fileno()
        result = self.stream.__exit__(*exception)
        self.fixture.events.append("data-closed")
        if self.fixture.fault == "close-reused":
            self.fixture.retired_descriptor = retired
            self.fixture.reused_descriptor = os.open(self.fixture.target.parent / "sentinel", os.O_RDWR)
            message = "final data descriptor close failed after number reuse"
            raise OSError(message)
        if self.fixture.fault == "close-error":
            message = "final data descriptor close failed after retirement"
            raise OSError(message)
        if self.fixture.fault == "close-cancel":
            raise KeyboardInterrupt
        if self.fixture.fault == "close-deadline":
            self.fixture.clock[0] = 11.0
        elif self.fixture.fault == "replacement-before-publication":
            self.fixture.target.write_bytes(b"replacement sentinel\n")
        return result


class _PairRetirementFault:
    def __init__(self, sentinel: Path, fault: str) -> None:
        self.sentinel, self.fault = sentinel, fault
        self.real_close, self.real_write = os.close, os.write
        self.retired: list[int] = []
        self.reused: list[int] = []

    def close(self, descriptor: int) -> None:
        self.retired.append(descriptor)
        self.real_close(descriptor)
        if self.fault == "recovery-close":
            self.reused.append(os.open(self.sentinel, os.O_RDWR))
            message = "failure-only close error after number reuse"
            raise OSError(message)

    def write(self, descriptor: int, body: bytes) -> int:
        return self.real_write(descriptor, body[:16] if self.fault == "recovery-write" else body)


class PairEvidenceRetirementTests(unittest.TestCase):
    execute = PhaseExecutionTests.execute
    pair = PairAuthorityTests.pair

    def failed_authority(self, evidence: dict) -> None:
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["qualification"], "none")
        self.assertNotEqual(evidence.get("oomAccountingStatus"), "complete")
        for phase in evidence["phases"]:
            self.assertEqual(phase["qualification"], "none")
            self.assertNotEqual(phase.get("oomAccountingStatus"), "complete")

    def write(
        self, target: Path, evidence: dict, fault: str, *, fixture: _PairPublicationFault | None = None
    ) -> _PairPublicationFault:
        fixture = fixture or _PairPublicationFault(target, [1.0], fault)

        def bound_open(path: Path, *arguments: object, **keywords: object) -> object:
            return fixture.open(path, *arguments, **keywords)

        with (
            patch.object(Path, "open", new=bound_open),
            patch.object(runtime_tests.os, "link", side_effect=fixture.link),
            patch.object(runtime_tests.time, "monotonic", side_effect=lambda: fixture.clock[0]),
        ):
            runtime_tests._write_pair_evidence(target, evidence, 10.0)
        return fixture

    def test_final_close_error_or_deadline_never_publishes_passing_authority(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("close-error", "close-deadline"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    evidence, _events = self.pair(engine=engine)
                    target = Path(directory) / "evidence.json"
                    if fault == "close-error":
                        with self.assertRaisesRegex(OSError, "final data descriptor close"):
                            self.write(target, evidence, fault)
                        self.assertFalse(target.exists())
                    else:
                        self.write(target, evidence, fault)
                        self.failed_authority(json.loads(target.read_text()))
                    self.failed_authority(evidence)

    def test_partial_write_and_flush_fail_before_publication(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("partial-write", "flush"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    evidence, _events = self.pair(engine=engine)
                    target = Path(directory) / "evidence.json"
                    with self.assertRaises(OSError):
                        self.write(target, evidence, fault)
                    self.assertFalse(target.exists())
                    self.failed_authority(evidence)

    def test_exclusive_publication_preserves_historical_and_replacement_outputs(self) -> None:
        for fault in ("historical", "replacement-before-publication"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                evidence, _events = self.pair(engine="podman")
                target = Path(directory) / "evidence.json"
                old = b'{"sourceRevision":"historical-source","runId":"old-run"}\n'
                if fault == "historical":
                    target.write_bytes(old)
                with self.assertRaises(FileExistsError):
                    self.write(target, evidence, fault)
                self.assertEqual(target.read_bytes(), old if fault == "historical" else b"replacement sentinel\n")
                self.failed_authority(evidence)

    def test_late_publication_invalidates_only_the_private_bound_inode(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("publication-deadline", "publication-error", "publication-replacement"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    evidence, _events = self.pair(engine=engine)
                    target = Path(directory) / "evidence.json"
                    if fault == "publication-error":
                        with self.assertRaisesRegex(OSError, "publication returned an error"):
                            self.write(target, evidence, fault)
                    else:
                        self.write(target, evidence, fault)
                    self.failed_authority(evidence)
                    if fault == "publication-replacement":
                        self.assertEqual(target.read_bytes(), b"replacement sentinel\n")
                    else:
                        self.failed_authority(json.loads(target.read_text()))

    def test_success_has_no_open_data_descriptor_after_exclusive_publication(self) -> None:
        for engine in ("podman", "docker"):
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as directory:
                evidence, _events = self.pair(engine=engine)
                target = Path(directory) / "evidence.json"
                fixture = self.write(target, evidence, "none")
                self.assertEqual(fixture.events, ["data-closed", "published"])
                self.assertEqual(json.loads(target.read_text()), evidence)
                anchors = list(Path(directory).glob(".runtime-evidence-*"))
                self.assertEqual(len(anchors), 1)
                self.assertEqual(stat.S_IMODE(anchors[0].stat().st_mode), 0o700)
                self.assertEqual(target.stat().st_ino, (anchors[0] / "record").stat().st_ino)
                self.assertEqual(target.stat().st_nlink, 2)
                self.assertEqual(list(Path(directory).glob("*.json")), [target])
                stored = _read(target)
                configuration = {"launcher": "systemd", "mode": "rootless"}
                if engine == "docker":
                    with self.assertRaises(EvidenceError):
                        require_ordinary_runtime_authority(stored, "docker", configuration)
                else:
                    require_ordinary_runtime_authority(stored, "podman", configuration)

    def test_close_error_never_reuses_a_retired_descriptor_number(self) -> None:
        for engine in ("podman", "docker"):
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as directory:
                evidence, _events = self.pair(engine=engine)
                target = Path(directory) / "evidence.json"
                sentinel = target.parent / "sentinel"
                sentinel.write_bytes(b"unrelated descriptor sentinel\n")
                fixture = _PairPublicationFault(target, [1.0], "close-reused")
                try:
                    with self.assertRaisesRegex(OSError, "after number reuse"):
                        self.write(target, evidence, fixture.fault, fixture=fixture)
                    self.assertEqual(fixture.retired_descriptor, fixture.reused_descriptor)
                    self.assertIsNotNone(fixture.reused_descriptor)
                    self.assertEqual(os.fstat(fixture.reused_descriptor).st_ino, sentinel.stat().st_ino)
                    self.assertEqual(sentinel.read_bytes(), b"unrelated descriptor sentinel\n")
                    self.assertFalse(target.exists())
                    self.failed_authority(evidence)
                finally:
                    if fixture.reused_descriptor is not None:
                        os.close(fixture.reused_descriptor)

    def test_failure_only_retirement_has_no_retry_or_passing_artifact(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("recovery-close", "recovery-write"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    evidence, _events = self.pair(engine=engine)
                    target = Path(directory) / "evidence.json"
                    sentinel = target.parent / "sentinel"
                    sentinel.write_bytes(b"unrelated descriptor sentinel\n")
                    retirement = _PairRetirementFault(sentinel, fault)
                    try:
                        with (
                            patch.object(runtime_tests.os, "close", side_effect=retirement.close),
                            patch.object(runtime_tests.os, "write", side_effect=retirement.write),
                            self.assertRaisesRegex(ProbeError, "uncertain; failed producer"),
                        ):
                            self.write(target, evidence, fault)
                        self.assertEqual(len(retirement.retired), 1)
                        if retirement.reused:
                            self.assertEqual(retirement.reused, retirement.retired)
                            self.assertEqual(os.fstat(retirement.reused[0]).st_ino, sentinel.stat().st_ino)
                        self.assertEqual(sentinel.read_bytes(), b"unrelated descriptor sentinel\n")
                        self.failed_authority(evidence)
                        if fault == "recovery-write":
                            with self.assertRaises(json.JSONDecodeError):
                                json.loads(target.read_text())
                        else:
                            self.failed_authority(json.loads(target.read_text()))
                    finally:
                        for descriptor in retirement.reused:
                            retirement.real_close(descriptor)

    def test_cancellation_clears_authority_before_or_after_publication(self) -> None:
        for fault in ("close-cancel", "publication-cancel"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                evidence, _events = self.pair(engine="podman")
                target = Path(directory) / "evidence.json"
                with self.assertRaises(KeyboardInterrupt):
                    self.write(target, evidence, fault)
                self.failed_authority(evidence)
                if target.exists():
                    self.failed_authority(_read(target))

    def test_lost_private_anchor_is_explicit_uncertainty_without_touching_sentinels(self) -> None:
        for fault in ("anchor-replacement", "anchor-symlink"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                evidence, _events = self.pair(engine="podman")
                target = Path(directory) / "evidence.json"
                sentinel = target.parent / "sentinel"
                sentinel.write_bytes(b"unrelated private sentinel\n")
                with self.assertRaisesRegex(ProbeError, "uncertain; failed producer"):
                    self.write(target, evidence, fault)
                self.failed_authority(evidence)
                self.assertEqual(sentinel.read_bytes(), b"unrelated private sentinel\n")
                anchor = next(Path(directory).glob(".runtime-evidence-*")) / "record"
                self.assertEqual(
                    anchor.read_bytes(),
                    b"unrelated private sentinel\n" if fault == "anchor-symlink" else b"private replacement sentinel\n",
                )
                self.assertIn("cleanupError", evidence)

    def test_existing_output_refusal_creates_no_accumulating_private_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence.json"
            first, _events = self.pair(engine="podman")
            self.write(target, first, "none")
            original = target.read_bytes()
            for _attempt in range(3):
                evidence, _events = self.pair(engine="podman")
                with self.assertRaisesRegex(FileExistsError, "not this producer's new report"):
                    self.write(target, evidence, "none")
                self.failed_authority(evidence)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(len(list(Path(directory).glob(".runtime-evidence-*"))), 1)

    def test_unlinked_failed_candidates_do_not_accumulate_over_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence.json"
            evidence, _events = self.pair(engine="podman")
            with self.assertRaisesRegex(OSError, "before creating a name"):
                self.write(target, evidence, "publication-before-error")
            self.failed_authority(evidence)
            anchor = next(Path(directory).glob(".runtime-evidence-*")) / "record"
            retained = anchor.read_bytes()
            self.failed_authority(_read(anchor))
            for _attempt in range(3):
                evidence, _events = self.pair(engine="podman")
                with self.assertRaisesRegex(FileExistsError, "custody already exists"):
                    self.write(target, evidence, "none")
                self.failed_authority(evidence)
                self.assertFalse(target.exists())
                self.assertEqual(anchor.read_bytes(), retained)
                self.assertEqual(len(list(Path(directory).glob(".runtime-evidence-*"))), 1)

    def test_actual_recursive_evidence_loaders_read_the_public_report_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "runtime-evidence"
            output.mkdir()
            target = output / "fixture-amd64.json"
            evidence, _events = self.pair(engine="podman")
            evidence.update(image="fixture", architecture="amd64")
            self.write(target, evidence, "none")
            self.assertEqual(release_evidence._attached_records(root, "*.json", "fixture", {"amd64"}), [evidence])
            builds, runtime = maintenance._load_evidence(root)
            self.assertEqual(builds, {})
            self.assertEqual(runtime, {"fixture": [evidence]})

    def test_private_name_collision_never_adopts_or_deletes_existing_custody(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence.json"
            custody = target.parent / (".runtime-evidence-" + "0" * 32)
            custody.mkdir(mode=0o700)
            sentinel = custody / "sentinel"
            sentinel.write_bytes(b"unrelated custody sentinel\n")
            evidence, _events = self.pair(engine="podman")
            with (
                patch.object(runtime_tests.uuid, "uuid5", return_value=SimpleNamespace(hex="0" * 32)),
                self.assertRaises(FileExistsError),
            ):
                self.write(target, evidence, "none")
            self.failed_authority(evidence)
            self.assertFalse(target.exists())
            self.assertEqual(sentinel.read_bytes(), b"unrelated custody sentinel\n")


class _PairCustodyFault(_PairPublicationFault):
    def __init__(self, target: Path, clock: list[float], fault: str) -> None:
        super().__init__(target, clock, fault)
        self.state: dict[str, Path] = {}

    def open(self, path: Path, *arguments: object, **keywords: object) -> object:
        stream = self.original_open(path, *arguments, **keywords)
        if path.name == "record" and arguments and arguments[0] == "xb":
            return _PairCustodyWriter(stream, self, path)
        return stream

    def replace(self, path: Path) -> None:
        owned, root = path.parent, self.target.parent
        if self.fault in {"directory", "directory-symlink"}:
            moved = root / "original-owned-directory"
            owned.rename(moved)
            self.state["original"] = moved
            if self.fault == "directory-symlink":
                replacement = root / "replacement-directory"
                replacement.mkdir(mode=0o700)
                owned.symlink_to(replacement, target_is_directory=True)
            else:
                owned.mkdir(mode=0o700)
                replacement = owned
            (replacement / "record").write_bytes(b"unrelated replacement record\n")
            self.state["replacement"] = replacement
        elif self.fault == "file":
            original = owned / "original-owned-record"
            path.rename(original)
            self.state["original"] = original
            path.write_bytes(b"unrelated replacement record\n")
        self.state["record"] = path
        sentinel = owned / "sentinel"
        sentinel.write_bytes(b"unrelated replacement sentinel\n")
        self.state["sentinel"] = sentinel
        if self.fault == "unknown-tree":
            nested = owned / "unrelated-directory"
            nested.mkdir()
            (nested / "sentinel").write_bytes(b"unrelated nested sentinel\n")
            self.state["tree"] = nested


class _PairCustodyWriter(_PairPublicationWriter):
    def __init__(self, stream: object, fixture: _PairCustodyFault, path: Path) -> None:
        super().__init__(stream, fixture)
        self.path = path

    def write(self, _body: bytes) -> int:
        self.fixture.replace(self.path)
        message = "injected write failure after private custody replacement"
        raise OSError(message)


class PairEvidenceCustodyPreservationTests(unittest.TestCase):
    execute = PhaseExecutionTests.execute
    pair = PairAuthorityTests.pair
    write = PairEvidenceRetirementTests.write
    failed_authority = PairEvidenceRetirementTests.failed_authority

    def test_prepublication_directory_replacement_preserves_both_custodies_on_both_routes(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("directory", "directory-symlink"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "evidence.json"
                    evidence, _events = self.pair(engine=engine)
                    fixture = _PairCustodyFault(target, [1.0], fault)
                    with self.assertRaisesRegex(ProbeError, "uncertain; failed producer"):
                        self.write(target, evidence, fault, fixture=fixture)
                    self.failed_authority(evidence)
                    self.assertFalse(target.exists())
                    self.assertTrue(fixture.state["original"].is_dir())
                    self.assertTrue((fixture.state["original"] / "record").exists())
                    self.assertEqual(fixture.state["record"].read_bytes(), b"unrelated replacement record\n")
                    self.assertEqual(fixture.state["sentinel"].read_bytes(), b"unrelated replacement sentinel\n")

    def test_replaced_file_or_unknown_contents_never_authorize_deletion(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("file", "unknown-file", "unknown-tree"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "evidence.json"
                    evidence, _events = self.pair(engine=engine)
                    fixture = _PairCustodyFault(target, [1.0], fault)
                    with self.assertRaises((ProbeError, OSError)):
                        self.write(target, evidence, fault, fixture=fixture)
                    self.failed_authority(evidence)
                    self.assertFalse(target.exists())
                    self.assertEqual(fixture.state["sentinel"].read_bytes(), b"unrelated replacement sentinel\n")
                    if fault == "file":
                        self.assertTrue(fixture.state["original"].exists())
                        self.assertEqual(fixture.state["record"].read_bytes(), b"unrelated replacement record\n")
                    else:
                        self.failed_authority(_read(fixture.state["record"]))
                    if fault == "unknown-tree":
                        self.assertEqual(
                            (fixture.state["tree"] / "sentinel").read_bytes(), b"unrelated nested sentinel\n"
                        )

    def test_prepublication_owned_failures_retain_only_failed_private_bytes(self) -> None:
        for engine in ("podman", "docker"):
            for fault in ("partial-write", "flush", "close-error"):
                with self.subTest(engine=engine, fault=fault), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "evidence.json"
                    evidence, _events = self.pair(engine=engine)
                    with self.assertRaises(OSError):
                        self.write(target, evidence, fault)
                    self.failed_authority(evidence)
                    self.assertFalse(target.exists())
                    anchor = next(Path(directory).glob(".runtime-evidence-*")) / "record"
                    self.failed_authority(_read(anchor))


class _PairFIFOFault(_PairCustodyFault):
    def replace(self, path: Path) -> None:
        path.unlink()
        os.mkfifo(path, 0o600)
        self.clock[0] = 11.0
        self.state["record"] = path


def _fifo_recovery_child(engine: str, directory: str) -> None:
    root = Path(directory)
    target = root / "evidence.json"
    evidence, _events = PairEvidenceRetirementTests().pair(engine=engine)
    fixture = _PairFIFOFault(target, [1.0], "fifo")
    original_open = os.open

    def recovery_open(path: Path, flags: int, *arguments: object, **keywords: object) -> int:
        (root / "recovery-open.json").write_text(
            json.dumps({"nonblocking": bool(flags & os.O_NONBLOCK), "clock": fixture.clock[0], "deadline": 10.0})
        )
        return original_open(path, flags, *arguments, **keywords)

    with patch.object(runtime_tests.os, "open", side_effect=recovery_open):
        try:
            PairEvidenceRetirementTests().write(target, evidence, "fifo", fixture=fixture)
        except ProbeError as error:
            (root / "finished.json").write_text(
                json.dumps(
                    {
                        "error": str(error),
                        "evidence": evidence,
                        "fifoPreserved": stat.S_ISFIFO(fixture.state["record"].lstat().st_mode),
                        "publicReportCreated": target.exists(),
                    }
                )
            )


class PairEvidenceFIFORecoveryTests(unittest.TestCase):
    failed_authority = PairEvidenceRetirementTests.failed_authority

    def test_no_reader_fifo_recovery_refuses_promptly_on_both_routes(self) -> None:
        program = (
            "import sys;from tests.test_runtime_oom_lifecycle import _fifo_recovery_child;"
            "_fifo_recovery_child(*sys.argv[1:])"
        )
        for engine in ("podman", "docker"):
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with subprocess.Popen(  # noqa: S603 - fixed inert child; parent bounds, kills and reaps it.
                    [sys.executable, "-B", "-c", program, engine, directory],
                    cwd=Path(__file__).resolve().parents[1],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ) as process:
                    try:
                        try:
                            _stdout, stderr = process.communicate(timeout=3.0)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            _stdout, stderr = process.communicate(timeout=2.0)
                            self.fail("no-reader FIFO recovery exceeded its bounded test-owned child lifetime")
                        self.assertEqual(process.returncode, 0, stderr.decode())
                        self.assertEqual(stderr, b"")
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate(timeout=2.0)
                marker = json.loads((root / "recovery-open.json").read_text())
                self.assertTrue(marker["nonblocking"])
                self.assertGreater(marker["clock"], marker["deadline"])
                result = json.loads((root / "finished.json").read_text())
                self.assertIn("uncertain; failed producer", result["error"])
                self.failed_authority(result["evidence"])
                self.assertTrue(result["fifoPreserved"])
                self.assertFalse(result["publicReportCreated"])
