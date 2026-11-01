"""Offline service/peer/lifetime faults; no root, parser, systemd or runtime is invoked."""

from __future__ import annotations

import io
import json
import os
import signal
import struct
import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from scripts import docker_userns_custody as custody
from scripts import docker_userns_custody_child as child
from scripts import docker_userns_hosted as hosted
from tests import test_docker_userns_custody as fixtures

if TYPE_CHECKING:
    from collections.abc import Iterator


class HostedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.CustodyTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(hosted, "_CANCELLATION", [False]))
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(hosted.time, "monotonic_ns", side_effect=self.fixture.clock.now_ns))
        self.locator, self.supervisor = self.fixture.armed()
        self.record = self.fixture.record(self.locator)
        self.intent = custody.ArmIntent(self.record.lease, self.record.generation - 1)
        self.coordinator, self.observer = MagicMock(), MagicMock()
        self.coordinator.expected = self.record.lease.coordinator
        self.coordinator.dead.return_value = False
        self.control = MagicMock()
        self.start = MagicMock()
        self.start.intent, self.start.started_ns = self.intent, self.fixture.clock.time
        self.start.until_ns, self.start.sha256 = self.fixture.clock.time + custody.HANDSHAKE_NS, "a" * 64
        self.control.read.side_effect = lambda _name: self.control.write.call_args.args[1]
        self.loop = hosted.OwnerLoop(
            hosted.OwnerContext(
                self.control,
                self.intent,
                self.locator,
                self.coordinator,
                self.observer,
                self.supervisor,
                self.record.owner,
                self.fixture.clock,
                self.start,
            )
        )
        self.loop.committed = True
        self.loop.events.append(
            {"kind": "ARMED_SEEN", "ns": self.fixture.clock.time, "generation": self.record.generation}
        )

    def test_coordinator_death_finalizes_cancelled_then_independent_receipt_is_checked(self) -> None:
        self.coordinator.dead.return_value = True
        with self.fixture.caller(self.record.owner.process):
            self.assertTrue(self.loop.finish())
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)
        receipt = hosted.closed_receipt(self.control, self.record, killed=True, committed_ns=self.fixture.clock.time)
        self.assertEqual(
            [event["kind"] for event in receipt["events"]], ["READY", "ARMED_SEEN", "COORDINATOR_DEATH", "FINALIZED"]
        )
        self.assertEqual(receipt["receipt"]["qualification"], "none")

    def test_normal_close_remains_normal_while_coordinator_lives(self) -> None:
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True
        with self.fixture.caller(self.record.owner.process):
            self.assertTrue(self.loop.finish())
        hosted.closed_receipt(self.control, self.record, killed=False, committed_ns=self.fixture.clock.time)
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.NORMAL)

    def test_coordinator_death_stays_cancelled_even_after_a_normal_close_request(self) -> None:
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True
        self.coordinator.dead.return_value = True
        with self.fixture.caller(self.record.owner.process):
            self.assertTrue(self.loop.finish())
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)
        self.assertEqual(self.loop.events[-2]["kind"], "COORDINATOR_DEATH")

    def test_term_wins_close_including_during_owner_observation(self) -> None:
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True
        original = self.supervisor.inspect_owner

        def interrupted(lease: custody.Lease, owner: custody.Owner, end: int) -> custody.OwnerObservation:
            self.loop.term(signal.SIGTERM, None)
            return original(lease, owner, end)

        self.supervisor.inspect_owner = interrupted
        with self.fixture.caller(self.record.owner.process):
            self.loop.finish()
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)

    def test_term_with_already_pending_close_remains_cancelled(self) -> None:
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True
        self.loop.term(signal.SIGTERM, None)
        with self.fixture.caller(self.record.owner.process):
            self.loop.finish()
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)

    def test_term_first_seen_during_durable_finalize_cannot_publish_normal_receipt(self) -> None:
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True
        original = custody.finalize_unused

        def interrupted(*arguments: object) -> custody.Receipt:
            receipt = original(*arguments)
            self.loop.term(signal.SIGTERM, None)
            return receipt

        with (
            patch.object(custody, "finalize_unused", side_effect=interrupted),
            self.fixture.caller(self.record.owner.process),
            self.assertRaises(custody.CustodyError),
        ):
            self.loop.finish()
        self.control.write.assert_not_called()

    def late_receipt_refuses(self, kind: str) -> None:
        """Inject only at the durable-write boundary, after every earlier guard."""
        custody.request_close_unused(self.locator, self.supervisor, self.fixture.clock)
        self.loop.close_requested = True

        def late(_name: str, _value: object, _deadline: int) -> None:
            if kind == "term":
                self.loop.term(signal.SIGTERM, None)
            elif kind == "death":
                self.coordinator.dead.return_value = True
            else:
                self.fixture.clock.time = self.record.lease.deadline_ns

        self.control.write.side_effect = late
        with self.fixture.caller(self.record.owner.process), self.assertRaises(custody.CustodyError):
            self.loop.finish()
        current = self.fixture.record(self.locator)
        self.assertEqual(current.state, custody.State.CLOSED)
        self.assertEqual(current.cause, custody.Cause.NORMAL)
        self.assertEqual(current.lease.deadline_ns, self.record.lease.deadline_ns)
        self.assertEqual(self.control.write.call_count, 1)

    def test_term_during_durable_receipt_write_cannot_return_normal_success(self) -> None:
        self.late_receipt_refuses("term")

    def test_coordinator_death_during_durable_receipt_write_cannot_return_normal_success(self) -> None:
        self.late_receipt_refuses("death")

    def test_durable_receipt_write_crossing_d_refuses_without_terminal_rewrite(self) -> None:
        self.late_receipt_refuses("deadline")

    def test_new_death_during_cancelled_receipt_write_requires_its_missing_death_event(self) -> None:
        self.loop.term(signal.SIGTERM, None)
        self.control.write.side_effect = lambda *_args: setattr(self.coordinator.dead, "return_value", True)
        with self.fixture.caller(self.record.owner.process), self.assertRaises(custody.CustodyError):
            self.loop.finish()
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)
        self.assertNotIn("COORDINATOR_DEATH", [event["kind"] for event in self.loop.events])
        self.assertEqual(self.control.write.call_count, 1)

    def test_write_probe_uses_original_bootstrap_work_and_final_deadlines(self) -> None:
        entry = self.fixture.clock.time
        deadline = entry + custody.CLEANUP_NS + 20 * hosted.NS
        bootstrap = {"deadlineNs": deadline, "uid": 1001, "gid": 1002}
        host = SimpleNamespace(
            interpreter=12345, admission=SimpleNamespace(bootstrap=SimpleNamespace(interpreter_sha256="d" * 64))
        )
        descriptor = os.dup(self.fixture.fds[0].descriptor)
        with (
            patch.object(hosted, "HostPort", return_value=host),
            patch.object(os, "open", return_value=descriptor),
            patch.object(child, "probe", return_value=child.Outcome(b"write-denied\n", dead=True)) as probe,
        ):
            result = hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)
        lease = probe.call_args.args[3]
        self.assertEqual(
            (lease.deadline_ns, lease.cleanup_deadline_ns),
            (entry + custody.CHILD_NS, entry + custody.CHILD_NS + hosted.NS),
        )
        self.assertEqual(result["workUntilNs"], deadline - custody.CLEANUP_NS)
        self.assertEqual(result["phaseWorkUntilNs"], lease.deadline_ns)
        self.assertEqual(result["phaseCleanupUntilNs"], lease.cleanup_deadline_ns)
        self.assertEqual(result["deadlineNs"], deadline)

    def test_write_probe_expired_entry_and_completion_do_not_start_or_renew_work(self) -> None:
        deadline = self.fixture.clock.time + custody.CLEANUP_NS + 20 * hosted.NS
        bootstrap = {"deadlineNs": deadline, "uid": 1001, "gid": 1002}
        for now in (deadline - custody.CLEANUP_NS, deadline, deadline + 1):
            self.fixture.clock.time = now
            with patch.object(hosted, "HostPort") as host, self.assertRaises(custody.CustodyError):
                hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)
            host.assert_not_called()
        self.fixture.clock.time = deadline - custody.CLEANUP_NS - hosted.NS
        host = SimpleNamespace(
            interpreter=12345, admission=SimpleNamespace(bootstrap=SimpleNamespace(interpreter_sha256="d" * 64))
        )
        descriptor = os.dup(self.fixture.fds[0].descriptor)

        def late(*_arguments: object) -> child.Outcome:
            self.fixture.clock.time = deadline - custody.CLEANUP_NS
            return child.Outcome(b"write-denied\n", dead=True)

        with (
            patch.object(hosted, "HostPort", return_value=host),
            patch.object(os, "open", return_value=descriptor),
            patch.object(child, "probe", side_effect=late),
            self.assertRaises(custody.CustodyError),
        ):
            hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)

    def test_write_probe_parent_phase_is_clipped_once_before_host_startup(self) -> None:
        entry = self.fixture.clock.time
        deadline = entry + custody.CLEANUP_NS + 2 * hosted.NS
        bootstrap = {"deadlineNs": deadline, "uid": 1001, "gid": 1002}
        host = SimpleNamespace(
            interpreter=12345, admission=SimpleNamespace(bootstrap=SimpleNamespace(interpreter_sha256="d" * 64))
        )
        descriptor = os.dup(self.fixture.fds[0].descriptor)
        with (
            patch.object(hosted, "HostPort", return_value=host),
            patch.object(os, "open", return_value=descriptor),
            patch.object(child, "probe", return_value=child.Outcome(b"write-denied\n", dead=True)) as probe,
        ):
            hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)
        lease = probe.call_args.args[3]
        self.assertEqual(lease.deadline_ns, deadline - custody.CLEANUP_NS)
        self.assertEqual(lease.cleanup_deadline_ns, min(deadline, entry + custody.CHILD_NS + hosted.NS))
        deadline = entry + custody.CLEANUP_NS + 120 * hosted.NS
        bootstrap["deadlineNs"] = deadline
        descriptor = os.dup(self.fixture.fds[0].descriptor)

        def late_host(*_args: object) -> object:
            self.fixture.clock.time = entry + custody.CHILD_NS
            return host

        with (
            patch.object(hosted, "HostPort", side_effect=late_host),
            patch.object(os, "open", return_value=descriptor),
            patch.object(child, "probe") as probe,
            self.assertRaises(custody.CustodyError),
        ):
            hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)
        probe.assert_not_called()

    def test_write_probe_completion_at_parent_phase_end_is_not_accepted(self) -> None:
        entry = self.fixture.clock.time
        bootstrap = {"deadlineNs": entry + custody.CLEANUP_NS + 120 * hosted.NS, "uid": 1001, "gid": 1002}
        host = SimpleNamespace(
            interpreter=12345, admission=SimpleNamespace(bootstrap=SimpleNamespace(interpreter_sha256="d" * 64))
        )
        descriptor = os.dup(self.fixture.fds[0].descriptor)

        def late(*_args: object) -> child.Outcome:
            self.fixture.clock.time = entry + custody.CHILD_NS
            return child.Outcome(b"write-denied\n", dead=True)

        with (
            patch.object(hosted, "HostPort", return_value=host),
            patch.object(os, "open", return_value=descriptor),
            patch.object(child, "probe", side_effect=late),
            self.assertRaises(custody.CustodyError),
        ):
            hosted.write_denial_probe(Path("/verified-stage"), bootstrap, self.fixture.clock)

    def test_privilege_receipts_reject_numeric_coercion_duplicates_and_extra_keys(self) -> None:
        lease = child.Build("probe", 1001, 1002, 100, 200)
        expected = {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"}
        child._privilege_receipt(json.dumps(expected).encode(), lease)
        for field in ("schema", "uid", "gid", "nnp"):
            for value in (True, float(expected[field])):
                bad = {**expected, field: value}
                with self.subTest(field=field, value=value), self.assertRaises(child.ChildError):
                    child._privilege_receipt(json.dumps(bad).encode(), lease)
        with self.assertRaises(child.ChildError):
            child._privilege_receipt(json.dumps({**expected, "extra": False}).encode(), lease)
        raw = json.dumps(expected).encode()
        with self.assertRaises(child.ChildError):
            child._privilege_receipt(raw[:-1] + b',"schema":1}', lease)

    def test_expiry_begins_at_work_cutoff_and_never_after_final_deadline(self) -> None:
        self.fixture.clock.time = self.record.lease.work_until_ns - 1
        self.assertFalse(self.loop.finish())
        self.fixture.clock.time += 1
        with self.fixture.caller(self.record.owner.process):
            self.assertTrue(self.loop.finish())
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.EXPIRY)
        self.fixture.clock.time = 1_000_000_000
        locator, supervisor = self.fixture.armed()
        record = self.fixture.record(locator)
        loop = hosted.OwnerLoop(
            hosted.OwnerContext(
                MagicMock(),
                custody.ArmIntent(record.lease, record.generation - 1),
                locator,
                self.coordinator,
                self.observer,
                supervisor,
                record.owner,
                self.fixture.clock,
                self.start,
            )
        )
        self.fixture.clock.time = record.lease.deadline_ns
        with self.fixture.caller(record.owner.process), self.assertRaises(custody.CustodyError):
            loop.finish()
        self.assertEqual(self.fixture.record(locator).state, custody.State.ARMED)
        loop.control.write.assert_not_called()

    def test_death_before_ready_or_durable_armed_never_finalizes_or_promotes(self) -> None:
        for ready in (False, True):
            locator = self.fixture.prepare()
            with custody._store(locator) as store:
                record = store.load()
                intent_record = custody._next(record, custody.State.ARM_INTENT, owner_attempted=True)
                store.save(intent_record)
            intent = custody.ArmIntent(intent_record.lease, intent_record.generation)
            supervisor = MagicMock()
            loop = hosted.OwnerLoop(
                hosted.OwnerContext(
                    MagicMock(),
                    intent,
                    locator,
                    self.coordinator,
                    self.observer,
                    supervisor,
                    self.record.owner,
                    self.fixture.clock,
                    self.start,
                )
            )
            loop.committed = ready
            self.coordinator.dead.return_value = True
            with self.subTest(ready=ready), self.assertRaises(custody.CustodyError):
                loop.finish()
            self.assertEqual(self.fixture.record(locator), intent_record)
            supervisor.inspect_owner.assert_not_called()
            loop.control.write.assert_not_called()

    def test_signal_term_maps_cancelled_without_renewal(self) -> None:
        deadline = self.record.lease.deadline_ns
        self.loop.term(signal.SIGTERM, None)
        with self.fixture.caller(self.record.owner.process):
            self.loop.finish()
        self.assertEqual(self.fixture.record(self.locator).cause, custody.Cause.CANCELLED)
        self.assertEqual(self.fixture.record(self.locator).lease.deadline_ns, deadline)

    def test_receipt_write_that_crosses_deadline_is_not_a_success(self) -> None:
        self.coordinator.dead.return_value = True
        self.fixture.clock.time = self.record.lease.deadline_ns - 1

        def late(_name: str, _value: object, deadline: int) -> None:
            self.fixture.clock.time = deadline
            hosted.remaining(deadline)

        self.control.write.side_effect = late
        with self.fixture.caller(self.record.owner.process), self.assertRaises(custody.CustodyError):
            self.loop.finish()

    def test_stale_generation_peer_pid_reuse_and_nonroot_peer_refuse(self) -> None:
        held = MagicMock()
        held.expected = self.record.lease.coordinator
        connection = MagicMock()
        for pid, uid, gid in (
            (held.expected.pid + 1, 0, 0),
            (held.expected.pid, 1000, 0),
            (held.expected.pid, 0, 1000),
        ):
            connection.getsockopt.return_value = struct.pack("3i", pid, uid, gid)
            with self.subTest(pid=pid, uid=uid, gid=gid), self.assertRaises(custody.CustodyError):
                hosted.peer(connection, held)
        connection.getsockopt.return_value = struct.pack("3i", held.expected.pid, 0, 0)
        held.live.side_effect = custody.CustodyError
        with self.assertRaises(custody.CustodyError):
            hosted.peer(connection, held)
        supervisor = hosted.SupervisorPort.__new__(hosted.SupervisorPort)
        supervisor.clock = self.fixture.clock
        supervisor.ack = self.loop.ack
        supervisor.start = self.start
        supervisor.validate_ack(self.intent, self.record.owner)
        for intent in (
            replace(self.intent, generation=self.intent.generation + 1),
            replace(self.intent, lease=replace(self.intent.lease, nonce="f" * 32)),
        ):
            with self.subTest(intent=intent.generation), self.assertRaises(custody.CustodyError):
                supervisor.validate_ack(intent, self.record.owner)

    def test_held_pidfd_rejects_identity_reuse_even_if_pid_exists(self) -> None:
        expected = self.record.owner.process
        with (
            patch.object(hosted, "process", return_value=expected),
            patch.object(hosted.os, "pidfd_open", return_value=10123, create=True),
            patch.object(hosted.select, "select", return_value=([], [], [])),
            patch.object(hosted.os, "close"),
        ):
            held = hosted.HeldProcess(expected)
            with (
                patch.object(hosted, "process", return_value=replace(expected, start_ticks=999)),
                self.assertRaises(custody.CustodyError),
            ):
                held.live()
            with patch.object(hosted.select, "select", return_value=([10123], [], [])):
                self.assertTrue(held.dead())
                with self.assertRaises(custody.CustodyError):
                    held.live()
            held.close()

    def test_unknown_termination_and_remaining_cgroup_or_unit_refuse_disposal_evidence(self) -> None:
        supervisor = hosted.SupervisorPort.__new__(hosted.SupervisorPort)
        supervisor.held = MagicMock()
        supervisor.held.expected = self.record.owner.process
        for dead, group_absent, cgroup_absent, unit_absent in (
            (False, True, True, True),
            (True, False, True, True),
            (True, True, False, True),
            (True, True, True, False),
        ):
            supervisor.held.dead.return_value = dead
            with (
                patch.object(hosted.os, "killpg", side_effect=ProcessLookupError if group_absent else None),
                patch.object(hosted, "absent", return_value=cgroup_absent),
                patch.object(hosted, "manager", return_value={"LoadState": "not-found" if unit_absent else "loaded"}),
                self.subTest(dead=dead, cgroup_absent=cgroup_absent),
                self.assertRaises(custody.CustodyError),
            ):
                supervisor.observe_termination(self.record.lease, self.record.owner)

    def test_fixed_probe_drops_saved_ids_groups_caps_before_parser_exec(self) -> None:
        for uid, groups, status in (
            ((0, 1001, 0), (), b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"),
            ((1001, 1001, 1001), (0,), b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"),
            ((1001, 1001, 1001), (), b"CapEff: 1\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"),
            ((1001, 1001, 1001), (), b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 0\n"),
        ):
            fake_os = SimpleNamespace(**vars(os))
            fake_os.getresuid, fake_os.getresgid = lambda current_uid=uid: current_uid, lambda: (1002, 1002, 1002)
            fake_os.getgroups = lambda current_groups=groups: list(current_groups)
            fake_os.execve = MagicMock()
            fake_os.listdir = MagicMock()
            fake_ctypes = MagicMock()
            fake_ctypes.CDLL.return_value.prctl.side_effect = [0, 1]
            with (
                patch.dict(
                    sys.modules, {"os": fake_os, "ctypes": fake_ctypes, "resource": MagicMock(), "signal": MagicMock()}
                ),
                patch.object(
                    sys,
                    "argv",
                    [
                        "probe",
                        "11",
                        "12",
                        "13",
                        "parser-version",
                        "1001",
                        "1002",
                        "2",
                        str(hosted.time.monotonic_ns() + 5 * hosted.NS),
                    ],
                ),
                patch("builtins.open", return_value=io.BytesIO(status)),
                self.subTest(uid=uid, groups=groups),
                self.assertRaises(SystemExit),
            ):
                exec(child.PROBE_CODE, {})  # noqa: S102 - fixed probe with entirely mocked privilege interfaces.
            fake_os.execve.assert_not_called()
            fake_os.listdir.assert_not_called()
            fake_ctypes.CDLL.assert_not_called()

    def test_fixed_version_probe_executes_only_version_argv_after_valid_privilege_receipt(self) -> None:
        for fault in (None, "unexpected-fd", "missing-target", "nnp-zero"):
            fake_os = SimpleNamespace(**vars(os))
            fake_os.getresuid, fake_os.getresgid = lambda: (1001, 1001, 1001), lambda: (1002, 1002, 1002)
            fake_os.getgroups, fake_os.close = list, MagicMock()
            fake_os.execve, fake_os.set_inheritable = MagicMock(side_effect=SystemExit(0)), MagicMock()
            fake_os.supports_fd = {fake_os.execve}
            fake_os.write = MagicMock(side_effect=lambda _descriptor, raw: len(raw))
            entries = ["0", "1", "2"] if fault == "missing-target" else ["0", "1", "2", "13"]
            if fault == "unexpected-fd":
                entries.append("99")
            fake_os.listdir = MagicMock(return_value=entries)
            fake_os.fstat = MagicMock(return_value=object())
            status = b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"
            if fault == "nnp-zero":
                status = status.replace(b"NoNewPrivs: 1", b"NoNewPrivs: 0")
            arguments = [
                "probe",
                "11",
                "12",
                "13",
                "parser-version",
                "1001",
                "1002",
                "2",
                str(hosted.time.monotonic_ns() + 5 * hosted.NS),
            ]
            with (
                self.subTest(fault=fault),
                patch.dict(sys.modules, {"os": fake_os}),
                patch.object(sys, "argv", arguments),
                patch("builtins.open", return_value=io.BytesIO(status)),
                self.assertRaises(SystemExit) as raised,
            ):
                exec(child.PROBE_CODE, {})  # noqa: S102 - fixed payload with explicit fake kernel/inventory facts.
            self.assertEqual(raised.exception.code, 0 if fault is None else 1 if fault == "nnp-zero" else 112)
            if fault is not None:
                fake_os.execve.assert_not_called()
            else:
                descriptor, argv, environment = fake_os.execve.call_args.args
                self.assertEqual(descriptor, 13)
                self.assertEqual(
                    argv, ["apparmor_parser", "--config-file=/dev/null", "--skip-cache", "--jobs=0", "--version"]
                )
                self.assertEqual(environment, hosted.ENV)
            if fault == "nnp-zero":
                fake_os.write.assert_not_called()
                fake_os.listdir.assert_not_called()
            else:
                fake_os.listdir.assert_called_once_with("/proc/self/fd")
                proof = json.loads(fake_os.write.call_args.args[1])
                self.assertEqual(
                    proof, {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"}
                )

    def test_probe_parent_requires_dead_child_exact_receipt_and_original_completion_deadline(self) -> None:
        # Real owned held identity, with mocked process/capture only; never an executable/native qualification.
        interpreter_path = self.fixture.root / "probe-interpreter"
        interpreter_raw = b"\x7fELFhermetic-interpreter"
        interpreter_path.write_bytes(interpreter_raw)
        interpreter_path.chmod(0o500)
        interpreter_fd = os.open(interpreter_path, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, interpreter_fd)
        interpreter = child.Interpreter(interpreter_fd, hosted.digest(interpreter_raw))
        lease = child.Build(
            "probe", 1001, 1002, self.fixture.clock.time + 5 * hosted.NS, self.fixture.clock.time + 6 * hosted.NS
        )
        process = MagicMock()
        process.stdout = io.BytesIO()
        proof = json.dumps(
            {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"}
        ).encode()
        with (
            patch.object(child.subprocess, "Popen", return_value=process) as popen,
            patch.object(child, "_capture", return_value=(b"write-denied\n", proof)) as capture,
            patch.object(child, "_stop", return_value=(0, True)),
        ):
            outcome = child.probe(
                interpreter, self.fixture.fds[0].descriptor, "write-denial", lease, self.fixture.clock
            )
            self.assertTrue(outcome.dead)
            self.assertEqual(popen.call_args.kwargs["user"], 1001)
            self.assertEqual(popen.call_args.kwargs["group"], 1002)
            self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            arguments = popen.call_args.args[0]
            self.assertEqual(arguments[5], child.PROBE_LAUNCHER)
            self.assertEqual(arguments[-2], str(lease.deadline_ns))
            binding = tuple(tuple(map(int, item.split(","))) for item in arguments[-1].split(";"))
            self.assertEqual(binding[0], child.file_mark(os.fstat(interpreter_fd)))
            self.assertEqual(binding[1][4] & 0o170000, 0o010000)
            self.assertEqual(binding[2], child.file_mark(os.fstat(self.fixture.fds[0].descriptor)))
            self.assertEqual(
                popen.call_args.kwargs["pass_fds"], (interpreter_fd, int(arguments[7]), self.fixture.fds[0].descriptor)
            )

            def late(*_arguments: object) -> tuple[bytes, bytes]:
                self.fixture.clock.time = lease.deadline_ns
                return b"write-denied\n", proof

            capture.side_effect = late
            with self.assertRaises(child.ChildError) as raised:
                child.probe(interpreter, self.fixture.fds[0].descriptor, "write-denial", lease, self.fixture.clock)
            self.assertEqual(raised.exception.lifetime, child.Lifetime.DEAD)

    def start_record(self) -> tuple[MagicMock, dict[str, object], custody.FileIdentity]:
        """Construct explicit fake root control data, never a host authority."""
        control = MagicMock()
        control.path = Path("/run") / (hosted.CONTROL_PREFIX + "a" * 32)
        control.mark = SimpleNamespace(st_dev=11, st_ino=22)
        lease = self.record.lease
        value = {
            "schema": 1,
            "intentSha256": hosted.intent_digest(self.intent),
            "leaseSha256": hosted.digest(hosted.encoded(asdict(lease))),
            "generation": self.intent.generation,
            "control": {"device": 11, "inode": 22},
            "custody": asdict(self.locator),
            "startedNs": self.fixture.clock.time,
            "handshakeUntilNs": self.fixture.clock.time + custody.HANDSHAKE_NS,
        }
        return control, value, self.record.lease.identities[0]

    def test_root_start_record_is_exact_immutable_and_retains_original_end(self) -> None:
        control, value, info = self.start_record()
        original = hosted.encoded(value)
        with patch.object(hosted, "read_root", return_value=(original, info)):
            start = hosted.StartBinding.load(control, self.intent)
            start.ready(self.fixture.clock)
            self.assertEqual(start.until_ns, value["handshakeUntilNs"])
            self.fixture.clock.time = start.until_ns
            with self.assertRaises(custody.CustodyError):
                start.ready(self.fixture.clock)
            for field, wrong in (
                ("intentSha256", "b" * 64),
                ("leaseSha256", "b" * 64),
                ("generation", self.intent.generation + 1),
                ("control", {"device": 11, "inode": 23}),
                ("custody", {**asdict(self.locator), "nonce": "b" * 32}),
                ("handshakeUntilNs", start.until_ns + 1),
            ):
                changed = {**value, field: wrong}
                with (
                    patch.object(hosted, "read_root", return_value=(hosted.encoded(changed), info)),
                    self.subTest(field=field),
                    self.assertRaises(custody.CustodyError),
                ):
                    hosted.StartBinding.load(control, self.intent)
            with (
                patch.object(hosted, "read_root", return_value=(original, replace(info, mtime_ns=info.mtime_ns + 1))),
                self.assertRaises(custody.CustodyError),
            ):
                start.stable()
            duplicate = original[:-1] + b',"schema":1}'
            with (
                patch.object(hosted, "read_root", return_value=(duplicate, info)),
                self.assertRaises(custody.CustodyError),
            ):
                hosted.StartBinding.load(control, self.intent)

    def test_delayed_service_intent_read_at_original_end_never_opens_ready_socket(self) -> None:
        control, value, info = self.start_record()
        with patch.object(hosted, "read_root", return_value=(hosted.encoded(value), info)):
            start = hosted.StartBinding.load(control, self.intent)

            def delayed(_locator: custody.Locator, intent: custody.ArmIntent, _clock: object) -> custody.ArmIntent:
                self.fixture.clock.time = start.until_ns
                return intent

            with (
                patch.object(hosted, "Control", return_value=control),
                patch.object(hosted.os, "umask"),
                patch.object(hosted, "Clock", return_value=self.fixture.clock),
                patch.object(hosted, "HeldProcess"),
                patch.object(
                    hosted,
                    "binding",
                    return_value=(
                        self.record,
                        self.intent,
                        self.locator,
                        {"observer": asdict(self.record.lease.coordinator)},
                    ),
                ),
                patch.object(hosted.StartBinding, "load", return_value=start),
                patch.object(custody, "read_owner_intent", side_effect=delayed),
                self.assertRaises(custody.CustodyError),
            ):
                hosted.owner_main("/verified-stage", str(control.path))
            control.listen.assert_not_called()

    def test_ready_at_end_and_send_crossing_original_end_are_never_accepted(self) -> None:
        control, value, info = self.start_record()
        connection = MagicMock()
        connection.getsockopt.return_value = struct.pack("3i", self.coordinator.expected.pid, 0, 0)
        with (
            patch.object(hosted, "read_root", return_value=(hosted.encoded(value), info)),
            patch.object(hosted, "peer"),
            patch.object(hosted, "receive", return_value={"kind": "ready", "intent": self.loop.ack["intent"]}),
            patch.object(hosted, "send") as send,
        ):
            self.loop.start = hosted.StartBinding.load(control, self.intent)
            self.fixture.clock.time = self.loop.start.until_ns
            with self.assertRaises(custody.CustodyError):
                self.loop.handle(connection)
            send.assert_not_called()
            self.fixture.clock.time -= 1
            send.side_effect = lambda *_arguments: setattr(self.fixture.clock, "time", self.loop.start.until_ns)
            with self.assertRaises(custody.CustodyError):
                self.loop.handle(connection)
            self.assertEqual(send.call_count, 1)

    def test_failure_metadata_is_closed_diagnostic_only_and_never_raw_error_output(self) -> None:
        control = hosted.Control.__new__(hosted.Control)
        control.phase, control.write = "prepare", MagicMock()
        control.failure(custody.CustodyError(self.locator, child_pending=True), self.record.lease.deadline_ns)
        name, value, deadline = control.write.call_args.args
        self.assertEqual(name, "failure.json")
        self.assertTrue(value["diagnosticOnly"])
        self.assertEqual(value["phase"], "prepare")
        self.assertEqual(value["custodyLocator"]["nonce"], self.locator.nonce)
        self.assertTrue(value["childPending"])
        self.assertEqual(deadline, self.record.lease.deadline_ns)
        self.assertEqual(set(value), {"schema", "diagnosticOnly", "phase", "ns", "custodyLocator", "childPending"})
        control.phase = "arbitrary-raw-tool-error"
        with self.assertRaises(custody.CustodyError):
            control.failure(ValueError("untrusted secret output"), deadline)

    def test_control_rejects_extra_leaves_and_wire_rejects_trailing_messages(self) -> None:
        control = hosted.Control.__new__(hosted.Control)
        control.path = self.fixture.root
        control.mark = control.path.lstat()
        for path in control.path.iterdir():
            if path.is_dir():
                continue
            path.unlink()
        with self.assertRaises(custody.CustodyError):
            control.check()
        connection = MagicMock()
        connection.recv.return_value = b'{"kind":"ready"}\n{"kind":"close"}\n'
        with self.assertRaises(custody.CustodyError):
            hosted.receive(connection, self.record.lease.deadline_ns)
        self.assertEqual(connection.getsockopt.call_count, 0)

    def test_manual_admission_invalidates_changed_source_contract_and_helper_content(self) -> None:
        root = Path(__file__).resolve().parents[1]
        receipt = {
            "interpreter": {"path": "/root-owned-system-python", "sha256": hosted.digest(b"OS ELF")},
            "helpers": {
                "scripts/" + name: hosted.digest((root / "scripts" / name).read_bytes()) for name in custody.HELPERS
            },
        }
        files = {
            str(path): path.read_bytes()
            for path in [
                root / ".github/docker-userns-unused-admission.json",
                root / ".github/docker-userns-policy-source.json",
                *(
                    root / "scripts" / name
                    for name in (*custody.HELPERS, "docker_userns_hosted.py", "docker_userns_policy_source.py")
                ),
                root / ".github/docker-userns-helper-closure.json",
            ]
        }

        def read(path: Path, _limit: int = 32768) -> tuple[bytes, object]:
            return files[str(path)], None

        with (
            patch.object(hosted, "read_root", side_effect=read),
            patch.object(hosted.os, "open", return_value=12345),
            patch.object(child, "bytes_at", return_value=b"OS ELF"),
        ):
            hosted.HostPort(root, receipt, self.fixture.clock, MagicMock())
            for name in (
                ".github/docker-userns-policy-source.json",
                "scripts/docker_userns_custody.py",
                "scripts/docker_userns_custody_child.py",
                "scripts/docker_userns_hosted.py",
            ):
                original = files[str(root / name)]
                files[str(root / name)] = original + b"\n"
                with self.subTest(name=name), self.assertRaises(custody.CustodyError):
                    hosted.HostPort(root, receipt, self.fixture.clock, MagicMock())
                files[str(root / name)] = original

    def test_manager_readback_rejects_wrong_cgroup_bounds_argv_and_root_ownership(self) -> None:
        lease = self.record.lease
        unit = "containers-userns-unused-" + lease.nonce + ".service"
        proc = replace(self.record.owner.process, cgroup=custody.Group("/system.slice/" + unit, 1, 88))
        owner = custody.Owner(unit.removesuffix(".service"), proc)
        state = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "Transient": "yes",
            "MainPID": str(proc.pid),
            "ControlGroup": proc.cgroup.path,
            "User": "root",
            "Group": "root",
            "DropInPaths": "",
            "Type": "exec",
            "Restart": "no",
            "Slice": "system.slice",
            "KillMode": "control-group",
            "SendSIGKILL": "yes",
            "FragmentPath": "/run/systemd/transient/" + unit,
            "ExecMainStartTimestampMonotonic": str(lease.start_ns // 1000),
            "RuntimeMaxUSec": "90s",
            "TimeoutStopUSec": "5s",
        }
        supervisor = hosted.SupervisorPort.__new__(hosted.SupervisorPort)
        supervisor.clock, supervisor.control = self.fixture.clock, MagicMock()
        supervisor.argv, supervisor.ack = ["/root-owned-python", "fixed-owner"], self.loop.ack
        supervisor.held = MagicMock()
        supervisor.held.expected = proc
        actual_argv = b"/root-owned-python\0fixed-owner\0"
        with (
            patch.object(hosted, "manager", return_value=state),
            patch.object(hosted, "read_root", return_value=(b"unit", self.record.lease.identities[0])),
            patch.object(hosted, "process", return_value=proc),
            patch.object(hosted, "group", return_value=proc.cgroup),
            patch.object(
                hosted.Path,
                "read_bytes",
                autospec=True,
                side_effect=lambda path: (
                    b"\0".join((key + "=" + value).encode() for key, value in hosted.ENV.items()) + b"\0"
                    if path.name == "environ"
                    else actual_argv
                ),
            ),
        ):
            self.assertEqual(supervisor.observe_live(lease, owner, lease.work_until_ns), owner)
            for key, value in (
                ("User", "runner"),
                ("ControlGroup", "/untrusted/cgroup"),
                ("Restart", "always"),
                ("Slice", "user.slice"),
                ("TimeoutStopUSec", "infinity"),
                ("RuntimeMaxUSec", "30min"),
                ("FragmentPath", "/untrusted/forged-unit"),
            ):
                original = state[key]
                state[key] = value
                with self.subTest(key=key), self.assertRaises(custody.CustodyError):
                    supervisor.observe_live(lease, owner, lease.work_until_ns)
                state[key] = original
            with (
                patch.object(hosted, "process", return_value=replace(proc, cgroup=lease.coordinator.cgroup)),
                self.assertRaises(custody.CustodyError),
            ):
                supervisor.observe_live(lease, owner, lease.work_until_ns)
            with (
                patch.object(hosted.Path, "read_bytes", return_value=b"forged\0"),
                self.assertRaises(custody.CustodyError),
            ):
                supervisor.observe_live(lease, owner, lease.work_until_ns)
        self.assertEqual(supervisor.control.mock_calls, [])

    def test_ambiguous_service_start_is_not_retried_or_inspected_as_ready(self) -> None:
        lease = replace(
            self.record.lease,
            deadline_ns=self.fixture.clock.time + hosted.CYCLE_NS,
            work_until_ns=self.fixture.clock.time + hosted.CYCLE_NS - custody.CLEANUP_NS,
        )
        supervisor = hosted.SupervisorPort.__new__(hosted.SupervisorPort)
        supervisor.clock = self.fixture.clock
        supervisor.control = MagicMock()
        supervisor.arguments, supervisor.observe_live = MagicMock(return_value=["fixed-owner"]), MagicMock()
        with (
            patch.object(hosted, "manager", return_value={"LoadState": "not-found"}) as manager,
            patch.object(hosted.StartBinding, "create", return_value=self.start),
            patch.object(hosted, "command", side_effect=TimeoutError) as command,
            patch.object(hosted, "safe_path", side_effect=lambda path: path),
            self.assertRaises(TimeoutError),
        ):
            supervisor.start_unused_owner(custody.ArmIntent(lease, self.intent.generation), lease.work_until_ns)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(manager.call_count, 1)
        supervisor.observe_live.assert_not_called()

    def child_kernel(self) -> ExitStack:
        """Install explicit fake pidfd APIs absent from the local portable Python build."""
        stack = ExitStack()
        stack.enter_context(patch.object(os, "P_PIDFD", 3, create=True))
        stack.enter_context(patch.object(os, "pidfd_open", return_value=12345, create=True))
        stack.enter_context(patch.object(signal, "pidfd_send_signal", create=True))
        return stack

    def test_child_pidfd_failure_still_cleans_only_proven_unreaped_fork_child(self) -> None:
        child_hold = hosted.ChildCustody(9001)
        live = [True]

        def state(*_arguments: object) -> object:
            return None if live[0] else SimpleNamespace(si_pid=9001)

        def terminate(pid: int, _number: int) -> None:
            self.assertEqual(pid, 9001)
            live[0] = False

        with (
            self.child_kernel(),
            patch.object(os, "waitid", side_effect=state),
            patch.object(os, "pidfd_open", side_effect=OSError, create=True),
            patch.object(os, "kill", side_effect=terminate) as kill,
            patch.object(os, "waitpid", return_value=(9001, 15)),
        ):
            with self.assertRaises(OSError):
                child_hold.hold()
            proof = child_hold.cleanup(self.record.lease.deadline_ns)
        kill.assert_called_once_with(9001, signal.SIGTERM)
        self.assertEqual(proof["lifetime"], "proven-dead-reaped")
        self.assertEqual(child_hold.status, 15)

    def test_echild_and_expired_cleanup_never_signal_or_claim_reaping(self) -> None:
        for expired in (False, True):
            child_hold = hosted.ChildCustody(9001)
            deadline = self.fixture.clock.time if expired else self.record.lease.deadline_ns
            with (
                self.child_kernel(),
                patch.object(os, "waitid", side_effect=ChildProcessError),
                patch.object(os, "kill") as kill,
                patch.object(os, "waitpid") as wait,
            ):
                proof = child_hold.cleanup(deadline)
                again = child_hold.cleanup(self.record.lease.deadline_ns)
            kill.assert_not_called()
            wait.assert_not_called()
            self.assertEqual(proof["lifetime"], "unknown")
            self.assertEqual(again["lifetime"], "unknown")

    def observer_fixture(self) -> hosted.CycleObserver:
        """Build an inert observer without any host/control acquisition."""
        observer = hosted.CycleObserver.__new__(hosted.CycleObserver)
        observer.plan = hosted.CyclePlan(Path("/verified-stage"), {}, self.record.lease.deadline_ns, killed=False)
        observer.clock, observer.control, observer.result = self.fixture.clock, MagicMock(), {}
        observer.observer, observer.coordinator = self.record.lease.coordinator, None
        return observer

    def test_fork_is_held_before_identity_and_malformed_frame_never_grants_work(self) -> None:
        observer = self.observer_fixture()
        hold = MagicMock()
        hold.reaped = False
        hold.cleanup.return_value = {"lifetime": "proven-dead-reaped"}
        ordering = []
        hold.hold.side_effect = lambda: ordering.append("held")

        def malformed(_descriptor: int, _end: int) -> bytes:
            ordering.append("identity")
            return b"malformed\n"

        with (
            patch.object(os, "pipe2", side_effect=[(11, 12), (13, 14)]),
            patch.object(os, "fork", return_value=9001),
            patch.object(os, "close"),
            patch.object(os, "write") as grant,
            patch.object(hosted, "ChildCustody", return_value=hold),
            patch.object(observer, "identity_frame", side_effect=malformed),
            self.assertRaises(ValueError),
        ):
            observer.spawn(MagicMock())
        self.assertEqual(ordering, ["held", "identity"])
        grant.assert_not_called()
        hold.cleanup.assert_called_once_with(observer.plan.deadline)

    def test_fork_pidfd_failure_uses_owned_child_cleanup_without_waiting_for_identity(self) -> None:
        observer = self.observer_fixture()
        hold = MagicMock()
        hold.hold.side_effect = OSError
        with (
            patch.object(os, "pipe2", side_effect=[(11, 12), (13, 14)]),
            patch.object(os, "fork", return_value=9001),
            patch.object(os, "close"),
            patch.object(hosted, "ChildCustody", return_value=hold),
            patch.object(observer, "identity_frame") as identity,
            self.assertRaises(OSError),
        ):
            observer.spawn(MagicMock())
        identity.assert_not_called()
        hold.cleanup.assert_called_once_with(observer.plan.deadline)

    def test_child_gate_eof_or_cancellation_prevents_custody_work(self) -> None:
        for cancelled in (False, True):
            observer = self.observer_fixture()
            observer.control.preparation_guard = "FD_NOT_ALLOWLISTED"
            hosted._CANCELLATION[0] = False
            with (
                patch.object(os, "pipe2", side_effect=[(11, 12), (13, 14)]),
                patch.object(os, "fork", return_value=0),
                patch.object(
                    os, "setsid", side_effect=lambda value=cancelled: hosted._CANCELLATION.__setitem__(0, value)
                ),
                patch.object(os, "close"),
                patch.object(os, "write", side_effect=lambda _fd, raw: len(raw)),
                patch.object(os, "read", return_value=b""),
                patch.object(os, "_exit", side_effect=SystemExit),
                patch.object(hosted, "process", return_value=self.record.lease.coordinator),
                patch.object(hosted.select, "select", return_value=([13], [], [])),
                patch.object(hosted, "coordinator_main") as work,
                self.assertRaises(SystemExit),
            ):
                observer.spawn(MagicMock())
            work.assert_not_called()
            self.assertIsNone(observer.control.preparation_guard)
            self.assertIsNone(observer.control.preparation_status)
            self.assertIsNone(observer.control.preparation_failure)
        hosted._CANCELLATION[0] = False

    def test_observer_error_cleans_its_already_spawned_exact_child(self) -> None:
        observer = self.observer_fixture()
        child_hold = MagicMock()
        child_hold.reaped = False
        listener = observer.control.listen.return_value
        listener.accept.return_value = (MagicMock(), None)

        def spawned(_listener: object) -> MagicMock:
            observer.coordinator = child_hold
            return child_hold

        with (
            patch.object(observer, "spawn", side_effect=spawned),
            patch.object(hosted.select, "select", return_value=([listener], [], [])),
            patch.object(observer, "authenticate", side_effect=custody.CustodyError),
            self.assertRaises(custody.CustodyError),
        ):
            observer.run()
        child_hold.cleanup.assert_called_once_with(observer.plan.deadline)
        child_hold.close.assert_called_once()

    def test_identity_timeout_keeps_exact_child_custody_and_original_cleanup_deadline(self) -> None:
        observer = self.observer_fixture()
        hold = MagicMock()
        with (
            patch.object(os, "pipe2", side_effect=[(11, 12), (13, 14)]),
            patch.object(os, "fork", return_value=9001),
            patch.object(os, "close"),
            patch.object(hosted, "ChildCustody", return_value=hold),
            patch.object(hosted.select, "select", return_value=([], [], [])),
            patch.object(os, "write") as grant,
            self.assertRaises(custody.CustodyError),
        ):
            observer.spawn(MagicMock())
        hold.hold.assert_called_once()
        hold.cleanup.assert_called_once_with(observer.plan.deadline)
        grant.assert_not_called()

    def test_observer_launch_checks_again_after_subreaper_setup_consumes_allowance(self) -> None:
        deadline = self.fixture.clock.time + custody.CLEANUP_NS + hosted.NS

        def late() -> None:
            self.fixture.clock.time = deadline - custody.CLEANUP_NS

        with (
            patch.object(hosted, "enable_subreaper", side_effect=late),
            patch.object(hosted, "ObserverProcess") as launch,
            patch.object(hosted, "family_cleanup", return_value={"complete": True}),
        ):
            result = hosted.capture_observer(Path("/verified-stage"), {"deadlineNs": deadline})
        self.assertFalse(result.accepted)
        self.assertIsNone(result.returncode)
        launch.assert_not_called()

    def test_subreaper_is_set_and_read_back_before_any_observer_launch(self) -> None:
        enabled = [0]
        libc = MagicMock()

        def prctl(operation: int, argument: int, *_unused: int) -> int:
            if operation == hosted.PR_SET_CHILD_SUBREAPER:
                enabled[0] = argument
            else:
                hosted.ctypes.c_int.from_address(argument).value = enabled[0]
            return 0

        libc.prctl.side_effect = prctl
        with (
            self.child_kernel(),
            patch.object(hosted, "reaper_invariant") as invariant,
            patch.object(hosted.ctypes, "CDLL", return_value=libc),
        ):
            hosted.enable_subreaper()
        invariant.assert_called_once()
        self.assertEqual(enabled[0], 1)
        self.assertEqual(
            [call.args[0] for call in libc.prctl.call_args_list],
            [hosted.PR_GET_CHILD_SUBREAPER, hosted.PR_SET_CHILD_SUBREAPER, hosted.PR_GET_CHILD_SUBREAPER],
        )

    def test_preexisting_children_refuse_reaper_invariant_without_reaping_them(self) -> None:
        with (
            patch.object(Path, "iterdir", return_value=[SimpleNamespace(name=str(os.getpid()))]),
            patch.object(signal, "signal") as disposition,
            patch.object(signal, "getsignal", return_value=signal.SIG_DFL),
            patch.object(hosted, "child_absent", return_value=False),
            self.assertRaises(custody.CustodyError),
        ):
            hosted.reaper_invariant()
        disposition.assert_called_once_with(signal.SIGCHLD, signal.SIG_DFL)

    def test_no_implicit_popen_reaper_or_fabricated_success_status(self) -> None:
        process_handle = hosted.ObserverProcess.__new__(hosted.ObserverProcess)
        with patch.object(hosted.ObserverProcess, "_internal_poll") as poll:
            process_handle.__del__()
        poll.assert_not_called()

    def test_successful_observer_with_remaining_adopted_children_stays_failed(self) -> None:
        child_hold = MagicMock()
        child_hold.pid, child_hold.reaped, child_hold.status = 9001, True, 0
        process = MagicMock()
        process.pid, process.returncode = 9001, None

        def finished(_process: object, _owned: object, _deadline: int, _buffers: object, eof: dict[str, bool]) -> None:
            eof.update(stdout=True, stderr=True)

        bootstrap = {
            "deadlineNs": self.fixture.clock.time + custody.CLEANUP_NS + hosted.NS,
            "interpreter": {"path": "/root-owned-python"},
        }
        with (
            patch.object(hosted, "enable_subreaper"),
            patch.object(hosted, "ObserverProcess", return_value=process),
            patch.object(hosted, "ChildCustody", return_value=child_hold),
            patch.object(hosted, "read_observer", side_effect=finished),
            patch.object(hosted, "child_absent", return_value=False),
            patch.object(hosted, "family_cleanup", return_value={"complete": False, "kernelEchild": False}),
        ):
            result = hosted.capture_observer(Path("/verified-stage"), bootstrap)
        self.assertFalse(result.accepted)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.proof["family"]["complete"])

    def test_observer_capture_refuses_expired_or_reserve_exhausted_entry_without_launch(self) -> None:
        for delta in (0, hosted.NS, custody.CLEANUP_NS):
            with (
                patch.object(hosted, "enable_subreaper") as subreaper,
                patch.object(hosted, "ObserverProcess") as launch,
                self.assertRaises(custody.CustodyError),
            ):
                hosted.capture_observer(Path("/verified-stage"), {"deadlineNs": self.fixture.clock.time + delta})
            subreaper.assert_not_called()
            launch.assert_not_called()

    def capture_fixture(
        self,
        *,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
        stall: bool = False,
        cancel: bool = False,
        unknown: bool = False,
    ) -> tuple[hosted.CaptureOutcome, MagicMock, MagicMock]:
        """Exercise real bounded stream logic with only fake processes/selectors/syscalls."""
        process = MagicMock()
        process.pid, process.returncode = 9001, None
        process.stdout.fileno.return_value, process.stderr.fileno.return_value = 11, 12
        child_hold = MagicMock()
        child_hold.pid, child_hold.reaped, child_hold.status = 9001, False, None

        def reap(_deadline: int) -> bool:
            child_hold.reaped, child_hold.status = True, 0
            return True

        child_hold.reap.side_effect = reap
        streams = {11: bytearray(stdout), 12: bytearray(stderr)}
        registered = {}
        child_hold.dead.side_effect = lambda: not registered
        selector = MagicMock()
        selector.__enter__.return_value = selector

        def register(stream: MagicMock, _event: int, data: object) -> None:
            registered[stream.fileno()] = SimpleNamespace(fileobj=stream, fd=stream.fileno(), data=data)

        selector.register.side_effect = register
        selector.get_map.side_effect = lambda: registered
        selector.unregister.side_effect = lambda stream: registered.pop(stream.fileno())

        def select_ready(_timeout: float) -> list[tuple[object, int]]:
            if cancel:
                hosted._CANCELLATION[0] = True
                return []
            if stall:
                self.fixture.clock.time += hosted.NS
                return []
            return [(key, 1) for key in list(registered.values())]

        selector.select.side_effect = select_ready

        def read(descriptor: int, size: int) -> bytes:
            value = bytes(streams[descriptor][:size])
            del streams[descriptor][:size]
            return value

        family = {"complete": not unknown, "kernelEchild": not unknown, "scope": "observer-descendants-only"}
        bootstrap = {
            "deadlineNs": self.fixture.clock.time + custody.CLEANUP_NS + 10 * hosted.NS,
            "interpreter": {"path": "/root-owned-python"},
        }
        with (
            patch.object(hosted, "enable_subreaper"),
            patch.object(hosted, "ObserverProcess", return_value=process),
            patch.object(hosted, "ChildCustody", return_value=child_hold),
            patch.object(hosted.selectors, "DefaultSelector", return_value=selector),
            patch.object(os, "set_blocking"),
            patch.object(os, "read", side_effect=read),
            patch.object(hosted, "child_absent", return_value=True),
            patch.object(hosted, "family_cleanup", return_value=family),
        ):
            result = hosted.capture_observer(Path("/verified-stage"), bootstrap)
        return result, process, child_hold

    def test_bounded_capture_requires_both_eof_and_independently_recorded_status(self) -> None:
        result, process, child_hold = self.capture_fixture()
        self.assertTrue(result.accepted)
        self.assertTrue(result.proof["stdoutEof"] and result.proof["stderrEof"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(process.returncode, 0)
        child_hold.reap.assert_called_once()

    def test_capture_late_status_conversion_cancellation_is_decided_after_scope_exit(self) -> None:
        original_scope = hosted.cancellation_scope
        original_conversion = os.waitstatus_to_exitcode
        exited, conversions = [False], [0]

        @contextmanager
        def scope() -> Iterator[None]:
            with original_scope():
                yield
            exited[0] = True

        def convert(status: int) -> int:
            conversions[0] += 1
            if conversions[0] > 1:
                self.assertTrue(exited[0])
                hosted._CANCELLATION[0] = True
            return original_conversion(status)

        with (
            patch.object(hosted, "cancellation_scope", side_effect=scope),
            patch.object(os, "waitstatus_to_exitcode", side_effect=convert),
        ):
            result, process, _ = self.capture_fixture()
        self.assertFalse(result.accepted)
        self.assertTrue(result.proof["cancelled"])
        self.assertTrue(result.proof["stdoutEof"] and result.proof["stderrEof"])
        self.assertTrue(result.proof["family"]["complete"])
        self.assertEqual((result.returncode, process.returncode), (0, 0))

    def test_capture_scope_exit_cancellation_rejects_known_clean_completion(self) -> None:
        original_scope = hosted.cancellation_scope

        @contextmanager
        def scope() -> Iterator[None]:
            with original_scope():
                yield
                hosted._CANCELLATION[0] = True

        with patch.object(hosted, "cancellation_scope", side_effect=scope):
            result, _, _ = self.capture_fixture()
        self.assertFalse(result.accepted)
        self.assertTrue(result.proof["cancelled"])
        self.assertTrue(result.proof["statusKnown"])
        self.assertEqual(result.returncode, 0)

    def test_observer_wrapper_scope_exit_cancellation_cannot_leave_status_zero(self) -> None:
        @contextmanager
        def scope() -> Iterator[None]:
            yield
            hosted._CANCELLATION[0] = True

        with (
            patch.object(hosted, "reaper_invariant"),
            patch.object(hosted, "observer_main", return_value=0),
            patch.object(hosted, "cancellation_scope", side_effect=scope),
        ):
            self.assertEqual(hosted.main("/verified-stage"), 1)

    def test_observer_wrapper_preserves_ordinary_status_after_scope_restoration(self) -> None:
        for status in (0, 7):
            with (
                patch.object(hosted, "reaper_invariant"),
                patch.object(hosted, "observer_main", return_value=status),
                self.subTest(status=status),
            ):
                self.assertEqual(hosted.main("/verified-stage"), status)

    def test_each_stream_overflow_is_detected_while_alive_and_never_promoted(self) -> None:
        for stream, cap in (("stdout", hosted.MAX_ARTIFACT), ("stderr", hosted.LIMIT)):
            result, process, _ = self.capture_fixture(**{stream: b"x" * (cap + 1)})
            self.assertFalse(result.accepted)
            self.assertEqual(len(getattr(result, stream)), cap + 1)
            self.assertIsNone(process.returncode)

    def test_stalled_eof_and_cancellation_keep_unknown_completion_failed(self) -> None:
        result, process, _ = self.capture_fixture(stall=True, unknown=True)
        self.assertFalse(result.accepted)
        self.assertFalse(result.proof["stdoutEof"])
        self.assertFalse(result.proof["family"]["complete"])
        self.assertIsNone(process.returncode)
        self.fixture.clock.time = 1_000_000_000
        result, _, _ = self.capture_fixture(cancel=True, unknown=True)
        self.assertFalse(result.accepted)
        self.assertTrue(result.proof["cancelled"])

    def test_family_cleanup_uses_only_kernel_child_membership_and_requires_echild(self) -> None:
        child_hold = MagicMock()
        child_hold.pid, child_hold.reaped = 9002, False

        def cleanup(_deadline: int) -> dict[str, object]:
            child_hold.reaped = True
            return {"lifetime": "proven-dead-reaped"}

        child_hold.cleanup.side_effect = cleanup
        with (
            patch.object(hosted, "direct_children", return_value=(9002,)),
            patch.object(hosted, "ChildCustody", return_value=child_hold),
            patch.object(hosted, "child_absent", return_value=True),
        ):
            result = hosted.family_cleanup({}, self.record.lease.deadline_ns)
        self.assertTrue(result["complete"])
        child_hold.hold.assert_called_once()
        child_hold.cleanup.assert_called_once_with(self.record.lease.deadline_ns)
        with (
            patch.object(hosted, "direct_children", return_value=(9002,)),
            patch.object(hosted, "ChildCustody", return_value=child_hold),
            patch.object(hosted, "child_absent", return_value=True),
        ):
            child_hold.hold.side_effect = ChildProcessError
            result = hosted.family_cleanup({}, self.record.lease.deadline_ns)
        self.assertFalse(result["complete"])

    def test_timespan_refuses_infinite_unknown_or_zero_manager_bounds(self) -> None:
        self.assertEqual(hosted.timespan("1min 5s"), 65 * hosted.NS)
        for value in ("infinity", "", "0", "0s", "5days", "-1s"):
            with self.subTest(value=value), self.assertRaises(custody.CustodyError):
                hosted.timespan(value)


class ToolDiagnosticTests(unittest.TestCase):
    """Exercise original installed-tool operations with entirely synthetic OS facts."""

    def setUp(self) -> None:
        self.artifact = {}
        self.diagnostic = hosted.ToolDiagnostic(self.artifact)
        self.file = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_uid=0,
            st_mode=0o100755,
            st_nlink=1,
            st_size=4,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        self.directory = SimpleNamespace(st_uid=0, st_mode=0o40755)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.lstat = self.stack.enter_context(patch.object(Path, "lstat", autospec=True, side_effect=self.metadata))
        self.open = self.stack.enter_context(patch.object(hosted.os, "open", return_value=77))
        self.fstat = self.stack.enter_context(patch.object(hosted.os, "fstat", return_value=self.file))
        self.read = self.stack.enter_context(patch.object(child, "bytes_at", return_value=b"\x7fELF"))
        self.close = self.stack.enter_context(patch.object(hosted.os, "close"))
        self.run = self.stack.enter_context(patch.object(hosted.subprocess, "run", side_effect=self.version))
        self.remaining = self.stack.enter_context(patch.object(hosted, "remaining", return_value=0.5))

    def metadata(self, path: Path) -> SimpleNamespace:
        return self.file if path.name in {"systemctl", "systemd-run", "env"} else self.directory

    @staticmethod
    def version(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=0, stdout=b"env 1\n" if argv[0].endswith("/env") else b"systemd 260\n", stderr=b""
        )

    def assert_failure(self, site: str, failure: str, operation: object = None) -> Exception:
        if operation is None:

            def operation() -> dict[str, object]:
                return hosted.installed_tools(123, self.diagnostic)

        with self.assertRaises(Exception) as raised:
            operation()
        self.assertEqual(self.artifact, {"systemToolsFailure": {"tool": "SYSTEMCTL", "site": site, "failure": failure}})
        self.assertLessEqual(self.open.call_count, 1)
        self.assertLessEqual(self.run.call_count, 1)
        return raised.exception

    def test_path_refusals_stop_before_open(self) -> None:
        cases = [
            ("PATH_ROOT_OWNER", "/", {"st_uid": 1001}),
            ("PATH_ROOT_MODE", "/", {"st_mode": 0o40777}),
            ("PATH_COMPONENT_OWNER", "/usr", {"st_uid": 1001}),
            ("PATH_COMPONENT_MODE", "/usr", {"st_mode": 0o40777}),
            ("PATH_COMPONENT_TYPE", "/usr", {"st_mode": 0o100755}),
        ]
        for site, target, changes in cases:
            with self.subTest(site=site):
                self.artifact.clear()

                def metadata(path: Path, target: str = target, changes: dict[str, int] = changes) -> SimpleNamespace:
                    if str(path) == target:
                        return SimpleNamespace(**(vars(self.metadata(path)) | changes))
                    return self.metadata(path)

                self.lstat.side_effect = metadata
                self.assert_failure(site, "REFUSED")
                self.open.assert_not_called()
        self.artifact.clear()
        self.assert_failure("PATH_ABSOLUTE", "REFUSED", lambda: hosted.safe_path(Path("relative"), self.diagnostic))

    def test_path_observation_and_symlink_failures(self) -> None:
        for site, target in (("PATH_ROOT_LSTAT", "/"), ("PATH_COMPONENT_LSTAT", "/usr")):
            with self.subTest(site=site):
                self.artifact.clear()

                def metadata(path: Path, target: str = target) -> SimpleNamespace:
                    if str(path) == target:
                        message = "private path and errno"
                        raise OSError(message)
                    return self.metadata(path)

                self.lstat.side_effect = metadata
                self.assert_failure(site, "OS_ERROR")
        self.artifact.clear()
        self.lstat.side_effect = lambda path: (
            SimpleNamespace(st_uid=0, st_mode=0o120777) if str(path) == "/usr" else self.metadata(path)
        )
        with patch.object(Path, "readlink", side_effect=OSError("private link")):
            self.assert_failure("PATH_READLINK", "OS_ERROR")
        self.artifact.clear()
        with patch.object(Path, "readlink", return_value=Path("/usr")) as readlink:
            self.assert_failure("PATH_SYMLINK_LIMIT", "REFUSED")
        self.assertEqual(readlink.call_count, hosted.MAX_LINKS)
        self.open.assert_not_called()

    def test_read_guards_and_operations(self) -> None:
        cases = [
            ("READ_REGULAR_FILE", {"st_mode": 0o40755}),
            ("READ_OWNER", {"st_uid": 1001}),
            ("READ_LINKS", {"st_nlink": 0}),
            ("READ_MODE", {"st_mode": 0o104755}),
        ]
        for site, changes in cases:
            with self.subTest(site=site):
                self.artifact.clear()
                self.open.reset_mock()
                self.close.reset_mock()
                self.fstat.return_value = SimpleNamespace(**(vars(self.file) | changes))
                self.assert_failure(site, "REFUSED")
                self.read.assert_not_called()
                self.close.assert_called_once_with(77)
        self.fstat.return_value = self.file
        for site, mock in (
            ("READ_OPEN", self.open),
            ("READ_INITIAL_FSTAT", self.fstat),
            ("READ_BYTES", self.read),
            ("READ_CLOSE", self.close),
        ):
            with self.subTest(site=site):
                self.artifact.clear()
                self.open.reset_mock()
                mock.side_effect = OSError("secret")
                self.assert_failure(site, "OS_ERROR")
                mock.side_effect = None
        self.run.assert_not_called()

    def test_read_rechecks_preserve_lazy_identity_checks(self) -> None:
        changed = SimpleNamespace(**(vars(self.file) | {"st_ino": 99}))
        for error in (changed, OSError("private fstat")):
            with self.subTest(error=type(error).__name__):
                self.artifact.clear()
                self.open.reset_mock()
                self.lstat.reset_mock()
                self.fstat.side_effect = [self.file, error]
                self.assert_failure("READ_FINAL_FSTAT", "OS_ERROR" if isinstance(error, Exception) else "REFUSED")
                self.assertEqual(self.lstat.call_count, 8)  # Two original safe-path walks; no final lstat.
        self.artifact.clear()
        self.open.reset_mock()
        self.fstat.side_effect = None
        visits = 0

        def metadata(path: Path) -> SimpleNamespace:
            nonlocal visits
            if path.name == "systemctl":
                visits += 1
                final_visit = 3
                if visits == final_visit:
                    return changed
            return self.metadata(path)

        self.lstat.side_effect = metadata
        self.assert_failure("READ_FINAL_LSTAT", "REFUSED")
        self.artifact.clear()
        self.open.reset_mock()
        visits = 0

        def failed_metadata(path: Path) -> SimpleNamespace:
            nonlocal visits
            if path.name == "systemctl":
                visits += 1
                final_visit = 3
                if visits == final_visit:
                    message = "private final lstat"
                    raise OSError(message)
            return self.metadata(path)

        self.lstat.side_effect = failed_metadata
        self.assert_failure("READ_FINAL_LSTAT", "OS_ERROR")
        self.run.assert_not_called()

    def test_canonical_path_and_cleanup_masking_keep_first_failure(self) -> None:
        with patch.object(hosted, "safe_path", return_value=Path("/other")):
            self.assert_failure(
                "READ_CANONICAL_PATH", "REFUSED", lambda: hosted.read_root(Path("/tool"), diagnostic=self.diagnostic)
            )
        self.artifact.clear()
        first = OSError("secret read contents")
        cleanup = OSError("secret close contents")
        self.read.side_effect = first
        self.close.side_effect = cleanup
        self.assertIs(self.assert_failure("READ_BYTES", "OS_ERROR"), cleanup)
        self.run.assert_not_called()
        self.assertNotIn("secret", json.dumps(self.artifact))
        self.assertIs(cleanup.__context__, first)

    def test_recorder_failure_preserves_original_exception_through_nested_fallback(self) -> None:
        original = OSError("original private operation", 123)
        recorder_failure = RuntimeError("private recorder text")
        self.read.side_effect = original
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(hosted.ToolDiagnostic, "record", side_effect=recorder_failure) as record,
            patch.object(sys, "stdout", stdout),
            patch.object(sys, "stderr", stderr),
            self.assertRaises(OSError) as raised,
        ):
            hosted.installed_tools(123, self.diagnostic)
        self.assertIs(raised.exception, original)
        self.assertEqual(raised.exception.args, ("original private operation", 123))
        self.assertEqual(
            record.call_args_list,
            [unittest.mock.call("READ_BYTES", original), unittest.mock.call("TOOL_FACTS", original)],
        )
        self.assertEqual(self.artifact, {})
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.open.assert_called_once()
        self.read.assert_called_once_with(77, child.MAX_INTERPRETER)
        self.close.assert_called_once_with(77)
        self.run.assert_not_called()
        self.remaining.assert_not_called()

    def test_command_failures_keep_original_order_and_bounds(self) -> None:
        operations = [
            ("COMMAND_DEADLINE_ENTRY", "REFUSED", self.remaining, [custody.CustodyError()]),
            ("COMMAND_RUN", "OS_ERROR", self.run, [OSError("secret command")]),
            (
                "COMMAND_RUN",
                "TIMEOUT",
                self.run,
                [hosted.subprocess.TimeoutExpired("private argv", 1, output=b"secret")],
            ),
            ("COMMAND_DEADLINE_COMPLETION", "REFUSED", self.remaining, [0.5, custody.CustodyError()]),
        ]
        for site, category, mock, values in operations:
            with self.subTest(site=site, category=category):
                self.artifact.clear()
                self.open.reset_mock()
                self.run.reset_mock()
                self.remaining.reset_mock()
                mock.side_effect = values
                self.assert_failure(site, category)
                if site == "COMMAND_DEADLINE_ENTRY":
                    self.run.assert_not_called()
                mock.side_effect = self.version if mock is self.run else None
        for site, changes in (
            ("COMMAND_EXIT", {"returncode": 1}),
            ("COMMAND_STDOUT_BOUND", {"stdout": b"x" * (hosted.LIMIT + 1)}),
            ("COMMAND_STDERR_BOUND", {"stderr": b"x" * (hosted.LIMIT + 1)}),
        ):
            with self.subTest(site=site):
                self.artifact.clear()
                self.open.reset_mock()
                self.run.reset_mock()
                self.run.side_effect = None
                self.run.return_value = SimpleNamespace(
                    **({"returncode": 0, "stdout": b"systemd 260\n", "stderr": b""} | changes)
                )
                self.assert_failure(site, "REFUSED")
        self.artifact.clear()
        self.assert_failure(
            "COMMAND_ALLOWLIST", "REFUSED", lambda: hosted.command(["/untrusted"], 123, self.diagnostic)
        )

    def test_version_and_fact_failures_never_scan_later_tools(self) -> None:
        cases = [
            ("VERSION_ASCII", "DECODE", b"\xffsecret"),
            ("VERSION_FIRST_LINE", "EMPTY_OUTPUT", b""),
            ("VERSION_PRINTABLE", "REFUSED", b"secret\x00"),
            ("VERSION_PRINTABLE", "REFUSED", b"x" * 257),
            ("VERSION_SYSTEMD_PATTERN", "REFUSED", b"unexpected secret version"),
        ]
        for site, category, output in cases:
            with self.subTest(site=site, output=output):
                self.artifact.clear()
                self.open.reset_mock()
                self.run.reset_mock()
                self.run.side_effect = None
                self.run.return_value = SimpleNamespace(returncode=0, stdout=output, stderr=b"secret ignored stderr")
                self.assert_failure(site, category)
                self.assertEqual(self.run.call_args.args[0], ["/usr/bin/systemctl", "--version"])
                self.assertNotIn("secret", json.dumps(self.artifact))
        self.artifact.clear()
        self.open.reset_mock()
        self.run.reset_mock()
        self.read.return_value = b"not ELF secret"
        self.assert_failure("ELF_MAGIC", "REFUSED")
        self.run.assert_not_called()
        self.artifact.clear()
        self.open.reset_mock()
        self.read.return_value = b"\x7fELF"
        self.run.side_effect = self.version
        with patch.object(hosted, "asdict", side_effect=ValueError("private identity")):
            self.assert_failure("FACT_SERIALIZATION", "INTERNAL")

    def test_success_facts_calls_and_recheck_equality_are_unchanged(self) -> None:
        calls = MagicMock()
        for name, mock in (
            ("lstat", self.lstat),
            ("open", self.open),
            ("fstat", self.fstat),
            ("read", self.read),
            ("close", self.close),
            ("run", self.run),
            ("remaining", self.remaining),
        ):
            calls.attach_mock(mock, name)
        observed = hosted.installed_tools(123, self.diagnostic)
        original_order = (
            ["lstat"] * 8
            + ["open", "fstat", "read", "fstat", "lstat", "close"]
            + ["lstat"] * 4
            + ["remaining", "run", "remaining"]
        )
        self.assertEqual([call[0] for call in calls.mock_calls], original_order * 3)
        expected = {}
        for path in ("/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/env"):
            expected[path] = {
                "path": path,
                "sha256": hosted.digest(b"\x7fELF"),
                "identity": asdict(hosted.identity(self.file)),
                "version": "env 1" if path.endswith("/env") else "systemd 260",
                "integrity": "preinstalled-root-owned-OS-tool-not-publisher-checksum",
            }
        self.assertEqual(observed, expected)
        self.assertEqual(self.artifact, {})
        self.assertEqual(self.lstat.call_count, 39)
        self.assertEqual(self.fstat.call_count, 6)
        self.assertEqual(self.remaining.call_count, 6)
        self.assertEqual(self.close.call_args_list, [unittest.mock.call(77)] * 3)
        self.assertEqual(self.read.call_args_list, [unittest.mock.call(77, child.MAX_INTERPRETER)] * 3)
        self.assertEqual(
            self.open.call_args_list,
            [unittest.mock.call(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC) for path in expected],
        )
        self.assertEqual(
            self.run.call_args_list,
            [
                unittest.mock.call(
                    [path, "--version"],
                    stdin=hosted.subprocess.DEVNULL,
                    capture_output=True,
                    env=hosted.ENV,
                    cwd="/",
                    timeout=0.5,
                    check=False,
                )
                for path in expected
            ],
        )
        self.assertEqual(hosted.installed_tools(123, hosted.ToolDiagnostic(self.artifact)), observed)
        self.assertEqual(self.artifact, {})

    def test_borrowed_os_tools_accept_stable_positive_link_counts(self) -> None:
        for links in (1, 2, 64):
            with self.subTest(links=links):
                self.file.st_nlink = links
                for mock in (self.open, self.fstat, self.read, self.close, self.run, self.remaining, self.lstat):
                    mock.reset_mock()
                accepted = hosted.installed_tools(123, self.diagnostic)
                self.assertEqual(list(accepted), ["/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/env"])
                self.assertEqual([fact["identity"]["links"] for fact in accepted.values()], [links] * 3)
                self.assertEqual(self.open.call_count, 3)
                self.assertEqual(self.read.call_count, 3)
                self.assertEqual(self.fstat.call_count, 6)
                self.assertEqual(self.lstat.call_count, 39)
                self.assertEqual(self.remaining.call_count, 6)
                self.assertEqual(self.run.call_count, 3)
                self.assertEqual(self.close.call_count, 3)
                self.assertEqual(hosted.installed_tools(123, self.diagnostic), accepted)
                self.assertEqual(self.artifact, {})

    def test_strict_root_reader_keeps_single_link_rule_including_os_names(self) -> None:
        paths = (
            "/usr/bin/systemctl",
            "/usr/bin/systemd-run",
            "/usr/bin/env",
            "/usr/bin/python3",
            "/stage/parser",
            "/stage/source",
            "/stage/control.json",
        )
        for name in paths:
            for links in (0, -1, 2, 64):
                with self.subTest(path=name, links=links):
                    self.artifact.clear()
                    self.open.reset_mock()
                    self.close.reset_mock()
                    self.file.st_nlink = links
                    path = Path(name)

                    def metadata(current: Path, target: Path = path) -> SimpleNamespace:
                        return self.file if current == target else self.directory

                    self.lstat.side_effect = metadata
                    self.assert_failure(
                        "READ_LINKS", "REFUSED", lambda path=path: hosted.read_root(path, diagnostic=self.diagnostic)
                    )
                    self.close.assert_called_once_with(77)
        self.read.assert_not_called()
        self.run.assert_not_called()

    def test_strict_root_reader_accepts_single_link_os_or_control_file(self) -> None:
        for path in (Path("/usr/bin/env"), Path("/stage/control.json")):
            with self.subTest(path=path):
                self.lstat.side_effect = lambda current, target=path: self.file if current == target else self.directory
                raw, info = hosted.read_root(path, diagnostic=self.diagnostic)
                self.assertEqual(raw, b"\x7fELF")
                self.assertEqual(info.links, 1)
        self.assertEqual(self.read.call_args_list, [unittest.mock.call(77, hosted.LIMIT)] * 2)
        self.assertEqual(self.artifact, {})
        self.run.assert_not_called()

    def test_unknown_borrowed_tool_selection_is_refused_before_io(self) -> None:
        for tool in ("/usr/bin/env", "unknown", "env", Path("/usr/bin/env"), None, []):
            with self.subTest(tool=tool), self.assertRaises(custody.CustodyError):
                hosted._read_installed_tool(tool, self.diagnostic)
        self.lstat.assert_not_called()
        self.open.assert_not_called()
        self.fstat.assert_not_called()
        self.read.assert_not_called()
        self.close.assert_not_called()
        self.run.assert_not_called()
        self.remaining.assert_not_called()
        self.assertEqual(self.artifact, {})

    def test_borrowed_reader_retains_other_file_guards_and_refuses_nonpositive_links(self) -> None:
        cases = [
            ("READ_REGULAR_FILE", {"st_mode": 0o40755}),
            ("READ_OWNER", {"st_uid": 1001}),
            ("READ_MODE", {"st_mode": 0o104755}),
            ("READ_MODE", {"st_mode": 0o100777}),
            ("READ_LINKS", {"st_nlink": 0}),
            ("READ_LINKS", {"st_nlink": -1}),
        ]
        self.file.st_nlink = 3
        for site, changes in cases:
            with self.subTest(site=site, changes=changes):
                self.artifact.clear()
                self.open.reset_mock()
                self.close.reset_mock()
                self.fstat.return_value = SimpleNamespace(**(vars(self.file) | changes))
                self.assert_failure(site, "REFUSED")
                self.close.assert_called_once_with(77)
        self.read.assert_not_called()
        self.run.assert_not_called()

    def test_borrowed_reader_detects_link_inode_and_content_metadata_drift(self) -> None:
        self.file.st_nlink = 3
        for field, value in (
            ("st_nlink", 4),
            ("st_nlink", 0),
            ("st_ino", 99),
            ("st_size", 99),
            ("st_mtime_ns", 99),
            ("st_ctime_ns", 99),
        ):
            changed = SimpleNamespace(**(vars(self.file) | {field: value}))
            for site in ("READ_FINAL_FSTAT", "READ_FINAL_LSTAT"):
                with self.subTest(field=field, value=value, site=site):
                    self.artifact.clear()
                    self.open.reset_mock()
                    self.read.reset_mock()
                    self.close.reset_mock()
                    self.lstat.side_effect = self.metadata
                    self.fstat.side_effect = [self.file, changed] if site == "READ_FINAL_FSTAT" else None
                    visits = 0
                    if site == "READ_FINAL_LSTAT":

                        def metadata(path: Path, final: SimpleNamespace = changed) -> SimpleNamespace:
                            nonlocal visits
                            if path.name == "systemctl":
                                visits += 1
                                final_visit = 3
                                if visits == final_visit:
                                    return final
                            return self.metadata(path)

                        self.lstat.side_effect = metadata
                    self.assert_failure(site, "REFUSED")
                    self.read.assert_called_once_with(77, child.MAX_INTERPRETER)
                    self.close.assert_called_once_with(77)
        self.run.assert_not_called()

    def test_borrowed_reader_resolves_alias_but_versions_original_fixed_name(self) -> None:
        self.file.st_nlink = 3
        original, resolved = Path("/usr/bin/env"), Path("/usr/lib/coreutils/env")

        def metadata(path: Path) -> SimpleNamespace:
            if path == original:
                return SimpleNamespace(st_uid=0, st_mode=0o120777)
            return self.metadata(path)

        self.lstat.side_effect = metadata
        with patch.object(Path, "readlink", return_value=resolved) as readlink:
            accepted = hosted.installed_tools(123, self.diagnostic)
        self.assertEqual(accepted[str(original)]["path"], str(resolved))
        self.assertEqual(accepted[str(original)]["identity"]["links"], 3)
        self.assertEqual(readlink.call_count, 2)
        self.assertEqual(self.open.call_args.args[0], resolved)
        self.assertEqual(self.run.call_args.args[0], [str(original), "--version"])
        self.assertEqual(self.artifact, {})

    def test_borrowed_content_hash_drift_still_refuses_final_observer_comparison(self) -> None:
        self.file.st_nlink = 3
        self.file.st_size = 7
        self.read.side_effect = [b"\x7fELFone"] * 3 + [b"\x7fELFtwo"] * 3
        bootstrap = {"uid": 1001, "gid": 1001, "deadlineNs": 123}
        output = io.StringIO()
        with (
            patch.object(hosted.os, "umask"),
            patch.object(hosted.os, "geteuid", return_value=0),
            patch.object(hosted, "read_root", return_value=(json.dumps(bootstrap).encode(), None)),
            patch.object(hosted, "audit_stage", return_value={}),
            patch.object(hosted, "write_denial_probe", return_value={}),
            patch.object(hosted, "Clock"),
            patch.object(hosted, "cycle") as cycle,
            patch.object(hosted.time, "monotonic_ns", return_value=0),
            patch.object(sys, "stdout", output),
        ):
            self.assertEqual(hosted.observer_main("/synthetic-stage"), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["outcome"], "retained-unknown")
        self.assertEqual(cycle.call_count, 2)
        self.assertEqual(self.read.call_count, 6)
        self.assertEqual(self.run.call_count, 6)
        self.assertNotIn("systemToolsFailure", result)
        self.assertEqual(result["systemTools"]["/usr/bin/env"]["sha256"], hosted.digest(b"\x7fELFone"))
        self.assertEqual(result["systemTools"]["/usr/bin/env"]["identity"]["links"], 3)
        self.assertEqual(result["qualification"], "none")
        self.assertFalse(result["policy_load_run"])
        self.assertFalse(result["container_run"])

    def test_each_tool_identity_and_observer_failure_artifact(self) -> None:
        for position, tool in enumerate(("SYSTEMCTL", "SYSTEMD_RUN", "ENV")):
            with self.subTest(tool=tool):
                self.artifact.clear()
                self.run.reset_mock()
                self.read.side_effect = [b"\x7fELF"] * position + [b"private invalid file"]
                with self.assertRaises(custody.CustodyError):
                    hosted.installed_tools(123, self.diagnostic)
                self.assertEqual(
                    self.artifact["systemToolsFailure"], {"tool": tool, "site": "ELF_MAGIC", "failure": "REFUSED"}
                )
                self.assertEqual(self.run.call_count, position)
        bootstrap = {"uid": 1001, "gid": 1001, "deadlineNs": 123}
        output = io.StringIO()

        def fail(_deadline: int, diagnostic: hosted.ToolDiagnostic) -> None:
            with hosted.tool_site(diagnostic, "READ_OPEN"):
                message = "private exception"
                raise OSError(message)

        with (
            patch.object(hosted.os, "umask"),
            patch.object(hosted.os, "geteuid", return_value=0),
            patch.object(hosted, "read_root", return_value=(json.dumps(bootstrap).encode(), None)),
            patch.object(hosted, "installed_tools", side_effect=fail),
            patch.object(hosted, "audit_stage") as audit,
            patch.object(hosted, "write_denial_probe") as probe,
            patch.object(sys, "stdout", output),
        ):
            self.assertEqual(hosted.observer_main("/synthetic-stage"), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(
            result["systemToolsFailure"], {"tool": "SYSTEMCTL", "site": "READ_OPEN", "failure": "OS_ERROR"}
        )
        self.assertNotIn("systemTools", result)
        self.assertNotIn("private exception", output.getvalue())
        audit.assert_not_called()
        probe.assert_not_called()


class PreparationWireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = {
            "schema": 1,
            "diagnosticOnly": True,
            "phase": "prepare",
            "ns": 17,
            "custodyLocator": None,
            "childPending": False,
        }
        self.detail = {"schema": 1, "context": "CUSTODY", "site": "C_CREATE_W02", "failure": "OS_ERROR"}

    def test_build_status_wire_accepts_eighteen_pairs_only_with_exact_original_refusal(self) -> None:
        fault = {"schema": 1, "context": "CHILD_PARENT", "site": "B_BUILD_STATUS_REFUSAL", "failure": "REFUSED"}
        for termination in (
            "EXIT_NONZERO",
            "SIGNAL_ALRM",
            "SIGNAL_XCPU",
            "SIGNAL_XFSZ",
            "SIGNAL_KILL",
            "OTHER_SIGNAL",
        ):
            for receipt in ("MATCH", "EMPTY", "MISMATCH"):
                observation = {"schema": 1, "terminationForm": termination, "receiptCheck": receipt}
                record = {**self.base, "workFailure": fault, "buildStatusObservation": observation}
                self.assertEqual(hosted._failure_diagnostic(record), record)
                self.assertLessEqual(len(json.dumps(observation).encode("ascii")), child.BUILD_STATUS_LIMIT)
        observation = {"schema": 1, "terminationForm": "SIGNAL_KILL", "receiptCheck": "MATCH"}
        invalid = (
            None,
            [],
            {},
            {**observation, "schema": True},
            {**observation, "schema": 1.0},
            {**observation, "terminationForm": "SIGKILL"},
            {**observation, "receiptCheck": "UNOBSERVED"},
            {**observation, "receiptCheck": 1},
            {**observation, "raw": "private"},
        )
        for value in invalid:
            self.assertEqual(
                hosted._failure_diagnostic({**self.base, "workFailure": fault, "buildStatusObservation": value}),
                {**self.base, "workFailure": fault},
            )
        for detail in (None, {}, self.detail, {**fault, "failure": "OS_ERROR"}):
            record = {**self.base, "workFailure": detail, "buildStatusObservation": observation}
            self.assertNotIn("buildStatusObservation", hosted._failure_diagnostic(record))
        self.assertEqual(hosted._failure_diagnostic({**self.base, "buildStatusObservation": observation}), self.base)
        for phase in ("binding", "owner", "close"):
            base = {**self.base, "phase": phase}
            self.assertEqual(
                hosted._failure_diagnostic({**base, "workFailure": fault, "buildStatusObservation": observation}), base
            )

    def test_extra_validation_failure_keeps_original_single_write_and_duplicate_rejection(self) -> None:
        fault = ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED")
        control = hosted.Control.__new__(hosted.Control)
        control.phase, control.write = "prepare", MagicMock()
        with patch.object(hosted.time, "monotonic_ns", return_value=17):
            control.failure(OSError(), 100, work_failure=fault, build_status=("SIGNAL_ALRM", "EMPTY"))
        value = control.write.call_args.args[1]
        self.assertEqual(
            value["buildStatusObservation"], {"schema": 1, "terminationForm": "SIGNAL_ALRM", "receiptCheck": "EMPTY"}
        )
        control.write.assert_called_once()
        control.write.reset_mock()
        with patch.object(child, "build_status_observation", side_effect=MemoryError):
            control.failure(OSError(), 100, work_failure=fault, build_status=("SIGNAL_ALRM", "EMPTY"))
            normalized = hosted._failure_diagnostic(value)
        self.assertIn("workFailure", normalized)
        self.assertNotIn("buildStatusObservation", normalized)
        self.assertIn("workFailure", control.write.call_args.args[1])
        self.assertNotIn("buildStatusObservation", control.write.call_args.args[1])
        control.write.assert_called_once()
        control.write.reset_mock()
        control.write.side_effect = OSError
        with self.assertRaises(OSError):
            control.failure(OSError(), 100, work_failure=fault, build_status=("SIGNAL_ALRM", "EMPTY"))
        control.write.assert_called_once()
        control.path, control.check = Path("/synthetic"), MagicMock()
        raw = json.dumps(value).replace('"receiptCheck": "EMPTY"', '"receiptCheck": "EMPTY", "receiptCheck": "MATCH"')
        with (
            patch.object(hosted, "read_root", return_value=(raw.encode(), None)),
            self.assertRaises(custody.CustodyError),
        ):
            control.read("failure.json")

    def test_optional_detail_is_closed_and_invalid_detail_keeps_only_valid_base(self) -> None:
        self.assertEqual(hosted._failure_diagnostic(self.base), self.base)
        self.assertEqual(
            hosted._failure_diagnostic({**self.base, "workFailure": self.detail}),
            {**self.base, "workFailure": self.detail},
        )
        invalid = [
            None,
            [],
            {},
            {**self.detail, "schema": True},
            {**self.detail, "schema": 1.0},
            {**self.detail, "context": "HOSTED"},
            {**self.detail, "site": "unknown"},
            {**self.detail, "failure": "private error"},
            {**self.detail, "raw": "private output"},
            {**self.detail, "site": "x" * (child.WORK_FAILURE_LIMIT + 1)},
            {"schema": 1, "context": "CHILD_PARENT", "site": "B_BUILD_STATUS_REFUSAL", "failure": "OS_ERROR"},
        ]
        for detail in invalid:
            with self.subTest(detail=detail):
                self.assertEqual(hosted._failure_diagnostic({**self.base, "workFailure": detail}), self.base)
        base = {**self.base, "phase": "binding"}
        self.assertEqual(hosted._failure_diagnostic({**base, "workFailure": self.detail}), base)

    def test_invalid_base_unknown_root_or_duplicate_keys_keep_existing_refusal(self) -> None:
        for value in (
            None,
            [],
            {**self.base, "unknown": 1},
            {**self.base, "schema": 0},
            {key: value for key, value in self.base.items() if key != "childPending"},
        ):
            with self.subTest(value=value), self.assertRaises(custody.CustodyError):
                hosted._failure_diagnostic(value)
        control = hosted.Control.__new__(hosted.Control)
        control.path, control.check = Path("/synthetic"), MagicMock()
        raw = (
            json.dumps({**self.base, "workFailure": self.detail})
            .replace('"site": "C_CREATE_W02"', '"site": "C_CREATE_W02", "site": "C_CREATE_W02"')
            .encode()
        )
        with patch.object(hosted, "read_root", return_value=(raw, None)), self.assertRaises(custody.CustodyError):
            control.read("failure.json")

    def test_single_failure_write_keeps_legacy_default_and_immutable_optional_input(self) -> None:
        control = hosted.Control.__new__(hosted.Control)
        control.phase, control.write = "prepare", MagicMock()
        fault = OSError("private exception path uid")
        with patch.object(hosted.time, "monotonic_ns", return_value=17):
            control.failure(fault, 100)
            self.assertEqual(set(control.write.call_args.args[1]), set(self.base))
            control.write.reset_mock()
            control.failure(fault, 100, work_failure=("CUSTODY", "C_CREATE_W02", "OS_ERROR"))
        self.assertEqual(control.write.call_count, 1)
        value = control.write.call_args.args[1]
        self.assertEqual(value["workFailure"], self.detail)
        self.assertTrue(value["diagnosticOnly"])
        self.assertNotIn("private", json.dumps(value))
        self.assertLessEqual(len(json.dumps(value["workFailure"]).encode()), child.WORK_FAILURE_LIMIT)
        for phase in ("binding", "owner"):
            control.phase = phase
            control.failure(fault, 100, work_failure=("CUSTODY", "C_CREATE_W02", "OS_ERROR"))
            self.assertNotIn("workFailure", control.write.call_args.args[1])
        control.phase = "prepare"
        control.write.reset_mock()
        control.write.side_effect = OSError("private failure capture")
        with self.assertRaises(OSError):
            control.failure(fault, 100, work_failure=("CUSTODY", "C_CREATE_W02", "OS_ERROR"))
        self.assertEqual(control.write.call_count, 1)

    def test_opaque_boot_and_distro_calls_are_unobserved(self) -> None:
        for kind in ("boot", "distro"):
            with self.subTest(kind=kind):
                observer = child.WorkObserver()
                fault = OSError("private opaque cleanup")
                with (
                    patch.object(Path, "read_text", side_effect=fault),
                    child.observing(observer),
                    self.assertRaises(OSError) as raised,
                ):
                    if kind == "boot":
                        clock = hosted.Clock.__new__(hosted.Clock)
                        clock.boot, clock.observer = "old", observer
                        clock.boot_id()
                    else:
                        host = hosted.HostPort.__new__(hosted.HostPort)
                        host.observer = observer
                        with patch.object(hosted, "safe_path", side_effect=lambda path, **_kwargs: path):
                            host.observe(MagicMock())
                self.assertIs(raised.exception, fault)
                self.assertIsNone(observer.snapshot())

    def test_shared_read_record_call_stays_default_none(self) -> None:
        store = MagicMock()
        marker = object()
        store.load.return_value = marker
        context = MagicMock()
        context.__enter__.return_value = store
        with patch.object(custody, "_store", return_value=context) as open_store:
            self.assertIs(hosted.read_record(marker), marker)
        open_store.assert_called_once_with(marker)


class CoordinatorObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hosted = HostedTests(methodName="runTest")
        self.hosted.setUp()
        self.addCleanup(self.hosted.doCleanups)
        self.fixture = self.hosted.fixture
        self.control = hosted.Control.__new__(hosted.Control)
        self.control.phase = "control"
        self.control.mark = SimpleNamespace(st_dev=1, st_ino=2)
        self.stale = ("CUSTODY", "C_CREATE_W02", "OS_ERROR")
        self.control.preparation_failure = self.stale
        self.binding_error = RuntimeError("private later binding")
        self.control.write = MagicMock(side_effect=self.binding_error)
        self.bootstrap = {
            "context": {"candidate": "a" * 40, "head": "b" * 40, "base": "c" * 40, "run": "17", "attempt": "2"},
            "uid": 1001,
            "gid": 1002,
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.close = self.stack.enter_context(patch.object(hosted.os, "close"))
        self.stack.enter_context(patch.object(hosted.os, "open", side_effect=(71, 72, 73, 74, 75, 76)))
        self.stack.enter_context(patch.object(hosted, "Clock", return_value=self.fixture.clock))
        self.stack.enter_context(
            patch.object(hosted, "HostPort", return_value=SimpleNamespace(admission=self.fixture.admission))
        )
        self.stack.enter_context(patch.object(hosted, "process", return_value=self.hosted.record.lease.coordinator))
        self.read = self.stack.enter_context(patch.object(hosted, "read_record", return_value=self.hosted.record))
        self.prepare = self.stack.enter_context(
            patch.object(custody, "_prepare_observed", return_value=self.hosted.locator)
        )

    def run_coordinator(self) -> int:
        return hosted.coordinator_main(
            Path("/synthetic"),
            self.control,
            self.bootstrap,
            self.hosted.record.lease.coordinator,
            self.fixture.clock.time + hosted.CYCLE_NS,
        )

    def test_status_pair_resets_and_survives_cleanup_without_masking_original_publication(self) -> None:
        status_fixture = fixtures.BuildStatusObservationTests(methodName="runTest")
        status_fixture.setUp()
        self.original = OSError("private prepare")
        release = OSError("private cleanup")

        def prepare(_arguments: object, observer: child.WorkObserver | None) -> None:
            self.assertIsNone(self.control.preparation_failure)
            self.assertIsNone(self.control.preparation_status)
            self.assertIs(type(observer), child.WorkObserver)
            claim = child.refused(observer, "CHILD_PARENT", "B_BUILD_STATUS_REFUSAL")
            observer.observe_status(claim, 1, status_fixture.lease, status_fixture.proof)
            observer.finish_status(completed=True)
            raise self.original

        self.control.preparation_status = ("SIGNAL_KILL", "EMPTY")
        self.prepare.side_effect, self.close.side_effect = prepare, release
        with patch.object(child, "_runtime_qualified", return_value=True), self.assertRaises(OSError) as raised:
            self.run_coordinator()
        self.assertIs(raised.exception, release)
        self.assertEqual(self.control.preparation_status, ("EXIT_NONZERO", "MATCH"))
        self.assertEqual(self.control.preparation_failure, ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED"))
        self.close.side_effect = None
        with (
            patch.object(child, "_runtime_qualified", return_value=True),
            patch.object(hosted.os, "open", side_effect=(71, 72, 73)),
            patch.object(hosted, "_sealed_build_status", side_effect=MemoryError),
            self.assertRaises(OSError) as raised,
        ):
            self.run_coordinator()
        self.assertIs(raised.exception, self.original)
        self.assertEqual(self.control.preparation_failure, ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED"))
        self.assertIsNone(self.control.preparation_status)

    def work_fault(self, _arguments: object, observer: child.WorkObserver | None) -> None:
        self.assertIsNone(self.control.preparation_failure)
        with child.work(observer, "CUSTODY", "C_CREATE_W02", (custody.CustodyError, child.ChildError)):
            raise self.original

    def test_guard_publication_reset_and_new_snapshot_fault_preserve_original_pair_and_masking(self) -> None:
        status_fixture = fixtures.BuildStatusObservationTests(methodName="runTest")
        status_fixture.setUp()
        self.original = OSError("private prepare")
        release = OSError("private release")

        def prepare(_arguments: object, observer: child.WorkObserver | None) -> None:
            self.assertIsNone(self.control.preparation_guard)
            claim = child.refused(observer, "CHILD_PARENT", "B_BUILD_STATUS_REFUSAL")
            observer.observe_status(
                claim, 111, status_fixture.lease, status_fixture.proof, sources=fixtures.guard_source_fixture()
            )
            observer.finish_status(completed=True)
            raise self.original

        self.control.preparation_guard = "FD_NOT_ALLOWLISTED"
        self.prepare.side_effect, self.close.side_effect = prepare, release
        with patch.object(child, "_runtime_qualified", return_value=True), self.assertRaises(OSError) as raised:
            self.run_coordinator()
        self.assertIs(raised.exception, release)
        self.assertEqual(self.control.preparation_guard, "FD_FSTAT_NON_EBADF")
        self.assertEqual(self.control.preparation_status, ("EXIT_NONZERO", "MATCH"))
        self.assertEqual(self.control.preparation_failure, ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED"))
        self.close.side_effect = None
        with (
            patch.object(hosted.os, "open", side_effect=(71, 72, 73)),
            patch.object(child, "_runtime_qualified", return_value=True),
            patch.object(child.WorkObserver, "guard_snapshot", side_effect=MemoryError),
            self.assertRaises(OSError) as raised,
        ):
            self.run_coordinator()
        self.assertIs(raised.exception, self.original)
        self.assertIsNone(self.control.preparation_guard)
        self.assertEqual(self.control.preparation_status, ("EXIT_NONZERO", "MATCH"))
        self.assertEqual(self.control.preparation_failure, ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED"))
        self.prepare.side_effect = None
        with patch.object(hosted.os, "open", side_effect=(71, 72, 73)), self.assertRaises(RuntimeError):
            self.run_coordinator()
        self.assertIsNone(self.control.preparation_guard)
        self.assertIsNone(self.control.preparation_status)
        self.assertIsNone(self.control.preparation_failure)

    def test_first_work_tuple_survives_original_exitstack_masking(self) -> None:
        self.original, release = OSError("private prepare"), OSError("private release")
        self.prepare.side_effect = self.work_fault
        self.close.side_effect = release
        with self.assertRaises(OSError) as raised:
            self.run_coordinator()
        self.assertIs(raised.exception, release)
        self.assertEqual(self.control.preparation_failure, self.stale)
        self.assertEqual(self.control.phase, "prepare")
        self.assertFalse(any(type(value) is child.WorkObserver for value in vars(self.control).values()))
        self.assertEqual(self.close.call_count, len(custody.LEAVES))
        self.control.write.reset_mock()
        self.control.write.side_effect = None
        self.control.failure(raised.exception, 100, work_failure=self.control.preparation_failure)
        self.assertEqual(self.control.write.call_count, 1)
        self.assertEqual(self.control.write.call_args.args[1]["workFailure"]["site"], "C_CREATE_W02")

    def test_reuse_clears_stale_tuple_and_later_binding_failure_has_no_work_detail(self) -> None:
        self.original = OSError("private prepare")
        self.prepare.side_effect = self.work_fault
        with self.assertRaises(OSError):
            self.run_coordinator()
        self.assertEqual(self.control.preparation_failure, self.stale)
        self.prepare.side_effect = None
        with self.assertRaises(RuntimeError) as raised:
            self.run_coordinator()
        self.assertIs(raised.exception, self.binding_error)
        self.assertIsNone(self.control.preparation_failure)
        self.assertEqual(self.control.phase, "binding")
        self.control.write.side_effect = None
        self.control.write.reset_mock()
        self.control.failure(raised.exception, 100, work_failure=self.stale)
        self.assertNotIn("workFailure", self.control.write.call_args.args[1])
        self.assertEqual(self.control.write.call_count, 1)

    def test_snapshot_seal_and_constructor_failures_preserve_original_and_single_capture(self) -> None:
        for target in ("snapshot", "seal", "new_observer"):
            with self.subTest(target=target):
                self.control.preparation_failure = self.stale
                self.original = OSError("private prepare")
                self.prepare.side_effect = self.work_fault
                self.close.reset_mock()
                self.control.write.reset_mock()
                owner = child if target == "new_observer" else child.WorkObserver
                effect = None if target == "new_observer" else RuntimeError("private diagnostic")
                kwargs = {"return_value": None} if target == "new_observer" else {"side_effect": effect}
                # Each case gets fresh fake descriptors; no native close/open is performed.
                with (
                    patch.object(hosted.os, "open", side_effect=(71, 72, 73)),
                    patch.object(owner, target, **kwargs),
                    self.assertRaises(OSError) as raised,
                ):
                    self.run_coordinator()
                self.assertIs(raised.exception, self.original)
                self.assertIsNone(self.control.preparation_failure)
                self.control.write.side_effect = None
                self.control.failure(raised.exception, 100, work_failure=self.control.preparation_failure)
                self.assertEqual(self.control.write.call_count, 1)
                self.assertNotIn("workFailure", self.control.write.call_args.args[1])

    def test_immediate_readback_can_author_before_binding(self) -> None:
        def read(_locator: object, observer: child.WorkObserver | None = None) -> None:
            with child.work(observer, "CUSTODY", "C_STORE_LOAD_G01", (custody.CustodyError, child.ChildError)):
                custody._need(value=False)

        self.read.side_effect = read
        with self.assertRaises(custody.CustodyError):
            self.run_coordinator()
        self.assertEqual(self.control.preparation_failure, ("CUSTODY", "C_STORE_LOAD_G01", "REFUSED"))
        self.assertEqual(self.control.phase, "prepare")
        self.control.write.assert_not_called()


class ComposedClockObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.CustodyTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def clock(self, observer: child.WorkObserver) -> hosted.Clock:
        with patch.object(Path, "read_text", return_value=fixtures.BOOT):
            return hosted.Clock(observer=observer)

    def invoke(self, kind: str, clock: hosted.Clock, observer: child.WorkObserver) -> None:
        f = self.fixture
        if kind == "initial":
            custody._initial(
                clock, fixtures.BOOT, f.request.original_deadline_ns - custody.CLEANUP_NS, observer=observer
            )
        else:
            custody._prepare_observed(
                custody._PrepareArgs(f.admission, f.request, tuple(f.fds), f.host, clock), observer
            )

    def test_composed_boot_read_and_internal_release_exceptions_remain_unobserved(self) -> None:
        for kind, target in (("initial", 1), ("initial", 2), ("prepare", 7), ("prepare", 8)):
            for failure_kind in ("read", "release"):
                with self.subTest(kind=kind, target=target, failure=failure_kind):
                    observer = child.WorkObserver()
                    clock = self.clock(observer)
                    original = OSError("private opaque boot " + failure_kind)
                    calls = 0

                    def read(
                        *_args: object, target: int = target, original: OSError = original, **_kwargs: object
                    ) -> str:
                        nonlocal calls
                        calls += 1
                        if calls == target:
                            raise original
                        return fixtures.BOOT

                    def opened(
                        *_args: object, target: int = target, original: OSError = original, **_kwargs: object
                    ) -> MagicMock:
                        nonlocal calls
                        calls += 1
                        stream = MagicMock()
                        stream.__enter__.return_value = stream
                        stream.read.return_value = fixtures.BOOT
                        stream.__exit__.return_value = False
                        if calls == target:
                            stream.__exit__.side_effect = original
                        return stream

                    owner = "read_text" if failure_kind == "read" else "open"
                    effect = read if failure_kind == "read" else opened
                    with (
                        patch.object(hosted.time, "monotonic_ns", return_value=self.fixture.clock.time),
                        patch.object(Path, owner, side_effect=effect),
                        child.observing(observer),
                        self.assertRaises(OSError) as raised,
                    ):
                        self.invoke(kind, clock, observer)
                    self.assertIs(raised.exception, original)
                    self.assertIsNone(observer.snapshot())
                    self.assertEqual(calls, target)

    def test_actual_false_composed_predicates_keep_original_lazy_read_counts(self) -> None:
        for kind, time_call, expected_site, reads in (
            ("initial", 1, "C_INITIAL_G01", 1),
            ("prepare", 3, "C_PREPARE_UNUSED_G04", 7),
        ):
            with self.subTest(kind=kind):
                observer = child.WorkObserver()
                clock = self.clock(observer)
                calls = 0
                cutoff = self.fixture.request.original_deadline_ns - custody.CLEANUP_NS

                def now(*, cutoff: int = cutoff, time_call: int = time_call) -> int:
                    nonlocal calls
                    calls += 1
                    return cutoff if calls == time_call else self.fixture.clock.time

                with (
                    patch.object(hosted.time, "monotonic_ns", side_effect=now),
                    patch.object(Path, "read_text", return_value=fixtures.BOOT) as read,
                    child.observing(observer),
                    self.assertRaises(custody.CustodyError),
                ):
                    self.invoke(kind, clock, observer)
                self.assertEqual(
                    observer.snapshot(),
                    {"schema": 1, "context": "CUSTODY", "site": expected_site, "failure": "REFUSED"},
                )
                self.assertEqual(calls, time_call)
                self.assertEqual(read.call_count, reads)

    def test_owned_inner_clock_fault_survives_without_composed_fallback(self) -> None:
        for kind, target, reads in (("initial", 1, 0), ("prepare", 3, 6)):
            with self.subTest(kind=kind):
                observer = child.WorkObserver()
                clock = self.clock(observer)
                original = OSError("private owned monotonic operation")
                calls = 0

                def now(*, target: int = target, original: OSError = original) -> int:
                    nonlocal calls
                    calls += 1
                    if calls == target:
                        raise original
                    return self.fixture.clock.time

                with (
                    patch.object(hosted.time, "monotonic_ns", side_effect=now),
                    patch.object(Path, "read_text", return_value=fixtures.BOOT) as read,
                    child.observing(observer),
                    self.assertRaises(OSError) as raised,
                ):
                    self.invoke(kind, clock, observer)
                self.assertIs(raised.exception, original)
                self.assertEqual(
                    observer.snapshot(),
                    {"schema": 1, "context": "HOSTED", "site": "H_CLOCK_NOW_NS_W01", "failure": "OS_ERROR"},
                )
                self.assertEqual(calls, target)
                self.assertEqual(read.call_count, reads)


class GuardPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fault = {"schema": 1, "context": "CHILD_PARENT", "site": "B_BUILD_STATUS_REFUSAL", "failure": "REFUSED"}
        self.pair = {"schema": 1, "terminationForm": "EXIT_NONZERO", "receiptCheck": "MATCH"}
        self.declaration = {"schema": 1, "category": "RESULT_TYPE_OR_SIZE"}
        self.base = {
            "schema": 1,
            "diagnosticOnly": True,
            "phase": "prepare",
            "ns": 17,
            "custodyLocator": None,
            "childPending": False,
            "workFailure": self.fault,
            "buildStatusObservation": self.pair,
        }
        self.triple = ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL", "REFUSED")

    def control(self) -> hosted.Control:
        control = hosted.Control.__new__(hosted.Control)
        control.phase = "prepare"
        control.write = MagicMock(side_effect=lambda _name, value, _deadline: hosted.encoded(value))
        return control

    def control_case(
        self, target: int, category: str
    ) -> tuple[dict[str, object], hosted.Control, custody.CustodyError]:
        locator = custody.Locator("", custody.DirectoryIdentity(1, 2))
        base = {**self.base, "custodyLocator": asdict(locator)}
        size = len(json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        locator = replace(locator, nonce="x" * (target - size))
        base["custodyLocator"] = asdict(locator)
        control = self.control()
        fault = custody.CustodyError(locator, child_pending=False)
        with patch.object(hosted.time, "monotonic_ns", return_value=17):
            control.failure(
                fault, 100, work_failure=self.triple, build_status=("EXIT_NONZERO", "MATCH"), child_guard=category
            )
        return base, control, fault

    def test_control_legacy_and_augmented_complete_caps_preserve_one_original_write(self) -> None:
        for category in ("FD_FSTAT_NON_EBADF", "FD_NOT_ALLOWLISTED", "RESULT_TYPE_OR_SIZE"):
            for target in (hosted.LIMIT - 1, hosted.LIMIT):
                with self.subTest(category=category, legacy=target):
                    base, control, _ = self.control_case(target, category)
                    self.assertEqual(control.write.call_args.args[1], base)
                    control.write.assert_called_once()
            control = self.control()
            locator = custody.Locator("", custody.DirectoryIdentity(1, 2))
            base = {**self.base, "custodyLocator": asdict(locator)}

            def body(value: object) -> bytes:
                return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

            declaration = {"schema": 1, "category": category}
            overhead = len(body({**base, "childGuardDeclaration": declaration})) - len(body(base))
            for target in (hosted.LIMIT - 1, hosted.LIMIT, hosted.LIMIT + 1):
                with self.subTest(category=category, augmented=target):
                    base, control, _ = self.control_case(target - overhead, category)
                    expected = {**base, "childGuardDeclaration": declaration} if target <= hosted.LIMIT else base
                    self.assertEqual(control.write.call_args.args[1], expected)
                    control.write.assert_called_once()
            oversized = replace(
                locator, nonce="x" * (hosted.LIMIT + 1 - len(body(base)) + len(base["custodyLocator"]["nonce"]))
            )
            control = self.control()
            with (
                patch.object(hosted.time, "monotonic_ns", return_value=17),
                self.assertRaises(custody.CustodyError),
            ):
                control.failure(
                    custody.CustodyError(oversized, child_pending=False),
                    100,
                    work_failure=self.triple,
                    build_status=("EXIT_NONZERO", "MATCH"),
                    child_guard=category,
                )
            control.write.assert_called_once()

    def test_wire_dependencies_unknown_roots_and_new_errors_keep_both_original_facts(self) -> None:
        valid = {**self.base, "childGuardDeclaration": self.declaration}
        self.assertEqual(hosted._failure_diagnostic(valid), valid)
        for value in (
            None,
            [],
            {},
            {**self.declaration, "schema": True},
            {**self.declaration, "schema": 1.0},
            {**self.declaration, "category": "actual-fd"},
            {**self.declaration, "raw": "private"},
        ):
            self.assertEqual(hosted._failure_diagnostic({**self.base, "childGuardDeclaration": value}), self.base)
        for dependency in (
            {"phase": "binding"},
            {"workFailure": {}},
            {"buildStatusObservation": {}},
            {"buildStatusObservation": {**self.pair, "receiptCheck": "EMPTY"}},
        ):
            self.assertNotIn("childGuardDeclaration", hosted._failure_diagnostic({**valid, **dependency}))
        with self.assertRaises(custody.CustodyError):
            hosted._failure_diagnostic({**valid, "unknown": True})
        for owner, name in (
            (child, "guard_declaration"),
            (hosted, "_publication_shape"),
            (hosted, "_control_declaration_fits"),
        ):
            control = self.control()
            with (
                patch.object(owner, name, side_effect=MemoryError),
                patch.object(hosted.time, "monotonic_ns", return_value=17),
            ):
                control.failure(
                    OSError(),
                    100,
                    work_failure=self.triple,
                    build_status=("EXIT_NONZERO", "MATCH"),
                    child_guard="RESULT_TYPE_OR_SIZE",
                )
            self.assertEqual(control.write.call_args.args[1], {**self.base, "childPending": None})
            control.write.assert_called_once()
        with patch.object(hosted, "_publication_shape", side_effect=AssertionError) as shape:
            self.control().failure(OSError(), 100)
            shape.assert_not_called()
        for category in child.GUARD_CATEGORIES:
            self.assertLessEqual(len(json.dumps({"schema": 1, "category": category}).encode("ascii")), 96)
        control = self.control()
        control.path, control.check = Path("/synthetic"), MagicMock()
        raw = json.dumps(valid).replace(
            '"category": "RESULT_TYPE_OR_SIZE"', '"category": "RESULT_TYPE_OR_SIZE", "category": "FD_NOT_ALLOWLISTED"'
        )
        with (
            patch.object(hosted, "read_root", return_value=(raw.encode(), None)),
            self.assertRaises(custody.CustodyError),
        ):
            control.read("failure.json")
        control = self.control()
        control.write.side_effect = OSError
        with self.assertRaises(OSError):
            control.failure(
                OSError(),
                100,
                work_failure=self.triple,
                build_status=("EXIT_NONZERO", "MATCH"),
                child_guard="RESULT_TYPE_OR_SIZE",
            )
        control.write.assert_called_once()

    def test_constructor_resets_closed_outputs_before_its_original_invalid_path_refusal(self) -> None:
        control = self.control()
        control.preparation_failure, control.preparation_status, control.preparation_guard = (
            self.triple,
            ("EXIT_NONZERO", "MATCH"),
            "FD_NOT_ALLOWLISTED",
        )
        with self.assertRaises(custody.CustodyError):
            control.__init__(Path("/invalid"))
        self.assertIsNone(control.preparation_failure)
        self.assertIsNone(control.preparation_status)
        self.assertIsNone(control.preparation_guard)

    def artifact(self, diagnostic: dict[str, object], padding: int = 0) -> tuple[str, dict[str, object]]:
        bootstrap = {
            "uid": 1001,
            "gid": 1002,
            "deadlineNs": 1_000_000_000_000,
            "padding": "x" * padding,
            "protected": {"childGuardDeclaration": "retain-user-field"},
        }
        observer = MagicMock()
        observer.run.side_effect = OSError
        observer.control.read.return_value = diagnostic
        self.output = io.StringIO()
        self.writer = MagicMock(wraps=self.output.write)
        with (
            patch.object(hosted.os, "umask"),
            patch.object(hosted.os, "geteuid", return_value=0),
            patch.object(hosted, "read_root", return_value=(json.dumps(bootstrap).encode(), None)),
            patch.object(hosted, "installed_tools", return_value={}),
            patch.object(hosted, "audit_stage", return_value={}),
            patch.object(hosted, "write_denial_probe", return_value={}),
            patch.object(hosted, "Clock"),
            patch.object(hosted, "CycleObserver", return_value=observer),
            patch.object(hosted.time, "monotonic_ns", return_value=0),
            patch.object(sys, "stdout", SimpleNamespace(write=self.writer)),
        ):
            self.assertEqual(hosted.observer_main("/synthetic-stage"), 1)
        return self.output.getvalue(), bootstrap

    def test_full_artifact_caps_count_outer_fields_and_lf_without_fixing_old_overflow(self) -> None:
        declared = {**self.base, "childGuardDeclaration": self.declaration}
        initial, _ = self.artifact(self.base)
        initial_size = len(initial.encode())
        for body_target in (hosted.MAX_ARTIFACT - 1, hosted.MAX_ARTIFACT, hosted.MAX_ARTIFACT + 1):
            padding = body_target + 1 - initial_size
            with self.subTest(legacy_body=body_target):
                if body_target > hosted.MAX_ARTIFACT:
                    with self.assertRaises(custody.CustodyError):
                        self.artifact(declared, padding)
                    self.writer.assert_not_called()
                else:
                    actual, _ = self.artifact(declared, padding)
                    old, _ = self.artifact(self.base, padding)
                    self.assertEqual(actual, old)
                    self.assertEqual(len(actual.encode()), body_target + 1)
                    self.writer.assert_called_once()
        emitted, _ = self.artifact(declared)
        for target in (hosted.MAX_ARTIFACT - 1, hosted.MAX_ARTIFACT, hosted.MAX_ARTIFACT + 1):
            actual, _ = self.artifact(declared, target - len(emitted.encode()))
            diagnostic = json.loads(actual)["cycles"][0]["diagnostic"]
            self.assertEqual("childGuardDeclaration" in diagnostic, target <= hosted.MAX_ARTIFACT)
            self.assertEqual(
                {key: value for key, value in diagnostic.items() if key != "childGuardDeclaration"}, self.base
            )
            self.assertLessEqual(len(actual.encode()), hosted.MAX_ARTIFACT)
            self.assertEqual(json.loads(actual)["bootstrap"]["protected"]["childGuardDeclaration"], "retain-user-field")
            self.writer.assert_called_once()

    def test_artifact_new_gate_faults_only_omit_known_slots_and_absence_skips_gate(self) -> None:
        for name in ("_publication_shape", "_artifact_declaration_fits"):
            with patch.object(hosted, name, side_effect=MemoryError):
                actual, _ = self.artifact({**self.base, "childGuardDeclaration": self.declaration})
            self.assertEqual(json.loads(actual)["cycles"][0]["diagnostic"], self.base)
            self.writer.assert_called_once()
        with patch.object(hosted, "_artifact_declaration_fits", side_effect=AssertionError) as gate:
            self.artifact(self.base)
            gate.assert_not_called()
        first = {**self.base, "childGuardDeclaration": self.declaration}
        second = {**self.base, "childGuardDeclaration": self.declaration}
        untouched = {"childGuardDeclaration": "user-data"}
        packet = {
            "cycles": [{"diagnostic": first}, {"diagnostic": second}, {"diagnostic": untouched}],
            "childGuardDeclaration": "outer-data",
            "bootstrap": untouched,
        }
        hosted._omit_artifact_declarations(packet)
        self.assertEqual(first, self.base)
        self.assertEqual(second, self.base)
        self.assertEqual(untouched, {"childGuardDeclaration": "user-data"})
        self.assertEqual(packet["childGuardDeclaration"], "outer-data")

    def test_whole_tree_screen_checks_integer_keys_values_bools_cycles_and_budgets_before_encoding(self) -> None:
        class IntSubclass(int):
            pass

        class Proxy:
            def __getattribute__(self, _name: str) -> object:
                raise AssertionError

        for value in (0, True, False, (1 << 64) - 1, -((1 << 64) - 1), {1: ["unicode-\U0001f60a", None]}):
            self.assertTrue(hosted._publication_shape(value, hosted.LIMIT))
        cycle = []
        cycle.append(cycle)
        cases = [
            1 << 64,
            -(1 << 64),
            {1 << 64: "key"},
            {"value": 1 << 30001},
            IntSubclass(1),
            Proxy(),
            cycle,
            "x" * (hosted.MAX_ARTIFACT + 2),
            [None] * (hosted.MAX_ARTIFACT + 2),
            {"nested": (Proxy(),)},
            {"prior-small": 1, "later-big": 1 << 30001},
        ]
        for value in cases:
            with (
                self.subTest(kind=type(value)),
                patch.object(hosted.json, "dumps", side_effect=AssertionError) as encode,
            ):
                self.assertFalse(hosted._control_declaration_fits(value))
                self.assertFalse(hosted._artifact_declaration_fits(value))
                encode.assert_not_called()
        with patch.object(hosted.json, "dumps", wraps=json.dumps) as encode:
            self.assertTrue(hosted._control_declaration_fits({"ok": True}))
            self.assertEqual(encode.call_count, 1)
            encode.reset_mock()
            self.assertTrue(hosted._artifact_declaration_fits({"ok": True}))
            self.assertEqual(encode.call_count, 2)

    def test_cold_disabled_digit_limit_omits_big_integer_keys_and_values_before_prospective_json(self) -> None:
        if not child._runtime_qualified():
            self.skipTest("cold publication proof requires CPython3.14.4 final")
        sources = tuple(
            (name, (fixtures.REPO / "scripts" / (name + ".py")).read_text())
            for name in ("docker_userns_custody_child", "docker_userns_custody", "docker_userns_hosted")
        )
        setup = (
            "import sys,types,builtins,hashlib,time,select\n"
            "package=types.ModuleType('scripts');package.__path__=[];sys.modules['scripts']=package\n"
            f"sources={sources!r}\n"
            "for name,source in sources:\n"
            " module=types.ModuleType('scripts.'+name);module.__file__='<inert-source>'\n"
            " sys.modules[module.__name__]=module;setattr(package,name,module)\n"
            " exec(compile(source,'<inert-source>','exec'),module.__dict__)\n"
            "h=package.docker_userns_hosted;c=package.docker_userns_custody\n"
        )
        exercise = r"""
assert h.child._runtime_qualified() and '_pylong' not in sys.modules
sys.set_int_max_str_digits(0)
large = 1 << 30001
held = {large:'inert'} if key else large
fault={'schema':1,'context':'CHILD_PARENT','site':'B_BUILD_STATUS_REFUSAL','failure':'REFUSED'}
pair={'schema':1,'terminationForm':'EXIT_NONZERO','receiptCheck':'MATCH'}
declaration={'schema':1,'category':'RESULT_TYPE_OR_SIZE'}
diagnostic={'schema':1,'diagnosticOnly':True,'phase':'prepare','ns':17,'custodyLocator':None,
            'childPending':False,'workFailure':fault,'buildStatusObservation':pair}
phase='legacy'
violations=[];prospective=[];gates=[];writes=[]
class Forbidden(BaseException): pass
def stop(name):
    violations.append(name)
    raise Forbidden(name)
def trap(name, operation):
    def run(*args,**kwargs):
        if phase=='gate': stop(name)
        return operation(*args,**kwargs)
    return run
def audit(event,args):
    if phase=='gate' and (event in ('open','import')
                         or event.startswith(('subprocess.','os.fork','os.exec','socket.'))):
        stop(event)
real_dumps=h.json.dumps
def dumps(*args,**kwargs):
    if phase=='gate':
        prospective.append(True)
        stop('prospective-json')
    return real_dumps(*args,**kwargs)
h.json.dumps=dumps
for name in ('time','time_ns','monotonic','monotonic_ns','perf_counter','perf_counter_ns','process_time'):
    operation=(lambda:17) if name=='monotonic_ns' else getattr(time,name)
    setattr(time,name,trap('clock:'+name,operation))
for name in ('open','read','pread','stat','lstat','fstat','wait','waitpid','waitid','getpid','getppid','write'):
    if hasattr(h.os,name): setattr(h.os,name,trap('os:'+name,getattr(h.os,name)))
for name in ('Popen','run','call','check_output','check_call'):
    setattr(h.subprocess,name,trap('process:'+name,getattr(h.subprocess,name)))
h.selectors.DefaultSelector=trap('selector',h.selectors.DefaultSelector)
select.select=trap('select',select.select)
builtins.open=trap('open',builtins.open)
builtins.print=trap('print',builtins.print)
class Stream:
    def __init__(self,real): self.real=real;self.buffer=self
    def write(self,value):
        if phase=='gate': stop('output')
        return self.real.write(value)
    def flush(self):
        if phase=='gate': stop('flush')
        return self.real.flush()
sys.stdout,sys.stderr=Stream(sys.stdout),Stream(sys.stderr)
sys.addaudithook(audit)
phase='gate'
for operation in (lambda:time.monotonic_ns(),lambda:h.os.read(-1,1),lambda:h.os.stat('/inert'),
                  lambda:builtins.__import__('inert_forbidden_import'),lambda:h.json.dumps({'small':1}),
                  lambda:select.select([],[],[],0),lambda:sys.stdout.write('inert')):
    before=len(violations)
    try:operation()
    except Forbidden:pass
    else:raise AssertionError('sentinel missed')
    assert len(violations)==before+1
phase='legacy';violations.clear();prospective.clear()
assert '_pylong' not in sys.modules
original_gate=h._control_declaration_fits if boundary=='control' else h._artifact_declaration_fits
def gate(value):
    global phase
    assert '_pylong' not in sys.modules
    gates.append(True);phase='gate'
    try:return original_gate(value)
    finally:phase='legacy'
if boundary=='control':
    control=h.Control.__new__(h.Control);control.phase='prepare'
    def writer(name,value,deadline):
        assert name=='failure.json' and phase=='legacy'
        assert 'childGuardDeclaration' not in value
        assert value['workFailure']==fault and value['buildStatusObservation']==pair
        assert value['custodyLocator']['nonce']==held
        writes.append(h.encoded(value))
    control.write=writer;h._control_declaration_fits=gate
    control.failure(c.CustodyError(c.Locator(held,c.DirectoryIdentity(1,2)),child_pending=False),100,
                    work_failure=('CHILD_PARENT','B_BUILD_STATUS_REFUSAL','REFUSED'),build_status=('EXIT_NONZERO','MATCH'),
                    child_guard='RESULT_TYPE_OR_SIZE' if declared else None)
else:
    packet={'bootstrap':{'held':held},'cycles':[{'diagnostic':diagnostic}]}
    if declared:
        diagnostic['childGuardDeclaration']=declaration
        assert gate(packet) is False
        h._omit_artifact_declarations(packet)
    assert diagnostic=={'schema':1,'diagnosticOnly':True,'phase':'prepare','ns':17,'custodyLocator':None,
                       'childPending':False,'workFailure':fault,'buildStatusObservation':pair}
    h.need(len(h.json.dumps(packet).encode())<=h.MAX_ARTIFACT)
    writes.append((h.json.dumps(packet,sort_keys=True)+'\n').encode())
assert len(gates)==int(declared) and len(writes)==1
assert not prospective and not violations
sys.stdout.write(hashlib.sha256(writes[0]).hexdigest()+'\n')
"""
        for boundary in ("control", "artifact"):
            for key in (False, True):
                outputs = []
                for declared in (False, True):
                    with self.subTest(boundary=boundary, key=key, declared=declared):
                        script = setup + f"boundary={boundary!r};key={key!r};declared={declared!r}\n" + exercise
                        result = subprocess.run(
                            ["/proc/self/exe", "-I", "-B", "-S", "-"],
                            input=script.encode("ascii"),
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        outputs.append(result.stdout)
                self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
