"""Offline service/peer/lifetime faults; no root, parser, systemd or runtime is invoked."""

from __future__ import annotations

import io
import json
import os
import signal
import struct
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
        ):
            fake_os = SimpleNamespace(**vars(os))
            fake_os.getresuid, fake_os.getresgid = lambda current_uid=uid: current_uid, lambda: (1002, 1002, 1002)
            fake_os.getgroups = lambda current_groups=groups: list(current_groups)
            fake_os.execve = MagicMock()
            fake_ctypes = MagicMock()
            fake_ctypes.CDLL.return_value.prctl.side_effect = [0, 1]
            with (
                patch.dict(
                    sys.modules, {"os": fake_os, "ctypes": fake_ctypes, "resource": MagicMock(), "signal": MagicMock()}
                ),
                patch.object(sys, "argv", ["probe", "1", "2", "3", "parser-version", "1001", "1002", "2"]),
                patch("builtins.open", return_value=io.BytesIO(status)),
                self.subTest(uid=uid, groups=groups),
                self.assertRaises(SystemExit),
            ):
                exec(child.PROBE_CODE, {})  # noqa: S102 - fixed probe with entirely mocked privilege interfaces.
            fake_os.execve.assert_not_called()

    def test_fixed_version_probe_executes_only_version_argv_after_valid_privilege_receipt(self) -> None:
        fake_os = SimpleNamespace(**vars(os))
        fake_os.getresuid, fake_os.getresgid = lambda: (1001, 1001, 1001), lambda: (1002, 1002, 1002)
        fake_os.getgroups, fake_os.close = list, MagicMock()
        fake_os.execve, fake_os.set_inheritable = MagicMock(side_effect=SystemExit(0)), MagicMock()
        fake_os.supports_fd = {fake_os.execve}
        fake_os.write = MagicMock(side_effect=lambda _descriptor, raw: len(raw))
        fake_ctypes = MagicMock()
        fake_ctypes.CDLL.return_value.prctl.side_effect = [0, 1]
        status = b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"
        with (
            patch.dict(
                sys.modules, {"os": fake_os, "ctypes": fake_ctypes, "resource": MagicMock(), "signal": MagicMock()}
            ),
            patch.object(sys, "argv", ["probe", "1", "2", "3", "parser-version", "1001", "1002", "2"]),
            patch("builtins.open", return_value=io.BytesIO(status)),
            self.assertRaises(SystemExit),
        ):
            exec(child.PROBE_CODE, {})  # noqa: S102 - fixed code, exclusively fake privilege/kernel functions.
        descriptor, argv, environment = fake_os.execve.call_args.args
        self.assertEqual(descriptor, 3)
        self.assertEqual(argv, ["apparmor_parser", "--config-file=/dev/null", "--skip-cache", "--jobs=0", "--version"])
        self.assertEqual(environment, hosted.ENV)
        proof = json.loads(fake_os.write.call_args.args[1])
        self.assertEqual(proof, {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"})

    def test_probe_parent_requires_dead_child_exact_receipt_and_original_completion_deadline(self) -> None:
        interpreter = child.Interpreter(12345, "d" * 64)
        lease = child.Build(
            "probe", 1001, 1002, self.fixture.clock.time + 5 * hosted.NS, self.fixture.clock.time + 6 * hosted.NS
        )
        process = MagicMock()
        process.stdout = io.BytesIO()
        proof = json.dumps(
            {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"}
        ).encode()
        with (
            patch.object(child, "_interpreter", return_value=((), b"trusted")),
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
            for name in (".github/docker-userns-policy-source.json", "scripts/docker_userns_custody.py"):
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


if __name__ == "__main__":
    unittest.main()
