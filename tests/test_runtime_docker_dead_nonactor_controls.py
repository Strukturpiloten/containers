"""Offline controls for mandatory registration, strict results and pre-write safety.

Every namespace, fork, mount, signal and allocator operation is inert here. These
tests establish orchestration/refusal behavior, never admitted-kernel success.
"""

from __future__ import annotations

import copy
import errno
import fnmatch
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import container_engine, runtime_docker
from scripts import runtime_docker_dead_nonactor_controls as launcher
from scripts.runtime_errors import ProbeError
from scripts.runtime_tests import RuntimeContext
from tests import native_docker_dead_nonactor_fixture as fixture

ASSOCIATION = {
    "candidate": "a" * 40,
    "run": "101",
    "attempt": "2",
    "job": "native-amd64",
    "bindingSha256": "b" * 64,
    "sourceSha256": hashlib.sha256(b"fixed fixture").hexdigest(),
}


def result(architecture: str = "amd64") -> dict:
    """Build the expected independent closed successful wire shape."""
    return {
        "schemaVersion": 1,
        "association": dict(ASSOCIATION),
        "architecture": architecture,
        "kernel": os.uname().release,
        "controls": {
            "certified-view": "passed",
            "retained-positive": "passed",
            "reaped-refusal": "passed",
            "numeric-reuse": "passed",
            "replacement-positive": "passed",
            "reserved-refusal": "passed",
            "leader-live-refusal": "passed",
            "last-thread-positive": "passed",
        },
        "status": "passed",
        "complete": True,
        "cleanup": True,
    }


class StrictNativeResults(unittest.TestCase):
    def test_both_existing_architectures_accept_only_complete_outcomes(self) -> None:
        self.assertEqual(fixture.CONTROLS, launcher.CONTROLS)
        for architecture in ("amd64", "arm64"):
            value = result(architecture)
            self.assertEqual(launcher.validate(json.dumps(value).encode(), ASSOCIATION, architecture), value)

    def test_refusal_unavailable_cleanup_timeout_and_missing_controls_never_pass(self) -> None:
        mutations = [
            lambda value: value.update(status="unavailable"),
            lambda value: value.update(status="failed"),
            lambda value: value.update(complete=False),
            lambda value: value.update(complete=1),
            lambda value: value.update(cleanup=False),
            lambda value: value.update(cleanup=1),
            lambda value: value.update(schemaVersion=True),
            lambda value: value.update(schemaVersion=2),
            lambda value: value.update(kernel="different-kernel"),
            lambda value: value.update(architecture="arm64"),
            lambda value: value.update(privatePath="private-operand"),
            lambda value: value["association"].update(candidate="c" * 40),
            lambda value: value["association"].update(extra="private-operand"),
            lambda value: value["controls"].pop("numeric-reuse"),
            lambda value: value["controls"].update(extra="passed"),
        ]
        for name in launcher.CONTROLS:
            for status in ("not-run", "failed", "unavailable", True, 1, None):
                value = result()
                value["controls"][name] = status
                with self.subTest(control=name, status=status), self.assertRaises(ProbeError):
                    launcher.validate(json.dumps(value).encode(), ASSOCIATION, "amd64")
        for mutate in mutations:
            value = result()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ProbeError):
                launcher.validate(json.dumps(value).encode(), ASSOCIATION, "amd64")

    def test_noise_duplicate_truncation_and_oversize_are_refused(self) -> None:
        raw = json.dumps(result()).encode()
        duplicate = raw[:-1] + b', "complete": true}'
        for malformed in (b"", raw[:-1], b"noise\n" + raw, raw + raw, duplicate, b" " * (launcher.MAX_RESULT + 1)):
            with self.subTest(size=len(malformed)), self.assertRaises((ProbeError, ValueError)):
                launcher.validate(malformed, ASSOCIATION, "amd64")

    def test_same_candidate_fixed_blob_capture_authenticates_tree_modes_and_bytes(self) -> None:
        def tree(mode: bytes, name: bytes, oid: str) -> bytes:
            return mode + b" " + name + b"\0" + bytes.fromhex(oid)

        commit = b"tree " + b"1" * 40 + b"\n"
        rows = [
            commit,
            tree(b"40000", b"tests", "2" * 40),
            tree(b"100644", b"native_docker_dead_nonactor_fixture.py", "3" * 40),
            b"fixed fixture",
        ]
        with patch.object(launcher.git, "git_object", side_effect=rows) as read:
            self.assertEqual(launcher.capture(ASSOCIATION["candidate"]), b"fixed fixture")
        self.assertEqual(read.call_args_list[-1].args, ("blob", "3" * 40))
        for mode in (b"120000", b"100755", b"40000"):
            with (
                patch.object(
                    launcher.git,
                    "git_object",
                    side_effect=[commit, rows[1], tree(mode, b"native_docker_dead_nonactor_fixture.py", "3" * 40)],
                ),
                self.assertRaises(ProbeError),
            ):
                launcher.capture(ASSOCIATION["candidate"])


class NativeRegistration(unittest.TestCase):
    def context(self) -> SimpleNamespace:
        binding = SimpleNamespace(
            **{key: ASSOCIATION[key] for key in ("candidate", "run", "attempt", "job")},
            architecture="amd64",
            validate=Mock(),
            digest=Mock(return_value=ASSOCIATION["bindingSha256"]),
        )
        stage = Path("/run/containers-userns-active." + "a" * 32)
        backend = SimpleNamespace(
            scoped_stage=stage,
            command_timeout=Mock(return_value=6),
            privileged=Mock(side_effect=lambda command, _allowance: command),
            check_deadline=Mock(),
        )
        ctx = SimpleNamespace(backend=backend, architecture="amd64", checks=[])
        backend.scoped_profile = SimpleNamespace(
            ctx=ctx, binding=binding, stage=stage, failures=[], _bootstrap_anchor=(stage, "b" * 64), witness=Mock()
        )
        response = io.BytesIO()
        ctx.private_native_controls_response = Mock(side_effect=lambda: nullcontext(response))
        ctx.reset_native_controls_response = Mock()
        ctx.command = Mock()
        ctx.read_native_controls_response = Mock(side_effect=lambda _response, _limit: json.dumps(result()).encode())
        return ctx

    def test_hook_orders_controls_before_ready_for_ordinary_direct_and_both_systemd_phases(self) -> None:
        for route in ("ordinary", "direct", "systemd-clean-control", "systemd-enforcement"):
            events = []
            profile = SimpleNamespace(witness=Mock(side_effect=events.append))
            ctx = SimpleNamespace(backend=SimpleNamespace(scoped_profile=profile), runtime_phase=route)
            with patch.object(
                launcher, "require_controls", side_effect=lambda _ctx, trace=events: trace.append("controls")
            ):
                runtime_docker._postexec_checkpoint(ctx, "ready")
                runtime_docker._postexec_checkpoint(ctx, "pre-close")
            self.assertEqual(events, ["controls", "ready", "pre-close"])
            with (
                patch.object(launcher, "require_controls", side_effect=ProbeError("refused")),
                self.assertRaises(ProbeError),
            ):
                runtime_docker._postexec_checkpoint(ctx, "ready")
            self.assertEqual(profile.witness.call_count, 2)
        runtime_docker._postexec_checkpoint(SimpleNamespace(), "ready")

    def test_success_is_per_invocation_bound_and_source_is_not_mutable_checkout_import(self) -> None:
        ctx = self.context()
        with patch.object(launcher, "capture", return_value=b"fixed fixture"):
            launcher.require_controls(ctx)
            launcher.require_controls(ctx)
        ctx.command.assert_called_once()
        call = ctx.command.call_args
        self.assertEqual(call.kwargs["timeout"], 6)
        self.assertIn("stdout", call.kwargs)
        self.assertEqual(call.args[1][:5], ["/usr/bin/python3.14", "-I", "-B", "-S", "-c"])
        self.assertEqual(call.args[1][5], "fixed fixture")
        self.assertEqual(ctx.checks[0]["observations"]["association"], ASSOCIATION)
        self.assertTrue(ctx.backend._dead_nonactor_controls["cleanup"])
        ctx.backend.scoped_profile.binding.run = "different"
        with patch.object(launcher, "capture", return_value=b"fixed fixture"), self.assertRaises(ProbeError):
            launcher.require_controls(ctx)
        self.assertEqual(ctx.command.call_count, 1)

    def test_timeout_command_failure_cleanup_failure_and_private_noise_propagate_without_cache(self) -> None:
        for fault in ("timeout", "command", "cleanup", "noise", "source", "allowance"):
            ctx = self.context()
            if fault in {"timeout", "command"}:
                ctx.command.side_effect = TimeoutError("private source /stage raw-command")
            if fault == "cleanup":
                ctx.read_native_controls_response.side_effect = lambda *_args: json.dumps(
                    {**result(), "cleanup": False}
                ).encode()
            if fault == "noise":
                ctx.read_native_controls_response.side_effect = lambda *_args: b"private source /stage raw-command"
            if fault == "allowance":
                ctx.backend.command_timeout.return_value = 2
            with (
                self.subTest(fault=fault),
                patch.object(
                    launcher,
                    "capture",
                    side_effect=ValueError("private source") if fault == "source" else None,
                    return_value=b"fixed fixture",
                ),
                self.assertRaises(ProbeError) as failure,
            ):
                launcher.require_controls(ctx)
            self.assertNotIn("private", str(failure.exception))
            self.assertNotIn("_dead_nonactor_controls", vars(ctx.backend))
            if fault in {"timeout", "command"}:
                self.assertEqual(ctx.checks[0]["status"], "failed")
            else:
                self.assertEqual(ctx.checks, [])
            if fault in {"source", "allowance"}:
                ctx.command.assert_not_called()

    def test_closed_unavailable_outcome_is_preserved_but_never_qualifies(self) -> None:
        ctx = self.context()
        unavailable = result()
        unavailable.update(status="unavailable", complete=False, cleanup=False)
        unavailable["controls"] = dict.fromkeys(launcher.CONTROLS, "not-run")
        ctx.command.side_effect = ProbeError("private exception operand")
        ctx.read_native_controls_response.side_effect = lambda *_args: json.dumps(unavailable).encode()
        with patch.object(launcher, "capture", return_value=b"fixed fixture"), self.assertRaises(ProbeError):
            launcher.require_controls(ctx)
        self.assertEqual(
            ctx.checks,
            [
                {
                    "name": "native dead-nonactor mechanism controls",
                    "status": "failed",
                    "observations": unavailable,
                }
            ],
        )
        self.assertNotIn("_dead_nonactor_controls", vars(ctx.backend))

    def test_fixture_and_launcher_select_existing_native_consumers_without_new_matrix_or_closure(self) -> None:
        for path in (launcher.FIXTURE, "scripts/runtime_docker_dead_nonactor_controls.py"):
            self.assertTrue(any(fnmatch.fnmatchcase(path, pattern) for pattern in container_engine.GLOBAL_IMAGE_INPUTS))
        from scripts import docker_userns_active as active  # noqa: PLC0415

        self.assertNotIn(launcher.FIXTURE, active.FILES)
        self.assertNotIn("scripts/runtime_docker_dead_nonactor_controls.py", active.FILES)

    def test_real_response_custody_does_not_consume_the_later_memory_diagnostic_leaf(self) -> None:
        for outcome in ("success", "failed", "partial"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                prototype = self.context()
                ctx = RuntimeContext.__new__(RuntimeContext)
                vars(ctx).update(vars(prototype))
                for name in (
                    "private_native_controls_response",
                    "reset_native_controls_response",
                    "read_native_controls_response",
                    "command",
                ):
                    delattr(ctx, name)
                ctx.backend.scoped_profile.ctx = ctx
                ctx.directory, ctx.timeout, ctx._fixture_archives = Path(temporary), 6, {}
                ctx._bind_fixture_directory()
                wire = result()
                if outcome == "failed":
                    wire.update(status="failed", complete=False, cleanup=False)
                raw = b'{"partial":' if outcome == "partial" else json.dumps(wire).encode()
                calls = []

                def command(  # noqa: PLR0913 - exact subprocess stream contract plus bound inert test data.
                    argv: list,
                    *,
                    stdout: int,
                    stderr: int,
                    stdin: int,
                    trace: list = calls,
                    payload: bytes = raw,
                    code: int = 0 if outcome == "success" else 1,
                    **_options: object,
                ) -> subprocess.CompletedProcess:
                    trace.append((stdout, stderr, stdin))
                    os.write(stdout, payload)
                    return subprocess.CompletedProcess(argv, code)

                with (
                    patch.object(launcher, "capture", return_value=b"fixed fixture"),
                    patch("scripts.runtime_tests.subprocess.run", side_effect=command),
                ):
                    if outcome == "success":
                        launcher.require_controls(ctx)
                    else:
                        with self.assertRaises(ProbeError):
                            launcher.require_controls(ctx)
                self.assertEqual(calls[0][1:], (subprocess.DEVNULL, subprocess.DEVNULL))
                controls_leaf = ctx.directory / "docker-native-controls-response.bin"
                controls_identity = controls_leaf.stat().st_ino
                self.assertEqual(controls_leaf.read_bytes(), raw)
                self.assertNotIn("private", json.dumps(ctx.checks))
                self.assertNotIn("fixed fixture", json.dumps(ctx.checks))
                self.assertNotIn('"stdout"', json.dumps(ctx.checks))
                self.assertNotIn('"stderr"', json.dumps(ctx.checks))
                with ctx.private_witness_response() as later:
                    ctx.reset_witness_response(later)
                    with self.assertRaises(ProbeError):
                        ctx.reset_native_controls_response(later)
                    later.write(b"later memory diagnostic")
                    self.assertEqual(ctx.read_witness_response(later, 128), b"later memory diagnostic")
                    self.assertNotEqual(os.fstat(later.fileno()).st_ino, controls_identity)
                self.assertEqual(
                    (ctx.directory / "docker-native-witness-response.bin").read_bytes(), b"later memory diagnostic"
                )
                with self.assertRaises(FileExistsError), ctx.private_native_controls_response():
                    self.fail("exclusive controls inode must not be silently reused")
                self.assertEqual(controls_leaf.read_bytes(), raw)
                self.assertEqual(ctx._fixture_archives, {})

    def test_new_fixed_controls_response_keeps_original_output_only_and_role_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ctx = RuntimeContext.__new__(RuntimeContext)
            ctx.directory, ctx.timeout, ctx.checks, ctx._fixture_archives = Path(temporary), 6, [], {}
            ctx._bind_fixture_directory()
            with ctx.private_native_controls_response() as controls:
                controls.write(b"closed controls response")
                with patch("scripts.runtime_tests.subprocess.run") as run:
                    for action in (
                        lambda: ctx.command("denied controls input", ["must-not-run"], stdin=controls),
                        lambda: ctx.reset_witness_response(controls),
                        lambda: ctx.read_witness_response(controls, 128),
                        lambda: ctx._read_fixture_response(controls, 128, role="image"),
                    ):
                        with self.assertRaises(ProbeError):
                            action()
                    run.assert_not_called()
                self.assertEqual(ctx.read_native_controls_response(controls, 128), b"closed controls response")
            self.assertEqual(ctx._fixture_archives, {})


class FixturePrewriteAndCleanup(unittest.TestCase):
    def test_parent_socket_close_failure_after_fork_still_owns_kills_and_actually_reaps_child(self) -> None:
        parent, child, target = Mock(), Mock(), Mock()
        child.close.side_effect = OSError(errno.EIO, "injected close failure")
        with (
            patch.object(fixture.os, "fork", return_value=42),
            patch.object(fixture.os, "pidfd_open") as acquired,
            patch.object(fixture.os, "kill") as killed,
            patch.object(fixture.os, "waitpid", return_value=(42, 0)) as waited,
            patch.object(fixture.time, "monotonic_ns", return_value=50),
            self.assertRaises(OSError),
            fixture.fork_owned(target, parent, child, 8, 100),
        ):
            self.fail("close failure cannot release a child to the caller")
        acquired.assert_not_called()
        killed.assert_called_once_with(42, fixture.signal.SIGKILL)
        waited.assert_called_once_with(42, os.WNOHANG)
        parent.close.assert_called_once()
        child.close.assert_called_once()
        target.assert_not_called()

    def test_fork_failure_attempts_both_endpoint_closures_even_if_first_close_fails(self) -> None:
        parent, child = Mock(), Mock()
        parent.close.side_effect = OSError(errno.EIO, "injected close failure")
        with (
            patch.object(fixture.os, "fork", side_effect=OSError(errno.EAGAIN, "injected fork failure")),
            patch.object(fixture.os, "kill") as killed,
            self.assertRaises(OSError),
            fixture.fork_owned(Mock(), parent, child, 8, 100),
        ):
            self.fail("fork failure cannot enter its body")
        parent.close.assert_called_once()
        child.close.assert_called_once()
        killed.assert_not_called()

    def test_child_branch_socket_close_failure_cannot_fall_into_supervisor_logic(self) -> None:
        class ChildExit(BaseException):
            pass

        for endpoint in ("parent", "child"):
            parent, child, target = Mock(), Mock(), Mock()
            (parent if endpoint == "parent" else child).close.side_effect = OSError(errno.EIO, "injected")
            with (
                self.subTest(endpoint=endpoint),
                patch.object(fixture.os, "fork", return_value=0),
                patch.object(fixture, "ExactChild") as registered,
                patch.object(fixture, "parent_death") as death,
                patch.object(fixture.os, "_exit", side_effect=ChildExit) as exited,
                self.assertRaises(ChildExit),
                fixture.fork_owned(target, parent, child, 8, 100),
            ):
                self.fail("a fork child must never enter its supervisor body")
            exited.assert_called_once_with(1)
            parent.close.assert_called_once()
            child.close.assert_called_once()
            registered.assert_not_called()
            if endpoint == "parent":
                death.assert_not_called()
                target.assert_not_called()

    def test_actual_cleanup_wait_reaps_first_despite_expiry_readiness_and_signal_errors(self) -> None:
        for fault in ("expired-reaped", "expired-pending", "readiness", "signal", "readiness-and-signal"):
            child = fixture.ExactChild(42, 1_000_000_000)
            child.pidfd = 9
            expired = fault.startswith("expired")
            reap = fault in {"expired-reaped", "signal"}
            readiness_error = OSError(errno.EIO, "injected readiness failure")
            selections = [readiness_error, readiness_error] if fault == "readiness" else [([], [], []), readiness_error]
            events = []

            def waitpid(pid: int, flags: int, *, trace: list = events, completed: bool = reap) -> tuple[int, int]:
                trace.append(("wait", pid, flags))
                return (42, 0) if completed else (0, 0)

            def now(*, trace: list = events, exhausted: bool = expired) -> int:
                trace.append(("deadline",))
                return 2_000_000_001 if exhausted else 1_100_000_000

            with (
                self.subTest(fault=fault),
                patch.object(fixture.os, "waitpid", side_effect=waitpid) as waited,
                patch.object(fixture.time, "monotonic_ns", side_effect=now),
                patch.object(fixture.select, "select", side_effect=selections),
                patch.object(
                    fixture.signal,
                    "pidfd_send_signal",
                    side_effect=OSError(errno.EPERM, "injected signal failure") if "signal" in fault else None,
                ),
                patch.object(fixture.os, "close") as closed,
                self.assertRaises(TimeoutError if expired else OSError),
            ):
                child.close()
            waited.assert_called_once_with(42, os.WNOHANG)
            self.assertEqual(events[0], ("wait", 42, os.WNOHANG))
            self.assertEqual(child.waited, reap)
            closed.assert_called_once_with(9)

    def test_sibling_proc_object_is_held_before_leader_exit_and_read_without_new_lookup(self) -> None:
        port = Mock()
        port._witness_proc.open.side_effect = [10, 11]
        leader = {"directory": 8, "pid": 3}
        with (
            ExitStack() as held,
            patch.object(fixture.os, "listdir", return_value=["3", "4"]),
            patch.object(fixture.os, "close"),
        ):
            sibling = fixture.hold_sibling(port, held, leader)
            self.assertEqual(sibling, {"directory": 11, "pid": 4})
            port._witness_proc.open.reset_mock()
            port.witness_read.return_value = b"State:\tS\nPid:\t4\nTgid:\t3\nUid:\t0 0 0 0\nNSpid:\t4 3\n"
            fixture.leader_sibling(port, leader, sibling)
            port._witness_proc.open.assert_not_called()
            port.witness_read.assert_called_once_with(11, "status")

    def allocator_context(self) -> tuple[SimpleNamespace, Mock, dict]:
        """Supply inert kernel observations for testing only the write barrier."""
        api = SimpleNamespace(PROC_PID_MAX=9_999_999_999, filesystem_magic=Mock())
        certificate = {
            "handshake": True,
            "idle": True,
            "mount": (1, 2),
            "originalMount": (1, 1),
            "namespace": (2, 2),
            "originalNamespace": (2, 1),
            "descendantPid": 2,
            "descendantPidfd": 20,
            "descendantDirectory": 21,
            "old": {"pid": 3, "directory": 30, "pidfd": 31},
        }
        view = Mock(root=10)
        view.pid.side_effect = [11, FileNotFoundError()]
        view.pid_namespace.return_value = (2, 2, fixture.PID_NS)
        view.self_pid.return_value = 1
        view.open.side_effect = [40, 41]
        port = Mock(_witness_proc=view)
        port.witness_read.side_effect = [
            b"State:\tS (sleeping)\nThreads:\t1\nPid:\t2\nTgid:\t2\nPPid:\t1\nNSpid:\t2 1\nUid:\t0 0 0 0\n",
            b"Pid:\t-1\nNSpid:\t-1\n",
        ]
        return api, port, certificate

    def test_allocator_checks_every_live_detached_absence_guard_before_one_fixed_write(self) -> None:
        for fault in (
            "none",
            "mount",
            "realm",
            "threads",
            "live-descendant",
            "attached-old",
            "old-present",
            "short-write",
            "readback",
            "denied-write",
        ):
            api, port, certificate = self.allocator_context()
            if fault == "realm":
                port._witness_proc.pid_namespace.return_value = (9, 9, fixture.PID_NS)
            if fault == "threads":
                port.witness_read.side_effect = [b"State:\tS\nThreads:\t2\nNSpid:\t2 1\nUid:\t0 0 0 0\n"]
            if fault == "attached-old":
                port.witness_read.side_effect = [
                    b"State:\tS\nThreads:\t1\nPid:\t2\nTgid:\t2\nPPid:\t1\nNSpid:\t2 1\nUid:\t0 0 0 0\n",
                    b"Pid:\t3\nNSpid:\t3 2\n",
                ]
            if fault == "old-present":
                port._witness_proc.pid.side_effect = [11, 12]
            with (
                self.subTest(fault=fault),
                ExitStack() as held,
                patch.object(fixture.os, "getpid", return_value=1),
                patch.object(fixture.os, "open", return_value=50),
                patch.object(fixture.os, "close"),
                patch.object(fixture, "verify_private_mounts"),
                patch.object(fixture, "namespace", return_value=(9, 9) if fault == "mount" else (1, 2)),
                patch.object(
                    fixture.select,
                    "select",
                    return_value=([20], [], []) if fault == "live-descendant" else ([], [], []),
                ),
                patch.object(
                    fixture.os,
                    "write",
                    return_value=0 if fault == "short-write" else 1,
                    side_effect=PermissionError(errno.EPERM, "injected") if fault == "denied-write" else None,
                ) as write,
                patch.object(fixture.os, "read", return_value=b"other" if fault == "readback" else b"2\n"),
            ):
                if fault == "none":
                    fixture.allocator_reset(api, port, held, certificate)
                else:
                    with self.assertRaises((AssertionError, PermissionError)):
                        fixture.allocator_reset(api, port, held, certificate)
            if fault in {"none", "short-write", "readback", "denied-write"}:
                write.assert_called_once_with(40, b"2")
                self.assertEqual(port._witness_proc.open.call_args_list[0].args[1], "sys/kernel/ns_last_pid")
            else:
                write.assert_not_called()
                port._witness_proc.open.assert_not_called()

    def test_mountinfo_must_be_fully_read_and_private_before_proc_mount(self) -> None:
        private = b"1 0 0:1 / / rw - rootfs rootfs rw\n"
        for chunks, accepted in (
            ([private, b""], True),
            ([private, b"2 1 0:2 / /proc rw shared:3 - proc proc rw\n", b""], False),
            ([b"x" * 262145], False),
        ):
            with (
                patch.object(fixture.os, "open", return_value=9),
                patch.object(fixture.os, "close"),
                patch.object(fixture.os, "read", side_effect=chunks),
            ):
                if accepted:
                    fixture.verify_private_mounts()
                else:
                    with self.assertRaises(AssertionError):
                        fixture.verify_private_mounts()

    def test_namespace_mount_or_barrier_refusal_prevents_every_allocator_write(self) -> None:
        certificate = {
            "handshake": True,
            "idle": True,
            "mount": (1, 2),
            "originalMount": (1, 1),
            "namespace": (2, 2),
            "originalNamespace": (2, 1),
        }
        for field, value in (("handshake", False), ("idle", False), ("mount", (1, 1)), ("namespace", (2, 1))):
            invalid = copy.deepcopy(certificate)
            invalid[field] = value
            with (
                self.subTest(field=field),
                patch.object(fixture.os, "write") as write,
                patch.object(fixture.os, "open") as opened,
                ExitStack() as held,
                self.assertRaises(AssertionError),
            ):
                fixture.allocator_reset(Mock(), Mock(), held, invalid)
            opened.assert_not_called()
            write.assert_not_called()

    def test_missing_external_ack_and_own_namespace_mismatch_cannot_mount_or_write(self) -> None:
        original = {"pid": (1, 1), "mnt": (2, 1)}
        for ack in ({"wrong": []}, {"namespace": [1, 1]}):
            with (
                patch.object(fixture, "receive", return_value=ack),
                patch.object(fixture, "send") as sent,
                patch.object(fixture.os, "open", return_value=9),
                patch.object(fixture.os, "close"),
                patch.object(fixture.os, "getpid", return_value=1),
                patch.object(fixture, "namespace", return_value=(1, 1)),
                patch.object(fixture.os, "unshare") as unshare,
                patch.object(fixture, "mount_private_proc") as mounted,
                patch.object(fixture.os, "write") as write,
            ):
                fixture.observer(Mock(), Mock(), original, 100)
            self.assertEqual(sent.call_args.args[1]["status"], "failed")
            unshare.assert_not_called()
            mounted.assert_not_called()
            write.assert_not_called()

    def test_exact_child_signal_error_still_waits_then_closes(self) -> None:
        child = fixture.ExactChild(42, 100)
        child.pidfd = 9
        events = []
        with (
            patch.object(fixture.select, "select", return_value=([], [], [])),
            patch.object(fixture.signal, "pidfd_send_signal", side_effect=PermissionError(errno.EPERM, "injected")),
            patch.object(child, "wait", side_effect=lambda _until: events.append("wait")),
            patch.object(fixture.os, "close", side_effect=lambda _fd: events.append("close")),
            self.assertRaises(PermissionError),
        ):
            child.close()
        self.assertEqual(events, ["wait", "close"])

    def test_acquisition_failure_still_kills_and_waits_exact_fork_child(self) -> None:
        parent, child = Mock(), Mock()
        with (
            patch.object(fixture.os, "fork", return_value=42),
            patch.object(fixture.os, "pidfd_open", side_effect=OSError(errno.EMFILE, "injected")),
            patch.object(fixture.os, "kill") as killed,
            patch.object(fixture.ExactChild, "wait") as waited,
            self.assertRaises(OSError),
            fixture.fork_owned(Mock(), parent, child, 8, 100),
        ):
            self.fail("must not release an unauthenticated child")
        killed.assert_called_once_with(42, fixture.signal.SIGKILL)
        waited.assert_called_once_with(100 + fixture.CLEANUP_NS)
        parent.close.assert_called_once()
        child.close.assert_called_once()

    def test_namespace_creation_failure_reports_unavailable_without_observer_mounts(self) -> None:
        api = Mock()
        with (
            patch.object(fixture.os, "open", side_effect=[3, 4, 5, 6]),
            patch.object(fixture.os, "close"),
            patch.object(fixture, "namespace", return_value=(1, 2)),
            patch.object(fixture.os, "pidfd_open", return_value=7),
            patch.object(fixture.os, "fstat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=0)),
            patch.object(fixture.os, "readlink", return_value=str(os.getpid())),
            patch.object(fixture.os, "unshare", side_effect=PermissionError(errno.EPERM, "injected")),
            patch.object(fixture.os, "fork") as fork,
            patch.object(fixture, "mount_private_proc") as mount,
            patch.object(fixture.os, "write") as write,
            self.assertRaises(PermissionError),
        ):
            fixture.supervise(api, 100)
        fork.assert_not_called()
        mount.assert_not_called()
        write.assert_not_called()
