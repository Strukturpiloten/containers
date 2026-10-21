"""Offline privacy and non-acceptance controls; no native runtime qualification."""

from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from scripts import runtime_docker_diagnostics as diagnostics
from scripts.runtime_docker import _run_nested_docker
from scripts.runtime_docker_backend import DockerBackend
from scripts.runtime_tests import ProbeError

if TYPE_CHECKING:
    from collections.abc import Callable

CONTAINER = "a" * 64
PRIVATE_MARKER = "must-not-appear-in-public-evidence"
FIXTURE_CLEANUP_SECONDS = 1
FIXTURE_PHASES = frozenset(
    {
        "initializing",
        "capture",
        "pending-latch",
        "metadata",
        "guard-proof",
        "query-proof",
        "query-reap",
        "query-absence",
        "guard-group-visible",
        "guard-proof-recheck",
        "guard-reap",
        "final-absence",
        "original-deadline",
        "parent-cleanup-timeout",
    }
)
FIXTURE_CHILD_EXITS = frozenset(
    {"unobserved", "killed-sigkill", "killed-other", "exited-137", "exited-other", "dumped", "other"}
)


def _closed_fixture_failure(result: dict[str, Any], errors: str) -> str:
    phase = result.get("phase")
    child_exit = result.get("childExit")
    error_type = result.get("failureType")
    categories = {
        None: "none",
        "AssertionError": "assertion",
        "TimeoutError": "timeout",
        "FileNotFoundError": "metadata-missing",
        "ChildProcessError": "child-ownership",
        "ProcessLookupError": "process-absent",
        "PermissionError": "permission",
    }
    return json.dumps(
        {
            "phase": phase if isinstance(phase, str) and phase in FIXTURE_PHASES else "unknown",
            "errorCategory": (
                "none"
                if error_type is None
                else categories.get(error_type, "other")
                if isinstance(error_type, str)
                else "other"
            ),
            "childExit": child_exit if isinstance(child_exit, str) and child_exit in FIXTURE_CHILD_EXITS else "unknown",
            "cleanupACK": result.get("cleanupACK") is True,
            "childrenRemain": bool(result.get("remainingChildren")),
            "groupsRemain": bool(result.get("remainingGroups")),
            "pidsRemain": bool(result.get("remainingPids")),
            "stderrPresent": bool(errors),
        },
        sort_keys=True,
    )


def _closed_child_exit(observed: os.waitid_result) -> str:
    if observed.si_code == os.CLD_KILLED:
        return "killed-sigkill" if observed.si_status == signal.SIGKILL else "killed-other"
    if observed.si_code == os.CLD_EXITED:
        return "exited-137" if observed.si_status == 128 + signal.SIGKILL else "exited-other"
    return "dumped" if observed.si_code == os.CLD_DUMPED else "other"


def _assert_sigkill_exit(pid: int, observed: os.waitid_result | None) -> None:
    if (
        observed is None
        or observed.si_pid != pid
        or observed.si_code != os.CLD_KILLED
        or observed.si_status != signal.SIGKILL
    ):
        message = "owned fixture child has not terminated by SIGKILL"
        raise AssertionError(message)


def _observe_owned_sigkill(pid: int, deadline: float, context: dict[str, str] | None = None) -> None:
    if context is not None:
        context["childExit"] = "unobserved"
    while time.monotonic() < deadline:
        try:
            observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            # The query remains the guard's child until the guard dies.
            observed = None
        if observed is not None:
            if context is not None:
                context["childExit"] = _closed_child_exit(observed)
            _assert_sigkill_exit(pid, observed)
            return
        time.sleep(min(0.001, max(0, deadline - time.monotonic())))
    message = "owned fixture child did not terminate before the original deadline"
    raise AssertionError(message)


def _drain_fixture_children(deadline: float) -> dict[str, Any]:
    children_file = Path(f"/proc/self/task/{os.getpid()}/children")
    owned_pids: set[int] = set()
    owned_groups: set[int] = set()
    while True:
        children = [int(value) for value in children_file.read_text().split()]
        if not children or time.monotonic() >= deadline:
            break
        for pid in children:
            try:
                # WNOWAIT establishes direct/adopted ownership without releasing
                # the PID; metadata files are never fallback signal authority.
                os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                continue
            owned_pids.add(pid)
            if os.getpgid(pid) == pid:
                owned_groups.add(pid)
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, os.WNOHANG)
        time.sleep(min(0.001, max(0, deadline - time.monotonic())))
    remaining_groups = []
    for group in sorted(owned_groups):
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            continue
        remaining_groups.append(group)
    remaining_pids = []
    for pid in sorted(owned_pids):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        remaining_pids.append(pid)
    return {
        "cleanupACK": not children and not remaining_groups and not remaining_pids,
        "remainingChildren": children,
        "remainingGroups": remaining_groups,
        "remainingPids": remaining_pids,
    }


def _run_owner_death_supervisor(sudo: tuple[str, ...], deadline: float, failure: str | None) -> None:
    # Confine orphan adoption to this disposable subprocess, never the test runner.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER.
        raise OSError(ctypes.get_errno(), "fixture subreaper unavailable")

    def stop_fixture(_signum: int, _frame: object) -> None:
        message = "original fixture deadline elapsed"
        raise TimeoutError(message)

    signal.signal(signal.SIGTERM, stop_fixture)
    test = RootlessFailureDiagnostics()
    test.setUp()
    test.fixture_context = {"phase": "initializing", "childExit": "unobserved"}
    error = None
    try:
        test._assert_owner_death_fixture(sudo, deadline, failure)
    except BaseException as caught:  # noqa: BLE001 - every fixture failure must preserve cleanup ownership.
        error = caught
    finally:
        # A late parent timeout must not interrupt the bounded adoption/reap loop.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup = _drain_fixture_children(deadline + FIXTURE_CLEANUP_SECONDS)
    cleanup.update(
        {
            "failureType": type(error).__name__ if error is not None else None,
            "failure": str(error),
            **test.fixture_context,
        }
    )
    sys.stdout.write(json.dumps(cleanup) + "\n")
    sys.stdout.flush()
    if error is not None or not cleanup["cleanupACK"]:
        raise SystemExit(1)


class RootlessFailureDiagnostics(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        self.backend.ready = True
        self.backend.deadline = 2000
        self.ctx = MagicMock()
        self.ctx.backend = self.backend
        self.ctx.containers = [CONTAINER]
        self.ctx.checks = []
        self.observed = {
            "id": CONTAINER,
            "owner": self.backend.owner,
            "cgroup": self.backend.slice,
            "privileged": True,
            "apparmor": "unconfined",
            "securityOptions": ["label=disable"],
            "state": "exited",
            "exitCode": 1,
            "oomKilled": False,
            "pid": 0,
        }

    def diagnose(self, replies: list[bytes | Exception]) -> tuple[dict[str, Any], MagicMock]:
        with (
            patch.object(diagnostics, "_capture", side_effect=replies) as capture,
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.time, "time", return_value=110),
            patch.object(diagnostics.shutil, "which", side_effect=lambda name: "/usr/bin/" + name),
        ):
            diagnostics.diagnose_rootless_failure(self.ctx, CONTAINER, 100)
        self.ctx.command.assert_not_called()
        self.ctx.podman.assert_not_called()
        return self.ctx.checks[-1], capture

    def test_only_closed_fields_and_exact_denial_record_count_leave_private_capture(self) -> None:
        self.observed["apparmor"] = PRIVATE_MARKER
        self.observed["securityOptions"] = ["label=disable", "seccomp=unconfined", PRIVATE_MARKER]
        messages = [
            f'audit: apparmor="DENIED" operation="userns_create" comm="rootlesskit" info="{PRIVATE_MARKER}"',
            'audit: apparmor="DENIED" operation="userns_create" comm="other"',
            'audit: apparmor="ALLOWED" operation="userns_create" comm="rootlesskit"',
            'audit: apparmor="DENIED" operation="open" comm="rootlesskit"',
        ]
        journal = "\n".join(json.dumps({"MESSAGE": message}) for message in messages).encode()
        record, capture = self.diagnose([json.dumps(self.observed).encode(), journal])
        self.assertEqual(record["status"], "failed")
        self.assertTrue(record["diagnosticOnly"])
        self.assertFalse(record["acceptanceEvidence"])
        self.assertEqual(record["container"]["apparmorProfile"], "other")
        self.assertEqual(record["container"]["unknownSecurityOptionCount"], 1)
        self.assertEqual(record["kernelJournal"]["rootlesskitUsernsDenialRecords"], 1)
        self.assertEqual(record["kernelJournal"]["attribution"], "host-task-window-only")
        self.assertFalse(record["container"]["hostPidAvailable"])
        serialized = json.dumps(record)
        for protected in (PRIVATE_MARKER, CONTAINER, self.backend.owner, str(self.backend.directory), "MESSAGE"):
            self.assertNotIn(protected, serialized)
        self.assertEqual(capture.call_args_list[0].args[1], ["inspect", CONTAINER])
        with patch.object(diagnostics.shutil, "which", side_effect=lambda name: "/usr/bin/" + name):
            inspect_arguments = diagnostics._worker_arguments(self.backend.directory, ["inspect", CONTAINER])
            journal_arguments = diagnostics._worker_arguments(self.backend.directory, capture.call_args_list[1].args[1])
        self.assertIn("unix:///owned-runtime/docker.sock", inspect_arguments)
        for argument in ("--boot=0", "--dmesg", "--since=@100.000000", "--until=@110.000000", "--lines=65"):
            self.assertIn(argument, journal_arguments)
        self.assertEqual([call.args[2] for call in capture.call_args_list], [1005, 1005])
        self.assertEqual(self.backend.deadline, 2000)

    def test_foreign_or_missing_identity_prevents_journal_read(self) -> None:
        for field in ("id", "owner", "cgroup"):
            with self.subTest(field=field):
                changed = self.observed | {field: PRIVATE_MARKER}
                record, capture = self.diagnose([json.dumps(changed).encode()])
                self.assertEqual(record["availability"], "ownership-unverified")
                self.assertEqual(capture.call_count, 1)
                self.assertNotIn(PRIVATE_MARKER, json.dumps(record))
        self.ctx.containers = []
        record, capture = self.diagnose([])
        self.assertEqual(record["availability"], "ownership-unverified")
        capture.assert_not_called()

    def test_every_missing_inspect_field_is_unavailable_not_a_default_observation(self) -> None:
        for field in self.observed:
            with self.subTest(field=field):
                changed = dict(self.observed)
                del changed[field]
                record, capture = self.diagnose([json.dumps(changed).encode()])
                self.assertNotIn("container", record)
                self.assertEqual(capture.call_count, 1)

    def test_missing_denied_malformed_and_overflow_journal_are_explicitly_unavailable(self) -> None:
        cases = [
            (OSError(PRIVATE_MARKER), "query-unavailable"),
            (diagnostics._UnavailableError("byte-limit"), "byte-limit"),
            (b"\n".join([b'{"MESSAGE":"rootlesskit"}'] * 65), "record-limit"),
            (b'{"MESSAGE":null}', "invalid-fields"),
            (json.dumps({"MESSAGE": 'unterminated quote "'}).encode(), "query-unavailable"),
        ]
        for reply, expected in cases:
            with self.subTest(expected=expected):
                record, _capture = self.diagnose([json.dumps(self.observed).encode(), reply])
                self.assertEqual(record["kernelJournal"]["availability"], expected)
                self.assertNotIn("rootlesskitUsernsDenialRecords", record["kernelJournal"])
                self.assertNotIn(PRIVATE_MARKER, json.dumps(record))

    def test_empty_journal_is_zero_records_not_a_successful_prerequisite_check(self) -> None:
        record, _capture = self.diagnose([json.dumps(self.observed).encode(), b""])
        self.assertEqual(record["kernelJournal"]["rootlesskitUsernsDenialRecords"], 0)
        self.assertEqual(record["status"], "failed")
        self.assertFalse(record["acceptanceEvidence"])

    def test_cleanup_reserve_is_preserved_without_new_allowance_or_late_results(self) -> None:
        self.backend.deadline = 1060
        record, capture = self.diagnose([])
        self.assertEqual(record["availability"], "budget-exhausted")
        capture.assert_not_called()
        self.backend.deadline = 1062
        record, capture = self.diagnose([json.dumps(self.observed).encode(), b""])
        self.assertEqual([call.args[2] for call in capture.call_args_list], [1002, 1002])
        self.assertEqual(self.backend.deadline, 1062)
        self.backend.deadline = 2000
        clock = [1000]

        def delayed_capture(*_args: object) -> bytes:
            clock[0] = 1006
            return json.dumps(self.observed).encode()

        with (
            patch.object(diagnostics, "_capture", side_effect=delayed_capture),
            patch.object(diagnostics.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(diagnostics.time, "time", return_value=110),
            patch.object(diagnostics.shutil, "which", side_effect=lambda name: None if name == "journalctl" else name),
        ):
            diagnostics.diagnose_rootless_failure(self.ctx, CONTAINER, 100)
        self.assertEqual(self.ctx.checks[-1]["availability"], "timeout")
        self.assertNotIn("container", self.ctx.checks[-1])

    def test_missing_journal_or_invalid_window_never_runs_a_broader_query(self) -> None:
        for started, executable, expected in ((100, None, "query-unavailable"), (111, "journalctl", "invalid-window")):
            with (
                self.subTest(expected=expected),
                patch.object(diagnostics, "_capture") as capture,
                patch.object(diagnostics.shutil, "which", return_value=executable),
            ):
                result = diagnostics._journal(self.backend, 1005, started, 110)
            self.assertEqual(result["availability"], expected)
            capture.assert_not_called()

    def test_native_launch_error_survives_private_diagnostic_exception_and_cleanup_still_runs(self) -> None:
        self.ctx.directory = Path("/owned-runtime")
        self.ctx.name = "docker-20.10-rootless"
        self.ctx.start.return_value = CONTAINER
        budget = MagicMock()
        with (
            patch("scripts.runtime_docker.verify_outer_container_limits", side_effect=ProbeError("original failure")),
            patch.object(diagnostics, "_capture", side_effect=OSError(PRIVATE_MARKER)),
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            self.assertRaisesRegex(ProbeError, "original failure"),
        ):
            _run_nested_docker(self.ctx, {"mode": "rootless", "outerPrivilege": "privileged"}, "1000", budget)
        self.assertEqual(self.ctx.checks[-1]["availability"], "query-unavailable")
        self.assertNotIn(PRIVATE_MARKER, json.dumps(self.ctx.checks))
        self.ctx.logs.assert_called_once_with(CONTAINER)
        self.assertTrue(
            any(call.args[0] == "wait for owned Docker daemon exit" for call in self.ctx.podman.call_args_list)
        )

    def test_rootful_or_post_api_failure_does_not_trigger_early_rootless_diagnostics(self) -> None:
        self.ctx.directory = Path("/owned-runtime")
        self.ctx.name = "docker-20.10-rootless"
        self.ctx.start.return_value = CONTAINER
        for mode in ("rootful", "rootless"):
            with self.subTest(mode=mode):
                self.ctx.exec.side_effect = ["", ProbeError("post-API failure")]
                early_failure = ProbeError("rootful launch failure") if mode == "rootful" else None
                with (
                    patch("scripts.runtime_docker.verify_outer_container_limits", side_effect=early_failure),
                    patch("scripts.runtime_docker.diagnose_rootless_failure") as diagnose,
                    self.assertRaises(ProbeError),
                ):
                    _run_nested_docker(self.ctx, {"mode": mode, "outerPrivilege": "privileged"}, "1000", MagicMock())
                diagnose.assert_not_called()

    def test_optional_capture_interrupt_retains_original_probe_failure(self) -> None:
        self.ctx.directory = Path("/owned-runtime")
        self.ctx.name = "docker-20.10-rootless"
        self.ctx.start.return_value = CONTAINER
        with (
            patch("scripts.runtime_docker.verify_outer_container_limits", side_effect=ProbeError("original failure")),
            patch.object(diagnostics, "_capture", side_effect=KeyboardInterrupt),
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            self.assertRaisesRegex(ProbeError, "original failure"),
        ):
            _run_nested_docker(self.ctx, {"mode": "rootless", "outerPrivilege": "privileged"}, "1000", MagicMock())
        self.assertEqual(self.ctx.checks[-1]["availability"], "interrupted")
        self.ctx.logs.assert_called_once_with(CONTAINER)

    def test_wrapper_exit_or_missing_teardown_ack_never_proves_query_cleanup(self) -> None:
        for payload in (b"", b"{}", b'{"status":"available","teardownVerified":false}', b"private malformed"):
            with self.subTest(payload=payload):
                self.backend.diagnostic_reader_pending = False
                process = MagicMock()
                process.wait.return_value = 0
                with (
                    patch.object(diagnostics.time, "monotonic", return_value=1000),
                    patch.object(diagnostics.subprocess, "Popen", return_value=process) as spawn,
                    patch.object(diagnostics, "_read_stdout", return_value=payload),
                    self.assertRaisesRegex(diagnostics._UnavailableError, "cleanup-unverified"),
                ):
                    diagnostics._capture(self.backend, ["inspect", CONTAINER], 1005)
                self.assertIs(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(spawn.call_args.args[0][:3], ["sudo", "-n", "timeout"])
                process.kill.assert_not_called()
                process.wait.assert_called_once_with(timeout=5)

    def test_killed_monitor_status_or_failed_query_drain_cannot_emit_successful_teardown(self) -> None:
        process = MagicMock()
        process.wait.return_value = 137
        with (
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.subprocess, "Popen", return_value=process),
            patch.object(
                diagnostics, "_read_stdout", return_value=b'{"status":"available","teardownVerified":true,"data":""}'
            ),
            self.assertRaisesRegex(diagnostics._UnavailableError, "cleanup-unverified"),
        ):
            diagnostics._capture(self.backend, ["inspect", CONTAINER], 1005)
        with (
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.subprocess, "Popen", return_value=process),
            patch.object(diagnostics, "_read_query", return_value=PRIVATE_MARKER.encode()),
            patch.object(diagnostics, "_drain_query", side_effect=diagnostics._UnavailableError("cleanup-unverified")),
        ):
            result = diagnostics._query_capture(["fixed-test-query"], 1005)
        self.assertEqual(result, {"status": "cleanup-unverified", "teardownVerified": False})
        self.assertNotIn(PRIVATE_MARKER, json.dumps(result))

    def test_actual_fake_query_is_reaped_on_overflow_early_eof_and_cancellation_in_both_wrapper_topologies(
        self,
    ) -> None:
        # These are disposable Python query fixtures, never Docker/journal/native
        # runtime operations. The second topology forks a sudo-like monitor.
        for sudo in ((), ("sudo", "-n")):
            for behavior in ("overflow", "early-eof", "cancel"):
                with self.subTest(sudo=sudo, behavior=behavior), tempfile.TemporaryDirectory() as directory:
                    pidfile = Path(directory) / "query.pid"
                    query = (
                        "import os,signal,time;from pathlib import Path;"
                        f"Path({str(pidfile)!r}).write_text(str(os.getpid()));"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                    )
                    if behavior == "overflow":
                        query += "os.write(1,b'x'*65537);"
                    elif behavior == "early-eof":
                        query += "os.close(1);"
                    query += "time.sleep(30)"
                    self.backend.sudo = sudo
                    self.backend.deadline = time.monotonic() + 100

                    def owned_wrapper(
                        arguments: list[str], _seconds: float, query: str = query, sudo: tuple[str, ...] = sudo
                    ) -> list[str]:
                        absolute = int(arguments[arguments.index("--deadline-ns") + 1]) / 1_000_000_000
                        owner = (
                            "import json,sys;from scripts.runtime_docker_diagnostics import _query_capture;"
                            f"print(json.dumps(_query_capture([sys.executable,'-c',{query!r}],{absolute!r})),flush=True)"
                        )
                        if not sudo:
                            return [sys.executable, "-c", owner]
                        monitor = (
                            "import subprocess,sys;"
                            f"child=subprocess.Popen([sys.executable,'-c',{owner!r}]);sys.exit(child.wait())"
                        )
                        return [sys.executable, "-c", monitor]

                    selector = diagnostics.selectors.DefaultSelector()
                    original_select = selector.select
                    calls = [0]

                    def select_with_optional_interrupt(
                        timeout: float,
                        calls: list[int] = calls,
                        behavior: str = behavior,
                        original_select: Callable[[float], list[Any]] = original_select,
                    ) -> list[Any]:
                        calls[0] += 1
                        if behavior == "cancel" and calls[0] == 1:
                            raise KeyboardInterrupt
                        return original_select(timeout)

                    expected_error = KeyboardInterrupt if behavior == "cancel" else diagnostics._UnavailableError
                    with (
                        patch.object(self.backend, "privileged", side_effect=owned_wrapper),
                        patch.object(diagnostics.selectors, "DefaultSelector", return_value=selector),
                        patch.object(selector, "select", side_effect=select_with_optional_interrupt),
                        self.assertRaises(expected_error),
                    ):
                        diagnostics._capture(self.backend, ["inspect", CONTAINER], time.monotonic() + 2)
                    query_pid = int(pidfile.read_text())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(query_pid, 0)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(query_pid, 0)
                    self.assertFalse(self.backend.diagnostic_reader_pending)

    def test_eof_waits_for_lagging_successful_guard_without_reaping_before_group_signal(self) -> None:
        process = MagicMock()
        process.pid = 123
        process.returncode = None
        events = []
        expected_observations = 3

        def observe(*_args: int) -> SimpleNamespace | None:
            events.append("observe")
            return SimpleNamespace(si_pid=123) if events.count("observe") == expected_observations else None

        def signal_group(_group: int, number: int) -> None:
            if number == 0:
                raise ProcessLookupError
            events.append("signal-held-group")

        def reap(**_kwargs: object) -> int:
            events.append("reap")
            process.returncode = 0
            return 0

        process.wait.side_effect = reap
        with (
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.time, "sleep"),
            patch.object(diagnostics, "_spawn_query", return_value=process),
            patch.object(diagnostics, "_read_stdout", return_value=b"closed-positive"),
            patch.object(diagnostics.os, "getpgid", return_value=123),
            patch.object(diagnostics.os, "waitid", side_effect=observe) as waitid,
            patch.object(diagnostics.os, "killpg", side_effect=signal_group),
        ):
            result = diagnostics._query_capture(["fixed-test-query"], 1005)
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["teardownVerified"])
        self.assertEqual(events, ["observe", "observe", "observe", "signal-held-group", "reap"])
        waitid.assert_called_with(
            diagnostics.os.P_PID, 123, diagnostics.os.WEXITED | diagnostics.os.WNOHANG | diagnostics.os.WNOWAIT
        )
        process.poll.assert_not_called()
        process.wait.assert_called_once_with(timeout=4.75)

    def test_real_print_and_exit_zero_queries_reliably_retain_positive_data(self) -> None:
        for attempt in range(10):
            with self.subTest(attempt=attempt):
                result = diagnostics._query_capture(
                    [sys.executable, "-c", "print('closed-positive',flush=True)"], time.monotonic() + 2
                )
                self.assertEqual(result["status"], "available")
                self.assertTrue(result["teardownVerified"])
                self.assertEqual(diagnostics.base64.b64decode(result["data"]), b"closed-positive\n")

    def test_owner_death_before_drain_leaves_an_independent_original_deadline_guard(self) -> None:
        for sudo in ((), ("sudo", "-n")):
            with self.subTest(sudo=sudo):
                result = self._run_owner_death_case(sudo)
                self.assertIsNone(result["failureType"])

    def test_owner_death_supervisor_reaps_children_after_early_fixture_and_parent_timeout_failures(self) -> None:
        for sudo in ((), ("sudo", "-n")):
            for failure, expected in (
                ("assertion", "AssertionError"),
                ("missing-metadata", "FileNotFoundError"),
                ("await-interruption", "TimeoutError"),
            ):
                with self.subTest(sudo=sudo, failure=failure):
                    result = self._run_owner_death_case(sudo, failure)
                    self.assertEqual(result["failureType"], expected)
                    if failure == "assertion":
                        self.assertEqual(result["failure"], "injected assertion before PID acquisition")
                    elif failure == "await-interruption":
                        self.assertEqual(result["failure"], "original fixture deadline elapsed")

    def _run_owner_death_case(self, sudo: tuple[str, ...], failure: str | None = None) -> dict[str, Any]:
        deadline = time.monotonic() + 2
        cleanup_deadline = deadline + FIXTURE_CLEANUP_SECONDS
        supervisor = (
            "from tests.test_runtime_docker_diagnostics import _run_owner_death_supervisor;"
            f"_run_owner_death_supervisor({sudo!r},{deadline!r},{failure!r})"
        )
        process = subprocess.Popen(  # noqa: S603 - fixed disposable Python fixture, never a native runtime.
            [sys.executable, "-c", supervisor], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            output, errors = process.communicate(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # Never use run(timeout), whose automatic SIGKILL could bypass reap.
            observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is None:
                os.kill(process.pid, signal.SIGTERM)
            try:
                output, errors = process.communicate(timeout=max(0, cleanup_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                # Retain the unreaped owner instead of destroying its reaper.
                self.unverified_supervisor = process
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text()
                self.fail(
                    _closed_fixture_failure(
                        {
                            "phase": "parent-cleanup-timeout",
                            "failureType": "TimeoutError",
                            "remainingChildren": children,
                        },
                        "",
                    )
                )
        result = json.loads(output)
        context = _closed_fixture_failure(result, errors)
        self.assertTrue(result["cleanupACK"], context)
        self.assertTrue(result["remainingChildren"] == [], context)
        self.assertTrue(result["remainingGroups"] == [], context)
        self.assertTrue(result["remainingPids"] == [], context)
        self.assertEqual(process.returncode, 0 if failure is None else 1, context)
        if failure is None:
            self.assertLess(time.monotonic(), deadline)
        self.assertLess(time.monotonic(), cleanup_deadline)
        return result

    def test_fixture_failure_context_is_closed_and_redacts_paths_pids_and_raw_errors(self) -> None:
        private_path = f"/private/{PRIVATE_MARKER}/fixture"
        private_pid = 987654321
        result = {
            "phase": "guard-proof",
            "failureType": "AssertionError",
            "childExit": "exited-137",
            "failure": private_path,
            "cleanupACK": True,
            "remainingChildren": [private_pid],
            "remainingGroups": [private_pid],
            "remainingPids": [private_pid],
        }
        context = _closed_fixture_failure(result, private_path)
        with self.assertRaises(AssertionError) as captured:
            self.assertEqual(1, 0, context)
        for private in (PRIVATE_MARKER, private_path, str(private_pid)):
            self.assertNotIn(private, str(captured.exception))
        self.assertEqual(
            json.loads(context),
            {
                "phase": "guard-proof",
                "errorCategory": "assertion",
                "childExit": "exited-137",
                "cleanupACK": True,
                "childrenRemain": True,
                "groupsRemain": True,
                "pidsRemain": True,
                "stderrPresent": True,
            },
        )
        result.update({"phase": private_path, "failureType": private_path, "childExit": private_path})
        unknown = json.loads(_closed_fixture_failure(result, private_path))
        self.assertEqual(unknown["phase"], "unknown")
        self.assertEqual(unknown["errorCategory"], "other")
        self.assertEqual(unknown["childExit"], "unknown")
        self.assertNotIn(PRIVATE_MARKER, json.dumps(unknown))

    def test_closed_guard_exit_diagnostic_does_not_accept_a_normal_137_exit(self) -> None:
        context = {"phase": "guard-proof"}
        observed = SimpleNamespace(si_pid=123, si_code=os.CLD_EXITED, si_status=128 + signal.SIGKILL)
        with (
            patch.object(time, "monotonic", return_value=1000),
            patch.object(os, "waitid", return_value=observed),
            self.assertRaisesRegex(AssertionError, "has not terminated by SIGKILL"),
        ):
            _observe_owned_sigkill(123, 1002, context)
        self.assertEqual(context, {"phase": "guard-proof", "childExit": "exited-137"})

    def test_owned_child_exit_oracle_rejects_a_running_child_and_accepts_sigkill(self) -> None:
        deadline = time.monotonic() + 2
        process = subprocess.Popen(
            [sys.executable, "-c", "import os,time;os.close(1);time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            self.assertEqual(diagnostics._read_stdout(process, deadline), b"")
            observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNone(observed)
            with self.assertRaisesRegex(AssertionError, "has not terminated by SIGKILL"):
                _assert_sigkill_exit(process.pid, observed)
            # An expired fixture-only cleanup reserve must neither signal the
            # live child nor acknowledge that teardown has been completed.
            incomplete = _drain_fixture_children(time.monotonic())
            self.assertFalse(incomplete["cleanupACK"])
            self.assertIn(process.pid, incomplete["remainingChildren"])
            self.assertIsNone(os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            os.kill(process.pid, signal.SIGKILL)
            _observe_owned_sigkill(process.pid, deadline)
            self.assertLess(time.monotonic(), deadline)
        finally:
            process.kill()
            process.wait(timeout=max(0, deadline - time.monotonic()))
            if process.stdout is not None:
                process.stdout.close()
        self.assertEqual(process.returncode, -signal.SIGKILL)

    def _assert_owner_death_fixture(self, sudo: tuple[str, ...], deadline: float, failure: str | None) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.backend.diagnostic_reader_pending = False
            self.backend.sudo = sudo
            self.backend.deadline = time.monotonic() + 100
            pidfile = Path(directory) / "query.pid"
            groupfile = Path(directory) / "guard.pid"
            query = (
                "import os,signal,time;from pathlib import Path;"
                f"Path({str(pidfile)!r}).write_text(str(os.getpid()));"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(1,b'x'*65537);time.sleep(30)"
            )

            def abandoned_owner(
                arguments: list[str],
                _seconds: float,
                sudo: tuple[str, ...] = sudo,
                groupfile: Path = groupfile,
                query: str = query,
            ) -> list[str]:
                absolute = int(arguments[arguments.index("--deadline-ns") + 1]) / 1_000_000_000
                owner = (
                    "import os,signal,sys;from pathlib import Path;"
                    "from scripts import runtime_docker_diagnostics as d\n"
                    "def abandon(process,deadline):\n"
                    f" Path({str(groupfile)!r}).write_text(str(process.pid))\n"
                    " os.kill(os.getpid(),signal.SIGKILL)\n"
                    "d._drain_query=abandon\n"
                    f"d._query_capture([sys.executable,'-c',{query!r}],{absolute!r})"
                )
                if not sudo:
                    return [sys.executable, "-c", owner]
                monitor = (
                    "import subprocess,sys;"
                    f"child=subprocess.Popen([sys.executable,'-c',{owner!r}]);sys.exit(child.wait())"
                )
                return [sys.executable, "-c", monitor]

            self.fixture_context["phase"] = "capture"
            with (
                patch.object(self.backend, "privileged", side_effect=abandoned_owner),
                self.assertRaisesRegex(diagnostics._UnavailableError, "cleanup-unverified"),
            ):
                diagnostics._capture(self.backend, ["inspect", CONTAINER], deadline)
            self.fixture_context["phase"] = "pending-latch"
            self.assertTrue(self.backend.diagnostic_reader_pending)
            if failure == "assertion":
                self.fail("injected assertion before PID acquisition")
            if failure == "missing-metadata":
                pidfile.unlink()
            if failure == "await-interruption":
                signal.pause()
                self.fail("fixture resumed without its deadline interruption")
            self.fixture_context["phase"] = "metadata"
            query_pid, guard_pid = int(pidfile.read_text()), int(groupfile.read_text())
            # Observe both deaths without reaping: orphan zombies can be
            # independently reaped, so query absence alone is not group absence.
            self.fixture_context["phase"] = "guard-proof"
            _observe_owned_sigkill(guard_pid, deadline, self.fixture_context)
            self.fixture_context["phase"] = "query-proof"
            _observe_owned_sigkill(query_pid, deadline, self.fixture_context)
            self.fixture_context["phase"] = "query-reap"
            self.assertEqual(os.waitpid(query_pid, os.WNOHANG)[0], query_pid)
            self.fixture_context["phase"] = "query-absence"
            with self.assertRaises(ProcessLookupError):
                os.kill(query_pid, 0)
            # Deterministically reproduce the old assertion's false premise:
            # the dead, unreaped guard still makes its group discoverable.
            self.fixture_context["phase"] = "guard-group-visible"
            os.killpg(guard_pid, 0)
            self.fixture_context["phase"] = "guard-proof-recheck"
            observed = os.waitid(os.P_PID, guard_pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.fixture_context["childExit"] = _closed_child_exit(observed) if observed is not None else "unobserved"
            _assert_sigkill_exit(guard_pid, observed)
            self.fixture_context["phase"] = "guard-reap"
            self.assertEqual(os.waitpid(guard_pid, os.WNOHANG)[0], guard_pid)
            self.fixture_context["phase"] = "final-absence"
            with self.assertRaises(ProcessLookupError):
                os.kill(query_pid, 0)
            with self.assertRaises(ProcessLookupError):
                os.killpg(guard_pid, 0)
            self.fixture_context["phase"] = "original-deadline"
            self.assertLess(time.monotonic(), deadline)

    def test_pending_reader_cannot_be_cleared_by_another_capture_or_erase_its_private_store(self) -> None:
        self.backend.diagnostic_reader_pending = True
        with (
            patch.object(diagnostics.subprocess, "Popen") as spawn,
            self.assertRaisesRegex(diagnostics._UnavailableError, "cleanup-unverified"),
        ):
            diagnostics._capture(self.backend, ["inspect", CONTAINER], 1005)
        spawn.assert_not_called()
        self.backend.ready = False
        self.ctx._owned_mounts.return_value = []
        with (
            patch.object(self.backend, "stop_services") as stop,
            patch.object(self.backend, "_call") as call,
            patch("shutil.rmtree") as remove,
            self.assertRaisesRegex(RuntimeError, "diagnostic query teardown.*retaining private runtime store"),
        ):
            self.backend.cleanup(self.ctx)
        stop.assert_called_once_with(self.ctx)
        call.assert_not_called()
        remove.assert_not_called()
        self.assertEqual(self.ctx.containers, [CONTAINER])
        self.assertTrue(self.backend.diagnostic_reader_pending)

    def test_known_spawn_failure_clears_but_ambiguous_launch_cancellation_retains_pending(self) -> None:
        for error, pending in ((OSError(PRIVATE_MARKER), False), (KeyboardInterrupt(), True)):
            with self.subTest(pending=pending):
                self.backend.diagnostic_reader_pending = False
                with (
                    patch.object(diagnostics.time, "monotonic", return_value=1000),
                    patch.object(diagnostics.subprocess, "Popen", side_effect=error),
                    self.assertRaises(type(error)),
                ):
                    diagnostics._capture(self.backend, ["inspect", CONTAINER], 1005)
                self.assertIs(self.backend.diagnostic_reader_pending, pending)

    def test_private_capture_discards_a_command_that_completes_after_its_deadline(self) -> None:
        process = MagicMock()
        clock = [1000]

        def late_wait(*_args: object, **_kwargs: object) -> int:
            clock[0] = 1006
            return 0

        process.wait.side_effect = late_wait
        with (
            patch.object(diagnostics.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(diagnostics.subprocess, "Popen", return_value=process),
            patch.object(
                diagnostics, "_read_stdout", return_value=b'{"status":"available","teardownVerified":true,"data":""}'
            ),
            self.assertRaisesRegex(diagnostics._UnavailableError, "timeout"),
        ):
            diagnostics._capture(self.backend, ["inspect", CONTAINER], 1005)


if __name__ == "__main__":
    unittest.main()
