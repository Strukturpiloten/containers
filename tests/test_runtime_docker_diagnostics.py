"""Offline privacy and non-acceptance controls; no native runtime qualification."""

from __future__ import annotations

import ctypes
import json
import os
import shlex
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
from scripts.runtime_docker_systemd_guard import PLACEMENT_GUARD, USER_MANAGER, guarded_command
from scripts.runtime_tests import DEFAULT_TIMEOUT, ProbeError, RuntimeContext

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
FIXTURE_EXIT_LABELS = {status: f"exited-{status}" for status in (0, 1, 124, 125, 126, 127, 137)}
FIXTURE_CHILD_EXITS = frozenset(
    {"unobserved", "killed-sigkill", "killed-other", "exited-other", "dumped", "other", *FIXTURE_EXIT_LABELS.values()}
)
FIXTURE_READ_OUTCOMES = frozenset({"byte-limit", "timeout", "EOF-success", "other"})


def _closed_fixture_failure(result: dict[str, Any], errors: str) -> str:
    phase = result.get("phase")
    child_exit = result.get("childExit")
    error_type = result.get("failureType")
    before_abandon = result.get("guardBeforeAbandon")
    read_outcome = result.get("readOutcome")
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
            "guardBeforeAbandon": before_abandon
            if isinstance(before_abandon, str) and before_abandon in FIXTURE_CHILD_EXITS | {"running"}
            else "unknown",
            "readOutcome": read_outcome
            if isinstance(read_outcome, str) and read_outcome in FIXTURE_READ_OUTCOMES
            else "unknown",
            "cleanupACK": result.get("cleanupACK") is True,
            "childrenRemain": bool(result.get("remainingChildren")),
            "groupsRemain": bool(result.get("remainingGroups")),
            "pidsRemain": bool(result.get("remainingPids")),
            "stderrPresent": bool(errors),
        },
        sort_keys=True,
    )


def _closed_child_exit(observed: os.waitid_result) -> str:
    code, status = getattr(observed, "si_code", None), getattr(observed, "si_status", None)
    if type(code) is not int or type(status) is not int:
        return "other"
    if code == os.CLD_KILLED:
        return "killed-sigkill" if status == signal.SIGKILL else "killed-other"
    if code == os.CLD_EXITED:
        return FIXTURE_EXIT_LABELS.get(status, "exited-other")
    return "dumped" if code == os.CLD_DUMPED else "other"


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


def _run_owner_death_supervisor(
    sudo: tuple[str, ...], deadline: float, failure: str | None, provider: tuple[str, str, str]
) -> None:
    # Confine orphan adoption to this disposable subprocess, never the test runner.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER.
        raise OSError(ctypes.get_errno(), "fixture subreaper unavailable")

    def stop_fixture(_signum: int, _frame: object) -> None:
        message = "original fixture deadline elapsed"
        raise TimeoutError(message)

    signal.signal(signal.SIGTERM, stop_fixture)
    test = RootlessFailureDiagnostics()
    test.gnu_timeout_provider = provider
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


def qualified_local_timeout() -> tuple[str, str, str]:
    """Offline prerequisite admission through the existing command/deadline owner."""
    ctx = RuntimeContext.__new__(RuntimeContext)
    ctx.timeout = DEFAULT_TIMEOUT
    ctx.backend = object()
    ctx.checks = []
    return diagnostics.qualify_gnu_timeout(ctx)


class GnuTimeoutAdmissionControls(unittest.TestCase):
    @staticmethod
    def context() -> RuntimeContext:
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.timeout = DEFAULT_TIMEOUT
        ctx.backend = object()
        ctx.checks = []
        return ctx

    def test_prefixed_preference_and_qualified_unprefixed_fallback_retain_one_private_path(self) -> None:
        for kind, candidates, banner in (
            ("prefixed", ["/private/gnutimeout"], "timeout (GNU coreutils) 9.7"),
            ("unprefixed", [None, "/private/timeout"], "timeout (GNU coreutils) 9.4"),
        ):
            with (
                self.subTest(kind=kind),
                patch.object(diagnostics.shutil, "which", side_effect=candidates) as which,
                patch.object(Path, "resolve", return_value=Path("/private/" + PRIVATE_MARKER)),
                patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, banner + "\n" + PRIVATE_MARKER, PRIVATE_MARKER),
                ) as run,
            ):
                ctx = self.context()
                provider = diagnostics.qualify_gnu_timeout(ctx)
                self.assertEqual(provider, ("/private/" + PRIVATE_MARKER, banner.split()[-1], kind))
                self.assertEqual(diagnostics.qualify_gnu_timeout(ctx), provider)
                run.assert_called_once()
                self.assertEqual(run.call_args.args[0], [provider[0], "--version"])
                self.assertEqual(
                    [call.args[0] for call in which.call_args_list],
                    ["gnutimeout"] if kind == "prefixed" else ["gnutimeout", "timeout"],
                )
                self.assertNotIn(PRIVATE_MARKER, json.dumps(ctx.checks))
                self.assertEqual(
                    ctx.checks[-1],
                    {
                        "name": "GNU timeout provider admission",
                        "status": "passed",
                        "provider": "gnu-coreutils",
                        "version": provider[1],
                        "pathKind": kind,
                    },
                )

    def test_selected_non_gnu_nonzero_and_malformed_providers_fail_closed_without_fallback(self) -> None:
        cases = (
            (0, "timeout (uutils coreutils) 0.10.0\n" + PRIVATE_MARKER),
            (0, "timeout (GNU coreutils) 9.7-unverified\n" + PRIVATE_MARKER),
            (0, "timeout (GNU coreutils) unknown"),
            (0, ""),
            (1, "timeout (GNU coreutils) 9.7\n" + PRIVATE_MARKER),
        )
        for status, output in cases:
            with (
                self.subTest(status=status, banner=output.splitlines()[:1]),
                patch.object(diagnostics.shutil, "which", return_value="/private/" + PRIVATE_MARKER) as which,
                patch.object(Path, "resolve", return_value=Path("/private/" + PRIVATE_MARKER)),
                patch("subprocess.run", return_value=subprocess.CompletedProcess([], status, output, PRIVATE_MARKER)),
                self.assertRaises(ValueError) as caught,
            ):
                ctx = self.context()
                diagnostics.qualify_gnu_timeout(ctx)
            which.assert_called_once_with("gnutimeout")
            self.assertNotIn(PRIVATE_MARKER, str(caught.exception) + json.dumps(ctx.checks))
            self.assertIsNone(vars(ctx).get("_gnu_timeout_provider"))
            self.assertTrue(all(record["status"] == "failed" for record in ctx.checks))

    def test_missing_or_unresolvable_selected_provider_never_launches_a_command(self) -> None:
        for candidate in (None, "/private/" + PRIVATE_MARKER):
            with (
                self.subTest(candidate=candidate is not None),
                patch.object(diagnostics.shutil, "which", return_value=candidate),
                patch.object(Path, "resolve", side_effect=OSError(PRIVATE_MARKER)),
                patch("subprocess.run") as run,
                self.assertRaises(ValueError) as caught,
            ):
                diagnostics.qualify_gnu_timeout(self.context())
            run.assert_not_called()
            self.assertNotIn(PRIVATE_MARKER, str(caught.exception))

    def test_provider_command_failure_redacts_arbitrary_records_and_errors(self) -> None:
        ctx = self.context()

        def fail(*_args: object) -> str:
            ctx.checks.append(
                {
                    "name": PRIVATE_MARKER,
                    "stdout": PRIVATE_MARKER,
                    "stderr": PRIVATE_MARKER,
                    "error": PRIVATE_MARKER,
                    "path": PRIVATE_MARKER,
                }
            )
            raise ProbeError(PRIVATE_MARKER)

        with (
            patch.object(diagnostics.shutil, "which", return_value="/private/timeout"),
            patch.object(Path, "resolve", return_value=Path("/private/timeout")),
            patch.object(ctx, "command", side_effect=fail),
            self.assertRaises(ValueError) as caught,
        ):
            diagnostics.qualify_gnu_timeout(ctx)
        self.assertNotIn(PRIVATE_MARKER, str(caught.exception) + json.dumps(ctx.checks))

    def test_invalid_cached_admission_and_unadmitted_queries_fail_closed(self) -> None:
        ctx = self.context()
        ctx._gnu_timeout_provider = ("relative", "9.7", "prefixed")
        with patch("subprocess.run") as run, self.assertRaises(ValueError):
            diagnostics.qualify_gnu_timeout(ctx)
        run.assert_not_called()
        with patch.object(diagnostics.subprocess, "Popen") as spawn:
            result = diagnostics._query_capture(["unused"], time.monotonic() + 2)
        spawn.assert_not_called()
        self.assertEqual(result, {"status": "query-unavailable", "teardownVerified": True})

    def test_root_entrypoint_remains_stdlib_only_under_isolated_python(self) -> None:
        result = subprocess.run(  # noqa: S603 - fixed isolated entrypoint help, never native runtime contact.
            [sys.executable, "-I", str(Path(diagnostics.__file__).resolve()), "--help"],
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        self.assertIn("--timeout-executable", result.stdout)


class GuestStartupProjection(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        self.backend.ready = True
        self.backend.deadline = 2000
        self.ctx = SimpleNamespace(
            backend=self.backend,
            name="docker-29-conformance-rootless",
            declared_launcher="systemd",
            container_launchers={CONTAINER: "systemd"},
            exec_guard=guarded_command(),
            containers=[CONTAINER],
            checks=[],
        )
        self.observed = {
            "id": CONTAINER,
            "owner": self.backend.owner,
            "cgroup": self.backend.slice,
            "privileged": True,
            "apparmor": "unconfined",
            "securityOptions": ["label=disable"],
            "state": "running",
            "exitCode": 0,
            "oomKilled": False,
            "pid": 123,
        }

    @staticmethod
    def report(*, manager: str = "running", service: str = "running") -> bytes:
        def fields(state: str) -> str:
            return (
                "LoadState=loaded\n"
                f"ActiveState={'failed' if state == 'failed' else 'active'}\nSubState={state}\n"
                f"Result={'exit-code' if state == 'failed' else 'success'}\n"
                f"ExecMainCode={1 if state == 'failed' else 0}\n"
                f"ExecMainStatus={1 if state == 'failed' else 0}\n"
                f"MainPID={0 if state == 'failed' else 123}\n"
            )

        return ("user-manager\n" + fields(manager) + "docker-service\n" + fields(service)).encode()

    def test_manager_failure_service_failure_and_running_api_pending_are_distinct(self) -> None:
        for manager, service in (("failed", "running"), ("running", "failed"), ("running", "running")):
            with self.subTest(manager=manager, service=service):
                result = diagnostics._guest_projection(self.report(manager=manager, service=service))
                self.assertEqual(result["userManager"]["SubState"], manager)
                self.assertEqual(result["dockerService"]["SubState"], service)
                self.assertEqual(result["userManager"]["Result"], "exit-code" if manager == "failed" else "success")
                self.assertEqual(result["dockerService"]["ExecMainStatus"], 1 if service == "failed" else 0)
                self.assertNotIn("apiReady", result)

    def test_absent_user_bus_preserves_only_validated_root_manager(self) -> None:
        manager = self.report(manager="failed").split(b"docker-service\n")[0]
        result = diagnostics._guest_projection(manager + b"docker-service\nUnavailable=user-bus-absent\n")
        self.assertEqual(result["userManager"]["ActiveState"], "failed")
        self.assertEqual(result["dockerService"], {"availability": "user-bus-absent"})

    def test_failed_service_retains_the_closed_exit_status(self) -> None:
        result = diagnostics._guest_projection(self.report(service="failed"))
        self.assertEqual(
            result["dockerService"],
            {
                "availability": "available",
                "LoadState": "loaded",
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "exit-code",
                "ExecMainCode": 1,
                "ExecMainStatus": 1,
                "MainPID": 0,
            },
        )

    def test_unknown_missing_duplicate_protected_and_malformed_fields_fail_closed(self) -> None:
        valid = self.report()
        for raw in (
            valid.replace(b"ActiveState=active", b"ActiveState=unknown", 1),
            valid.replace(b"SubState=running", b"SubState=" + PRIVATE_MARKER.encode(), 1),
            valid.replace(b"Result=success\n", b"", 1),
            valid.replace(b"Result=success\n", b"Result=success\nResult=success\n", 1),
            valid + b"Environment=" + PRIVATE_MARKER.encode(),
            valid + b"ExecStart=" + PRIVATE_MARKER.encode(),
            valid.replace(b"MainPID=123", b"MainPID=-1", 1),
            valid.replace(b"MainPID=123", b"MainPID=2147483648", 1),
            valid.replace(b"ExecMainCode=0", b"ExecMainCode=4", 1),
            valid.replace(b"ExecMainStatus=0", b"ExecMainStatus=256", 1),
            valid.replace(b"ExecMainStatus=0", b"ExecMainStatus=00", 1),
            valid.replace(b"user-manager", b"other-user", 1),
            valid + b"docker-service\n",
            valid + b"\xff",
            b"",
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(diagnostics._UnavailableError) as caught:
                diagnostics._guest_projection(raw)
            self.assertEqual(str(caught.exception), "invalid-fields")
            self.assertNotIn(PRIVATE_MARKER, str(caught.exception))

    def test_raw_and_projected_byte_limits_are_fixed(self) -> None:
        with self.assertRaisesRegex(diagnostics._UnavailableError, "byte-limit"):
            diagnostics._guest_projection(b"x" * (diagnostics.GUEST_BYTE_LIMIT + 1))
        with (
            patch.object(diagnostics, "GUEST_RECORD_LIMIT", 1),
            self.assertRaisesRegex(diagnostics._UnavailableError, "byte-limit"),
        ):
            diagnostics._guest_projection(self.report())

    def test_optional_query_shares_host_deadline_and_cannot_erase_host_evidence(self) -> None:
        for reply, expected in (
            (self.report(service="failed"), "collected"),
            (OSError(PRIVATE_MARKER), "query-unavailable"),
            (diagnostics._UnavailableError("timeout"), "timeout"),
            (diagnostics._UnavailableError("cleanup-unverified"), "cleanup-unverified"),
            (b"Environment=" + PRIVATE_MARKER.encode(), "invalid-fields"),
        ):
            with (
                self.subTest(expected=expected),
                patch.object(diagnostics.time, "monotonic", return_value=1000),
                patch.object(diagnostics.time, "time", return_value=110),
                patch.object(diagnostics.shutil, "which", return_value="/usr/bin/journalctl"),
                patch.object(
                    diagnostics, "_capture", side_effect=[json.dumps(self.observed).encode(), b"", reply]
                ) as capture,
            ):
                diagnostics.diagnose_rootless_failure(self.ctx, CONTAINER, 100)
            record = self.ctx.checks[-1]
            self.assertEqual(record["container"]["state"], "running")
            self.assertEqual(record["kernelJournal"]["rootlesskitUsernsDenialRecords"], 0)
            self.assertEqual(record["guestSystemd"]["availability"], expected)
            self.assertEqual(record["status"], "failed")
            self.assertFalse(record["acceptanceEvidence"])
            self.assertEqual([call.args[2] for call in capture.call_args_list], [1005, 1005, 1005])
            self.assertEqual(capture.call_args_list[-1].args[1], ["guest-systemd", CONTAINER, self.backend.owner])
            self.assertEqual(self.backend.deadline, 2000)
            self.assertNotIn(PRIVATE_MARKER, json.dumps(record))

    def test_wrong_profile_launcher_or_missing_guard_never_queries_guest(self) -> None:
        for changes, availability in (
            ({"name": "docker-29-rootless"}, "profile-not-applicable"),
            ({"declared_launcher": "direct"}, "profile-not-applicable"),
            ({"container_launchers": {}}, "profile-not-applicable"),
            ({"exec_guard": ()}, "placement-unverified"),
        ):
            with self.subTest(changes=changes), patch.object(diagnostics, "_capture") as capture:
                ctx = SimpleNamespace(**(vars(self.ctx) | changes))
                self.assertEqual(diagnostics._guest(ctx, self.backend, CONTAINER, 1005), {"availability": availability})
                capture.assert_not_called()

    def test_exhausted_shared_budget_does_not_create_query_or_wait(self) -> None:
        with (
            patch.object(diagnostics.time, "monotonic", return_value=1005),
            patch.object(diagnostics.time, "sleep") as sleep,
            patch.object(diagnostics, "_capture") as capture,
        ):
            self.assertEqual(
                diagnostics._guest(self.ctx, self.backend, CONTAINER, 1005),
                {"availability": "budget-exhausted"},
            )
        capture.assert_not_called()
        sleep.assert_not_called()

    def test_optional_envelope_boundary_uses_canonical_serialization_and_preserves_old_record(self) -> None:
        old = {"status": "failed", "legacy": PRIVATE_MARKER}
        guest = {"availability": "query-unavailable"}
        expected = old | {"guestSystemd": guest}
        size = len((json.dumps(expected, indent=2) + "\n").encode("utf-8"))
        for maximum, included in ((size, True), (size - 1, False), (1, False)):
            with self.subTest(maximum=maximum), patch.object(diagnostics, "DIAGNOSTIC_RECORD_LIMIT", maximum):
                observed = diagnostics._with_guest(old, guest)
                self.assertEqual(observed, expected if included else old)
                if not included:
                    self.assertIs(observed, old)
        with patch.object(diagnostics, "_record_size", side_effect=ValueError(PRIVATE_MARKER)):
            self.assertIs(diagnostics._with_guest(old, guest), old)
        self.assertEqual(old, {"status": "failed", "legacy": PRIVATE_MARKER})

    def test_root_receiver_refuses_foreign_dead_malformed_or_unprivileged_container_before_guest_exec(self) -> None:
        variants = [
            self.observed | {key: value}
            for key, value in (
                ("id", "b" * 64),
                ("owner", "b" * 32),
                ("cgroup", "other.slice"),
                ("state", "exited"),
                ("pid", 0),
                ("privileged", False),
            )
        ]
        for raw in [*(json.dumps(value).encode() for value in variants), b"malformed"]:
            with (
                self.subTest(raw=raw[:50]),
                patch.object(diagnostics.time, "monotonic", return_value=1000),
                patch.object(diagnostics.shutil, "which", return_value="/usr/bin/docker"),
                patch.object(diagnostics, "_guest_worker_arguments") as guest,
                patch.object(
                    diagnostics, "_query_capture", side_effect=[self.daemon_protocol(), self.protocol(raw)]
                ) as query,
            ):
                result = diagnostics._guest_query_capture(
                    self.backend.directory, ["guest-systemd", CONTAINER, self.backend.owner], 1005, "/fixed/timeout"
                )
            self.assertEqual(result, {"status": "query-unavailable", "teardownVerified": True})
            guest.assert_not_called()
            self.assertEqual(query.call_count, 2)

    @staticmethod
    def protocol(raw: bytes) -> dict[str, Any]:
        return {"status": "available", "teardownVerified": True, "data": diagnostics.base64.b64encode(raw).decode()}

    def daemon_protocol(self) -> dict[str, Any]:
        return self.protocol(json.dumps({"root": str(self.backend.directory / "root"), "securityOptions": []}).encode())

    def test_root_receiver_checks_ownership_before_loading_guard_and_only_queries_fixed_services(self) -> None:
        events = []

        def query(arguments: list[str], deadline: float, provider: str) -> dict[str, Any]:
            self.assertEqual((deadline, provider), (1005, "/fixed/timeout"))
            operation = "info" if "info" in arguments else "inspect" if "inspect" in arguments else "exec"
            events.append(operation)
            return (
                self.daemon_protocol()
                if operation == "info"
                else self.protocol(json.dumps(self.observed).encode() if operation == "inspect" else self.report())
            )

        original = diagnostics._guest_guard_contract

        def contract() -> dict[str, Any]:
            events.append("guard-load")
            return original()

        with (
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.shutil, "which", return_value="/usr/bin/docker"),
            patch.object(diagnostics, "_query_capture", side_effect=query),
            patch.object(diagnostics, "_guest_guard_contract", side_effect=contract),
        ):
            result = diagnostics._guest_query_capture(
                self.backend.directory, ["guest-systemd", CONTAINER, self.backend.owner], 1005, "/fixed/timeout"
            )
            arguments = diagnostics._guest_worker_arguments(self.backend.directory, CONTAINER)
        self.assertEqual(events[:4], ["info", "inspect", "guard-load", "exec"])
        self.assertEqual(result["status"], "available")
        index = arguments.index("exec")
        self.assertEqual(arguments[index + 1 : index + 7], [CONTAINER, *guarded_command(), "sh"])
        self.assertIn("unix:///owned-runtime/docker.sock", arguments[:index])
        script = arguments[-1]
        self.assertIn("user@1000.service", script)
        self.assertIn(shlex.join(USER_MANAGER), script)
        self.assertIn("docker.service", script)
        self.assertNotIn("journal", script)
        self.assertNotIn("Environment", script)
        self.assertNotIn("ExecStart", script)

    def test_extracted_contract_preserves_public_reexports_and_original_guard_bytes(self) -> None:
        from scripts import runtime_docker_systemd  # noqa: PLC0415

        self.assertIs(runtime_docker_systemd.guarded_command, guarded_command)
        self.assertEqual(runtime_docker_systemd.USER_MANAGER, USER_MANAGER)
        self.assertEqual(runtime_docker_systemd.PLACEMENT_GUARD, PLACEMENT_GUARD)
        contract = diagnostics._guest_guard_contract()
        self.assertEqual(contract["PLACEMENT_GUARD"], PLACEMENT_GUARD)
        self.assertEqual(contract["USER_MANAGER"], USER_MANAGER)
        self.assertEqual(
            contract["guarded_command"]("printf", "literal $value"), guarded_command("printf", "literal $value")
        )

    def test_isolated_root_worker_loads_only_fixed_stdlib_helper_without_package_imports(self) -> None:
        code = (
            "import runpy,sys; "
            "namespace=runpy.run_path(sys.argv[1]); "
            "contract=namespace['_guest_guard_contract'](); "
            "assert contract['USER_MANAGER'][2]=='dockertest'; "
            "assert contract['guarded_command']()[0]=='sh'; "
            "assert not any(name.startswith('scripts.') for name in sys.modules); "
            "print('fixed-guard-available')"
        )
        result = subprocess.run(  # noqa: S603 - fixed isolated helper read; no daemon or guest operation.
            [sys.executable, "-I", "-c", code, str(Path(diagnostics.__file__).resolve())],
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        self.assertEqual(result.stdout, "fixed-guard-available\n")

    def test_placement_refusal_precedes_systemctl_for_host_outside_leaf_root_and_malformed_contexts(self) -> None:
        # Exercise the unchanged real guard with synthetic proc/cgroup readers, never host state changes.
        prelude = (
            'cut() { case "$*" in */proc/1/cgroup) printf %s "$INIT";; *) printf %s "$CURRENT";; esac; }; '
            'cat() { case "$1" in /sys/fs/cgroup/cgroup.procs) printf %s "$ROOT_PROCS";; '
            '*) printf %s "$SUBTREE";; esac; }; '
            "systemctl() { printf SYSTEMCTL_CALLED; }; "
        )
        guard = guarded_command("systemctl", "show", "user@1000.service", "--property=ActiveState")
        for context, init, current, root_processes, success in (
            ("admitted-guest-leaf", "/init.scope", "/init.scope", "", True),
            ("host-populated-distributor", "/host.scope", "/host.scope", "1 2 3", False),
            ("outside-pid1-leaf", "/init.scope", "/outside.scope", "", False),
            ("namespace-root", "/", "/", "", False),
            ("malformed-parent", "/../init.scope", "/../init.scope", "", False),
            ("malformed-empty", "", "", "", False),
        ):
            with self.subTest(context=context):
                result = subprocess.run(  # noqa: S603 - fixed offline shell guard with literal synthetic readers.
                    ["/bin/sh", "-euc", prelude + guard[2], *guard[3:]],
                    env={"INIT": init, "CURRENT": current, "ROOT_PROCS": root_processes, "SUBTREE": ""},
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=2,
                )
                self.assertEqual(result.returncode == 0, success)
                self.assertEqual(result.stdout, "SYSTEMCTL_CALLED" if success else "")

    def test_root_receiver_budget_or_inspect_teardown_failure_never_execs(self) -> None:
        for observed, now in (
            (self.protocol(json.dumps(self.observed).encode()), 1005),
            ({"status": "timeout", "teardownVerified": True}, 1000),
            ({"status": "cleanup-unverified", "teardownVerified": False}, 1000),
        ):
            with (
                self.subTest(observed=observed.get("status"), now=now),
                patch.object(diagnostics.time, "monotonic", return_value=now),
                patch.object(diagnostics.shutil, "which", return_value="/usr/bin/docker"),
                patch.object(diagnostics, "_query_capture", return_value=observed) as query,
                patch.object(diagnostics, "_guest_worker_arguments") as guest,
            ):
                result = diagnostics._guest_query_capture(
                    self.backend.directory, ["guest-systemd", CONTAINER, self.backend.owner], 1005, "/fixed/timeout"
                )
            if now == 1005:  # noqa: PLR2004 - exact shared-deadline boundary.
                self.assertEqual(result["status"], "budget-exhausted")
                query.assert_not_called()
            else:
                self.assertEqual(result["status"], observed["status"])
                query.assert_called_once()
            guest.assert_not_called()

    def test_root_receiver_rejects_arbitrary_selectors_without_query_or_source_loading(self) -> None:
        for request in (
            ["guest-systemd", "short", self.backend.owner],
            ["guest-systemd", CONTAINER, "foreign"],
            ["guest-systemd", CONTAINER, self.backend.owner, "other.service"],
            ["other-operation", CONTAINER, self.backend.owner],
        ):
            with (
                self.subTest(request=request),
                patch.object(diagnostics, "_query_capture") as query,
                patch.object(diagnostics, "_guest_guard_contract") as contract,
            ):
                self.assertEqual(
                    diagnostics._guest_query_capture(self.backend.directory, request, 1005, "/fixed/timeout"),
                    {"status": "invalid-fields", "teardownVerified": True},
                )
            query.assert_not_called()
            contract.assert_not_called()

    def test_fixed_source_loader_refuses_symlink_nonregular_oversize_and_changed_helper(self) -> None:
        source = Path(diagnostics.__file__).with_name("runtime_docker_systemd_guard.py").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            fake_script = Path(directory) / "runtime_docker_diagnostics.py"
            helper = fake_script.with_name("runtime_docker_systemd_guard.py")
            target = Path(directory) / "target"
            target.write_bytes(source)
            original_read = os.read
            for kind in ("symlink", "directory", "oversize", "changed"):
                with self.subTest(kind=kind), patch.object(diagnostics, "__file__", str(fake_script)):
                    if kind == "symlink":
                        helper.symlink_to(target)
                    elif kind == "directory":
                        helper.mkdir()
                    else:
                        helper.write_bytes(
                            b"x" * (diagnostics.GUARD_SOURCE_LIMIT + 1) if kind == "oversize" else source
                        )

                    def changed_read(descriptor: int, size: int) -> bytes:
                        result = original_read(descriptor, size)
                        if result:
                            helper.write_bytes(source + b"\n")
                        return result

                    with (
                        patch.object(
                            diagnostics.os, "read", side_effect=changed_read if kind == "changed" else original_read
                        ),
                        self.assertRaises((OSError, diagnostics._UnavailableError)),
                    ):
                        diagnostics._guest_guard_contract()
                    if kind == "directory":
                        helper.rmdir()
                    else:
                        helper.unlink()

    def test_guest_capture_timeout_preserves_original_start_failure_and_orderly_cleanup(self) -> None:
        ctx = MagicMock()
        for name, value in vars(self.ctx).items():
            setattr(ctx, name, value)
        ctx.directory = self.backend.directory
        ctx.timeout = 45
        ctx.start.return_value = CONTAINER
        profile = {"mode": "rootless", "outerPrivilege": "privileged", "launcher": "systemd"}
        with (
            patch("scripts.runtime_docker.runtime_docker_systemd.verify_runtime"),
            patch("scripts.runtime_docker.runtime_docker_systemd.systemd_options", return_value=()),
            patch(
                "scripts.runtime_docker._prepare_started_daemon", side_effect=ProbeError("original startup deadline")
            ),
            patch("scripts.runtime_docker._shutdown_docker_phase") as shutdown,
            patch.object(diagnostics.time, "monotonic", return_value=1000),
            patch.object(diagnostics.time, "time", return_value=110),
            patch.object(diagnostics.shutil, "which", return_value="/usr/bin/journalctl"),
            patch.object(
                diagnostics,
                "_capture",
                side_effect=[json.dumps(self.observed).encode(), b"", diagnostics._UnavailableError("timeout")],
            ),
            self.assertRaisesRegex(ProbeError, "original startup deadline"),
        ):
            _run_nested_docker(ctx, profile, "0", MagicMock())
        self.assertEqual(ctx.checks[-1]["guestSystemd"]["availability"], "timeout")
        shutdown.assert_called_once_with(ctx, CONTAINER, systemd=True, diagnostics=None)

    def test_wrong_backend_never_enters_private_docker_lane(self) -> None:
        self.ctx.backend = SimpleNamespace()
        with patch.object(diagnostics, "_capture") as capture:
            diagnostics.diagnose_rootless_failure(self.ctx, CONTAINER, 100)
        capture.assert_not_called()
        self.assertEqual(self.ctx.checks, [])

    def test_root_receiver_refuses_wrong_private_daemon_or_rootless_endpoint_before_cid_read(self) -> None:
        for value in (
            {"root": "/var/lib/docker", "securityOptions": []},
            {"root": str(self.backend.directory / "root"), "securityOptions": ["name=rootless"]},
            {"root": str(self.backend.directory / "root"), "securityOptions": None},
            {"root": str(self.backend.directory / "root"), "securityOptions": [PRIVATE_MARKER, None]},
        ):
            with (
                self.subTest(value=value),
                patch.object(diagnostics.time, "monotonic", return_value=1000),
                patch.object(diagnostics.shutil, "which", return_value="/usr/bin/docker"),
                patch.object(
                    diagnostics, "_query_capture", return_value=self.protocol(json.dumps(value).encode())
                ) as query,
                patch.object(diagnostics, "_guest_worker_arguments") as guest,
            ):
                result = diagnostics._guest_query_capture(
                    self.backend.directory, ["guest-systemd", CONTAINER, self.backend.owner], 1005, "/fixed/timeout"
                )
            self.assertEqual(result, {"status": "query-unavailable", "teardownVerified": True})
            query.assert_called_once()
            self.assertIn("info", query.call_args.args[0])
            guest.assert_not_called()
            self.assertNotIn(PRIVATE_MARKER, json.dumps(result))


class RootlessFailureDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Before each fixture's original two-second proof deadline is created.
        cls.gnu_timeout_provider = qualified_local_timeout()

    def setUp(self) -> None:
        self.backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        self.backend._gnu_timeout_provider = self.gnu_timeout_provider
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
                self.assertEqual(spawn.call_args.args[0][:3], ["sudo", "-n", self.gnu_timeout_provider[0]])
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
            result = diagnostics._query_capture(["fixed-test-query"], 1005, self.gnu_timeout_provider[0])
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
                        provider = arguments[arguments.index("--timeout-executable") + 1]
                        owner = (
                            "import json,sys;from scripts.runtime_docker_diagnostics import _query_capture;"
                            f"print(json.dumps(_query_capture([sys.executable,'-c',{query!r}],{absolute!r},{provider!r})),flush=True)"
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
            result = diagnostics._query_capture(["fixed-test-query"], 1005, self.gnu_timeout_provider[0])
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
                    [sys.executable, "-c", "print('closed-positive',flush=True)"],
                    time.monotonic() + 2,
                    self.gnu_timeout_provider[0],
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
            f"_run_owner_death_supervisor({sudo!r},{deadline!r},{failure!r},{self.gnu_timeout_provider!r})"
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
            "guardBeforeAbandon": "running",
            "readOutcome": "byte-limit",
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
                "guardBeforeAbandon": "running",
                "readOutcome": "byte-limit",
                "cleanupACK": True,
                "childrenRemain": True,
                "groupsRemain": True,
                "pidsRemain": True,
                "stderrPresent": True,
            },
        )
        result.update(
            {
                "phase": private_path,
                "failureType": private_path,
                "childExit": private_path,
                "guardBeforeAbandon": private_path,
                "readOutcome": private_path,
            }
        )
        unknown = json.loads(_closed_fixture_failure(result, private_path))
        self.assertEqual(unknown["phase"], "unknown")
        self.assertEqual(unknown["errorCategory"], "other")
        self.assertEqual(unknown["childExit"], "unknown")
        self.assertEqual(unknown["guardBeforeAbandon"], "unknown")
        self.assertEqual(unknown["readOutcome"], "unknown")
        self.assertNotIn(PRIVATE_MARKER, json.dumps(unknown))
        result.update({"guardBeforeAbandon": {"raw": private_path}, "readOutcome": [private_path]})
        self.assertNotIn(PRIVATE_MARKER, _closed_fixture_failure(result, private_path))

    def test_closed_guard_exit_categories_accept_only_known_numeric_statuses(self) -> None:
        for status, expected in (
            (0, "exited-0"),
            (1, "exited-1"),
            (124, "exited-124"),
            (125, "exited-125"),
            (126, "exited-126"),
            (127, "exited-127"),
            (137, "exited-137"),
            (138, "exited-other"),
        ):
            with self.subTest(status=status):
                observed = SimpleNamespace(si_code=os.CLD_EXITED, si_status=status)
                self.assertEqual(_closed_child_exit(observed), expected)
        for code, status in (
            (os.CLD_EXITED, PRIVATE_MARKER),
            (PRIVATE_MARKER, 1),
            (os.CLD_EXITED, True),
            (None, None),
        ):
            with self.subTest(code=code, status=status):
                self.assertEqual(_closed_child_exit(SimpleNamespace(si_code=code, si_status=status)), "other")
        self.assertEqual(_closed_child_exit(SimpleNamespace()), "other")

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
            self.backend.sudo, self.backend.deadline = sudo, time.monotonic() + 100
            pidfile, groupfile = Path(directory) / "query.pid", Path(directory) / "guard.pid"
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
                absolute, provider = (
                    int(arguments[arguments.index("--deadline-ns") + 1]) / 1_000_000_000,
                    arguments[arguments.index("--timeout-executable") + 1],
                )
                owner = (
                    "import json,os,signal,sys;from pathlib import Path;"
                    "from scripts import runtime_docker_diagnostics as d\n"
                    "original_read=d._read_query\n"
                    "read_outcome='other'\n"
                    "def record_read(process,deadline):\n"
                    " global read_outcome\n"
                    " try:\n"
                    "  output=original_read(process,deadline)\n"
                    " except d._UnavailableError as error:\n"
                    "  read_outcome=str(error) if str(error) in ('byte-limit','timeout') else 'other'\n"
                    "  raise\n"
                    " read_outcome='EOF-success'\n"
                    " return output\n"
                    "d._read_query=record_read\n"
                    "def abandon(process,deadline):\n"
                    " observed=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)\n"
                    " before='running' if observed is None else (\n"
                    f"  {FIXTURE_EXIT_LABELS!r}.get(observed.si_status,'exited-other')\n"
                    "  if observed.si_code==os.CLD_EXITED\n"
                    "  else ('killed-sigkill' if observed.si_status==signal.SIGKILL else 'killed-other')\n"
                    "  if observed.si_code==os.CLD_KILLED else 'dumped'\n"
                    "  if observed.si_code==os.CLD_DUMPED else 'other')\n"
                    f" Path({str(groupfile)!r}).write_text(json.dumps(\n"
                    "  {'pid':process.pid,'guardBeforeAbandon':before,'readOutcome':read_outcome}))\n"
                    " os.kill(os.getpid(),signal.SIGKILL)\n"
                    "d._drain_query=abandon\n"
                    f"d._query_capture([sys.executable,'-c',{query!r}],{absolute!r},{provider!r})"
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
            guard_metadata = json.loads(groupfile.read_text())
            query_pid, guard_pid = int(pidfile.read_text()), int(guard_metadata["pid"])
            self.fixture_context.update(
                {name: guard_metadata.get(name) for name in ("guardBeforeAbandon", "readOutcome")}
            )
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
