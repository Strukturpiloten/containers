"""Post-admission watchdog privacy controls using only fake launchers."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
import traceback
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import runtime_tests
from scripts.runtime_docker_backend import DockerBackend, DockerBackendError
from scripts.runtime_docker_diagnostics import redact_timeout_provider
from scripts.runtime_resource_budgets import IsolatedStoreDiskBudget
from scripts.runtime_tests import ProbeError, RuntimeContext

PRIVATE_PATH = "/private/provider-sentinel-'\"\\\t\né/gnutimeout"
REDACTED = "[gnu-timeout]"


class TimeoutProviderPrivacy(unittest.TestCase):
    def test_phase_failure_envelope_redacts_provider_without_mutating_owned_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            backend._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
            ctx = MagicMock()
            ctx.backend = backend
            ctx.checks = [{"name": "native observation", "status": "passed", "detail": PRIVATE_PATH}]
            ctx.observations = [{"name": "diagnostic", "detail": PRIVATE_PATH}]
            ctx.prepare.return_value = {"engine": "docker", "clientVersion": "Docker version 29.8.2"}
            plan = runtime_tests._DockerPhasePlan(
                args=SimpleNamespace(timeout=45, outer_engine="profile"),
                metadata={"name": "docker-29-conformance-rootless", "tests": {"docker": {"launcher": "systemd"}}},
                architecture="amd64",
                use_sudo=True,
                archive=MagicMock(),
                phase=runtime_tests.DockerProbePhase.ENFORCEMENT,
                deadline=200,
                cancellation=runtime_tests._PairCancellation(),
                expected_identity=None,
            )
            with (
                patch("scripts.runtime_tests.RuntimeContext", return_value=ctx),
                patch("scripts.runtime_tests.time.monotonic", return_value=100),
                patch(
                    "scripts.runtime_tests._docker_phase_work",
                    side_effect=ProbeError(f"original failure {PRIVATE_PATH!r}"),
                ),
            ):
                result = runtime_tests._execute_docker_phase(plan)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["cleanupVerified"])
            self.assertNotIn("provider-sentinel", json.dumps(result))
            self.assertIn(REDACTED, result["error"])
            self.assertEqual(ctx.checks[0]["detail"], PRIVATE_PATH)
            self.assertEqual(ctx.observations[0]["detail"], PRIVATE_PATH)

    @staticmethod
    def context(*, admitted: bool = True) -> RuntimeContext:
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = object()
        ctx.timeout = 5
        ctx.checks = []
        if admitted:
            ctx._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
        return ctx

    def test_public_record_copies_redact_escaped_paths_without_changing_native_output_or_argv(self) -> None:
        for spelling in (
            PRIVATE_PATH,
            repr(PRIVATE_PATH),
            ascii(PRIVATE_PATH),
            json.dumps(PRIVATE_PATH),
            shlex.quote(PRIVATE_PATH),
        ):
            with self.subTest(spelling=spelling):
                ctx = self.context()
                output, errors = (
                    f"identity={spelling}; native detail",
                    f"permission denied: {spelling}; check execute permission",
                )
                command = [PRIVATE_PATH, "--signal=TERM", "1s", "native-fixture"]
                with patch(
                    "scripts.runtime_tests.subprocess.run",
                    return_value=subprocess.CompletedProcess(command, 0, output, errors),
                ) as run:
                    self.assertEqual(ctx.command("native observation", command), output)
                self.assertEqual(run.call_args.args[0], command)
                self.assertEqual(ctx.checks[-1]["stdout"], f"identity={REDACTED}; native detail")
                self.assertEqual(ctx.checks[-1]["stderr"], f"permission denied: {REDACTED}; check execute permission")
                self.assertEqual(ctx._gnu_timeout_provider[0], PRIVATE_PATH)

    def test_direct_and_sudo_provider_failures_keep_status_and_actionable_text_private(self) -> None:
        for sudo in ([], ["sudo", "-n"]):
            for status in (126, 127):
                with self.subTest(sudo=bool(sudo), status=status):
                    ctx = self.context()
                    command = [*sudo, PRIVATE_PATH, "native-fixture"]
                    errors = f"unable to execute {PRIVATE_PATH!r}: Permission denied; verify executable permissions"
                    with (
                        patch(
                            "scripts.runtime_tests.subprocess.run",
                            return_value=subprocess.CompletedProcess(command, status, "", errors),
                        ),
                        self.assertRaises(ProbeError) as caught,
                    ):
                        ctx.command("guarded launch", command)
                    expected = f"unable to execute {REDACTED}: Permission denied; verify executable permissions"
                    self.assertEqual(ctx.checks[-1]["stderr"], expected)
                    self.assertEqual(ctx.checks[-1]["exitCode"], status)
                    self.assertEqual(str(caught.exception), f"guarded launch: exit {status}: {expected}")

    def test_public_error_redacts_before_truncating_but_held_binary_bytes_are_unchanged(self) -> None:
        ctx = self.context()
        errors = PRIVATE_PATH + ":" + "x" * 980
        with (
            patch("scripts.runtime_tests.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", errors)),
            self.assertRaises(ProbeError) as caught,
        ):
            ctx.command("bounded observation", [PRIVATE_PATH])
        self.assertEqual(str(caught.exception), f"bounded observation: exit 1: {REDACTED}:" + "x" * 980)
        with tempfile.TemporaryDirectory() as directory:
            ctx.directory, ctx._fixture_archives = Path(directory), {}
            ctx._bind_fixture_directory()
            payload = PRIVATE_PATH.encode("utf-8") + b"\x00\xff"

            def export(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
                self.assertEqual(os.write(options["stdout"], payload), len(payload))
                return subprocess.CompletedProcess(command, 0, None, None)

            with ctx.private_fixture_archive() as archive:
                with patch("scripts.runtime_tests.subprocess.run", side_effect=export):
                    self.assertEqual(ctx.command("binary export", [PRIVATE_PATH], stdout=archive), "")
                archive.seek(0)
                self.assertEqual(archive.read(), payload)
            self.assertNotIn("provider-sentinel", json.dumps(ctx.checks))

    def test_missing_and_inaccessible_admitted_provider_errors_do_not_chain_private_paths(self) -> None:
        for error in (
            FileNotFoundError(2, "No such file or directory", PRIVATE_PATH),
            PermissionError(13, "Permission denied", PRIVATE_PATH),
        ):
            ctx = self.context()
            with (
                self.subTest(error=type(error).__name__),
                patch("scripts.runtime_tests.subprocess.run", side_effect=error),
                self.assertRaises(ProbeError) as caught,
            ):
                ctx.command("guarded launch", [PRIVATE_PATH])
            expected = "guarded launch: " + str(error).replace(repr(PRIVATE_PATH), REDACTED)
            self.assertEqual(str(caught.exception), expected)
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn("provider-sentinel", "".join(traceback.format_exception(caught.exception)))
            self.assertNotIn("provider-sentinel", json.dumps(ctx.checks))

    def test_timeout_cmd_and_partial_output_cannot_leak_through_exception_chaining(self) -> None:
        ctx = self.context()
        error = subprocess.TimeoutExpired(["sudo", "-n", PRIVATE_PATH], 5, PRIVATE_PATH, PRIVATE_PATH)
        with (
            patch("scripts.runtime_tests.subprocess.run", side_effect=error),
            self.assertRaises(ProbeError) as caught,
        ):
            ctx.command("guarded launch", ["sudo", "-n", PRIVATE_PATH])
        self.assertEqual(str(caught.exception), "guarded launch: command timed out")
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("provider-sentinel", "".join(traceback.format_exception(caught.exception)))
        self.assertEqual(ctx.checks[-1]["error"], "command timed out after 5s")

    def test_unadmitted_text_and_unrelated_launch_errors_keep_existing_behavior(self) -> None:
        ctx = self.context(admitted=False)
        self.assertEqual(redact_timeout_provider(ctx, PRIVATE_PATH), PRIVATE_PATH)
        with patch(
            "scripts.runtime_tests.subprocess.run", return_value=subprocess.CompletedProcess([], 0, PRIVATE_PATH, "")
        ):
            self.assertEqual(ctx.command("unadmitted observation", ["native-fixture"]), PRIVATE_PATH)
        self.assertEqual(ctx.checks[-1]["stdout"], PRIVATE_PATH)
        error = FileNotFoundError(2, "No such file or directory", "/unrelated/native-client")
        with (
            patch("scripts.runtime_tests.subprocess.run", side_effect=error),
            self.assertRaises(FileNotFoundError) as caught,
        ):
            ctx.command("unrelated launch", ["native-fixture"])
        self.assertIs(caught.exception, error)

    def test_sampler_missing_provider_and_sudo_stderr_remain_private_in_record_and_checkpoint(self) -> None:
        for sudo in ([], ["sudo", "-n"]):
            ctx = SimpleNamespace(directory=Path("owned-store"), _sudo=sudo, checks=[])
            ctx._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
            budget = IsolatedStoreDiskBudget(ctx)
            for error in (
                FileNotFoundError(2, "No such file or directory", PRIVATE_PATH),
                PermissionError(13, "Permission denied", PRIVATE_PATH),
            ):
                with (
                    self.subTest(sudo=bool(sudo), error=type(error).__name__),
                    patch("scripts.runtime_resource_budgets.subprocess.Popen", side_effect=error),
                    self.assertRaises(ProbeError) as caught,
                ):
                    budget.__enter__()
                self.assertIn(REDACTED, str(caught.exception))
                self.assertNotIn("provider-sentinel", json.dumps(ctx.checks))
                self.assertNotIn("provider-sentinel", "".join(traceback.format_exception(caught.exception)))
            process = MagicMock()
            process.communicate.return_value = (
                "",
                f"sudo: {PRIVATE_PATH!r}: Permission denied; verify executable permissions",
            )
            process.returncode = 126
            process.poll.return_value = 126
            with (
                patch("scripts.runtime_resource_budgets.subprocess.Popen", return_value=process),
                self.assertRaises(ProbeError) as caught,
            ):
                budget.__enter__()
            self.assertEqual(
                str(caught.exception),
                f"isolated Docker store disk measurement failed (exit 126): sudo: {REDACTED}: "
                "Permission denied; verify executable permissions",
            )
            self.assertNotIn("provider-sentinel", json.dumps(ctx.checks))
            with self.assertRaises(ProbeError) as checkpoint:
                budget.checkpoint()
            self.assertEqual(str(checkpoint.exception), str(caught.exception))

    def test_final_run_evidence_and_errors_are_private_without_changing_original_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            args = argparse.Namespace(
                metadata=None,
                image_name="docker-29-rootless",
                arch="amd64",
                evidence=str(output),
                sudo=False,
                no_sudo=True,
                archive="source.tar",
                image_ref=None,
                timeout=5,
                allow_privileged=False,
                skip_nested=True,
                outer_engine="profile",
            )
            backend = DockerBackend(Path(directory), ())
            backend._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
            ctx = MagicMock()
            ctx.observations = []
            ctx.backend, ctx.checks = (
                backend,
                [{"name": "native observation", "detail": [PRIVATE_PATH], "exitCode": 126}],
            )
            ctx.prepare.side_effect = ProbeError(f"launch {PRIVATE_PATH!r}: Permission denied")
            ctx.cleanup.side_effect = ProbeError(f"cleanup {PRIVATE_PATH!a}: unavailable")
            with patch("scripts.runtime_tests.RuntimeContext", return_value=ctx):
                result = runtime_tests.run(args)
            self.assertEqual(result["error"], f"ProbeError: launch {REDACTED}: Permission denied")
            self.assertEqual(result["cleanupError"], f"ProbeError: cleanup {REDACTED}: unavailable")
            self.assertEqual(result["checks"][0], {"name": "native observation", "detail": [REDACTED], "exitCode": 126})
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertEqual(ctx.checks[0]["detail"], [PRIVATE_PATH])

    def test_late_failure_rewrite_redacts_each_written_body_and_returned_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            args = argparse.Namespace(
                metadata=None,
                image_name="docker-29-rootless",
                arch="amd64",
                evidence=str(output),
                sudo=False,
                no_sudo=True,
                archive="source.tar",
                image_ref=None,
                timeout=5,
                allow_privileged=False,
                skip_nested=True,
                outer_engine="profile",
            )
            backend = DockerBackend(Path(directory), ())
            backend._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
            ctx = MagicMock()
            ctx.observations = []
            ctx.backend, ctx.checks = backend, [{"name": "private observation", "detail": PRIVATE_PATH}]
            ctx.prepare.return_value = {"engine": "docker", "clientVersion": "Docker version 29.8.2"}
            ctx.load_archive.return_value = {}
            observations = []

            def deadline() -> None:
                observations.append("check")
                if len(observations) > 1:
                    first = json.loads(output.read_text())
                    self.assertEqual(first["status"], "passed")
                    self.assertEqual(first["checks"][0]["detail"], REDACTED)
                    message = f"late completion {PRIVATE_PATH!r}: original deadline exhausted"
                    raise DockerBackendError(message)

            with (
                patch("scripts.runtime_tests.RuntimeContext", return_value=ctx),
                patch("scripts.runtime_tests._docker"),
                patch.object(backend, "check_deadline", side_effect=deadline),
            ):
                result = runtime_tests.run(args)
            self.assertEqual(len(observations), 2)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["cleanupError"], f"late completion {REDACTED}: original deadline exhausted")
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertNotIn("provider-sentinel", output.read_text())

    def test_sampler_poll_and_invalid_byte_count_never_expose_admitted_path(self) -> None:
        ctx = SimpleNamespace(directory=Path("owned-store"), _sudo=[], checks=[])
        ctx._gnu_timeout_provider = (PRIVATE_PATH, "9.7", "prefixed")
        budget = IsolatedStoreDiskBudget(ctx)
        error = FileNotFoundError(2, "No such file or directory", PRIVATE_PATH)
        with (
            patch.object(budget._stop, "wait", return_value=False),
            patch("scripts.runtime_resource_budgets.subprocess.Popen", side_effect=error),
        ):
            budget._poll()
        budget._record()
        self.assertEqual(ctx.checks[-1]["status"], "failed")
        self.assertIn(REDACTED, ctx.checks[-1]["error"])
        self.assertNotIn("provider-sentinel", json.dumps(ctx.checks))
        process = MagicMock()
        process.communicate.return_value = (PRIVATE_PATH, "")
        process.returncode, process.poll.return_value = 0, 0
        with (
            patch("scripts.runtime_resource_budgets.subprocess.Popen", return_value=process),
            self.assertRaisesRegex(ProbeError, "returned no byte count") as caught,
        ):
            budget._measure()
        self.assertNotIn("provider-sentinel", "".join(traceback.format_exception(caught.exception)))


if __name__ == "__main__":
    unittest.main()
