"""Execute inert workflow guards against independent finite manual expectations."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from tests import test_docker_direct_startup_aggregate as aggregate_tests

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "docker-direct-rootless-diagnostic"
REF = "refs/heads/TheRealBecks/issue442-direct-startup-20261031"


def action() -> dict:
    """Read the checked-in shared action as the runner does."""
    return yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())


def workflow() -> dict:
    """Read the generated canonical workflow without interpreting on as Boolean."""
    return yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)  # noqa: S506 - BaseLoader constructs strings only.


def step(steps: list[dict], name: str) -> dict:
    """Select one uniquely named canonical step."""
    return next(item for item in steps if item.get("name") == name)


def shell(script: str, environment: dict[str, str], directory: Path) -> subprocess.CompletedProcess:
    """Run only authored guards or bash parsing; never a runtime or bootstrap."""
    return subprocess.run(  # noqa: S603 - fixed interpreter and inert authored snippets.
        ["/bin/bash", "-c", script],
        cwd=directory,
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


class DirectWorkflowTests(unittest.TestCase):
    def test_action_guard_admits_only_the_exact_two_rows_and_manual_source(self) -> None:
        guard = step(action()["runs"]["steps"], "Validate focused runtime request")["run"]
        environment = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": REF,
            "GITHUB_JOB": "smoke-build",
            "VALIDATION_PROFILE": PROFILE,
            "FOCUSED_RUNTIME": "direct-startup-diagnostic",
            "OOM_ACCOUNTING_MODE": "qualification",
            "IMAGE_NAME": "docker-20.10-rootless",
            "IMAGE_ARCH": "amd64",
            "SELECTED_IMAGE_NAME": "docker-20.10-rootless",
            "SELECTED_IMAGE_ARCH": "amd64",
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for image, architecture in (("docker-20.10-rootless", "amd64"), ("docker-26-rootless", "arm64")):
                result = shell(guard, {**environment, "IMAGE_NAME": image, "IMAGE_ARCH": architecture}, directory)
                self.assertEqual(result.returncode, 0, result.stderr)
            for key, value in (
                ("GITHUB_EVENT_NAME", "pull_request"),
                ("GITHUB_REF", "refs/heads/main"),
                ("GITHUB_REF", "refs/heads/TheRealBecks/issue442-diagnostic-workflow-20261031"),
                ("GITHUB_JOB", "build"),
                ("VALIDATION_PROFILE", "full"),
                ("OOM_ACCOUNTING_MODE", "diagnostic"),
                ("IMAGE_NAME", "docker-26-rootless"),
                ("IMAGE_ARCH", "arm64"),
                ("IMAGE_NAME", "docker-29-conformance-rootless"),
                ("FOCUSED_RUNTIME", "unknown"),
            ):
                with self.subTest(key=key, value=value):
                    self.assertNotEqual(shell(guard, {**environment, key: value}, directory).returncode, 0)

    def test_selection_is_exact_and_existing_modes_keep_their_values(self) -> None:
        selection = step(workflow()["jobs"]["plan"]["steps"], "Select validation profile")["run"]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            environment = {
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": REF,
                "GITHUB_JOB": "plan",
                "VALIDATION_PROFILE": PROFILE,
                "FOCUSED_RUNTIME": "witness-diagnostic",
                "GITHUB_OUTPUT": str(directory / "outputs"),
            }
            result = shell(selection, environment, directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads((directory / "focused-runtime-selection.json").read_text()),
                {
                    "validationProfile": PROFILE,
                    "focusedRuntimeRequested": "witness-diagnostic",
                    "focusedRuntime": "direct-startup-diagnostic",
                    "oomAccountingMode": "qualification",
                    "qualification": "none",
                },
            )
            for key, value in (
                ("GITHUB_REF", "refs/heads/main"),
                ("GITHUB_JOB", "smoke-build"),
                ("FOCUSED_RUNTIME", "mandatory-accounting"),
            ):
                with self.subTest(key=key):
                    self.assertNotEqual(shell(selection, {**environment, key: value}, directory).returncode, 0)
            for event, profile in (
                ("pull_request", "full"),
                ("merge_group", "full"),
                ("workflow_dispatch", "full"),
                ("workflow_dispatch", "docker-rootless-qualification"),
            ):
                result = shell(
                    selection, {**environment, "GITHUB_EVENT_NAME": event, "VALIDATION_PROFILE": profile}, directory
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads((directory / "focused-runtime-selection.json").read_text())
                self.assertEqual(
                    (record["focusedRuntime"], record["oomAccountingMode"], record["qualification"]),
                    ("none", "qualification", "pending"),
                )

    def test_build_outputs_must_match_the_independent_selected_input_row(self) -> None:
        runtime = step(action()["runs"]["steps"], "Verify image runtime")
        self.assertEqual(runtime["env"]["SELECTED_IMAGE_NAME"], "${{ fromJSON(inputs.entry).name }}")
        self.assertEqual(runtime["env"]["SELECTED_IMAGE_ARCH"], "${{ fromJSON(inputs.entry).arch }}")
        guard = runtime["run"].split("mkdir -p", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            for image, architecture, expected in (
                ("docker-20.10-rootless", "amd64", 0),
                ("docker-26-rootless", "arm64", 1),
                ("docker-20.10-rootless", "arm64", 1),
            ):
                result = shell(
                    guard,
                    {
                        "IMAGE_NAME": image,
                        "IMAGE_ARCH": architecture,
                        "SELECTED_IMAGE_NAME": "docker-20.10-rootless",
                        "SELECTED_IMAGE_ARCH": "amd64",
                    },
                    Path(temporary),
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_original_clock_is_established_before_bootstrap_and_forwarded(self) -> None:
        runtime = step(action()["runs"]["steps"], "Verify image runtime")["run"]
        boundary = 'if [ "${ACTIVE_USERNS_CONTEXT}" = "true" ] && {'
        prefix = runtime.split(boundary, 1)[0]
        self.assertIn('active_deadline="${direct_deadline_ns}"', runtime)
        self.assertIn('"${ACTIVE_JOB}" "${IMAGE_NAME}" "${active_arm}"', runtime)
        self.assertLess(
            runtime.index('direct_started_ns="$('), runtime.index("scripts.docker_userns_active_bootstrap_bundle")
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = shell(
                prefix + '\nprintf "%s\\n" "${direct_started_ns}" "${direct_deadline_ns}" "${runtime_args[@]}"\n',
                {
                    "RUNNER_TEMP": temporary,
                    "OOM_ACCOUNTING_MODE": "qualification",
                    "FOCUSED_RUNTIME": "direct-startup-diagnostic",
                    "VALIDATION_PROFILE": PROFILE,
                    "ACTIVE_USERNS_CONTEXT": "true",
                    "IMAGE_NAME": "docker-20.10-rootless",
                    "IMAGE_ARCH": "amd64",
                    "SELECTED_IMAGE_NAME": "docker-20.10-rootless",
                    "SELECTED_IMAGE_ARCH": "amd64",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REF": REF,
                    "GITHUB_JOB": "smoke-build",
                    "TRUSTED_RUNTIME": "true",
                },
                Path(temporary),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            started, deadline, *arguments = result.stdout.splitlines()
            self.assertEqual(int(deadline) - int(started), 900_000_000_000)
            self.assertIn("--direct-startup-diagnostic", arguments)
            self.assertEqual(arguments[arguments.index("--direct-started-ns") + 1], started)
            self.assertEqual(arguments[arguments.index("--direct-deadline-ns") + 1], deadline)

    def test_distinct_aggregate_fails_planning_without_required_ci_or_authority(self) -> None:
        aggregate_job = workflow()["jobs"]["required-ci"]
        self.assertIn("Direct-rootless startup diagnostic (qualification:none)", aggregate_job["name"])
        self.assertIn("inputs.validation_profile", aggregate_job["name"])
        guard = step(aggregate_job["steps"], "Require validation, planning, and selected builds")["run"]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            environment = {
                "REQUESTED_PROFILE": PROFILE,
                "REQUESTED_DIAGNOSTIC_ONLY": "true",
                "SELECTED_PROFILE": "",
                "DIAGNOSTIC_ONLY": "",
                "HAS_BUILDS": "",
                "HAS_PAYLOADS": "",
                "PAYLOAD_RESULT": "skipped",
                "PLAN_RESULT": "failure",
                "SMOKE_RESULT": "skipped",
                "VALIDATE_RESULT": "success",
                "GITHUB_STEP_SUMMARY": str(directory / "summary"),
                "RUNNER_TEMP": temporary,
            }
            self.assertNotEqual(shell(guard, environment, directory).returncode, 0)
            self.assertIn("qualification:none", (directory / "summary").read_text())
            self.assertEqual(
                json.loads((directory / "direct-startup-aggregate.json").read_text())["qualification"], "none"
            )
            environment.update(
                SELECTED_PROFILE=PROFILE,
                DIAGNOSTIC_ONLY="true",
                HAS_BUILDS="true",
                HAS_PAYLOADS="true",
                PAYLOAD_RESULT="success",
                PLAN_RESULT="success",
                SMOKE_RESULT="success",
            )
            self.assertEqual(shell(guard, environment, directory).returncode, 0)
            for key, value in (
                ("PLAN_RESULT", "skipped"),
                ("SMOKE_RESULT", "cancelled"),
                ("HAS_PAYLOADS", "false"),
                ("DIAGNOSTIC_ONLY", "false"),
                ("SELECTED_PROFILE", "full"),
            ):
                with self.subTest(key=key):
                    self.assertNotEqual(shell(guard, {**environment, key: value}, directory).returncode, 0)
        steps = aggregate_job["steps"]
        self.assertIn(
            "scripts.docker_direct_startup_aggregate",
            step(steps, "Validate both nonqualifying direct startup pairs")["run"],
        )
        self.assertFalse(any(item.get("continue-on-error") for item in steps))

    def test_pair_retention_projects_only_validated_exports_and_preserves_original(self) -> None:
        steps = action()["runs"]["steps"]
        retention = step(steps, "Retain a closed direct diagnostic fallback when no pair was produced")
        self.assertNotIn("steps.build.outcome", retention["if"])
        self.assertIn("fromJSON(inputs.entry).name", retention["env"]["IMAGE_NAME"])
        for contents in (None, "", "PRIVATE-SECRET", "PRIVATE-SECRET" * 1000):
            with self.subTest(contents=contents is None), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                original = directory / "runtime-evidence/docker-20.10-rootless-amd64.json"
                original.parent.mkdir()
                if contents is not None:
                    original.write_text(contents)
                environment = {
                    "RUNNER_TEMP": temporary,
                    "IMAGE_NAME": "docker-20.10-rootless",
                    "IMAGE_ARCH": "amd64",
                    "SELECTED_IMAGE_NAME": "docker-20.10-rootless",
                    "SELECTED_IMAGE_ARCH": "amd64",
                    "GITHUB_SHA": aggregate_tests.pair()["candidate"],
                    "GITHUB_RUN_ID": "145",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_JOB": "smoke-build",
                    "PYTHON_VERSION": "3.14",
                    "PYTHONPATH": str(ROOT),
                }
                shim = "uv() { shift 5; " + shlex.quote(sys.executable) + ' "$@"; }\n'
                result = shell(shim + retention["run"], environment, directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                exported = directory / "direct-startup-pair-export/docker-20.10-rootless-amd64.json"
                record = json.loads(exported.read_text())
                self.assertEqual((record["qualification"], record["status"]), ("none", "failed"))
                self.assertNotIn("PRIVATE-SECRET", exported.read_text() + result.stdout + result.stderr)
                if contents is None:
                    self.assertFalse(original.exists())
                else:
                    self.assertEqual(original.read_text(), contents)
        upload = step(steps, "Upload one closed direct diagnostic pair report")
        self.assertIn("steps.direct-report-retention.outcome == 'success'", upload["if"])
        self.assertIn("direct-startup-pair-export/", upload["with"]["path"])
        self.assertNotIn("runtime-evidence", upload["with"]["path"])
        hosts = step(steps, "Upload separate nonqualifying direct host observations")["with"]
        self.assertNotIn("*", hosts["path"])
        self.assertIn("-cleanup-failure.json", hosts["path"])
        self.assertNotIn("direct-startup-pair-", hosts["name"])
        download = step(workflow()["jobs"]["required-ci"]["steps"], "Download direct diagnostic pair reports")
        self.assertEqual(download["with"]["pattern"], "direct-startup-pair-*")
        runtime = step(steps, "Verify image runtime")["run"]
        self.assertIn('--image "${SELECTED_IMAGE_NAME}" --architecture "${SELECTED_IMAGE_ARCH}"', runtime)

    def test_disposal_failure_preserves_first_failure_and_cancellation_status(self) -> None:
        runtime = step(action()["runs"]["steps"], "Verify image runtime")["run"]
        function = runtime[runtime.index("finish_active_stage() {") : runtime.index("trap finish_active_stage EXIT")]
        for status in (0, 7, 130, 143):
            for cleanup_status in (0, 1):
                with (
                    self.subTest(status=status, cleanup_status=cleanup_status),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    directory = Path(temporary)
                    (directory / "runtime-evidence").mkdir()
                    script = (
                        f"set -euo pipefail\nactive_stage=/inert/no-host-stage\nsudo() {{ return {cleanup_status}; }}\n"
                        + function
                        + f"trap finish_active_stage EXIT\nexit {status}\n"
                    )
                    result = shell(
                        script,
                        {
                            "RUNNER_TEMP": temporary,
                            "FOCUSED_RUNTIME": "direct-startup-diagnostic",
                            "IMAGE_NAME": "docker-20.10-rootless",
                            "IMAGE_ARCH": "amd64",
                            "SELECTED_IMAGE_NAME": "docker-20.10-rootless",
                            "SELECTED_IMAGE_ARCH": "amd64",
                        },
                        directory,
                    )
                    expected = status or cleanup_status
                    self.assertEqual(result.returncode, expected, result.stderr)
                    diagnostic = directory / "runtime-evidence/docker-20.10-rootless-amd64-cleanup-failure.json"
                    self.assertEqual(diagnostic.exists(), cleanup_status != 0)
                    if cleanup_status:
                        record = json.loads(diagnostic.read_text())
                        self.assertEqual(record["originalExitCode"], status)
                        self.assertEqual(
                            (record["qualification"], record["reason"]), ("none", "stage-disposal-unverified")
                        )

    def test_shells_parse_and_ordinary_authority_is_still_guarded(self) -> None:
        all_steps = (
            action()["runs"]["steps"] + workflow()["jobs"]["plan"]["steps"] + workflow()["jobs"]["required-ci"]["steps"]
        )
        for item in all_steps:
            if item.get("shell") == "bash" and "run" in item:
                result = subprocess.run(
                    ["/bin/bash", "-n"], input=item["run"], text=True, capture_output=True, check=False, timeout=10
                )
                self.assertEqual(result.returncode, 0, item["name"] + result.stderr)
        runtime = step(action()["runs"]["steps"], "Verify image runtime")
        self.assertIn('if [ "${FOCUSED_RUNTIME}" = none ]; then', runtime["run"])
        self.assertIn("require_ordinary_runtime_authority", runtime["run"])
        self.assertIn("FIXED_ACTIVE_ROOT_BOOTSTRAP", runtime["env"])
