"""Manual diagnostics use canonical builds without qualifying as Required CI."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts import container_engine as engine
from scripts.workflow_config import load_config
from tests.test_evidence_gate import maintained_runtime


def render_workflow_value(
    value: str, *, event: str, profile: str, ref: str = "refs/heads/candidate", focused: str = "witness-diagnostic"
) -> str:
    """Evaluate the small Actions expression subset used here, including folded equality."""
    context = {
        "github.event_name": event,
        "inputs.validation_profile": profile,
        "github.ref": ref,
        "inputs.focused_runtime": focused,
    }
    checks = unittest.TestCase()

    def evaluate(node: ast.AST) -> str | bool:
        if isinstance(node, ast.Constant):
            checks.assertIsInstance(node.value, (str, bool))
            return node.value
        if isinstance(node, ast.Attribute):
            return context[ast.unparse(node)]
        if isinstance(node, ast.Compare):
            checks.assertEqual(len(node.ops), 1)
            checks.assertIsInstance(node.ops[0], (ast.Eq, ast.NotEq))
            left, right = evaluate(node.left), evaluate(node.comparators[0])
            equal = (
                left.casefold() == right.casefold()
                if isinstance(left, str) and isinstance(right, str)
                else left == right
            )
            return equal if isinstance(node.ops[0], ast.Eq) else not equal
        if isinstance(node, ast.BoolOp):
            result: str | bool = False
            for part in node.values:
                result = evaluate(part)
                if bool(result) == isinstance(node.op, ast.Or):
                    break
            return result
        message = f"Unsupported workflow expression: {ast.dump(node)}"
        raise AssertionError(message)

    def replace(match: re.Match[str]) -> str:
        expression = match[1].strip().replace("&&", " and ").replace("||", " or ")
        result = evaluate(ast.parse(expression, mode="eval").body)
        return str(result).lower() if isinstance(result, bool) else result

    return re.sub(r"\$\{\{(.*?)\}\}", replace, value)


class DiagnosticDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = engine._repo_root()
        cls.workflow = yaml.safe_load((cls.root / ".github/workflows/ci.yml").read_text())
        cls.jobs = cls.workflow["jobs"]
        cls.selector = next(step for step in cls.jobs["plan"]["steps"] if step.get("id") == "mode")

    def select(
        self,
        event: str,
        profile: str,
        focused: str = "witness-diagnostic",
        *,
        ref: str = "refs/heads/TheRealBecks/issue527",
        job: str = "plan",
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run(  # noqa: S603 - Execute the repository-owned workflow with inputs only in env.
                ["/bin/bash", "-c", self.selector["run"]],
                cwd=directory,
                env={
                    **os.environ,
                    "GITHUB_EVENT_NAME": event,
                    "GITHUB_REF": ref,
                    "GITHUB_JOB": job,
                    "FOCUSED_RUNTIME": focused,
                    "VALIDATION_PROFILE": render_workflow_value(
                        self.selector["env"]["VALIDATION_PROFILE"], event=event, profile=profile
                    ),
                    "GITHUB_OUTPUT": str(output),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
            selection = Path(directory) / "focused-runtime-selection.json"
            self.selection = json.loads(selection.read_text()) if selection.exists() else None
            return result, values

    def test_nonmanual_events_ignore_injected_profiles(self) -> None:
        for event in ("pull_request", "push", "merge_group", "workflow_call", "schedule"):
            for profile in ("full", "docker-rootless-diagnostic", "unknown", "$(exit 19)"):
                with self.subTest(event=event, profile=profile):
                    result, values = self.select(event, profile)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        values,
                        {
                            "scope": "all",
                            "target": "",
                            "diagnostic_only": "false",
                            "runtime_mode": "qualification",
                            "focused_runtime": "none",
                            "validation_profile": "full",
                        },
                    )

    def test_manual_default_and_full_remain_full(self) -> None:
        dispatch = self.workflow[True]["workflow_dispatch"]["inputs"]["validation_profile"]
        self.assertEqual(dispatch["type"], "choice")
        self.assertEqual(dispatch["default"], "full")
        self.assertEqual(
            dispatch["options"],
            [
                "full",
                "docker-rootless-qualification",
                "docker-rootless-diagnostic",
                "docker-direct-rootless-diagnostic",
            ],
        )
        self.assertEqual(self.selector["env"]["VALIDATION_PROFILE"], "${{ inputs.validation_profile || 'full' }}")
        for profile in ("", dispatch["default"], "FULL", "FuLl"):
            with self.subTest(profile=profile):
                result, values = self.select("workflow_dispatch", profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    values,
                    {
                        "scope": "all",
                        "target": "",
                        "diagnostic_only": "false",
                        "runtime_mode": "qualification",
                        "focused_runtime": "none",
                        "validation_profile": "full",
                    },
                )

    def test_manual_diagnostic_case_variants_match_the_requested_mode_and_check_name(self) -> None:
        aggregate = self.jobs["required-ci"]
        requested = aggregate["steps"][0]["env"]["REQUESTED_DIAGNOSTIC_ONLY"]
        for profile in ("docker-rootless-diagnostic", "DOCKER-ROOTLESS-DIAGNOSTIC", "Docker-Rootless-Diagnostic"):
            with self.subTest(profile=profile):
                result, values = self.select("workflow_dispatch", profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    values,
                    {
                        "scope": "image",
                        "target": "docker-29-conformance-rootless",
                        "diagnostic_only": "true",
                        "runtime_mode": "diagnostic",
                        "focused_runtime": "witness-diagnostic",
                        "validation_profile": "docker-rootless-diagnostic",
                    },
                )
                self.assertEqual(render_workflow_value(requested, event="workflow_dispatch", profile=profile), "true")
                self.assertEqual(
                    render_workflow_value(aggregate["name"], event="workflow_dispatch", profile=profile),
                    "Docker fixture diagnostic (not Required CI)",
                )

    def test_unknown_manual_inputs_refuse_without_executing_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "injected"
            for profile in (
                "unknown",
                " ",
                " full",
                "full ",
                "docker-rootless-diagnostic ",
                f"$(touch {sentinel})",
                f"full; touch {sentinel}",
                "full\nscope=image",
            ):
                with self.subTest(profile=profile):
                    result, values = self.select("workflow_dispatch", profile)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(values, {})
                    self.assertFalse(sentinel.exists())

    def test_selected_diagnostic_uses_catalogue_image_on_both_canonical_architectures(self) -> None:
        result, values = self.select("workflow_dispatch", "docker-rootless-diagnostic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {
                "scope": "image",
                "target": "docker-29-conformance-rootless",
                "diagnostic_only": "true",
                "runtime_mode": "diagnostic",
                "focused_runtime": "witness-diagnostic",
                "validation_profile": "docker-rootless-diagnostic",
            },
        )
        steps = self.jobs["plan"]["steps"]
        create = next(step for step in steps if step["name"] == "Create build plan")
        expressions = {
            "${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha || '' }}": "",
            "${{ steps.mode.outputs.scope }}": values["scope"],
            "${{ steps.mode.outputs.target }}": values["target"],
            "${{ steps.mode.outputs.validation_profile }}": values["validation_profile"],
            "${{ github.head_ref || github.ref_name }}": "issue521",
            "${{ github.sha }}": "a" * 40,
        }
        with tempfile.TemporaryDirectory() as directory:
            shim = Path(directory) / "uv"
            arguments_output = Path(directory) / "arguments"
            shim.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$ARGUMENTS_OUTPUT"\n')
            shim.chmod(0o700)
            command = create["run"].replace("${{ github.event.repository.default_branch }}", "main")
            invocation = subprocess.run(  # noqa: S603 - Repository-owned workflow; uv only records argv.
                ["/bin/bash", "-c", command],
                env={
                    **os.environ,
                    **{name: expressions[value] for name, value in create["env"].items()},
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "ARGUMENTS_OUTPUT": str(arguments_output),
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "PYTHON_VERSION": "3.14",
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(invocation.returncode, 0, invocation.stderr)
            arguments = arguments_output.read_text().splitlines()
        self.assertEqual(
            arguments[:7], ["run", "--frozen", "--python", "3.14", "python", "-m", "scripts.container_engine"]
        )
        parsed = engine._parser().parse_args(arguments[7:])
        plan = engine._build_plan(
            engine._load_images(),
            engine.PlanOptions(
                parsed.event_name,
                parsed.ref_name,
                parsed.default_branch,
                parsed.before,
                parsed.sha,
                parsed.max_stages,
                parsed.scope,
                parsed.target,
            ),
        )
        self.assertEqual([image["name"] for image in plan["images"]], ["docker-29-conformance-rootless"])
        entries = plan["smokeBuildMatrix"]["include"]
        self.assertEqual({entry["arch"] for entry in entries}, {"amd64", "arm64"})
        self.assertEqual({entry["name"] for entry in entries}, {"docker-29-conformance-rootless"})
        self.assertEqual({entry["runner"] for entry in entries}, set(engine.RUNNERS.values()))
        self.assertLess(steps.index(self.selector), steps.index(create))
        self.assertEqual(create["env"]["BUILD_SCOPE"], "${{ steps.mode.outputs.scope }}")
        self.assertEqual(create["env"]["BUILD_TARGET"], "${{ steps.mode.outputs.target }}")
        self.assertIn('--scope "${BUILD_SCOPE}"', create["run"])
        self.assertIn('--target "${BUILD_TARGET}"', create["run"])
        build = self.jobs["smoke-build"]["steps"][-1]
        self.assertEqual(build["uses"], "./.github/actions/build-arch-image")
        self.assertEqual(build["with"]["upload-archive"], "false")

    def test_diagnostic_context_cannot_report_required_ci_even_when_plan_fails(self) -> None:
        aggregate = self.jobs["required-ci"]
        self.assertEqual(
            render_workflow_value(aggregate["name"], event="workflow_dispatch", profile="docker-rootless-diagnostic"),
            "Docker fixture diagnostic (not Required CI)",
        )
        self.assertNotIn("needs.plan", aggregate["name"])
        self.assertEqual(aggregate["if"], "${{ always() }}")
        self.assertEqual(set(aggregate["needs"]), {"validate", "plan", "smoke-build", "payloads"})
        self.assertEqual(self.jobs["plan"]["outputs"]["diag_only"], "${{ steps.mode.outputs.diagnostic_only }}")
        self.assertEqual(aggregate["steps"][0]["env"]["DIAGNOSTIC_ONLY"], "${{ needs.plan.outputs.diag_only }}")

    def test_aggregate_preserves_failures_and_refuses_missing_outputs(self) -> None:
        script = self.jobs["required-ci"]["steps"][0]["run"]
        baseline = {
            "SELECTED_PROFILE": "full",
            "REQUESTED_PROFILE": "full",
            "DIAGNOSTIC_ONLY": "false",
            "REQUESTED_DIAGNOSTIC_ONLY": "false",
            "HAS_BUILDS": "true",
            "HAS_PAYLOADS": "true",
            "PAYLOAD_RESULT": "success",
            "PLAN_RESULT": "success",
            "SMOKE_RESULT": "success",
            "VALIDATE_RESULT": "success",
        }
        cases = [
            ({}, True),
            (
                {
                    "DIAGNOSTIC_ONLY": "true",
                    "REQUESTED_DIAGNOSTIC_ONLY": "true",
                    "SELECTED_PROFILE": "docker-rootless-diagnostic",
                    "REQUESTED_PROFILE": "docker-rootless-diagnostic",
                },
                True,
            ),
            ({"DIAGNOSTIC_ONLY": "true"}, False),
            ({"REQUESTED_DIAGNOSTIC_ONLY": "true"}, False),
            (
                {
                    "HAS_BUILDS": "false",
                    "HAS_PAYLOADS": "false",
                    "SMOKE_RESULT": "skipped",
                    "PAYLOAD_RESULT": "skipped",
                },
                True,
            ),
            ({"HAS_BUILDS": "false"}, False),
            (
                {
                    "DIAGNOSTIC_ONLY": "true",
                    "REQUESTED_DIAGNOSTIC_ONLY": "true",
                    "SELECTED_PROFILE": "docker-rootless-diagnostic",
                    "REQUESTED_PROFILE": "docker-rootless-diagnostic",
                    "HAS_BUILDS": "false",
                    "SMOKE_RESULT": "skipped",
                },
                False,
            ),
        ]
        cases.extend(
            ({key: value}, False)
            for key in ("DIAGNOSTIC_ONLY", "REQUESTED_DIAGNOSTIC_ONLY", "HAS_BUILDS", "HAS_PAYLOADS")
            for value in ("", "unknown")
        )
        cases.extend(
            ({key: value}, False)
            for key in ("VALIDATE_RESULT", "PLAN_RESULT", "SMOKE_RESULT", "PAYLOAD_RESULT")
            for value in ("failure", "cancelled", "skipped", "")
        )
        cases.extend(
            (
                {
                    "DIAGNOSTIC_ONLY": "true",
                    "REQUESTED_DIAGNOSTIC_ONLY": "true",
                    "SELECTED_PROFILE": "docker-rootless-diagnostic",
                    "REQUESTED_PROFILE": "docker-rootless-diagnostic",
                    key: value,
                },
                False,
            )
            for key in ("VALIDATE_RESULT", "PLAN_RESULT", "SMOKE_RESULT", "PAYLOAD_RESULT")
            for value in ("failure", "cancelled", "skipped", "")
        )
        for changes, success in cases:
            with self.subTest(changes=changes):
                result = subprocess.run(  # noqa: S603 - Exercise the repository-owned aggregate script.
                    ["/bin/bash", "-c", script],
                    env={**os.environ, **baseline, **changes},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if changes.get("DIAGNOSTIC_ONLY") == "true" and success:
                    self.assertIn("Nonqualifying", result.stdout)
                    self.assertNotIn("Required repository checks passed", result.stdout)

    def test_concurrency_separates_event_and_manual_profile(self) -> None:
        concurrency = self.workflow["concurrency"]
        expected_groups = {
            "full": ("", "full", "FULL", "FuLl"),
            "qualification": (
                "docker-rootless-qualification",
                "DOCKER-ROOTLESS-QUALIFICATION",
                "Docker-Rootless-Qualification",
            ),
            "diagnostic": ("docker-rootless-diagnostic", "DOCKER-ROOTLESS-DIAGNOSTIC", "Docker-Rootless-Diagnostic"),
            "invalid": (
                "unknown",
                "UNKNOWN",
                " ",
                " full",
                "full ",
                "docker-rootless-diagnostic ",
                "$(exit 19)",
                "full\nscope=image",
            ),
        }
        groups = {}
        for mode, profiles in expected_groups.items():
            for profile in profiles:
                with self.subTest(mode=mode, profile=profile):
                    group = render_workflow_value(concurrency["group"], event="workflow_dispatch", profile=profile)
                    self.assertEqual(group, f"validate-containers-workflow_dispatch-{mode}-refs/heads/candidate")
                    groups[mode] = group.casefold()
        self.assertEqual(len(set(groups.values())), 4)
        for event in ("pull_request", "push", "merge_group", "workflow_call"):
            for profiles in expected_groups.values():
                for profile in profiles:
                    group = render_workflow_value(concurrency["group"], event=event, profile=profile)
                    self.assertEqual(group, f"validate-containers-{event}-full-refs/heads/candidate")
                    self.assertNotIn(group.casefold(), groups.values())
        different_ref = render_workflow_value(
            concurrency["group"], event="workflow_dispatch", profile="full", ref="refs/heads/other"
        )
        self.assertNotEqual(different_ref.casefold(), groups["full"])
        self.assertTrue(concurrency["cancel-in-progress"])

    def test_execution_mode_and_focused_selection_use_only_validated_plan_outputs(self) -> None:
        build = self.jobs["smoke-build"]["steps"][-1]
        self.assertEqual(build["with"]["oom-accounting-mode"], "${{ needs.plan.outputs.runtime_mode }}")
        self.assertEqual(build["with"]["focused-runtime"], "${{ needs.plan.outputs.focused_runtime }}")
        outputs = self.jobs["plan"]["outputs"]
        self.assertEqual(outputs["runtime_mode"], "${{ steps.mode.outputs.runtime_mode }}")
        self.assertEqual(outputs["focused_runtime"], "${{ steps.mode.outputs.focused_runtime }}")
        action = yaml.safe_load((self.root / ".github/actions/build-arch-image/action.yml").read_text())
        self.assertEqual(action["inputs"]["oom-accounting-mode"]["default"], "qualification")
        self.assertEqual(action["inputs"]["focused-runtime"]["default"], "none")
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        self.assertEqual(runtime["env"]["OOM_ACCOUNTING_MODE"], "${{ inputs.oom-accounting-mode }}")
        self.assertEqual(runtime["env"]["FOCUSED_RUNTIME"], "${{ inputs.focused-runtime }}")
        publication = yaml.safe_load((self.root / ".github/workflows/publish-one-image.yml").read_text())
        consumers = [
            step
            for job in publication["jobs"].values()
            for step in job.get("steps", [])
            if step.get("uses") == "./.github/actions/build-arch-image"
        ]
        self.assertEqual(len(consumers), 1)
        self.assertEqual(consumers[0]["with"].get("oom-accounting-mode", "qualification"), "qualification")
        self.assertEqual(consumers[0]["with"].get("focused-runtime", "none"), "none")

    def test_mandatory_accounting_is_focused_qualification_work_without_native_authority(self) -> None:
        choices = self.workflow[True]["workflow_dispatch"]["inputs"]["focused_runtime"]
        self.assertEqual(choices["default"], "witness-diagnostic")
        self.assertEqual(choices["options"], ["witness-diagnostic", "mandatory-accounting"])
        result, values = self.select("workflow_dispatch", "docker-rootless-diagnostic", "mandatory-accounting")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {
                "scope": "image",
                "target": "docker-29-conformance-rootless",
                "diagnostic_only": "true",
                "runtime_mode": "qualification",
                "focused_runtime": "mandatory-accounting",
                "validation_profile": "docker-rootless-diagnostic",
            },
        )
        self.assertEqual(self.selection["qualification"], "none")
        self.assertEqual(self.selection["oomAccountingMode"], "qualification")
        self.assertEqual(self.selection["focusedRuntime"], "mandatory-accounting")

    def test_unknown_inapplicable_or_wrong_context_focused_requests_refuse_without_fallback(self) -> None:
        for choice in ("", "unknown", "MANDATORY-ACCOUNTING", "$(exit 19)"):
            with self.subTest(choice=choice):
                result, values = self.select("workflow_dispatch", "docker-rootless-diagnostic", choice)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(values, {})
        for event, profile, ref, job in (
            ("workflow_dispatch", "full", "refs/heads/TheRealBecks/issue527", "plan"),
            ("workflow_dispatch", "docker-rootless-diagnostic", "refs/heads/main", "plan"),
            ("workflow_dispatch", "docker-rootless-diagnostic", "refs/heads/TheRealBecks/issue527", "smoke-build"),
            ("pull_request", "docker-rootless-diagnostic", "refs/heads/TheRealBecks/issue527", "plan"),
            ("merge_group", "full", "refs/heads/TheRealBecks/issue527", "plan"),
        ):
            with self.subTest(event=event, profile=profile, ref=ref, job=job):
                result, values = self.select(event, profile, "mandatory-accounting", ref=ref, job=job)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(values, {})

    def test_action_rechecks_focused_context_and_explicit_mode_before_privileged_bootstrap(self) -> None:
        action = yaml.safe_load((self.root / ".github/actions/build-arch-image/action.yml").read_text())
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        prelude = runtime["run"].split('if [ "${TRUSTED_RUNTIME}" = "true" ]; then', 1)[0]
        base = {
            "OOM_ACCOUNTING_MODE": "qualification",
            "FOCUSED_RUNTIME": "mandatory-accounting",
            "ACTIVE_USERNS_CONTEXT": "true",
            "VALIDATION_PROFILE": "docker-rootless-diagnostic",
            "IMAGE_NAME": "docker-29-conformance-rootless",
            "IMAGE_ARCH": "amd64",
            "SELECTED_IMAGE_NAME": "docker-29-conformance-rootless",
            "SELECTED_IMAGE_ARCH": "amd64",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/TheRealBecks/issue527",
            "GITHUB_JOB": "smoke-build",
        }
        for change in (
            {},
            {"GITHUB_JOB": "publish"},
            {"GITHUB_REF": "refs/heads/main"},
            {"IMAGE_NAME": "other"},
            {"IMAGE_ARCH": "arm64"},
            {"SELECTED_IMAGE_NAME": "docker-20.10-rootless"},
            {"SELECTED_IMAGE_ARCH": "arm64"},
            {"ACTIVE_USERNS_CONTEXT": "false"},
            {"VALIDATION_PROFILE": "full"},
            {"OOM_ACCOUNTING_MODE": "diagnostic"},
            {"FOCUSED_RUNTIME": "unknown"},
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run(  # noqa: S603 - only ordinary shell validation, no bootstrap/runtime command.
                    ["/bin/bash", "-c", prelude],
                    env={**os.environ, **base, **change, "RUNNER_TEMP": temporary},
                    cwd=temporary,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, not change, result.stderr)

    def test_focused_action_refuses_before_any_tool_install_or_image_build(self) -> None:
        action = yaml.safe_load((self.root / ".github/actions/build-arch-image/action.yml").read_text())
        first = action["runs"]["steps"][0]
        self.assertEqual(first["name"], "Validate focused runtime request")
        base = {
            "OOM_ACCOUNTING_MODE": "qualification",
            "FOCUSED_RUNTIME": "mandatory-accounting",
            "VALIDATION_PROFILE": "docker-rootless-diagnostic",
            "IMAGE_NAME": "docker-29-conformance-rootless",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/TheRealBecks/issue527",
            "GITHUB_JOB": "smoke-build",
        }
        for change in (
            {},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_EVENT_NAME": "merge_group"},
            {"VALIDATION_PROFILE": "full"},
            {"GITHUB_JOB": "publish"},
            {"GITHUB_REF": "refs/heads/main"},
            {"IMAGE_NAME": "other"},
            {"FOCUSED_RUNTIME": "unknown"},
        ):
            with self.subTest(change=change):
                result = subprocess.run(  # noqa: S603 - plain validation, no native operation.
                    ["/bin/bash", "-c", first["run"]],
                    env={**os.environ, **base, **change},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, not change, result.stderr)

    def test_ordinary_action_rejects_exit_zero_with_none_native_authority(self) -> None:
        action = yaml.safe_load((self.root / ".github/actions/build-arch-image/action.yml").read_text())
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        script = runtime["run"].split("<<'PY_AUTHORITY'\n", 1)[1].split("\nPY_AUTHORITY", 1)[0]
        self.assertIn('if [ "${FOCUSED_RUNTIME}" = none ]', runtime["run"])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "operational-success.json"
            path.write_text(
                json.dumps(
                    {
                        "image": "docker-29-conformance-rootless",
                        "architecture": "amd64",
                        "profile": "docker",
                        "status": "passed",
                        "qualification": "none",
                        "oomAccountingStatus": "complete",
                    }
                )
            )
            result = subprocess.run(  # noqa: S603 - only the data-only ordinary authority guard.
                [os.sys.executable, "-c", script, "docker-29-conformance-rootless", "amd64", str(path)],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qualification", result.stderr)

    def test_generated_workflow_matches_canonical_template(self) -> None:
        generated = engine._workflow_environment().get_template("ci.yml.j2").render(config=load_config(self.root))
        self.assertEqual(generated, (self.root / ".github/workflows/ci.yml").read_text())

    def test_actual_action_retains_failure_fallback_until_maintained_disposal_and_authority(self) -> None:
        action = yaml.safe_load((self.root / ".github/actions/build-arch-image/action.yml").read_text())
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        tail = "finish_active_stage() {" + runtime["run"].split("finish_active_stage() {", 1)[1]
        # Only runtime and sudo boundaries are inert; execute the actual ordinary guard and EXIT trap.
        shim = r"""set -euo pipefail
runtime_args=()
active_stage=/run/containers-userns-active.ffffffffffffffffffffffffffffffff
sudo() {
  printf 'fallback-dispose\n' >> "${TEST_EVENTS}"
  return "${TEST_DISPOSAL_EXIT}"
}
uv() {
  if [[ "$*" == *"scripts.runtime_tests"* ]]; then
    printf 'runtime\n' >> "${TEST_EVENTS}"
    cp "${TEST_FIXTURE}" "${RUNNER_TEMP}/runtime-evidence/${IMAGE_NAME}-${IMAGE_ARCH}.json"
    return "${TEST_RUNTIME_EXIT}"
  fi
  printf 'authority\n' >> "${TEST_EVENTS}"
  while [ "$1" != python ]; do shift; done
  shift
  "${TEST_PYTHON}" "$@"
}
if true; then
"""
        for architecture, profile, fault in (
            (architecture, profile, fault)
            for architecture in ("amd64", "arm64")
            for profile in ("full", "docker-rootless-qualification")
            for fault in (None, "runtime", "invalid-ack", "fallback-failure")
        ):
            with (
                self.subTest(architecture=architecture, profile=profile, fault=fault),
                tempfile.TemporaryDirectory() as directory,
            ):
                root_path = Path(directory)
                (root_path / "runtime-evidence").mkdir()
                fixture = root_path / "fixture.json"
                events = root_path / "events"
                record = maintained_runtime(architecture, profile)
                if fault in {"invalid-ack", "fallback-failure"}:
                    record["stageDisposal"]["stageDisposed"] = False
                fixture.write_text(json.dumps(record))
                result = subprocess.run(  # noqa: S603 - inert runtime/sudo functions; actual repository shell and data guard.
                    ["/bin/bash", "-c", shim + tail],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": directory,
                        "TEST_FIXTURE": str(fixture),
                        "TEST_EVENTS": str(events),
                        "TEST_PYTHON": os.sys.executable,
                        "TEST_RUNTIME_EXIT": "1" if fault == "runtime" else "0",
                        "TEST_DISPOSAL_EXIT": "1" if fault == "fallback-failure" else "0",
                        "IMAGE_NAME": record["image"],
                        "IMAGE_ARCH": architecture,
                        "VALIDATION_PROFILE": profile,
                        "IMAGE_PATH": "unused.tar",
                        "PYTHON_VERSION": "3.14",
                        "FOCUSED_RUNTIME": "none",
                    },
                )
                self.assertEqual(result.returncode == 0, fault is None, result.stderr)
                expected = ["runtime", "authority"]
                if fault == "runtime":
                    expected = ["runtime"]
                if fault is not None:
                    expected.append("fallback-dispose")
                self.assertEqual(events.read_text().splitlines(), expected)


if __name__ == "__main__":
    unittest.main()
