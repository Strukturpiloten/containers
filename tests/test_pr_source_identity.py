"""PR jobs build the synthetic merge checkout and label that same revision."""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from scripts import container_engine as engine

ROOT = Path(__file__).resolve().parents[1]


class PullRequestSourceIdentityTests(unittest.TestCase):
    def test_merge_queue_runs_required_ci_against_the_queue_revision(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        # PyYAML's YAML 1.1 loader treats the unquoted workflow key 'on' as True.
        self.assertEqual(workflow[True]["merge_group"]["types"], ["checks_requested"])
        for job in ("validate", "plan"):
            with self.subTest(job=job):
                step = next(step for step in workflow["jobs"][job]["steps"] if "BEFORE" in step.get("env", {}))
                self.assertEqual(
                    step["env"]["BEFORE"],
                    "${{ github.event.merge_group.base_sha || github.event.pull_request.base.sha || '' }}",
                )
                if job == "plan":
                    self.assertEqual(step["env"]["SOURCE_SHA"], "${{ github.sha }}")
        required = workflow["jobs"]["required-ci"]
        self.assertEqual(required["name"], "Required CI")
        self.assertEqual(required["if"], "${{ always() }}")
        self.assertEqual(set(required["needs"]), {"validate", "plan", "payloads", "smoke-build"})
        self.assertEqual(workflow["permissions"], {})
        for job in workflow["jobs"].values():
            self.assertNotIn("write", job.get("permissions", {}).values())

    def test_pr_plan_and_payload_use_merge_sha_without_overriding_checkout_ref(self) -> None:
        paths = (
            (".github/workflow-templates/ci.yml.j2", "SOURCE_SHA: ${{ github.sha }}"),
            (".github/workflows/ci.yml", "SOURCE_SHA: ${{ github.sha }}"),
            (".github/workflow-templates/build-one-payload.yml.j2", "SOURCE_REVISION: ${{ github.sha }}"),
            (".github/workflows/build-one-payload.yml", "SOURCE_REVISION: ${{ github.sha }}"),
        )
        for relative, expected in paths:
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text()
                self.assertIn(expected, source)
                self.assertNotIn("github.event.pull_request.head.sha", source)
        for relative, jobs in (
            (".github/workflows/ci.yml", ("plan", "smoke-build")),
            (".github/workflows/build-one-payload.yml", ("build",)),
        ):
            workflow = yaml.safe_load((ROOT / relative).read_text())
            for job in jobs:
                with self.subTest(workflow=relative, job=job):
                    checkout = next(
                        step for step in workflow["jobs"][job]["steps"] if "actions/checkout@" in step.get("uses", "")
                    )
                    self.assertNotIn("ref", checkout.get("with", {}))

    def test_architecture_build_rejects_mismatched_plan_before_running_builder(self) -> None:
        merge_sha = "b" * 40
        head_sha = "a" * 40
        args = SimpleNamespace(entry_json='{"name":"fixture","arch":"amd64"}', plan="unused-plan.json")
        with (
            patch.object(engine, "_entry", return_value=("fixture", "amd64")),
            patch.object(engine, "_github_context", return_value=SimpleNamespace()),
            patch.object(engine, "_load_json", return_value={"sourceRevision": head_sha}),
            patch.object(engine, "_plan_image", return_value={}),
            patch.object(engine, "_run", return_value=merge_sha),
            patch.object(engine, "_source_timestamp") as timestamp,
            self.assertRaisesRegex(engine.ContainerEngineError, "does not match checkout HEAD"),
        ):
            engine._command_build_arch_image(args)
        timestamp.assert_not_called()

    def test_plan_and_build_guard_reject_head_sha_for_merge_checkout(self) -> None:
        merge_sha = "b" * 40
        head_sha = "a" * 40
        with patch.object(engine, "_run", return_value=merge_sha):
            with self.assertRaisesRegex(engine.ContainerEngineError, "does not match checkout HEAD"):
                engine._require_checkout_revision(head_sha)
            engine._require_checkout_revision(merge_sha)


if __name__ == "__main__":
    unittest.main()
