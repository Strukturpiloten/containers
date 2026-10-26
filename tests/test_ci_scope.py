"""Tool-only plans must remain small without hiding unrelated executable changes."""

from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import ci_scope
from scripts import container_engine as engine


class ToolClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        templates = self.root / ".github/workflow-templates"
        templates.mkdir(parents=True)
        (templates / "ci.yml.j2").touch()
        self.workflow = ".github/workflows/ci.yml"
        self.files = [ci_scope.CONFIG_PATH, self.workflow]
        old = {"UV_VERSION": "9.8.7", "ACTIONLINT_VERSION": "1.2.3", "AMD64_RUNNER": "ubuntu-26.04"}
        workflow = {"env": {"UV_VERSION": "9.8.7", "ACTIONLINT_VERSION": "1.2.3"}, "jobs": {"test": {"run": "check"}}}
        self.documents = {
            ("before", ci_scope.CONFIG_PATH): old,
            ("after", ci_scope.CONFIG_PATH): {**old, "UV_VERSION": "9.8.9"},
            ("before", self.workflow): workflow,
            ("after", self.workflow): {**workflow, "env": {**workflow["env"], "UV_VERSION": "9.8.9"}},
        }

    def classify(self) -> bool:
        def read(_root: Path, revision: str, path: str) -> dict:
            return copy.deepcopy(self.documents[revision, path])

        with patch.object(ci_scope, "_document", side_effect=read):
            return ci_scope.is_tool_only_change(self.root, "before", "after", self.files)

    def test_coordinated_tool_only_update_is_accepted(self) -> None:
        self.assertTrue(self.classify())

    def test_actionlint_update_uses_the_same_guard(self) -> None:
        self.documents["after", ci_scope.CONFIG_PATH]["ACTIONLINT_VERSION"] = "1.3.0"
        self.documents["after", self.workflow]["env"]["ACTIONLINT_VERSION"] = "1.3.0"
        self.assertTrue(self.classify())

    def test_changed_runner_or_unknown_config_key_retains_broad_validation(self) -> None:
        original = copy.deepcopy(self.documents["after", ci_scope.CONFIG_PATH])
        for key in ("AMD64_RUNNER", "PYTHON_VERSION", "SYFT_VERSION", "NEW_KEY"):
            with self.subTest(key=key):
                self.documents["after", ci_scope.CONFIG_PATH] = {**original}
                self.documents["after", ci_scope.CONFIG_PATH][key] = "different"
                self.assertFalse(self.classify())

    def test_modified_workflow_command_cannot_hide_behind_a_tool_bump(self) -> None:
        self.documents["after", self.workflow] = copy.deepcopy(self.documents["after", self.workflow])
        self.documents["after", self.workflow]["jobs"]["test"]["run"] = "different executable behavior"
        self.assertFalse(self.classify())

    def test_stale_generated_workflow_is_rejected_even_if_absent_from_changed_files(self) -> None:
        self.files = [ci_scope.CONFIG_PATH]
        self.documents["after", self.workflow] = copy.deepcopy(self.documents["before", self.workflow])
        self.assertFalse(self.classify())

    def test_mixed_source_template_or_image_changes_retain_broad_validation(self) -> None:
        for path in ("scripts/runtime_tests.py", ".github/workflow-templates/ci.yml.j2", "images/app/container.yaml"):
            with self.subTest(path=path):
                self.files.append(path)
                self.assertFalse(self.classify())
                self.files.pop()

    def test_major_tool_upgrade_retains_broad_validation(self) -> None:
        self.documents["after", ci_scope.CONFIG_PATH]["UV_VERSION"] = "10.0.0"
        self.documents["after", self.workflow]["env"]["UV_VERSION"] = "10.0.0"
        self.assertFalse(self.classify())

    def test_missing_templates_retain_broad_validation(self) -> None:
        (self.root / ".github/workflow-templates/ci.yml.j2").unlink()
        self.assertFalse(self.classify())

    def test_unavailable_history_and_invalid_documents_retain_broad_validation(self) -> None:
        for error in (ValueError("invalid YAML"), OSError("missing git"), subprocess.CalledProcessError(1, "git")):
            with self.subTest(error=error), patch.object(ci_scope, "_document", side_effect=error):
                self.assertFalse(ci_scope.is_tool_only_change(self.root, "before", "after", self.files))


class ToolBuildPlanTests(unittest.TestCase):
    def test_pr_and_queue_select_six_canaries_but_push_publishes_nothing(self) -> None:
        images = engine._load_images()
        for event in ("pull_request", "merge_group", "push"):
            options = engine.PlanOptions(event, "main", "main", "a" * 40, "b" * 40, None)
            with (
                self.subTest(event=event),
                patch.object(engine, "_changed_files", return_value=[ci_scope.CONFIG_PATH]),
                patch.object(ci_scope, "is_tool_only_change", return_value=True),
            ):
                plan = engine._build_plan(images, options)
                if event == "push":
                    self.assertFalse(plan["hasImages"])
                    self.assertEqual(plan["payloadMatrix"]["include"], [])
                else:
                    self.assertEqual({image["name"] for image in plan["images"]}, ci_scope.CANARY_IMAGES)
                    self.assertEqual(len(plan["smokeBuildMatrix"]["include"]), 6)
                    self.assertEqual(
                        {entry["arch"] for entry in plan["smokeBuildMatrix"]["include"]}, {"amd64", "arm64"}
                    )
                    self.assertEqual(len(plan["payloadMatrix"]["include"]), 2)

    def test_scheduled_and_manual_runs_do_not_use_the_tool_shortcut(self) -> None:
        images = engine._load_images()
        for event in ("schedule", "workflow_dispatch"):
            options = engine.PlanOptions(event, "main", "main", "a" * 40, "b" * 40, None)
            with self.subTest(event=event), patch.object(ci_scope, "is_tool_only_change") as classifier:
                plan = engine._build_plan(images, options)
                self.assertGreater(len(plan["images"]), len(ci_scope.CANARY_IMAGES))
                classifier.assert_not_called()
