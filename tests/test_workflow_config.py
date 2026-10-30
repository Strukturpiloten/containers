"""Workflow configuration updates must reach planner and literal YAML together."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import container_engine as engine
from scripts.workflow_config import CONFIG_PATH, load_config

FIXTURE = {
    "AMD64_RUNNER": "ubuntu-24.04",
    "ARM64_RUNNER": "ubuntu-24.04-arm",
    "PYTHON_VERSION": "3.14",
    "UV_VERSION": "0.9.0",
    "SYFT_VERSION": "v1.30.0",
    "ACTIONLINT_VERSION": "1.7.0",
}


class WorkflowConfigurationTests(unittest.TestCase):
    def test_invalid_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / CONFIG_PATH
            path.parent.mkdir()
            for changes in ({"AMD64_RUNNER": "ubuntu-latest"}, {"PYTHON_VERSION": 3.14}, {"unexpected": "value"}):
                with self.subTest(changes=changes):
                    path.write_text(yaml.safe_dump({**FIXTURE, **changes}))
                    with self.assertRaises(ValueError):
                        load_config(root)

    def test_representative_runner_and_tool_update_reaches_every_generated_workflow(self) -> None:
        upgraded = {
            **FIXTURE,
            "AMD64_RUNNER": "ubuntu-26.04",
            "ARM64_RUNNER": "ubuntu-26.04-arm",
            "UV_VERSION": "0.10.0",
        }
        environment = engine._workflow_environment()
        templates = sorted((engine._repo_root() / engine.PUBLISH_WORKFLOW_TEMPLATE_PATH.parent).glob("*.yml.j2"))
        for path in templates:
            with self.subTest(template=path.name):
                workflow = yaml.safe_load(
                    environment.get_template(path.name).render(stages=[0], single_stage=True, config=upgraded)
                )
                for job in workflow["jobs"].values():
                    runner = job.get("runs-on", "")
                    if runner and not runner.startswith("${{"):
                        self.assertEqual(runner, upgraded["AMD64_RUNNER"])
                if "UV_VERSION" in workflow.get("env", {}):
                    self.assertEqual(workflow["env"]["UV_VERSION"], upgraded["UV_VERSION"])
        with patch.object(engine, "RUNNERS", {"amd64": upgraded["AMD64_RUNNER"], "arm64": upgraded["ARM64_RUNNER"]}):
            image = {"name": "fixture", "level": 0, "build": {"architectures": ["amd64", "arm64"]}}
            entries = engine._stage_build_matrix([image], 0)["include"]
        self.assertEqual({entry["runner"] for entry in entries}, {upgraded["AMD64_RUNNER"], upgraded["ARM64_RUNNER"]})

    def test_renovate_extracts_both_native_runner_labels_from_canonical_source(self) -> None:
        config = json.loads((engine._repo_root() / ".github/renovate.json").read_text())
        manager = next(item for item in config["customManagers"] if item.get("datasourceTemplate") == "github-runners")
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        matches = list(re.finditer(pattern, yaml.safe_dump(FIXTURE)))
        self.assertEqual({match.group("currentValue") for match in matches}, {"24.04", "24.04-arm"})

    def test_action_template_updates_capture_tag_and_commit_together(self) -> None:
        config = json.loads((engine._repo_root() / ".github/renovate.json").read_text())
        manager = next(
            item
            for item in config["customManagers"]
            if item.get("description", "").startswith("Keep pinned action references")
        )
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        for tag in ("v4", "v4.2", "v4.2.0"):
            with self.subTest(tag=tag):
                match = re.search(pattern, f"uses: actions/checkout@{'a' * 40} # {tag}")
                self.assertIsNotNone(match)
                self.assertEqual(
                    match.groupdict(), {"depName": "actions/checkout", "currentDigest": "a" * 40, "currentValue": tag}
                )
        source = (engine._repo_root() / ".github/workflow-templates/documentation.yml.j2").read_text()
        packages = {match.group("depName") for match in re.finditer(pattern, source)}
        self.assertTrue({"actions/deploy-pages", "actions/upload-pages-artifact"} <= packages)

    def test_python_runtime_and_project_updates_share_an_automatic_group(self) -> None:
        config = json.loads((engine._repo_root() / ".github/renovate.json").read_text())
        manager = next(item for item in config["customManagers"] if item.get("datasourceTemplate") == "python-version")
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        self.assertEqual(re.search(pattern, 'PYTHON_VERSION: "3.14"').group("currentValue"), "3.14")
        self.assertEqual(re.search(pattern, 'PYTHON_VERSION: "3.14.10"').group("currentValue"), "3.14.10")
        self.assertEqual(manager["depNameTemplate"], "python")
        self.assertEqual(manager["versioningTemplate"], "python")
        rule = next(item for item in config["packageRules"] if item.get("matchDatasources") == ["python-version"])
        self.assertEqual(rule["matchPackageNames"], ["python"])
        self.assertEqual(rule["groupName"], "Python runtime")
        self.assertTrue(rule.get("automerge", config["automerge"]))
        self.assertEqual(rule["recreateWhen"], "always")
        self.assertEqual(rule["rangeStrategy"], "bump")

    def test_python_release_filter_waits_for_patch_four_on_new_lines(self) -> None:
        config = json.loads((engine._repo_root() / ".github/renovate.json").read_text())
        rule = next(item for item in config["packageRules"] if item.get("matchDatasources") == ["python-version"])
        for current, accepted, rejected in (
            (
                "3.14",
                ("3.14.1", "3.14.10", "3.15.4", "3.15.9", "3.15.10", "3.16.4", "4.0.4"),
                ("3.15", "3.15.0", "3.15.1", "3.15.2", "3.15.3", "3.15.4rc1", "3.16.0", "4.0.0"),
            ),
            ("3.15", ("3.15.5", "3.16.4", "3.16.10"), ("3.16.1", "3.16.3", "3.16.4a1", "3.16.4.dev1")),
        ):
            major, minor = current.split(".")
            pattern = rule["allowedVersions"][1:-1].replace("{{major}}", major).replace("{{minor}}", minor)
            for version in accepted:
                with self.subTest(current=current, accepted=version):
                    self.assertIsNotNone(re.fullmatch(pattern, version))
            for version in rejected:
                with self.subTest(current=current, rejected=version):
                    self.assertIsNone(re.fullmatch(pattern, version))

    def test_repository_python_pin_is_exact_and_mature(self) -> None:
        # Required CI also runs against the combined merge-queue tree. This blocks
        # stale Python PRs even if their earlier PR checks were already green.
        version = load_config(engine._repo_root())["PYTHON_VERSION"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertGreaterEqual(int(version.split(".")[2]), 4)

    def test_all_dependency_updates_inherit_checked_platform_automerge(self) -> None:
        config = json.loads((engine._repo_root() / ".github/renovate.json").read_text())
        self.assertTrue(config["automerge"])
        self.assertEqual(config["automergeType"], "pr")
        self.assertEqual(config["automergeStrategy"], "squash")
        self.assertTrue(config["platformAutomerge"])
        self.assertTrue(config["ignoreUnstable"])
        for rule in [config, *config["packageRules"]]:
            with self.subTest(rule=rule.get("description", "default")):
                self.assertTrue(rule.get("automerge", config["automerge"]))
                self.assertFalse(rule.get("ignoreTests", False))
                self.assertNotEqual(rule.get("requiredStatusChecks"), [])


if __name__ == "__main__":
    unittest.main()
