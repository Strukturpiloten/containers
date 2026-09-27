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
        match = re.search(pattern, f"uses: actions/checkout@{'a' * 40} # v4.2.0")
        self.assertIsNotNone(match)
        if match is not None:
            self.assertEqual(
                match.groupdict(), {"depName": "actions/checkout", "currentDigest": "a" * 40, "currentValue": "v4.2.0"}
            )


if __name__ == "__main__":
    unittest.main()
