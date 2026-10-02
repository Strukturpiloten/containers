"""Release automation separates discovery, upstream execution and write credentials."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(Path(".github/workflows/upstream-releases.yml").read_text())

    def test_scheduled_and_manual_runs_only_discover_on_default_branch(self) -> None:
        self.assertEqual(self.workflow[True]["schedule"], [{"cron": "13 6 * * *"}])
        self.assertTrue(self.workflow[True]["workflow_dispatch"]["inputs"]["dry_run"]["default"] is True)
        self.assertIn("github.event.repository.default_branch", self.workflow["jobs"]["discover"]["if"])
        self.assertEqual(self.workflow["permissions"], {})
        self.assertTrue(self.workflow["concurrency"]["cancel-in-progress"] is False)

    def test_native_probe_has_no_write_token_and_publisher_does_not_execute_archives(self) -> None:
        jobs = self.workflow["jobs"]
        self.assertEqual(jobs["probe"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["probe"]["runs-on"], "${{ matrix.runner }}")
        self.assertNotIn("GH_TOKEN", str(jobs["probe"]))
        self.assertNotIn("secrets.", str(jobs["probe"]))
        self.assertEqual(jobs["propose"]["needs"], ["discover", "probe"])
        self.assertNotIn("docker_release_updates probe", str(jobs["propose"]))
        self.assertEqual(jobs["propose"]["permissions"], {"contents": "read"})
        for name, job in jobs.items():
            for step in job["steps"]:
                if "actions/checkout@" in step.get("uses", ""):
                    self.assertTrue(step["with"]["persist-credentials"] is False)
            if name != "propose":
                self.assertNotIn("RELEASE_AUTOMATION_TOKEN", str(job))
        publish = jobs["propose"]["steps"][-1]
        self.assertEqual(publish["env"]["GH_TOKEN"], "${{ secrets.RELEASE_AUTOMATION_TOKEN }}")
        self.assertIn('if [[ -z "${GH_TOKEN}" ]]', publish["run"])

    def test_dry_run_suppresses_all_mutations_and_binary_execution(self) -> None:
        jobs = self.workflow["jobs"]
        for name in ("notify", "probe"):
            self.assertIn("!inputs.dry_run", jobs[name]["if"])
        self.assertEqual(jobs["notify"]["permissions"], {"contents": "read", "issues": "write"})
        self.assertNotIn("always()", jobs["propose"].get("if", ""))


if __name__ == "__main__":
    unittest.main()
