"""Keep documentation checks and deployment separate from image publication."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class DocumentationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(Path(".github/workflows/documentation.yml").read_text(encoding="utf-8"))

    def test_pages_deployment_follows_trusted_publish_completion(self) -> None:
        triggers = self.workflow[True]
        self.assertEqual(triggers["workflow_run"]["workflows"], ["Publish images"])
        self.assertEqual(triggers["workflow_run"]["types"], ["completed"])
        self.assertEqual(triggers["schedule"], [{"cron": "23 7 * * *"}])
        push_paths = triggers["push"]["paths"]
        for source in ("CONTRIBUTING.md", "SECURITY.md", "shared/**/README.md", "shared/**/docs/**"):
            self.assertIn(source, push_paths)
        gate = self.workflow["jobs"]["gate"]
        self.assertIn("head_repository.full_name == github.repository", gate["if"])
        self.assertIn("head_branch == 'main'", gate["if"])
        self.assertIn("workflow_run.path == '.github/workflows/publish-images.yml'", gate["if"])
        self.assertIn("conclusion == 'failure'", gate["if"])
        self.assertIn("github.event_name == 'schedule'", gate["if"])
        self.assertIn("git merge-base --is-ancestor", gate["steps"][1]["run"])
        self.assertIn("git diff --no-renames --name-only", gate["steps"][1]["run"])

    def test_only_deploy_job_gets_pages_credentials(self) -> None:
        jobs = self.workflow["jobs"]
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(jobs["gate"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["build"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["deploy"]["permissions"], {"pages": "write", "id-token": "write"})
        self.assertEqual(jobs["deploy"]["needs"], "build")
        self.assertIn("scripts.docs_observations", str(jobs["build"]["steps"]))
        self.assertIn("--snapshot", str(jobs["build"]["steps"]))
        self.assertEqual(jobs["build"]["steps"][0]["with"]["fetch-depth"], 0)

    def test_documentation_only_pushes_do_not_enter_publish_workflow(self) -> None:
        publish = yaml.safe_load(Path(".github/workflows/publish-images.yml").read_text(encoding="utf-8"))
        paths = publish[True]["push"]["paths"]
        self.assertIn("images/**", paths)
        self.assertIn("!images/**/README.md", paths)
        self.assertIn("!images/**/docs/**", paths)
        self.assertIn("!shared/**/README.md", paths)
        self.assertIn("!shared/**/docs/**", paths)
        self.assertIn("!scripts/documentation.py", paths)
        self.assertIn("!scripts/docs_catalogue.py", paths)
        self.assertIn("!scripts/docs_observations.py", paths)
        self.assertIn("!scripts/docs_site.py", paths)
        self.assertIn("!.github/workflow-templates/documentation.yml.j2", paths)

    def test_pull_request_validates_site_without_registry_observation(self) -> None:
        ci = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))
        validate = ci["jobs"]["validate"]
        run = next(step["run"] for step in validate["steps"] if step.get("name") == "Validate repository")
        self.assertIn("scripts.documentation", run)
        self.assertNotIn("scripts.docs_observations", run)
        self.assertNotIn("--snapshot", run)


if __name__ == "__main__":
    unittest.main()
