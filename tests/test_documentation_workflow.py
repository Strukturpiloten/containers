"""Keep documentation checks and deployment separate from image publication."""

from __future__ import annotations

import fnmatch
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import container_engine as engine

WEBSITE_PATHS = (
    "docs/legal-notice.md",
    "docs/impressum.md",
    "docs/privacy-policy.md",
    "docs/datenschutz.md",
    "docs/index.md",
    "docs/documentation-site.md",
    "documentation/theme/main.html",
    "documentation/assets/site.css",
    "scripts/documentation.py",
    "scripts/docs_site.py",
    "tests/test_docs_site.py",
    "tests/test_documentation_workflow.py",
)


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

    def test_site_build_checkout_fetches_shared_documentation_submodule(self) -> None:
        jobs = self.workflow["jobs"]
        self.assertNotIn("submodules", jobs["gate"]["steps"][0]["with"])
        submodules = jobs["build"]["steps"][0]["with"]["submodules"]
        self.assertIsInstance(submodules, bool)
        self.assertTrue(submodules)

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
        self.assertIn("pull_request", ci[True])
        self.assertIn("merge_group", ci[True])
        self.assertNotIn("paths", ci[True]["pull_request"] or {})
        self.assertNotIn("paths", ci[True]["merge_group"])
        validate = ci["jobs"]["validate"]
        run = next(step["run"] for step in validate["steps"] if step.get("name") == "Validate repository")
        self.assertIn("scripts.documentation", run)
        self.assertNotIn("scripts.docs_observations", run)
        self.assertNotIn("--snapshot", run)

    def test_legal_website_paths_trigger_site_refresh_without_image_publication(self) -> None:
        publish = yaml.safe_load(Path(".github/workflows/publish-images.yml").read_text(encoding="utf-8"))
        publish_paths = publish[True]["push"]["paths"]
        site_paths = self.workflow[True]["push"]["paths"]
        for path in WEBSITE_PATHS:
            with self.subTest(path=path):
                # GitHub evaluates positive/negative path filters in their listed order.
                publish_matches = False
                for pattern in publish_paths:
                    if fnmatch.fnmatchcase(path, pattern.removeprefix("!")):
                        publish_matches = not pattern.startswith("!")
                self.assertFalse(publish_matches, f"Website path would enter image publication: {path}")
                self.assertTrue(any(fnmatch.fnmatchcase(path, pattern) for pattern in site_paths))

    def test_legal_website_plans_have_no_images_or_payloads(self) -> None:
        images = engine._load_images()
        for event in ("pull_request", "merge_group", "push"):
            options = engine.PlanOptions(
                event_name=event,
                ref_name="main",
                default_branch="main",
                before="1" * 40,
                sha="2" * 40,
                max_stages=None,
            )
            with self.subTest(event=event), patch.object(engine, "_changed_files", return_value=list(WEBSITE_PATHS)):
                plan = engine._build_plan(images, options)
                self.assertFalse(plan["hasImages"])
                self.assertEqual(plan["smokeBuildMatrix"], {"include": []})
                self.assertEqual(plan["payloadMatrix"], {"include": []})
                for stage in plan["stageMatrices"]:
                    self.assertEqual(stage["buildMatrix"], {"include": []})
                    self.assertEqual(stage["publishMatrix"], {"include": []})


if __name__ == "__main__":
    unittest.main()
