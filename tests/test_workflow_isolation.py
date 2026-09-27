"""Guard publication boundaries independently of catalogue size."""

from __future__ import annotations

import unittest

import yaml

from scripts import container_engine as engine


class PublicationIsolationTests(unittest.TestCase):
    def test_each_image_gets_only_its_own_architecture_builds(self) -> None:
        images = [
            {
                "name": name,
                "level": stage,
                "build": {"architectures": architectures},
                "tests": {},
            }
            for name, stage, architectures in (
                ("one", 0, ["amd64", "arm64"]),
                ("two", 0, ["amd64"]),
                ("dependent", 1, ["arm64"]),
            )
        ]
        entries = engine._stage_publish_matrix(images, 0)["include"]
        self.assertEqual([entry["name"] for entry in entries], ["one", "two"])
        for entry in entries:
            builds = entry["buildMatrix"]["include"]
            self.assertEqual({build["name"] for build in builds}, {entry["name"]})
        self.assertEqual(len(entries[0]["buildMatrix"]["include"]), 2)
        self.assertEqual(len(entries[1]["buildMatrix"]["include"]), 1)

    def test_publication_waits_only_for_own_builds_and_finalization_for_publication(self) -> None:
        path = engine._repo_root() / ".github/workflows/publish-one-image.yml"
        jobs = yaml.safe_load(path.read_text())["jobs"]
        self.assertEqual(jobs["publish"]["needs"], "build")
        self.assertEqual(jobs["finalize"]["needs"], "publish")
        self.assertNotIn("if", jobs["publish"])
        self.assertFalse(jobs["build"]["strategy"]["fail-fast"])
        self.assertLessEqual(jobs["build"]["strategy"]["max-parallel"], 2)
        self.assertEqual(jobs["build"]["permissions"], {"contents": "read", "packages": "read"})

    def test_later_stages_can_try_independent_images_after_a_failure(self) -> None:
        jobs = yaml.safe_load(engine._publish_workflow(2))["jobs"]
        stage = jobs["publish-stage-1"]
        self.assertEqual(stage["needs"], ["plan", "publish-stage-0"])
        self.assertIn("always()", stage["if"])
        self.assertIn("!cancelled()", stage["if"])
        self.assertIn("needs.plan.result == 'success'", stage["if"])
        self.assertFalse(stage["strategy"]["fail-fast"])
        self.assertLessEqual(stage["strategy"]["max-parallel"], 4)


if __name__ == "__main__":
    unittest.main()
