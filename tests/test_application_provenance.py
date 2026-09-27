"""Application input pins and build evidence stay traceable across metadata and Renovate."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts import container_engine as engine

NOTIFY_PATH = Path("images/nextcloud/nextcloud-notifypush/container.yaml")
PHP_PATHS = (
    Path("images/nextcloud/nextcloud-phpfpm/container.yaml"),
    Path("images/typo3/typo3-phpfpm/container.yaml"),
)


class ApplicationProvenanceTests(unittest.TestCase):
    def test_notify_version_and_commit_are_a_single_renovate_update(self) -> None:
        config = json.loads(Path(".github/renovate.json").read_text(encoding="utf-8"))
        manager = next(
            manager
            for manager in config["customManagers"]
            if "NOTIFYPUSH_COMMIT" in " ".join(manager.get("matchStrings", []))
        )
        match = re.search(manager["matchStrings"][0].replace("(?<", "(?P<"), NOTIFY_PATH.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        self.assertEqual(match.group("currentValue"), "1.4.1")
        self.assertEqual(match.group("currentDigest"), "3cbef8d0abd401bfa1ce4c39428fc445059654bc")
        self.assertEqual(manager["datasourceTemplate"], "github-tags")
        self.assertTrue(re.search(manager["managerFilePatterns"][0][1:-1], NOTIFY_PATH.as_posix()))

    def test_php_version_managers_match_both_images_and_require_review(self) -> None:
        config = json.loads(Path(".github/renovate.json").read_text(encoding="utf-8"))
        versions = {
            "PHP_APCU_VERSION": "5.1.28",
            "PHP_IMAGICK_VERSION": "3.8.1",
            "PHP_REDIS_VERSION": "6.3.0",
            "COMPOSER_VERSION": "2.10.3",
        }
        for name, version in versions.items():
            manager = next(
                manager for manager in config["customManagers"] if name in " ".join(manager.get("matchStrings", []))
            )
            for path in PHP_PATHS:
                with self.subTest(input=name, image=path):
                    match = re.search(
                        manager["matchStrings"][0].replace("(?<", "(?P<"), path.read_text(encoding="utf-8")
                    )
                    self.assertIsNotNone(match)
                    self.assertEqual(match.group("currentValue"), version)
                    self.assertTrue(re.search(manager["managerFilePatterns"][0][1:-1], path.as_posix()))
        review_rule = next(
            rule
            for rule in config["packageRules"]
            if rule.get("description", "").startswith("PHP extension and Composer")
        )
        self.assertFalse(review_rule["automerge"])
        self.assertEqual(len(review_rule["matchPackageNames"]), 4)

    def test_existing_digest_and_patch_automerge_policy_is_preserved(self) -> None:
        config = json.loads(Path(".github/renovate.json").read_text(encoding="utf-8"))
        descriptions = (
            "Squash-merge pinned container digest updates after required CI",
            "Squash-merge patch updates for externally pinned container images after required CI",
            "Squash-merge tested notify_push patch updates after required CI",
        )
        for description in descriptions:
            with self.subTest(rule=description):
                rule = next(rule for rule in config["packageRules"] if rule.get("description") == description)
                self.assertTrue(rule["automerge"])

    def test_build_result_ties_inputs_to_source_and_architecture_digests(self) -> None:
        image = next(image for image in engine._load_images() if image["name"] == "nextcloud-notifypush")
        inputs = engine._component_inputs(image)
        self.assertEqual(inputs["NOTIFYPUSH_VERSION"], "v1.4.1")
        self.assertEqual(inputs["NOTIFYPUSH_COMMIT"], "3cbef8d0abd401bfa1ce4c39428fc445059654bc")
        with tempfile.TemporaryDirectory() as directory:
            result = engine._BuildResult(
                image_name="nextcloud-notifypush",
                image_ref=image["image"],
                version=image["version"],
                source_revision="a" * 40,
                index_digest=f"sha256:{'b' * 64}",
                architecture_digests={"amd64": f"sha256:{'c' * 64}", "arm64": f"sha256:{'d' * 64}"},
                component_inputs=inputs,
                tags=["run-1-1"],
                run_id="1",
                run_attempt="1",
            )
            recorded = json.loads(engine._write_build_result(Path(directory), result).read_text(encoding="utf-8"))
        self.assertEqual(recorded["sourceRevision"], "a" * 40)
        self.assertEqual(set(recorded["architectureDigests"]), {"amd64", "arm64"})
        self.assertEqual(recorded["componentInputs"], inputs)


if __name__ == "__main__":
    unittest.main()
