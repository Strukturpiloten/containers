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
# Authored test data only: this tag/commit pair is not an upstream release or captured evidence.
SYNTHETIC_NOTIFY_YAML = """---
build:
  args:
    NOTIFYPUSH_VERSION:
      value: v98.76.54
      type: static
    NOTIFYPUSH_COMMIT:
      value: 0123456789abcdef0123456789abcdef01234567
      type: static
"""


class ApplicationProvenanceTests(unittest.TestCase):
    def test_notify_version_and_commit_are_a_single_renovate_update(self) -> None:
        config = json.loads(Path(".github/renovate.json").read_text(encoding="utf-8"))
        managers = [
            manager
            for manager in config["customManagers"]
            if "NOTIFYPUSH_COMMIT" in " ".join(manager.get("matchStrings", []))
        ]
        self.assertEqual(len(managers), 1)
        manager = managers[0]
        self.assertEqual(manager["customType"], "regex")
        self.assertEqual(len(manager["matchStrings"]), 1)
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        match = re.search(pattern, SYNTHETIC_NOTIFY_YAML)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("currentValue"), "98.76.54")
        self.assertEqual(match.group("currentDigest"), "0123456789abcdef0123456789abcdef01234567")
        changed_commit = SYNTHETIC_NOTIFY_YAML.replace(
            "0123456789abcdef0123456789abcdef01234567", "fedcba9876543210fedcba9876543210fedcba98"
        )
        changed_match = re.search(pattern, changed_commit)
        self.assertIsNotNone(changed_match)
        self.assertEqual(changed_match.group("currentValue"), "98.76.54")
        self.assertEqual(changed_match.group("currentDigest"), "fedcba9876543210fedcba9876543210fedcba98")
        self.assertIsNone(re.search(pattern, SYNTHETIC_NOTIFY_YAML.replace("v98.76.54", "v98.76")))
        self.assertEqual(manager["depNameTemplate"], "nextcloud/notify_push")
        self.assertEqual(manager["packageNameTemplate"], "nextcloud/notify_push")
        self.assertEqual(manager["datasourceTemplate"], "github-tags")
        self.assertEqual(manager["versioningTemplate"], "semver")
        self.assertEqual(manager["extractVersionTemplate"], "^v(?<version>.+)$")
        version_pattern = manager["extractVersionTemplate"].replace("(?<", "(?P<")
        version_match = re.search(version_pattern, "v98.76.54")
        self.assertIsNotNone(version_match)
        self.assertEqual(version_match.group("version"), "98.76.54")
        self.assertIsNone(re.search(version_pattern, "98.76.54"))
        self.assertEqual(manager["managerFilePatterns"], [r"/^images/nextcloud/nextcloud-notifypush/container\.yaml$/"])
        file_pattern = manager["managerFilePatterns"][0][1:-1]
        self.assertIsNotNone(re.search(file_pattern, NOTIFY_PATH.as_posix()))
        for path in (*PHP_PATHS, NOTIFY_PATH.with_suffix(".yaml.backup")):
            with self.subTest(path=path):
                self.assertIsNone(re.search(file_pattern, path.as_posix()))

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
        # Independently authored mapping; no catalogue load or network/native build is involved.
        image = {
            "name": "nextcloud-notifypush",
            "image": "registry.example.invalid/tests/notify-push",
            "version": "v98.0.0",
            "build": {
                "args": {
                    "NOTIFYPUSH_VERSION": {"value": "v98.76.54", "type": "static"},
                    "NOTIFYPUSH_COMMIT": {"value": "0123456789abcdef0123456789abcdef01234567", "type": "static"},
                },
            },
        }
        inputs = engine._component_inputs(image)
        expected_inputs = {
            "NOTIFYPUSH_VERSION": "v98.76.54",
            "NOTIFYPUSH_COMMIT": "0123456789abcdef0123456789abcdef01234567",
        }
        self.assertEqual(inputs, expected_inputs)
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
        self.assertEqual(recorded["indexDigest"], f"sha256:{'b' * 64}")
        self.assertEqual(
            recorded["architectureDigests"], {"amd64": f"sha256:{'c' * 64}", "arm64": f"sha256:{'d' * 64}"}
        )
        self.assertEqual(recorded["componentInputs"], expected_inputs)


if __name__ == "__main__":
    unittest.main()
