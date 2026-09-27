"""Tests for catalogue evidence boundaries and visible gaps."""

from __future__ import annotations

import unittest

from scripts.maintenance import MaintenanceError, catalogue, markdown_catalogue

DIGEST = f"sha256:{'a' * 64}"
IMAGE = {
    "name": "example",
    "image": "ghcr.io/strukturpiloten/example",
    "version": "v1.0.0",
    "build": {"architectures": ["amd64"]},
    "lifecycle": {
        "state": "maintained",
        "admission": "production",
        "reviewAfter": "2026-12-31",
        "supportBoundary": "Repository maintains this example image.",
        "requiredRuntimeProfiles": ["docker"],
    },
}
BUILD = {
    "imageName": "example",
    "image": IMAGE["image"],
    "version": "1.0.0",
    "sourceRevision": "b" * 40,
    "indexDigest": DIGEST,
    "architectureDigests": {"amd64": DIGEST},
    "buildSucceededAt": "2026-09-27T12:00:00+00:00",
    "runId": "123",
    "runAttempt": "1",
}


class CatalogueTests(unittest.TestCase):
    def test_missing_proof_stays_unknown(self) -> None:
        row = catalogue([IMAGE])["images"][0]
        self.assertEqual(row["build"]["status"], "unknown")
        self.assertEqual(row["registry"]["status"], "unknown")
        self.assertEqual(row["runtimeCoverage"]["amd64"]["docker"]["status"], "unknown")

    def test_skipped_check_is_visible_even_when_profile_passes(self) -> None:
        runtime = [
            {
                "image": "example",
                "architecture": "amd64",
                "profile": "docker",
                "status": "passed",
                "checks": [{"name": "daemon", "status": "passed"}, {"name": "rootless", "status": "skipped"}],
                "imageIdentity": {
                    "architecture": "amd64",
                    "manifestDigest": DIGEST,
                    "configDigest": DIGEST,
                    "archiveSha256": DIGEST,
                    "sourceRevision": BUILD["sourceRevision"],
                    "version": "v1.0.0",
                },
                "host": {"architecture": "amd64", "kernel": "test"},
                "runId": "123",
                "runAttempt": "1",
            }
        ]
        report = catalogue([IMAGE], build_results={"example": BUILD}, runtime_results={"example": runtime})
        self.assertIn("skipped checks", markdown_catalogue(report))
        self.assertEqual(report["images"][0]["build"]["buildSucceededAt"], BUILD["buildSucceededAt"])

    def test_registry_proof_must_match_build_and_reference(self) -> None:
        good = {
            "image": IMAGE["image"],
            "digest": DIGEST,
            "reference": f"{IMAGE['image']}@{DIGEST}",
            "observedAt": "2026-09-27T13:00:00+00:00",
        }
        row = catalogue([IMAGE], build_results={"example": BUILD}, registry_observations={"example": good})["images"][0]
        self.assertEqual(row["registry"]["status"], "observed")
        with self.assertRaises(MaintenanceError):
            catalogue(
                [IMAGE],
                build_results={"example": BUILD},
                registry_observations={"example": {**good, "reference": "latest"}},
            )

    def test_unrecognized_evidence_is_rejected(self) -> None:
        with self.assertRaises(MaintenanceError):
            catalogue([IMAGE], build_results={"unexpected": BUILD})


if __name__ == "__main__":
    unittest.main()
