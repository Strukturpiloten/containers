"""Tests for catalogue evidence boundaries and visible gaps."""

from __future__ import annotations

import copy
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


class RuntimeAuthorityCatalogueTests(unittest.TestCase):
    def test_experimental_or_forged_private_completion_cannot_be_native_coverage(self) -> None:
        image = copy.deepcopy(IMAGE)
        image["tests"] = {"docker": {"launcher": "systemd", "mode": "rootless"}}
        for qualification in ("none", "complete", None):
            with self.subTest(qualification=qualification):
                runtime = {
                    "image": "example",
                    "architecture": "amd64",
                    "profile": "docker",
                    "status": "passed",
                    "checks": [{"name": "actual accounting", "status": "passed"}],
                    "host": {"architecture": "amd64"},
                    "oomAccountingMode": "qualification",
                    "oomAccountingStatus": "complete",
                    "imageIdentity": {
                        "architecture": "amd64",
                        "manifestDigest": DIGEST,
                        "configDigest": DIGEST,
                        "archiveSha256": DIGEST,
                        "sourceRevision": BUILD["sourceRevision"],
                        "version": "v1.0.0",
                    },
                }
                if qualification is not None:
                    runtime["qualification"] = qualification
                before = copy.deepcopy(runtime)
                report = catalogue([image], runtime_results={"example": [runtime]})
                view = report["images"][0]["runtimeCoverage"]["amd64"]["docker"]
                self.assertEqual(view["status"], "nonqualifying")
                self.assertEqual(view["operationalStatus"], "passed")
                self.assertEqual(view["oomAccountingStatus"], "complete")
                self.assertEqual(view["nativeAuthority"], "none")
                self.assertEqual(view["qualification"], qualification)
                self.assertEqual(runtime, before)
                self.assertIn("nonqualifying", markdown_catalogue(report))

    def test_failed_operational_record_is_not_relabelled_as_normal_success(self) -> None:
        from scripts.maintenance import _runtime_authority_view  # noqa: PLC0415 - focused pure projection check.

        raw = {"status": "failed", "qualification": "none", "oomAccountingStatus": "incomplete"}
        view = _runtime_authority_view(IMAGE, "docker", raw)
        self.assertEqual(view["status"], "failed")
        self.assertEqual(view["operationalStatus"], "failed")
        self.assertEqual(view["nativeAuthority"], "none")
