"""Immutable release evidence preserves original and later build provenance."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from scripts.release_evidence import ReleaseEvidenceError, asset_name, record, upload

BUILD = {
    "imageName": "example",
    "image": "ghcr.io/strukturpiloten/example",
    "version": "1.0.0",
    "sourceRevision": "b" * 40,
    "indexDigest": f"sha256:{'a' * 64}",
    "architectureDigests": {"amd64": f"sha256:{'c' * 64}"},
    "buildSucceededAt": "2026-09-27T12:00:00+00:00",
    "runId": "101",
    "runAttempt": "2",
    "releaseTag": "example/v1.0.0",
}


class ReleaseEvidenceTests(unittest.TestCase):
    def test_later_rebuild_does_not_claim_original_release_source(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        self.assertEqual(evidence["releaseOriginRevision"], "d" * 40)
        self.assertEqual(evidence["buildSourceRevision"], "b" * 40)
        self.assertIn(BUILD["indexDigest"].replace(":", "-"), asset_name(evidence))

    def test_wrong_scan_source_is_rejected_even_if_architecture_matches(self) -> None:
        scan = {"image": BUILD["image"], "architecture": "amd64", "candidateSource": {"sourceRevision": "d" * 40}}
        with self.assertRaises(ReleaseEvidenceError):
            record(BUILD, release_origin_revision="d" * 40, scan_reports=[scan])

    def test_archive_config_must_match_published_config(self) -> None:
        published = {
            "amd64": {
                "architecture": "amd64",
                "manifestDigest": BUILD["architectureDigests"]["amd64"],
                "configDigest": f"sha256:{'e' * 64}",
            }
        }
        scan = {
            "image": BUILD["image"],
            "architecture": "amd64",
            "candidateSource": {"sourceRevision": BUILD["sourceRevision"], "configDigest": f"sha256:{'f' * 64}"},
        }
        with self.assertRaises(ReleaseEvidenceError):
            record(BUILD, release_origin_revision="d" * 40, scan_reports=[scan], published_configs=published)

    def test_existing_asset_must_have_identical_bytes(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        payload = json.dumps(evidence).encode()
        correct = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        with patch(
            "scripts.release_evidence._github_request",
            return_value=json.dumps([{"name": asset_name(evidence), "digest": correct}]).encode(),
        ) as request:
            upload(evidence, payload, repository="org/repo", token=BUILD["runId"], release={"id": 1})
        request.assert_called_once()
        with (
            patch(
                "scripts.release_evidence._github_request",
                return_value=json.dumps([{"name": asset_name(evidence), "digest": "sha256:wrong"}]).encode(),
            ),
            self.assertRaises(ReleaseEvidenceError),
        ):
            upload(evidence, payload, repository="org/repo", token=BUILD["runId"], release={"id": 1})


if __name__ == "__main__":
    unittest.main()
