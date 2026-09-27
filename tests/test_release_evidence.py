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

    def test_complete_release_requires_one_matching_runtime_and_scan_per_architecture(self) -> None:
        config = f"sha256:{'e' * 64}"
        manifest = f"sha256:{'f' * 64}"
        published = {
            "amd64": {
                "architecture": "amd64",
                "manifestDigest": BUILD["architectureDigests"]["amd64"],
                "configDigest": config,
            }
        }
        runtime = {
            "image": "example",
            "architecture": "amd64",
            "profile": "docker",
            "status": "passed",
            "runId": "101",
            "runAttempt": "2",
            "imageIdentity": {
                "architecture": "amd64",
                "sourceRevision": BUILD["sourceRevision"],
                "version": "1.0.0",
                "configDigest": config,
                "manifestDigest": manifest,
                "archiveSha256": "a" * 64,
            },
        }
        scan = {
            "image": BUILD["image"],
            "architecture": "amd64",
            "admission": "isolated-test",
            "decision": "passed",
            "sourceRevision": BUILD["sourceRevision"],
            "runId": "101",
            "runAttempt": "2",
            "candidateDigest": manifest,
            "baselineStatus": "absent",
            "baselineDigest": None,
            "baselineSource": {"status": "absent"},
            "candidateSource": {
                "architecture": "amd64",
                "sourceRevision": BUILD["sourceRevision"],
                "version": "1.0.0",
                "configDigest": config,
                "manifestDigest": manifest,
                "archiveSha256": f"sha256:{'a' * 64}",
            },
        }
        with patch(
            "scripts.release_evidence.image_policy",
            return_value={"requiredRuntimeProfile": "docker", "admission": "isolated-test"},
        ):
            result = record(
                BUILD,
                release_origin_revision="d" * 40,
                runtime_evidence=[runtime],
                scan_reports=[scan],
                published_configs=published,
                require_complete=True,
                execution_attempt=2,
            )
            self.assertEqual(len(result["runtimeEvidence"]), 1)
            with self.assertRaisesRegex(ReleaseEvidenceError, "Scan evidence"):
                record(
                    BUILD,
                    release_origin_revision="d" * 40,
                    runtime_evidence=[runtime],
                    scan_reports=[{**scan, "baselineSource": None}],
                    published_configs=published,
                    require_complete=True,
                    execution_attempt=2,
                )
            with self.assertRaises(ReleaseEvidenceError):
                record(
                    BUILD,
                    release_origin_revision="d" * 40,
                    runtime_evidence=[runtime],
                    scan_reports=[],
                    published_configs=published,
                    require_complete=True,
                    execution_attempt=2,
                )

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

    def test_retry_finds_existing_asset_on_second_page(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        payload = json.dumps(evidence).encode()
        digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        pages = [
            json.dumps([{"name": f"older-{number}"} for number in range(100)]).encode(),
            json.dumps([{"name": asset_name(evidence), "digest": digest}]).encode(),
        ]
        with patch("scripts.release_evidence._github_request", side_effect=pages) as request:
            upload(evidence, payload, repository="org/repo", token=BUILD["runId"], release={"id": 1})
        self.assertEqual(request.call_count, 2)
        self.assertIn("page=2", request.call_args.args[0])

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
