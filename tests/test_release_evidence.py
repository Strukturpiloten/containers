"""Immutable release evidence preserves original and later build provenance."""

from __future__ import annotations

import hashlib
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from scripts.release_evidence import ReleaseEvidenceError, _github_request, asset_name, publish, record, upload

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


class FakeGitHub:
    """Exercise ordering and immutable retry against the GitHub REST boundary."""

    def __init__(
        self, evidence: dict, asset: bytes | None = None, *, published: bool = False, race: bool = False
    ) -> None:
        """Initialize in-memory release state."""
        self.evidence = evidence
        self.asset = asset
        self.release = self._release(draft=False) if published else None
        self.race = race
        self.tag_sha = evidence["evidenceReleaseRevision"]
        self.tag_exists_when_draft = False
        self.calls: list[str] = []

    def _release(self, *, draft: bool) -> dict:
        return {
            "id": 1,
            "tag_name": self.evidence["evidenceReleaseTag"],
            "name": self.evidence["evidenceReleaseTag"],
            "target_commitish": self.evidence["evidenceReleaseRevision"],
            "draft": draft,
            "immutable": not draft,
            "upload_url": "https://uploads.github.com/repos/org/repo/releases/1/assets{?name,label}",
        }

    def __call__(  # noqa: C901, PLR0911, PLR0912
        self, url: str, _token: str, *, data: bytes | None = None, method: str | None = None, **_kwargs: object
    ) -> bytes:
        if "/releases/tags/" in url:
            self.calls.append("lookup")
            if self.release is None:
                message = "missing"
                raise ReleaseEvidenceError(message, status_code=404)
            return json.dumps(self.release).encode()
        if "/commits/" in url:
            self.calls.append("verify-tag")
            if self.release is None or (self.release["draft"] and not self.tag_exists_when_draft):
                message = "missing tag"
                raise ReleaseEvidenceError(message, status_code=404)
            return json.dumps({"sha": self.tag_sha}).encode()
        if url.startswith("https://api.github.com/") and "/releases/1/assets?" in url:
            self.calls.append("list-assets")
            assets = []
            if self.asset is not None:
                assets = [
                    {
                        "name": asset_name(self.evidence),
                        "digest": f"sha256:{hashlib.sha256(self.asset).hexdigest()}",
                        "size": len(self.asset),
                        "url": "https://api.github.com/repos/org/repo/releases/assets/55",
                    }
                ]
            return json.dumps(assets).encode()
        if url.endswith("/assets/55"):
            self.calls.append("download")
            return self.asset
        if url.startswith("https://uploads.github.com/"):
            self.calls.append("upload")
            if self.release is None or not self.release["draft"]:
                message = "uploaded outside draft"
                raise AssertionError(message)
            self.asset = data
            return json.dumps(
                {
                    "name": asset_name(self.evidence),
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                    "size": len(data),
                }
            ).encode()
        if url.endswith("/releases/1") and method == "PATCH":
            self.calls.append("publish")
            if self.asset is None:
                message = "published before upload"
                raise AssertionError(message)
            self.release = self._release(draft=False)
            return json.dumps(self.release).encode()
        if url.endswith("/releases") and data is not None:
            self.calls.append("create-draft")
            self.release = self._release(draft=True)
            if self.race:
                message = "raced"
                raise ReleaseEvidenceError(message, status_code=422)
            return json.dumps(self.release).encode()
        message = f"unexpected API request: {url}"
        raise AssertionError(message)


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

    def test_draft_upload_publish_and_published_retry(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        payload = json.dumps(evidence).encode()
        api = FakeGitHub(evidence)
        with patch("scripts.release_evidence._github_request", side_effect=api):
            self.assertEqual(publish(evidence, payload, repository="org/repo", token=BUILD["runId"]), payload)
            self.assertEqual(publish(evidence, payload, repository="org/repo", token=BUILD["runId"]), payload)
        self.assertEqual(
            api.calls[:7], ["lookup", "create-draft", "verify-tag", "list-assets", "upload", "publish", "lookup"]
        )
        self.assertEqual(api.calls.count("upload"), 1)
        self.assertEqual(api.calls.count("publish"), 1)
        self.assertEqual(api.calls.count("verify-tag"), 3)
        self.assertTrue(api.release["immutable"])

    def test_create_race_reuses_matching_draft(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        payload = json.dumps(evidence).encode()
        api = FakeGitHub(evidence, race=True)
        with patch("scripts.release_evidence._github_request", side_effect=api):
            self.assertEqual(publish(evidence, payload, repository="org/repo", token=BUILD["runId"]), payload)
        self.assertEqual(api.calls.count("create-draft"), 1)
        self.assertEqual(api.calls.count("upload"), 1)
        self.assertEqual(api.calls.count("publish"), 1)

    def test_published_retry_reuses_canonical_timestamp_but_rejects_changed_evidence(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        old = json.dumps(evidence).encode()
        changed = {**evidence, "buildSucceededAt": "2026-09-27T13:00:00+00:00"}
        api = FakeGitHub(evidence, old, published=True)
        with patch("scripts.release_evidence._github_request", side_effect=api):
            self.assertEqual(
                publish(changed, json.dumps(changed).encode(), repository="org/repo", token=BUILD["runId"]), old
            )
            divergent = {**changed, "indexDigest": f"sha256:{'f' * 64}"}
            with self.assertRaisesRegex(ReleaseEvidenceError, "no matching asset"):
                publish(divergent, json.dumps(divergent).encode(), repository="org/repo", token=BUILD["runId"])
        self.assertNotIn("upload", api.calls)
        self.assertNotIn("publish", api.calls)

    def test_published_release_without_asset_fails_without_mutation(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        api = FakeGitHub(evidence, published=True)
        with (
            patch("scripts.release_evidence._github_request", side_effect=api),
            self.assertRaisesRegex(ReleaseEvidenceError, "no matching asset"),
        ):
            publish(evidence, json.dumps(evidence).encode(), repository="org/repo", token=BUILD["runId"])
        self.assertEqual(api.calls, ["lookup", "list-assets"])

    def test_existing_draft_with_wrong_git_tag_is_not_published(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        api = FakeGitHub(evidence)
        api.release = api._release(draft=True)
        api.tag_exists_when_draft = True
        api.tag_sha = "c" * 40
        with (
            patch("scripts.release_evidence._github_request", side_effect=api),
            self.assertRaisesRegex(ReleaseEvidenceError, "does not resolve"),
        ):
            publish(evidence, json.dumps(evidence).encode(), repository="org/repo", token=BUILD["runId"])
        self.assertNotIn("upload", api.calls)
        self.assertNotIn("publish", api.calls)

    def test_existing_asset_must_preserve_valid_timestamp_and_nested_evidence(self) -> None:
        evidence = record(BUILD, release_origin_revision="d" * 40)
        current = {**evidence, "buildSucceededAt": "2026-09-27T13:00:00+00:00"}
        for existing in (
            {key: value for key, value in evidence.items() if key != "buildSucceededAt"},
            {**evidence, "runtimeEvidence": [{"profile": "incorrect"}]},
        ):
            api = FakeGitHub(evidence, json.dumps(existing).encode(), published=True)
            with (
                patch("scripts.release_evidence._github_request", side_effect=api),
                self.assertRaisesRegex(ReleaseEvidenceError, "different contents"),
            ):
                publish(current, json.dumps(current).encode(), repository="org/repo", token=BUILD["runId"])
            self.assertNotIn("publish", api.calls)

    def test_http_failure_includes_bounded_response_detail(self) -> None:
        error = urllib.error.HTTPError("https://api.github.com/", 422, "unprocessable", {}, io.BytesIO(b"x" * 2000))
        with (
            patch("scripts.release_evidence.urllib.request.urlopen", side_effect=error),
            self.assertRaises(ReleaseEvidenceError) as failure,
        ):
            _github_request("https://api.github.com/", "token")
        self.assertIn("HTTP 422", str(failure.exception))
        self.assertLess(len(str(failure.exception)), 1200)
        self.assertEqual(failure.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
