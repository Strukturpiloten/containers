"""The publication snapshot must not promote mismatched or failed evidence."""

from __future__ import annotations

import copy
import datetime as dt
import json
import unittest
import urllib.error
from unittest.mock import patch

from scripts import docs_observations as observations

IMAGE = "ghcr.io/strukturpiloten/example"
SHA = "a" * 40
INDEX_DIGEST = "sha256:" + "1" * 64
MANIFEST_DIGEST = "sha256:" + "2" * 64
CONFIG_DIGEST = "sha256:" + "3" * 64
OTHER_DIGEST = "sha256:" + "4" * 64
NOW = dt.datetime.now(dt.UTC).isoformat()
METADATA = {"name": "example", "image": IMAGE, "version": "v1.2.3", "build": {"architectures": ["amd64"], "args": {}}}
PLATFORM = {
    "architecture": "amd64",
    "manifestDigest": MANIFEST_DIGEST,
    "configDigest": CONFIG_DIGEST,
    "labels": {"org.opencontainers.image.revision": SHA, "org.opencontainers.image.version": "1.2.3"},
    "configCreatedAt": NOW,
}
INDEX = {
    "annotations": {
        "io.github.strukturpiloten.publish.run-id": "123",
        "io.github.strukturpiloten.publish.run-attempt": "1",
        "org.opencontainers.image.revision": SHA,
    }
}


class FakeRegistry:
    """A small mutable registry with digest-addressed platform fixtures."""

    def tags(self, _image: str) -> list[str]:
        return ["latest", "main", "v1", "v1.2.3", "v1.2.2", "sha-" + SHA]

    def raw(self, _image: str, selector: str, *, expected: str | None = None) -> tuple[str, dict]:
        if selector == ":v1.2.2":
            return OTHER_DIGEST, INDEX
        if expected and expected != MANIFEST_DIGEST:
            msg = "Digest mismatch"
            raise observations.ObservationError(msg)
        return INDEX_DIGEST, INDEX


def observed_row() -> dict:
    """Return a structurally valid retained observation."""
    return {
        "name": "example",
        "image": IMAGE,
        "status": "observed",
        "observedAt": NOW,
        "stale": False,
        "refreshFailed": False,
        "refreshError": None,
        "ageSeconds": 0,
        "latest": {
            "digest": INDEX_DIGEST,
            "reference": f"{IMAGE}@{INDEX_DIGEST}",
            "sourceRevision": SHA,
            "runId": "123",
            "runAttempt": "1",
            "publishedAt": None,
            "platforms": [PLATFORM],
            "evidence": {"status": "unavailable", "reason": "No release"},
            "declarationAlignment": {"status": "unknown", "reason": "No verified release.", "differences": []},
        },
        "tags": {"listed": ["latest"], "currentAliases": ["latest"], "history": [], "unresolved": []},
    }


def verified_row() -> dict:
    """Return a previous observation with verified immutable release evidence."""
    row = observed_row()
    row["latest"]["publishedAt"] = NOW
    row["latest"]["evidence"] = {
        "status": "verified",
        "releaseUrl": None,
        "assetUrl": None,
        "assetDigest": CONFIG_DIGEST,
        "buildSucceededAt": NOW,
        "runtime": "verified",
        "scan": "verified",
        "signature": "unknown",
        "provenance": "unknown",
    }
    row["latest"]["declarationAlignment"] = {"status": "matched", "differences": []}
    return row


class ObservationTests(unittest.TestCase):
    def _collect_with_previous(self, prior: dict | None, registry: FakeRegistry | None = None) -> dict:
        previous = (
            {"schemaVersion": 1, "repository": "Strukturpiloten/containers", "generatedAt": NOW, "images": [prior]}
            if prior
            else None
        )
        with (
            patch.object(observations.container_engine, "_load_images", return_value=[METADATA]),
            patch.object(observations.container_engine, "_validate_images"),
            patch.object(observations, "_platforms", return_value=[PLATFORM]),
        ):
            return observations.collect(previous=previous, registry=registry or FakeRegistry(), workers=1)["images"][0]

    def test_transient_github_500_retains_same_digest_verified_observation_as_stale(self) -> None:
        prior = verified_row()
        failure = urllib.error.HTTPError("https://api.github.com/", 500, "server error", {}, None)
        with patch.object(observations.urllib.request, "urlopen", side_effect=failure):
            row = self._collect_with_previous(prior)
        self.assertEqual(row["status"], "stale")
        self.assertEqual(row["observedAt"], prior["observedAt"])
        self.assertTrue(row["refreshFailed"])
        self.assertIn("500", row["refreshError"])
        self.assertEqual(row["latest"]["evidence"], prior["latest"]["evidence"])
        self.assertEqual(row["latest"]["publishedAt"], prior["latest"]["publishedAt"])
        self.assertEqual(row["latest"]["declarationAlignment"]["status"], "unknown")
        self.assertEqual(prior["latest"]["declarationAlignment"]["status"], "matched")

    def test_transient_github_500_does_not_restore_proof_for_changed_digest(self) -> None:
        class ChangedRegistry(FakeRegistry):
            def raw(self, image: str, selector: str, *, expected: str | None = None) -> tuple[str, dict]:
                digest, index = super().raw(image, selector, expected=expected)
                return (OTHER_DIGEST if selector == ":latest" else digest), index

        failure = urllib.error.HTTPError("https://api.github.com/", 500, "server error", {}, None)
        with patch.object(observations.urllib.request, "urlopen", side_effect=failure):
            row = self._collect_with_previous(verified_row(), ChangedRegistry())
        self.assertEqual(row["status"], "observed")
        self.assertEqual(row["latest"]["digest"], OTHER_DIGEST)
        self.assertEqual(row["latest"]["evidence"]["status"], "unavailable")
        self.assertIsNone(row["latest"]["publishedAt"])

    def test_missing_or_mismatched_release_never_restores_prior_proof(self) -> None:
        for failure in (
            urllib.error.HTTPError("https://api.github.com/", 404, "not found", {}, None),
            observations.ObservationError("Evidence asset digest mismatch."),
        ):
            with self.subTest(failure=failure):
                if isinstance(failure, urllib.error.HTTPError):
                    context = patch.object(observations.urllib.request, "urlopen", side_effect=failure)
                else:
                    context = patch.object(observations, "_release_proof", side_effect=failure)
                with context:
                    row = self._collect_with_previous(verified_row())
                self.assertEqual(row["status"], "observed")
                self.assertEqual(row["latest"]["evidence"]["status"], "unavailable")
                self.assertIsNone(row["latest"]["publishedAt"])

    def test_transient_github_500_without_prior_keeps_fresh_registry_observation(self) -> None:
        failure = urllib.error.HTTPError("https://api.github.com/", 500, "server error", {}, None)
        with patch.object(observations.urllib.request, "urlopen", side_effect=failure):
            row = self._collect_with_previous(None)
        self.assertEqual(row["status"], "observed")
        self.assertEqual(row["latest"]["evidence"]["status"], "unavailable")

    def test_registry_fallback_clears_old_alignment_without_mutating_previous(self) -> None:
        prior = verified_row()
        row = observations._fallback(
            METADATA, prior, observations.ObservationError("registry failed"), dt.datetime.now(dt.UTC)
        )
        self.assertEqual(row["status"], "stale")
        self.assertEqual(row["latest"]["declarationAlignment"]["status"], "unknown")
        self.assertEqual(prior["latest"]["declarationAlignment"]["status"], "matched")

    def test_current_aliases_and_historical_digest_are_separate(self) -> None:
        with (
            patch.object(observations, "_platforms", return_value=[PLATFORM]),
            patch.object(observations, "_release_proof", side_effect=observations.ObservationError("No release")),
        ):
            row = observations._observe_one(METADATA, FakeRegistry(), "Strukturpiloten/containers", None, 5)
        self.assertEqual(row["tags"]["currentAliases"], ["latest", "main", "v1", "v1.2.3"])
        self.assertEqual(row["tags"]["history"], [{"digest": OTHER_DIGEST, "tags": ["v1.2.2"]}])
        self.assertEqual(row["tags"]["unresolved"], ["sha-" + SHA])
        self.assertIsNone(row["latest"]["publishedAt"])

    def test_digest_mismatch_rejects_configuration(self) -> None:
        class WrongConfig(observations.PublicRegistry):
            def _config_blob(self, *_args: str) -> bytes:
                return b"{}"

        with self.assertRaisesRegex(observations.ObservationError, "config digest mismatch"):
            WrongConfig(1).config(IMAGE, MANIFEST_DIGEST, CONFIG_DIGEST)

    def test_stale_previous_observation_retains_identity_and_age(self) -> None:
        retained = observed_row()
        retained["observedAt"] = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)).isoformat()
        retained["latest"]["evidence"] = {
            "status": "verified",
            "releaseUrl": "https://github.com/Strukturpiloten/containers/releases/tag/example",
            "assetUrl": "https://github.com/Strukturpiloten/containers/releases/download/example/asset.json",
            "assetDigest": CONFIG_DIGEST,
            "buildSucceededAt": NOW,
            "runtime": "verified",
            "scan": "verified",
            "signature": "unknown",
            "provenance": "unknown",
        }
        previous = {
            "schemaVersion": 1,
            "repository": "Strukturpiloten/containers",
            "generatedAt": NOW,
            "images": [retained],
        }
        with (
            patch.object(observations.container_engine, "_load_images", return_value=[METADATA]),
            patch.object(observations.container_engine, "_validate_images"),
            patch.object(observations, "_observe_one", side_effect=observations.ObservationError("network timeout")),
        ):
            result = observations.collect(previous=previous, workers=1)
        row = result["images"][0]
        self.assertEqual(row["status"], "stale")
        self.assertEqual(row["latest"]["digest"], INDEX_DIGEST)
        self.assertEqual(row["latest"]["evidence"]["status"], "verified")
        self.assertEqual(row["observedAt"], retained["observedAt"])
        self.assertTrue(row["refreshFailed"])
        self.assertIn("network timeout", row["refreshError"])
        self.assertGreaterEqual(row["ageSeconds"], 3 * 60 * 60)

    def test_partial_refresh_keeps_success_separate(self) -> None:
        second = {**METADATA, "name": "other", "image": "ghcr.io/strukturpiloten/other"}

        def refresh(image: dict, *_args: object, **_kwargs: object) -> dict:
            if image["name"] == "other":
                msg = "missing"
                raise observations.ObservationError(msg)
            return copy.deepcopy(observed_row())

        with (
            patch.object(observations.container_engine, "_load_images", return_value=[METADATA, second]),
            patch.object(observations.container_engine, "_validate_images"),
            patch.object(observations, "_observe_one", side_effect=refresh),
        ):
            result = observations.collect(workers=2)
        self.assertEqual([row["status"] for row in result["images"]], ["observed", "unavailable"])
        self.assertIsNone(result["images"][1]["latest"])

    def test_release_asset_must_match_registry_architecture_mapping(self) -> None:
        asset = {
            "schemaVersion": 1,
            "imageName": "example",
            "image": IMAGE,
            "version": "1.2.3",
            "buildSourceRevision": SHA,
            "evidenceReleaseRevision": SHA,
            "evidenceReleaseTag": "example/maintenance/123-1",
            "releaseTag": "example/v1.2.3",
            "indexDigest": INDEX_DIGEST,
            "runId": "123",
            "runAttempt": "1",
            "componentInputs": {},
            "architectureDigests": {"amd64": MANIFEST_DIGEST},
            "publicationMapping": {
                "amd64": {"architecture": "amd64", "manifestDigest": MANIFEST_DIGEST, "configDigest": OTHER_DIGEST}
            },
            "buildSucceededAt": NOW,
            "publishedAt": "2026-09-27T12:34:56+00:00",
        }
        raw = json.dumps(asset).encode()
        release = {
            "tag_name": "example/maintenance/123-1",
            "draft": False,
            "immutable": True,
            "target_commitish": SHA,
            "assets": [
                {
                    "name": f"maintenance-evidence-{INDEX_DIGEST.replace(':', '-')}-123-1.json",
                    "url": "https://api.github.com/repos/Strukturpiloten/containers/releases/assets/1",
                    "size": len(raw),
                    "digest": observations._digest(raw),
                }
            ],
        }

        def response(url: str, *, accept: str = "application/vnd.github+json", **_kwargs: object) -> bytes:
            if accept == "application/octet-stream":
                return raw
            if "/git/ref/tags/" in url:
                return json.dumps(
                    {"ref": "refs/tags/example/maintenance/123-1", "object": {"type": "commit", "sha": SHA}}
                ).encode()
            return json.dumps(release).encode()

        with (
            patch.object(observations, "_github_json", side_effect=response),
            self.assertRaisesRegex(observations.ObservationError, "does not match registry"),
        ):
            observations._release_proof(
                repository="Strukturpiloten/containers",
                name="example",
                image=IMAGE,
                digest=INDEX_DIGEST,
                index=INDEX,
                platforms=[PLATFORM],
                token=None,
                timeout=5,
            )
        with (
            patch.object(observations, "_github_json", side_effect=response),
            patch.object(observations, "_platforms", return_value=[PLATFORM]),
        ):
            mismatched = observations._observe_one(METADATA, FakeRegistry(), "Strukturpiloten/containers", None, 5)
        self.assertIsNone(mismatched["latest"]["publishedAt"])
        self.assertEqual(mismatched["latest"]["evidence"]["status"], "unavailable")

        asset["publicationMapping"]["amd64"]["configDigest"] = CONFIG_DIGEST
        raw = json.dumps(asset).encode()
        release["assets"][0]["size"] = len(raw)
        release["assets"][0]["digest"] = observations._digest(raw)
        with (
            patch.object(observations, "_github_json", side_effect=response),
            patch.object(observations.release_evidence, "_require_complete"),
        ):
            proof, fetched_asset = observations._release_proof(
                repository="Strukturpiloten/containers",
                name="example",
                image=IMAGE,
                digest=INDEX_DIGEST,
                index=INDEX,
                platforms=[PLATFORM],
                token=None,
                timeout=5,
            )
        with (
            patch.object(observations, "_release_proof", return_value=(proof, fetched_asset)),
            patch.object(observations, "_platforms", return_value=[PLATFORM]),
        ):
            row = observations._observe_one(METADATA, FakeRegistry(), "Strukturpiloten/containers", None, 5)
        self.assertEqual(row["latest"]["publishedAt"], asset["publishedAt"])

        asset["publishedAt"] = "2026-09-27T12:34:56"
        raw = json.dumps(asset).encode()
        release["assets"][0]["size"] = len(raw)
        release["assets"][0]["digest"] = observations._digest(raw)
        with (
            patch.object(observations, "_github_json", side_effect=response),
            self.assertRaisesRegex(observations.ObservationError, "timezone"),
        ):
            observations._release_proof(
                repository="Strukturpiloten/containers",
                name="example",
                image=IMAGE,
                digest=INDEX_DIGEST,
                index=INDEX,
                platforms=[PLATFORM],
                token=None,
                timeout=5,
            )

    def test_verified_live_release_can_differ_from_current_declaration(self) -> None:
        metadata = copy.deepcopy(METADATA)
        metadata["build"]["args"] = {"DISTRO_IMAGE": {"value": "base@sha256:new"}}
        asset = {
            "version": "1.2.3",
            "architectureDigests": {"amd64": MANIFEST_DIGEST},
            "componentInputs": {"DISTRO_IMAGE": "base@sha256:old"},
        }
        proof = {
            "status": "verified",
            "releaseUrl": None,
            "assetUrl": None,
            "assetDigest": CONFIG_DIGEST,
            "buildSucceededAt": NOW,
            "runtime": "verified",
            "scan": "verified",
            "signature": "unknown",
            "provenance": "unknown",
        }
        with (
            patch.object(observations, "_platforms", return_value=[PLATFORM]),
            patch.object(observations, "_release_proof", return_value=(proof, asset)),
        ):
            row = observations._observe_one(metadata, FakeRegistry(), "Strukturpiloten/containers", None, 5)
        self.assertEqual(row["latest"]["evidence"]["status"], "verified")
        alignment = row["latest"]["declarationAlignment"]
        self.assertEqual(alignment["status"], "different")
        self.assertEqual(
            alignment["differences"],
            [{"field": "buildInputs.DISTRO_IMAGE", "published": "base@sha256:old", "declared": "base@sha256:new"}],
        )

    def test_alignment_reports_version_architecture_and_payload_hash(self) -> None:
        metadata = copy.deepcopy(METADATA)
        metadata["version"] = "v2.0.0"
        metadata["build"]["architectures"] = ["amd64", "arm64"]
        asset = {
            "version": "1.2.3",
            "architectureDigests": {"amd64": MANIFEST_DIGEST},
            "componentInputs": {"payload": {"manifestSha256": "sha256:old"}},
        }
        with patch.object(
            observations.container_engine,
            "_component_inputs",
            return_value={"payload": {"manifestSha256": "sha256:new"}},
        ):
            alignment = observations._declaration_alignment(metadata, asset)
            expected_fingerprint = observations.declaration_fingerprint(metadata)
        self.assertEqual(alignment["status"], "different")
        self.assertEqual(
            {item["field"] for item in alignment["differences"]},
            {"version", "architectures", "buildInputs.payload.manifestSha256"},
        )
        self.assertEqual(alignment["declarationFingerprint"], expected_fingerprint)
        row = observed_row()
        row["latest"]["declarationAlignment"] = alignment
        observations.validate(
            {"schemaVersion": 1, "repository": "Strukturpiloten/containers", "generatedAt": NOW, "images": [row]}
        )

    def test_declaration_fingerprint_binds_compared_inputs_only(self) -> None:
        metadata = copy.deepcopy(METADATA)
        with patch.object(observations.container_engine, "_component_inputs", return_value={"BASE": "old"}):
            original = observations.declaration_fingerprint(metadata)
            metadata["title"] = "Unrelated documentation title"
            self.assertEqual(observations.declaration_fingerprint(metadata), original)
            metadata["version"] = "v2.0.0"
            self.assertNotEqual(observations.declaration_fingerprint(metadata), original)
        metadata["version"] = METADATA["version"]
        with patch.object(observations.container_engine, "_component_inputs", return_value={"BASE": "new"}):
            self.assertNotEqual(observations.declaration_fingerprint(metadata), original)

    def test_schema_rejects_claimed_publication_time(self) -> None:
        row = observed_row()
        row["latest"]["publishedAt"] = NOW
        snapshot = {"schemaVersion": 1, "repository": "Strukturpiloten/containers", "generatedAt": NOW, "images": [row]}
        with self.assertRaisesRegex(observations.ObservationError, "Publication time requires"):
            observations.validate(snapshot)

    def test_snapshot_rejects_reference_digest_mismatch(self) -> None:
        row = observed_row()
        row["latest"]["reference"] = f"{IMAGE}@{OTHER_DIGEST}"
        snapshot = {"schemaVersion": 1, "repository": "Strukturpiloten/containers", "generatedAt": NOW, "images": [row]}
        with self.assertRaisesRegex(observations.ObservationError, "reference does not match digest"):
            observations.validate(snapshot)

    def test_index_source_must_match_config_labels(self) -> None:
        changed = copy.deepcopy(PLATFORM)
        changed["labels"]["org.opencontainers.image.revision"] = "b" * 40
        with (
            patch.object(observations, "_platforms", return_value=[changed]),
            self.assertRaisesRegex(observations.ObservationError, "source revisions differ"),
        ):
            observations._observe_one(METADATA, FakeRegistry(), "Strukturpiloten/containers", None, 5)


if __name__ == "__main__":
    unittest.main()
