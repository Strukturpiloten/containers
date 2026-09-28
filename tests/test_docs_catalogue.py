"""Checks for declared image catalogue and registry evidence separation."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from scripts import docs_observations
from scripts.docs_catalogue import catalogue, image_markdown, index_markdown

ROOT = Path(__file__).resolve().parent.parent
DIGEST = f"sha256:{'a' * 64}"
VERSION = "v6.1.2"
PODMAN = {
    "name": "podman-6.1-rootless",
    "image": "ghcr.io/strukturpiloten/podman-6.1-rootless",
    "title": "Podman 6.1 rootless",
    "description": "Podman built from upstream source",
    "version": VERSION,
    "metadataFile": "images/podman/podman-6.1-rootless/container.yaml",
    "build": {
        "architectures": ["amd64", "arm64"],
        "runtimeBaseArg": "FEDORA_IMAGE",
        "args": {"FEDORA_IMAGE": {"value": f"registry.fedoraproject.org/fedora-minimal:44@{DIGEST}"}},
    },
    "lifecycle": {
        "state": "maintained",
        "admission": "isolated-test",
        "supportBoundary": "For isolated compatibility tests.",
        "reviewAfter": "2026-12-31",
        "requiredRuntimeProfiles": ["podman"],
    },
    "tests": {"podman": {"mode": "rootless", "outerPrivilege": "unprivileged"}},
}


def _snapshot_row() -> dict:
    return {
        "name": PODMAN["name"],
        "image": PODMAN["image"],
        "status": "observed",
        "observedAt": "2026-09-28T12:00:00+00:00",
        "stale": False,
        "refreshFailed": False,
        "refreshError": None,
        "ageSeconds": 0,
        "latest": {
            "digest": DIGEST,
            "reference": f"{PODMAN['image']}@{DIGEST}",
            "sourceRevision": "b" * 40,
            "runId": "123",
            "runAttempt": "1",
            "publishedAt": None,
            "platforms": [
                {
                    "architecture": "amd64",
                    "manifestDigest": DIGEST,
                    "configDigest": DIGEST,
                    "configCreatedAt": "2026-09-28T11:00:00+00:00",
                    "labels": {"org.opencontainers.image.version": "6.1.2"},
                }
            ],
            "evidence": {"status": "unknown", "reason": "No matching release."},
        },
        "tags": {
            "listed": ["latest", "main", "v6.1.2", "sha-deadbeef"],
            "currentAliases": ["latest", "main"],
            "history": [{"digest": f"sha256:{'c' * 64}", "tags": ["v6.1.2"]}],
            "unresolved": ["sha-deadbeef"],
        },
    }


def _verified_alignment_row() -> dict:
    row = _snapshot_row()
    row["latest"]["publishedAt"] = "2026-09-28T11:30:00+00:00"
    row["latest"]["evidence"] = {
        "status": "verified",
        "releaseUrl": None,
        "assetUrl": None,
        "assetDigest": DIGEST,
        "buildSucceededAt": "2026-09-28T11:00:00+00:00",
        "runtime": "verified",
        "scan": "verified",
        "signature": "unknown",
        "provenance": "unknown",
    }
    row["latest"]["declarationAlignment"] = {
        "status": "matched",
        "differences": [],
        "declarationFingerprint": docs_observations.declaration_fingerprint(PODMAN),
    }
    return row


class DocsCatalogueTests(unittest.TestCase):
    def test_matching_declaration_fingerprint_preserves_current_alignment(self) -> None:
        observation = _verified_alignment_row()
        report = catalogue([PODMAN], {"schemaVersion": 1, "images": [observation]}, source_revision="c" * 40)
        latest = report["images"][0]["observation"]["latest"]
        self.assertEqual(latest["declarationAlignment"]["status"], "matched")
        self.assertEqual(latest["evidence"], observation["latest"]["evidence"])

    def test_changed_or_legacy_declarations_invalidate_only_alignment(self) -> None:
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                observation = _verified_alignment_row()
                metadata = {**PODMAN, "version": "v6.2.0"}
                if legacy:
                    del observation["latest"]["declarationAlignment"]["declarationFingerprint"]
                    metadata = PODMAN
                report = catalogue([metadata], {"schemaVersion": 1, "images": [observation]}, source_revision="c" * 40)
                latest = report["images"][0]["observation"]["latest"]
                self.assertEqual(latest["declarationAlignment"]["status"], "unknown")
                self.assertEqual(latest["evidence"], observation["latest"]["evidence"])
                self.assertEqual(latest["digest"], observation["latest"]["digest"])
                self.assertEqual(latest["publishedAt"], observation["latest"]["publishedAt"])
                self.assertEqual(observation["latest"]["declarationAlignment"]["status"], "matched")

    def test_unrecomputable_fingerprint_invalidates_only_alignment(self) -> None:
        observation = _verified_alignment_row()
        with patch.object(docs_observations, "declaration_fingerprint", side_effect=ValueError("inputs missing")):
            report = catalogue([PODMAN], {"schemaVersion": 1, "images": [observation]}, source_revision="c" * 40)
        latest = report["images"][0]["observation"]["latest"]
        self.assertEqual(latest["declarationAlignment"]["status"], "unknown")
        self.assertEqual(latest["evidence"]["status"], "verified")

    def test_declarations_without_snapshot_do_not_claim_registry_success(self) -> None:
        report = catalogue([PODMAN], None, source_revision="b" * 40)
        row = report["images"][0]
        self.assertIsNone(report["generatedAt"])
        self.assertIsNone(row["observation"])
        self.assertEqual(row["softwareVersion"], "6.1.2")
        self.assertEqual(row["rootMode"], "rootless")
        self.assertEqual(row["declaredTags"], ["v6.1.2", "v6.1", "v6", "main", "latest"])
        self.assertIn("No verified current digest", image_markdown(row))
        self.assertIn('data-family="podman"', index_markdown(report))
        self.assertIn("unknown", index_markdown(report))
        schema = json.loads((ROOT / "docs/catalogue.schema.json").read_text())
        Draft202012Validator(schema).validate(report)

    def test_observed_aliases_history_and_timestamps_remain_separate(self) -> None:
        observation = _snapshot_row()
        report = catalogue(
            [PODMAN],
            {"schemaVersion": 1, "generatedAt": "2026-09-28T12:00:00+00:00", "images": [observation]},
            source_revision="b" * 40,
        )
        page = image_markdown(report["images"][0])
        self.assertIn("Aliases resolved to the observed current digest", page)
        self.assertIn("Other resolved aliases at observation time", page)
        self.assertIn("sha-deadbeef", page)
        self.assertIn("| Build succeeded | unknown |", page)
        self.assertIn("| Published | unknown |", page)
        self.assertIn("2026-09-28T12:00:00+00:00", page)
        schema = json.loads((ROOT / "docs/catalogue.schema.json").read_text())
        Draft202012Validator(schema).validate(report)

    def test_distro_software_version_is_unknown_and_debian_11_oom_option_visible(self) -> None:
        metadata = {
            **PODMAN,
            "name": "docker-debian-11-rootless",
            "image": "ghcr.io/strukturpiloten/docker-debian-11-rootless",
            "version": "v1.0.0",
            "title": "Docker Debian 11 rootless",
            "metadataFile": "images/docker/docker-debian-11-rootless/container.yaml",
        }
        row = catalogue([metadata], None, source_revision="b" * 40)["images"][0]
        self.assertIsNone(row["softwareVersion"])
        self.assertEqual(row["distribution"], "debian-11")
        self.assertIn("--oom-score-adj=0", image_markdown(row))

    def test_mismatched_registry_identity_is_rejected(self) -> None:
        observation = _snapshot_row()
        observation["image"] = "ghcr.io/strukturpiloten/another"
        with self.assertRaises(ValueError):
            catalogue([PODMAN], {"schemaVersion": 1, "images": [observation]}, source_revision="b" * 40)

    def test_stale_and_unavailable_observations_show_refresh_failure(self) -> None:
        observation = _snapshot_row()
        observation.update({"status": "stale", "stale": True, "refreshFailed": True, "refreshError": "GHCR timed out"})
        report = catalogue([PODMAN], {"schemaVersion": 1, "images": [observation]}, source_revision="b" * 40)
        page = image_markdown(report["images"][0])
        self.assertIn("retained stale data", page)
        self.assertIn("GHCR timed out", page)

        observation.update({"status": "unavailable", "latest": None, "tags": None, "observedAt": None})
        report = catalogue([PODMAN], {"schemaVersion": 1, "images": [observation]}, source_revision="b" * 40)
        page = image_markdown(report["images"][0])
        self.assertIn("No verified current digest", page)
        self.assertIn("GHCR timed out", page)


if __name__ == "__main__":
    unittest.main()
