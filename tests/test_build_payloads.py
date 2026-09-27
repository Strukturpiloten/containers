"""Private payloads must be shared exactly and consumed only with matching evidence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import build_payloads as payloads

REVISION = "a" * 40


class SharedPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.manifest_path = "images/payload.yaml"
        (self.root / "images").mkdir()
        (self.root / "images/Containerfile").write_text("FROM scratch\n")
        self.manifest = {
            "schemaVersion": 1,
            "name": "fixture-payload",
            "build": {
                "context": ".",
                "containerfile": "images/Containerfile",
                "architectures": ["amd64", "arm64"],
                "args": {},
            },
            "provenance": {"source": "test fixture"},
        }
        self.write_manifest()

    def write_manifest(self) -> None:
        (self.root / self.manifest_path).write_text(yaml.safe_dump(self.manifest))

    def image(self, name: str, architectures: list[str]) -> dict:
        return {"name": name, "build": {"payload": self.manifest_path, "architectures": architectures}}

    def evidence(self) -> Path:
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        archive = artifacts / "fixture-payload-amd64.tar"
        archive.write_bytes(b"fixture OCI archive")
        evidence = {
            "schemaVersion": 1,
            "name": "fixture-payload",
            "architecture": "amd64",
            "sourceRevision": REVISION,
            "manifest": self.manifest_path,
            "manifestSha256": payloads.sha256(self.root / self.manifest_path),
            "archive": archive.name,
            "archiveSha256": payloads.sha256(archive),
        }
        (artifacts / "fixture-payload-amd64.json").write_text(json.dumps(evidence))
        return artifacts

    def test_rootful_and_rootless_variants_share_one_build_per_selected_architecture(self) -> None:
        images = [self.image("rootful", ["amd64", "arm64"]), self.image("rootless", ["amd64"])]
        result = payloads.plan_payloads(self.root, images, {"amd64": "x86-runner", "arm64": "arm-runner"})
        self.assertEqual(len(result["include"]), 2)
        self.assertEqual({entry["arch"] for entry in result["include"]}, {"amd64", "arm64"})

    def test_unrequested_architectures_are_not_built(self) -> None:
        result = payloads.plan_payloads(self.root, [self.image("rootful", ["amd64"])], {"amd64": "x86-runner"})
        self.assertEqual([entry["arch"] for entry in result["include"]], ["amd64"])

    def test_unsupported_variant_architecture_fails_planning(self) -> None:
        self.manifest["build"]["architectures"] = ["amd64"]
        self.write_manifest()
        with self.assertRaisesRegex(payloads.PayloadError, "does not support arm64"):
            payloads.plan_payloads(self.root, [self.image("rootless", ["arm64"])], {"arm64": "arm-runner"})

    def test_payload_build_rejects_head_sha_when_checkout_is_merge_sha(self) -> None:
        with (
            patch.object(payloads.subprocess, "check_output", return_value="b" * 40),
            patch.object(payloads, "_run") as run,
            self.assertRaisesRegex(payloads.PayloadError, "does not match checkout HEAD"),
        ):
            payloads.build_payload(self.root, self.manifest_path, "amd64", REVISION, self.root / "artifacts")
        run.assert_not_called()

    def test_missing_same_run_evidence_never_falls_back_to_a_registry(self) -> None:
        with patch.object(payloads, "_run") as run, self.assertRaisesRegex(payloads.PayloadError, "Missing same-run"):
            payloads.import_payload(self.root, self.manifest_path, "amd64", REVISION, self.root)
        run.assert_not_called()

    def test_changed_source_metadata_and_archive_are_rejected_before_import(self) -> None:
        artifacts = self.evidence()
        with patch.object(payloads, "_run") as run:
            with self.assertRaisesRegex(payloads.PayloadError, "sourceRevision"):
                payloads.import_payload(self.root, self.manifest_path, "amd64", "b" * 40, artifacts)
            self.manifest["provenance"]["source"] = "changed"
            self.write_manifest()
            with self.assertRaisesRegex(payloads.PayloadError, "manifestSha256"):
                payloads.import_payload(self.root, self.manifest_path, "amd64", REVISION, artifacts)
            self.manifest["provenance"]["source"] = "test fixture"
            self.write_manifest()
            (artifacts / "fixture-payload-amd64.tar").write_bytes(b"corrupted")
            with self.assertRaisesRegex(payloads.PayloadError, "integrity"):
                payloads.import_payload(self.root, self.manifest_path, "amd64", REVISION, artifacts)
        run.assert_not_called()

    def test_verified_archive_is_imported_to_local_container_storage(self) -> None:
        artifacts = self.evidence()
        with patch.object(payloads, "_run") as run:
            image = payloads.import_payload(self.root, self.manifest_path, "amd64", REVISION, artifacts)
        self.assertEqual(image, f"localhost/fixture-payload:{REVISION}-amd64")
        self.assertIn(f"containers-storage:{image}", run.call_args.args[0])

    def test_manifest_paths_cannot_escape_repository(self) -> None:
        with self.assertRaisesRegex(payloads.PayloadError, "escapes"):
            payloads.load_manifest(self.root, "../payload.yaml")


if __name__ == "__main__":
    unittest.main()
