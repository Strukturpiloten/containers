"""Publication requires runtime and scanner proof for the same OCI archive."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evidence_gate import EvidenceError, main, verify_architecture

NAME = "example"
IMAGE = "ghcr.io/strukturpiloten/example"
SOURCE = "b" * 40
DIGEST = f"sha256:{'a' * 64}"
CONFIG = f"sha256:{'c' * 64}"
IDENTITY = {
    "architecture": "amd64",
    "manifestDigest": DIGEST,
    "configDigest": CONFIG,
    "archiveSha256": "d" * 64,
    "sourceRevision": SOURCE,
    "version": "1.0.0",
}
RUNTIME = {
    "image": NAME,
    "architecture": "amd64",
    "profile": "docker",
    "status": "passed",
    "imageIdentity": IDENTITY,
    "host": {"architecture": "x86_64"},
    "runId": "123",
    "runAttempt": "1",
    "checks": [{"name": "Docker CLI", "status": "passed"}],
}
SCAN = {
    "image": IMAGE,
    "architecture": "amd64",
    "admission": "isolated-test",
    "decision": "passed",
    "sourceRevision": SOURCE,
    "runId": "123",
    "runAttempt": "1",
    "candidateDigest": DIGEST,
    "candidateSource": {**IDENTITY, "archiveSha256": f"sha256:{IDENTITY['archiveSha256']}"},
    "baselineStatus": "absent",
    "baselineDigest": None,
    "baselineSource": {"status": "absent", "image": IMAGE, "architecture": "amd64"},
    "scanner": {"version": "0.119.0"},
    "database": {"schemaVersion": "6"},
}


class ArchitectureEvidenceTests(unittest.TestCase):
    def _verify(self, *, runtime: dict = RUNTIME, scan: dict = SCAN) -> None:
        with (
            patch(
                "scripts.evidence_gate.image_policy",
                return_value={"image": IMAGE, "admission": "isolated-test", "requiredRuntimeProfile": "docker"},
            ),
            patch("scripts.evidence_gate.archive_identity", return_value=IDENTITY),
            patch(
                "scripts.evidence_gate.container_engine._load_images",
                return_value=[{"name": NAME, "tests": {"docker": {}}}],
            ),
        ):
            verify_architecture(
                name=NAME,
                architecture="amd64",
                source_revision=SOURCE,
                version="1.0.0",
                run_id="123",
                execution_attempt=2,
                archive=Path("archive.tar"),
                runtime=runtime,
                scan=scan,
            )

    def test_cli_reads_exact_uploaded_artifact_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            plan = root_path / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "sourceRevision": SOURCE,
                        "images": [{"name": NAME, "version": "1.0.0", "build": {"architectures": ["amd64"]}}],
                    }
                ),
                encoding="utf-8",
            )
            runtime_dir = root_path / "runtime"
            scan_dir = root_path / "scan"
            runtime_dir.mkdir()
            scan_dir.mkdir()
            (runtime_dir / "example-amd64.json").write_text(json.dumps(RUNTIME), encoding="utf-8")
            (scan_dir / "example-amd64-vulnerability-report.json").write_text(json.dumps(SCAN), encoding="utf-8")
            argv = [
                "evidence_gate",
                "--name",
                NAME,
                "--plan",
                str(plan),
                "--archives-dir",
                str(root_path),
                "--runtime-dir",
                str(runtime_dir),
                "--scan-dir",
                str(scan_dir),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict("os.environ", {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}),
                patch("scripts.evidence_gate.verify_architecture") as verify,
            ):
                main()
            self.assertEqual(verify.call_args.kwargs["runtime"], RUNTIME)
            self.assertEqual(verify.call_args.kwargs["scan"], SCAN)
            self.assertEqual(verify.call_args.kwargs["archive"], root_path / "example-amd64.tar")

    def test_same_run_prior_attempt_is_accepted(self) -> None:
        self._verify()

    def test_missing_or_mismatched_identity_is_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            self._verify(runtime={**RUNTIME, "imageIdentity": {**IDENTITY, "configDigest": DIGEST}})
        with self.assertRaises(EvidenceError):
            self._verify(scan={**SCAN, "candidateSource": {**SCAN["candidateSource"], "sourceRevision": "e" * 40}})
        with self.assertRaises(EvidenceError):
            self._verify(scan={**SCAN, "runId": "another"})

    def test_untrusted_runtime_skip_is_not_publication_proof(self) -> None:
        skipped = {
            **RUNTIME,
            "checks": [
                {
                    "name": "nested Docker runtime",
                    "status": "skipped",
                    "reason": "privileged test requires trusted context",
                }
            ],
        }
        with self.assertRaisesRegex(EvidenceError, "without a declared exemption"):
            self._verify(runtime=skipped)


if __name__ == "__main__":
    unittest.main()
