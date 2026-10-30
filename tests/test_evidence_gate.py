"""Publication requires runtime and scanner proof for the same OCI archive."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evidence_gate import (
    EvidenceError,
    _outer_runtime,
    _systemd_phase_backends,
    main,
    require_ordinary_runtime_authority,
    verify_architecture,
)

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
    "host": {
        "architecture": "x86_64",
        "outerEngineSelection": "profile",
        "outerRuntime": {
            "engine": "docker",
            "clientVersion": "Docker version 29.8.2",
            "serverVersion": "29.8.2",
            "containerdVersion": "containerd 2.2.0",
            "systemdVersion": "systemd 259",
            "rootMode": "rootful",
            "endpoint": "private-unix",
            "storage": "invocation-owned",
        },
    },
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
    def test_each_required_systemd_phase_proves_the_same_private_docker_policy(self) -> None:
        configuration = {"mode": "rootless", "launcher": "systemd"}
        record = copy.deepcopy(RUNTIME)
        record["phases"] = [
            {
                "phase": name,
                "status": "passed",
                "cleanupVerified": True,
                "imageIdentity": copy.deepcopy(IDENTITY),
                "checks": [{"name": "independent native phase result", "status": "passed"}],
                "outerRuntime": copy.deepcopy(RUNTIME["host"]["outerRuntime"]),
            }
            for name in ("clean-control", "enforcement")
        ]
        _systemd_phase_backends(record, "docker", configuration)
        for change in ("missing", "engine", "cleanup", "identity", "phase", "skip"):
            changed = copy.deepcopy(record)
            if change == "missing":
                changed["phases"].pop()
            elif change == "engine":
                changed["phases"][0]["outerRuntime"]["engine"] = "podman"
            elif change == "cleanup":
                changed["phases"][1]["cleanupVerified"] = False
            elif change == "identity":
                changed["phases"][1]["imageIdentity"]["archiveSha256"] = "e" * 64
            elif change == "phase":
                changed["phases"].reverse()
            else:
                changed["phases"][1]["checks"][0]["status"] = "skipped"
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                _systemd_phase_backends(changed, "docker", configuration)

    def _verify(self, *, runtime: dict = RUNTIME, scan: dict = SCAN, configuration: dict | None = None) -> None:
        with (
            patch(
                "scripts.evidence_gate.image_policy",
                return_value={"image": IMAGE, "admission": "isolated-test", "requiredRuntimeProfile": "docker"},
            ),
            patch("scripts.evidence_gate.archive_identity", return_value=IDENTITY),
            patch(
                "scripts.evidence_gate.container_engine._load_images",
                return_value=[{"name": NAME, "tests": {"docker": configuration or {}}}],
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

    def test_private_required_route_never_invents_normal_prerequisite_authority(self) -> None:
        # Deliberately forged completion labels, not an accepted future normal fixture.
        record = copy.deepcopy(RUNTIME)
        record.update(
            qualification="complete",
            oomAccountingMode="qualification",
            oomAccountingStatus="complete",
            oomAccountingRequired=True,
            focusedRuntime="none",
        )
        record["phases"] = [
            {
                "phase": name,
                "status": "passed",
                "cleanupVerified": True,
                "imageIdentity": copy.deepcopy(IDENTITY),
                "qualification": "complete",
                "oomAccountingMode": "qualification",
                "oomAccountingStatus": "complete",
                "oomAccountingRequired": True,
                "focusedRuntime": "none",
                "checks": [
                    {
                        "name": "owned parent OOM lifecycle accounting",
                        "status": "passed",
                        "mode": "qualification",
                        "property": "no-additional-oom-killed-process-in-bound-lifetime",
                    }
                ],
                "outerRuntime": copy.deepcopy(RUNTIME["host"]["outerRuntime"]),
            }
            for name in ("clean-control", "enforcement")
        ]
        configuration = {"launcher": "systemd", "mode": "rootless"}
        with self.assertRaisesRegex(EvidenceError, "no supported maintained normal prerequisite"):
            self._verify(runtime=record, configuration=configuration)
        for change in ("missing", "none", "experimental", "mixed", "accounting", "missing-outcome", "focused"):
            changed = copy.deepcopy(record)
            if change == "missing":
                del changed["qualification"]
            elif change == "none":
                changed["qualification"] = "none"
            elif change == "experimental":
                changed["scopedProfileRequired"] = False
                changed["phases"][0]["scopedProfile"] = {"qualification": "experimental-candidate-only"}
            elif change == "mixed":
                changed["phases"][1]["qualification"] = "none"
            elif change == "accounting":
                changed["phases"][0]["oomAccountingStatus"] = "incomplete"
            elif change == "missing-outcome":
                changed["phases"][1]["checks"] = [{"name": "label only", "status": "passed"}]
            else:
                changed["focusedRuntime"] = "mandatory-accounting"
            with (
                self.subTest(change=change),
                patch.dict(
                    "os.environ",
                    {
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_REF": "refs/heads/main",
                        "VALIDATION_PROFILE": "full",
                    },
                ),
                self.assertRaises(EvidenceError),
            ):
                self._verify(runtime=changed, configuration=configuration)

    def test_actual_supported_ordinary_routes_keep_legacy_authority_contract(self) -> None:
        for profile in ("docker", "podman", "phpFpm", "notifyPush"):
            with self.subTest(profile=profile):
                require_ordinary_runtime_authority({"status": "passed"}, profile, {"launcher": "direct"})
                with self.assertRaises(EvidenceError):
                    require_ordinary_runtime_authority({"status": "passed", "qualification": "none"}, profile, {})

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

    def test_wrong_or_unobserved_outer_runtime_cannot_admit_an_archive(self) -> None:
        for key, value in (
            ("engine", "podman"),
            ("rootMode", "rootless"),
            ("storage", "shared"),
            ("endpoint", "ambient"),
            ("clientVersion", ""),
            ("serverVersion", "unknown"),
            ("containerdVersion", "unknown"),
            ("systemdVersion", ""),
        ):
            record = json.loads(json.dumps(RUNTIME))
            record["host"]["outerRuntime"][key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                self._verify(runtime=record)
        for change in ({"outerEngineSelection": "docker"}, {"podmanVersion": "podman version 5.4.2"}):
            record = json.loads(json.dumps(RUNTIME))
            record["host"].update(change)
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                self._verify(runtime=record)

    def test_non_docker_profiles_derive_podman_not_image_name_or_inner_mode(self) -> None:
        for profile in ("podman", "phpFpm", "notifyPush"):
            record = {
                "host": {
                    "outerEngineSelection": "profile",
                    "podmanVersion": "podman version 5.4.2",
                    "outerRuntime": {
                        "engine": "podman",
                        "clientVersion": "podman version 5.4.2",
                        "rootMode": "rootful",
                        "storage": "invocation-owned",
                    },
                }
            }
            with self.subTest(profile=profile):
                _outer_runtime(record, profile)
                record["host"]["outerRuntime"]["engine"] = "docker"
                with self.assertRaises(EvidenceError):
                    _outer_runtime(record, profile)

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


class AuthorityImportOrderTests(unittest.TestCase):
    def test_cold_import_orders_and_deferred_catalogue_import_remain_acyclic(self) -> None:
        modules = ["evidence_gate", "admission", "maintenance", "release_evidence", "docs_observations"]
        root = Path(__file__).resolve().parents[1]
        program = (
            "import importlib,json,sys;sys.path.insert(0,sys.argv[1]);"
            "[importlib.import_module('scripts.'+name) for name in json.loads(sys.argv[2])];"
            "from scripts.maintenance import _runtime_authority_view;"
            "assert _runtime_authority_view({'tests':{}},'docker',{'status':'passed'})=={'status':'passed'};print('ok')"
        )
        for index in range(len(modules)):
            order = modules[index:] + modules[:index]
            for selected in (order, list(reversed(order))):
                with self.subTest(order=selected):
                    result = subprocess.run(  # noqa: S603 - fixed data-only import order regression.
                        [sys.executable, "-I", "-B", "-c", program, str(root), json.dumps(selected)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "ok")
