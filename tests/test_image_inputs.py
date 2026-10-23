"""Selected manifests must be usable before their consumers enter the build matrix."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from scripts import container_engine as engine
from scripts import image_inputs as inputs

MIN_SHARED_CONSUMERS = 3


def index_bytes(architectures: tuple[str, ...] = ("amd64", "arm64")) -> bytes:
    """Create a small multi-platform registry index independently of live metadata."""
    return json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {"platform": {"os": "linux", "architecture": arch}, "digest": "sha256:" + "a" * 64, "size": 100}
                for arch in architectures
            ],
        }
    ).encode()


def image_input(raw: bytes, architectures: set[str] | None = None) -> inputs.ImageInput:
    """Pin a synthetic manifest by its exact serialized identity."""
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return inputs.ImageInput(f"registry.example/image@{digest}", architectures or {"amd64", "arm64"}, {"fixture.yaml"})


class ManifestInputTests(unittest.TestCase):
    def test_valid_multiarch_index_passes(self) -> None:
        raw = index_bytes()
        with patch.object(inputs, "_inspect", return_value=raw) as inspect:
            self.assertEqual(inputs.check_input(image_input(raw))["status"], "passed")
            inspect.assert_called_once()

    def test_empty_or_missing_architecture_index_fails(self) -> None:
        for architectures in ((), ("amd64",), ("arm64",)):
            raw = index_bytes(architectures)
            with self.subTest(architectures=architectures), patch.object(inputs, "_inspect", return_value=raw):
                report = inputs.check_input(image_input(raw))
                self.assertEqual(report["status"], "failed")
                self.assertIn("lacks Linux platform", report["error"])

    def test_manifest_bytes_must_match_the_pin(self) -> None:
        with patch.object(inputs, "_inspect", return_value=index_bytes(("amd64",))):
            report = inputs.check_input(image_input(index_bytes()))
            self.assertEqual(report["status"], "failed")
            self.assertIn("do not match", report["error"])

    def test_single_manifest_requires_a_matching_linux_configuration(self) -> None:
        raw = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "b" * 64}}).encode()
        configuration = json.dumps({"os": "linux", "architecture": "arm64"}).encode()
        with patch.object(inputs, "_inspect", side_effect=[raw, configuration]):
            self.assertEqual(inputs.check_input(image_input(raw, {"arm64"}))["status"], "passed")
        with patch.object(inputs, "_inspect", side_effect=[raw, configuration]):
            self.assertEqual(inputs.check_input(image_input(raw))["status"], "failed")

    def test_reference_normalization_preserves_registry_ports(self) -> None:
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            inputs.pinned_reference(f"registry.example:5000/app:1.2.3@{digest}"), f"registry.example:5000/app@{digest}"
        )
        with self.assertRaises(inputs.InputError):
            inputs.pinned_reference("registry.example/app:latest")

    def test_missing_manifest_is_not_retried(self) -> None:
        result = SimpleNamespace(returncode=1, stderr=b"manifest unknown", stdout=b"")
        with (
            patch.object(inputs.subprocess, "run", return_value=result) as run,
            patch.object(inputs.time, "sleep") as sleep,
            self.assertRaisesRegex(inputs.InputError, "manifest unknown"),
        ):
            inputs._inspect("registry.example/app@sha256:" + "a" * 64)
        run.assert_called_once()
        sleep.assert_not_called()

    def test_transient_failure_has_a_bounded_retry_budget(self) -> None:
        failed = SimpleNamespace(returncode=1, stderr=b"HTTP 503 Service Unavailable", stdout=b"")
        good = SimpleNamespace(returncode=0, stderr=b"", stdout=b"{}")
        with (
            patch.object(inputs.subprocess, "run", side_effect=[failed, good]) as run,
            patch.object(inputs.time, "sleep") as sleep,
        ):
            self.assertEqual(inputs._inspect("registry.example/image"), b"{}")
            self.assertEqual(run.call_count, 2)
            sleep.assert_called_once_with(2)
        with (
            patch.object(inputs.subprocess, "run", side_effect=subprocess.TimeoutExpired("skopeo", 30)) as run,
            patch.object(inputs.time, "sleep"),
            self.assertRaises(inputs.InputError),
        ):
            inputs._inspect("registry.example/image")
        self.assertEqual(run.call_count, inputs.ATTEMPTS)

    def test_registry_failure_is_reported_with_its_consumers(self) -> None:
        with patch.object(inputs, "_inspect", side_effect=inputs.InputError("manifest unknown")):
            report = inputs.check_input(image_input(index_bytes()))
        self.assertEqual(report["sources"], ["fixture.yaml"])
        self.assertEqual(report["status"], "failed")


class InputSelectionTests(unittest.TestCase):
    def test_shared_inputs_are_deduplicated_across_the_full_catalogue(self) -> None:
        options = engine.PlanOptions("workflow_dispatch", "main", "main", None, "a" * 40, None)
        plan = engine._build_plan(engine._load_images(), options)
        collected = inputs.collect_inputs(engine._repo_root(), plan)
        self.assertEqual(len({item.reference for item in collected}), len(collected))
        self.assertLess(len(collected), len(plan["images"]))
        self.assertTrue(any(len(item.sources) >= MIN_SHARED_CONSUMERS for item in collected))

    def test_only_selected_inputs_are_checked_and_failures_fail_the_report(self) -> None:
        raw = index_bytes()
        fixture = image_input(raw)
        plan = {"images": [], "smokeBuildMatrix": {"include": []}, "payloadMatrix": {"include": []}}
        with patch.object(inputs, "_inspect") as inspect:
            self.assertTrue(inputs.preflight(Path.cwd(), plan)["passed"])
            inspect.assert_not_called()
        with (
            patch.object(inputs, "collect_inputs", return_value=[fixture]),
            patch.object(inputs, "_inspect", side_effect=inputs.InputError("manifest unknown")),
        ):
            report = inputs.preflight(Path.cwd(), plan)
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["checks"]), 1)

    def test_workflows_preflight_before_scheduling_builds_and_keep_failure_artifacts(self) -> None:
        for path in (".github/workflows/ci.yml", ".github/workflows/publish-images.yml"):
            jobs = yaml.safe_load(Path(path).read_text())["jobs"]
            steps = jobs["plan"]["steps"]
            preflight = next(
                i for i, step in enumerate(steps) if step.get("uses") == "./.github/actions/preflight-images"
            )
            upload = next(i for i, step in enumerate(steps) if step.get("name") == "Upload build plan")
            with self.subTest(path=path):
                self.assertLess(preflight, upload)
                self.assertIn("has_builds", steps[preflight]["if"])
                self.assertEqual(steps[preflight].get("continue-on-error", False), path.endswith("publish-images.yml"))
                self.assertIn("always()", steps[upload]["if"])
                self.assertIn("image-inputs.json", steps[upload]["with"]["path"])
