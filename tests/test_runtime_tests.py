"""Regression tests for runtime command boundaries."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_tests
from scripts.runtime_tests import ProbeError, RuntimeContext


class RuntimeCommandTests(unittest.TestCase):
    def test_image_precedes_guest_command_and_follows_podman_options(self) -> None:
        context = RuntimeContext.__new__(RuntimeContext)
        context.image_ref = "localhost/test:runtime"
        context.podman = MagicMock(return_value="ok")

        context.run("guest command", "sh", "-c", "id -u", options=("--privileged",))

        self.assertEqual(
            context.podman.call_args.args,
            (
                "guest command",
                "run",
                "--rm",
                "--security-opt",
                "label=disable",
                "--privileged",
                "localhost/test:runtime",
                "sh",
                "-c",
                "id -u",
            ),
        )

    def test_failed_container_removal_preserves_isolated_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = ["owned-id"]
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []

            def podman(name: str, *_args: str, **_kwargs: object) -> str:
                context.checks.append(
                    {"name": name, "status": "failed" if name == "cleanup owned container" else "passed"}
                )
                return ""

            context.podman = podman
            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                with self.assertRaisesRegex(ProbeError, "preserving isolated store"):
                    context.cleanup()
                remove.assert_not_called()
            self.assertTrue(context.directory.exists())

    def test_failed_unmount_preserves_isolated_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = []
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []
            context.podman = MagicMock(side_effect=ProbeError("unmount failed"))
            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                with self.assertRaisesRegex(ProbeError, "unmount failed"):
                    context.cleanup()
                remove.assert_not_called()
            self.assertTrue(context.directory.exists())

    def test_cleanup_failure_is_recorded_in_architecture_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = MagicMock()
            context.checks = []
            context.load_archive.return_value = {}
            context.podman.return_value = "podman fixture"
            context.cleanup.side_effect = ProbeError("isolated store retained")
            evidence_path = Path(directory) / "evidence.json"
            args = argparse.Namespace(
                metadata=str(
                    Path(runtime_tests.__file__).resolve().parents[1]
                    / "images/podman/podman-6.1-rootless/container.yaml"
                ),
                image_name=None,
                archive=str(Path(directory) / "image.tar"),
                image_ref=None,
                arch="amd64",
                evidence=str(evidence_path),
                sudo=False,
                no_sudo=True,
                allow_privileged=False,
                skip_nested=True,
                timeout=5,
            )
            with (
                patch("scripts.runtime_tests.RuntimeContext", return_value=context),
                patch("scripts.runtime_tests._podman"),
            ):
                evidence = runtime_tests.run(args)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("isolated store retained", evidence["cleanupError"])
            self.assertEqual(json.loads(evidence_path.read_text())["cleanupError"], evidence["cleanupError"])


if __name__ == "__main__":
    unittest.main()
