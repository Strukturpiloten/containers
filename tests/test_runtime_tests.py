"""Regression tests for runtime command boundaries."""

from __future__ import annotations

import argparse
import json
import subprocess
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

    def test_run_rejects_caller_ownership_overrides(self) -> None:
        context = RuntimeContext.__new__(RuntimeContext)
        context.image_ref = "localhost/test:runtime"
        context.command = MagicMock()
        for option in ("--name=other", "--cidfile=other", "--rmi"):
            with self.subTest(option=option), self.assertRaises(ProbeError):
                context.podman("probe", "run", option, context.image_ref)
        context.command.assert_not_called()

    def test_interrupted_run_tracks_exact_id_or_name_for_cleanup(self) -> None:
        for interruption in ("timeout", "cancel"):
            for write_cidfile in (True, False):
                with (
                    self.subTest(interruption=interruption, write_cidfile=write_cidfile),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    context = RuntimeContext.__new__(RuntimeContext)
                    context.directory = Path(directory)
                    context._podman = ["podman"]
                    context._sudo = []
                    context.timeout = 5
                    context.image_ref = "localhost/test:runtime"
                    context.containers = []
                    context.run_containers = set()
                    context.checks = []
                    context._owned_mounts = MagicMock(return_value=[])
                    container = "a" * 64
                    commands: list[list[str]] = []

                    def run(
                        command: list[str],
                        *,
                        commands: list[list[str]] = commands,
                        container: str = container,
                        interruption: str = interruption,
                        write_cidfile: bool = write_cidfile,
                        **_kwargs: object,
                    ) -> subprocess.CompletedProcess[str]:
                        commands.append(command)
                        if command[1] == "run":
                            if write_cidfile:
                                Path(command[command.index("--cidfile") + 1]).write_text(container + "\n")
                            if interruption == "timeout":
                                raise subprocess.TimeoutExpired(command, 5)
                            raise KeyboardInterrupt
                        return subprocess.CompletedProcess(command, 0, "", "")

                    with patch("scripts.runtime_tests.subprocess.run", side_effect=run):
                        if interruption == "timeout":
                            with self.assertRaisesRegex(ProbeError, "timed out"):
                                context.podman("interrupted probe", "run", "--rm", context.image_ref)
                        else:
                            with self.assertRaises(KeyboardInterrupt):
                                context.podman("interrupted probe", "run", "--rm", context.image_ref)
                        tracked = context.containers[0]
                        self.assertEqual(tracked, container if write_cidfile else commands[0][3])
                        self.assertEqual(context.run_containers, {tracked})
                        with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                            context.cleanup()
                            remove.assert_called_once_with(context.directory)
                    self.assertNotIn("--rm", commands[0][2 : commands[0].index(context.image_ref)])
                    self.assertIn(["podman", "rm", "--force", "--volumes", "--time", "2", tracked], commands)

    def test_normal_one_shot_cleanup_keeps_evidence_passing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory) / "store"
            context.directory.mkdir()
            context._podman = ["podman"]
            context._sudo = []
            context.timeout = 5
            context.image_ref = "localhost/test:runtime"
            context.containers = []
            context.run_containers = set()
            context.checks = []
            context._owned_mounts = MagicMock(return_value=[])
            context.load_archive = MagicMock(return_value={})
            container = "b" * 64
            commands: list[list[str]] = []

            def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                if command[1] == "run":
                    Path(command[command.index("--cidfile") + 1]).write_text(container + "\n")
                    return subprocess.CompletedProcess(command, 0, "ok", "")
                if command[1] == "inspect":
                    return subprocess.CompletedProcess(command, 0, "false", "")
                return subprocess.CompletedProcess(command, 0, "", "")

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
                patch("scripts.runtime_tests.subprocess.run", side_effect=run),
                patch("scripts.runtime_tests.RuntimeContext", return_value=context),
                patch(
                    "scripts.runtime_tests._podman",
                    side_effect=lambda ctx, *_args, **_kwargs: ctx.run("one-shot probe", "sh", "-c", "true", "--rm"),
                ),
            ):
                evidence = runtime_tests.run(args)
            self.assertEqual(evidence["status"], "passed")
            self.assertTrue(all(check["status"] == "passed" for check in evidence["checks"]))
            self.assertEqual(json.loads(evidence_path.read_text())["status"], "passed")
            outer_run = next(command for command in commands if command[1] == "run")
            self.assertNotIn("--rm", outer_run[2 : outer_run.index(context.image_ref)])
            self.assertEqual(outer_run[-1], "--rm")
            self.assertIn(["podman", "rm", "--force", "--volumes", "--time", "2", container], commands)

    def test_successful_run_requires_valid_cidfile(self) -> None:
        for cidfile_contents in (None, "not-an-id"):
            with self.subTest(cidfile_contents=cidfile_contents), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.__new__(RuntimeContext)
                context.directory = Path(directory)
                context._podman = ["podman"]
                context.timeout = 5
                context.image_ref = "localhost/test:runtime"
                context.containers = []
                context.run_containers = set()
                context.checks = []

                def run(
                    command: list[str], *, cidfile_contents: str | None = cidfile_contents, **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    if cidfile_contents is not None:
                        Path(command[command.index("--cidfile") + 1]).write_text(cidfile_contents)
                    return subprocess.CompletedProcess(command, 0, "", "")

                with (
                    patch("scripts.runtime_tests.subprocess.run", side_effect=run),
                    self.assertRaisesRegex(ProbeError, "invalid Podman cidfile|without cidfile"),
                ):
                    context.podman("one-shot probe", "run", "--rm", context.image_ref)
                self.assertEqual(len(context.containers), 1)
                self.assertEqual(context.run_containers, set(context.containers))

    def test_exact_run_absence_is_recorded_as_passed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = ["strukturpiloten-runtime-missing"]
            context.run_containers = set(context.containers)
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []
            context._owned_mounts = MagicMock(return_value=[])

            def podman(name: str, *_args: str, **_kwargs: object) -> str:
                context.checks.append({"name": name, "status": "failed", "exitCode": 1, "stderr": "not found"})
                return ""

            context.podman = podman
            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                context.cleanup()
                remove.assert_called_once_with(context.directory)
            self.assertEqual(context.checks[0]["status"], "passed")
            self.assertEqual(context.checks[0]["exitCode"], 1)
            self.assertEqual(context.checks[0]["expectedExitCode"], 1)
            self.assertEqual(context.checks[0]["stderr"], "not found")

    def test_uncertain_run_existence_preserves_isolated_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = ["c" * 64]
            context.run_containers = {"c" * 64}
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []

            def podman(name: str, *_args: str, **_kwargs: object) -> str:
                context.checks.append({"name": name, "status": "failed", "exitCode": 125})
                return ""

            context.podman = podman
            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                with self.assertRaisesRegex(ProbeError, "preserving isolated store"):
                    context.cleanup()
                remove.assert_not_called()
            self.assertTrue(context.directory.exists())

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

    def test_untracked_stopped_container_preserves_isolated_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = []
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []
            context._owned_mounts = MagicMock(return_value=[])
            context.podman = MagicMock(
                side_effect=lambda name, *_args, **_kwargs: "stopped-id" if name == "audit isolated containers" else ""
            )

            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                with self.assertRaisesRegex(ProbeError, "remaining containers"):
                    context.cleanup()
                remove.assert_not_called()
            context.podman.assert_any_call("audit isolated containers", "ps", "--all", "--quiet", timeout=10)
            self.assertTrue(context.directory.exists())

    def test_clean_isolated_store_is_removed_after_container_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.__new__(RuntimeContext)
            context.directory = Path(directory)
            context.containers = []
            context.checks = []
            context.image_ref = "localhost/test:runtime"
            context._sudo = []
            context._owned_mounts = MagicMock(return_value=[])
            context.podman = MagicMock(return_value="")

            with patch("scripts.runtime_tests.shutil.rmtree") as remove:
                context.cleanup()
                remove.assert_called_once_with(context.directory)
            context.podman.assert_any_call("audit isolated containers", "ps", "--all", "--quiet", timeout=10)
            self.assertEqual(context.checks[-1], {"name": "cleanup isolated store", "status": "passed"})

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
