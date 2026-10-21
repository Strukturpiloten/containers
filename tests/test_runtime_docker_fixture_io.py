"""Private binary fixture handoff controls using only benign child processes."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts.runtime_docker import _run_nested_docker
from scripts.runtime_docker_backend import DockerBackend
from scripts.runtime_tests import ProbeError, RuntimeContext

PAYLOAD = b"private-synthetic-fixture\x00\xff\xfe\n"
CONTAINER = "a" * 64


class DockerFixtureIO(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="fixture-io-controls-")
        self.addCleanup(directory.cleanup)
        self.ctx = RuntimeContext.__new__(RuntimeContext)
        self.ctx.directory = Path(directory.name)
        self.ctx._fixture_archives = {}
        self.ctx.timeout = 5
        self.ctx.checks = []
        self.ctx.containers = [CONTAINER]
        self.ctx.run_containers = set()
        self.ctx.backend = object()
        self.ctx._podman = ["fixture-client"]
        self.ctx.image_ref = "localhost/fixture:owned"
        self.ctx.name = "docker-debian-11-rootless"

    def test_real_binary_export_and_import_reuse_parent_owned_private_inode_without_public_bytes(self) -> None:
        results = []
        calls = []
        real_run = subprocess.run

        def run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
            calls.append(options)
            result = real_run(command, **options)
            results.append(result)
            return result

        with self.ctx.private_fixture_archive() as archive:
            descriptor = archive.fileno()
            before = os.fstat(descriptor)
            self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
            self.assertEqual(before.st_uid, os.geteuid())
            self.assertTrue(stat.S_ISREG(before.st_mode))
            with patch("scripts.runtime_tests.subprocess.run", side_effect=run):
                output = self.ctx.command(
                    "export synthetic binary fixture",
                    [sys.executable, "-c", f"import os;os.write(1,{PAYLOAD!r});os.write(2,{PAYLOAD!r})"],
                    stdout=archive,
                )
                self.assertEqual(output, "")
                self.assertFalse(archive.closed)
                archive.seek(0)
                output = self.ctx.command(
                    "import synthetic binary fixture",
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,sys;data=os.read(0,4096);os.write(1,data);os.write(2,data);"
                            f"sys.exit(data!={PAYLOAD!r})"
                        ),
                    ],
                    stdin=archive,
                )
            self.assertEqual(output, "")
            after = os.fstat(descriptor)
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(after.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
            self.assertEqual(calls[0]["stdout"], descriptor)
            self.assertEqual(calls[1]["stdin"], descriptor)
            for options, result in zip(calls, results, strict=True):
                self.assertNotIn("capture_output", options)
                self.assertIs(options["stderr"], subprocess.DEVNULL)
                self.assertIsNone(result.stdout)
                self.assertIsNone(result.stderr)
            archive.seek(0)
            self.assertEqual(archive.read(), PAYLOAD)
        self.assertTrue(archive.closed)
        self.assertFalse(self.ctx._fixture_archives)
        self.assertNotIn("private-synthetic-fixture", json.dumps(self.ctx.checks))
        self.assertTrue(all(check["status"] == "passed" for check in self.ctx.checks))

    def test_unregistered_closed_replaced_or_changed_metadata_handles_never_launch(self) -> None:
        with tempfile.TemporaryFile("w+b") as foreign, patch("scripts.runtime_tests.subprocess.run") as run:
            with self.assertRaisesRegex(ProbeError, "not an owned held descriptor"):
                self.ctx.command("foreign input", ["unreachable"], stdin=foreign)
            run.assert_not_called()
        with self.ctx.private_fixture_archive() as archive:
            original = os.fstat(archive.fileno())
            for change in ({"st_mode": stat.S_IFREG | 0o644}, {"st_uid": os.geteuid() + 1}, {"st_nlink": 2}):
                values = {
                    name: getattr(original, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink")
                } | change
                with (
                    self.subTest(change=change),
                    patch("scripts.runtime_tests.os.fstat", return_value=SimpleNamespace(**values)),
                    patch("scripts.runtime_tests.subprocess.run") as run,
                    self.assertRaisesRegex(ProbeError, "ownership changed"),
                ):
                    self.ctx.command("changed input", ["unreachable"], stdin=archive)
                run.assert_not_called()
            path = self.ctx.directory / "docker-native-fixture.tar"
            path.rename(self.ctx.directory / "held-original.tar")
            path.write_bytes(b"replacement")
            with (
                patch("scripts.runtime_tests.subprocess.run") as run,
                self.assertRaisesRegex(ProbeError, "ownership changed"),
            ):
                self.ctx.command("replaced input", ["unreachable"], stdin=archive)
            run.assert_not_called()
        with patch("scripts.runtime_tests.subprocess.run") as run, self.assertRaises(ProbeError):
            self.ctx.command("closed input", ["unreachable"], stdin=archive)
        run.assert_not_called()

    def test_interactive_import_requires_exact_held_id_and_rewound_nonempty_same_descriptor(self) -> None:
        with self.ctx.private_fixture_archive() as archive:
            archive.write(PAYLOAD)
            with self.assertRaisesRegex(ProbeError, "rewound"):
                self.ctx.load_fixture_archive("import", CONTAINER, archive)
            archive.seek(0)
            for identifier in ("owned-name", "b" * 64):
                with self.subTest(identifier=identifier), self.assertRaisesRegex(ProbeError, "exact held container ID"):
                    self.ctx.load_fixture_archive("import", identifier, archive)
            self.ctx.backend = DockerBackend(self.ctx.directory, ())
            self.ctx.backend._gnu_timeout_provider = ("/qualified/gnu-timeout", "9.7", "prefixed")
            with (
                patch.object(self.ctx.backend, "_tool", return_value="/usr/bin/docker"),
                patch.object(self.ctx, "command", return_value="") as command,
            ):
                self.ctx.load_fixture_archive("import", CONTAINER, archive)
            argv = command.call_args.args[1]
            self.assertEqual(argv[-5:], ["exec", "--interactive", CONTAINER, "docker", "load"])
            self.assertIn("unix://" + str(self.ctx.directory / "docker.sock"), argv)
            self.assertIs(command.call_args.kwargs["stdin"], archive)
            self.assertIsNone(command.call_args.kwargs["timeout"])

    def test_failed_save_never_seeks_imports_or_starts_and_closes_owned_descriptor(self) -> None:
        with (
            patch.object(self.ctx, "podman", side_effect=ProbeError("checked save failed")) as save,
            patch.object(self.ctx, "start") as start,
            patch.object(self.ctx, "load_fixture_archive") as load,
            self.assertRaisesRegex(ProbeError, "checked save failed"),
        ):
            _run_nested_docker(self.ctx, {"mode": "rootless", "outerPrivilege": "privileged"}, "1000", MagicMock())
        archive = save.call_args.kwargs["stdout"]
        self.assertTrue(archive.closed)
        self.assertNotIn("--output", save.call_args.args)
        self.assertEqual(save.call_args.kwargs["timeout"], 180)
        start.assert_not_called()
        load.assert_not_called()

    def test_checked_stream_failure_and_timeout_have_closed_errors_and_retain_handle_until_return(self) -> None:
        with self.ctx.private_fixture_archive() as archive:
            with self.assertRaisesRegex(ProbeError, "binary fixture stream command failed"):
                self.ctx.command(
                    "failed export",
                    [sys.executable, "-c", f"import os;os.write(2,{PAYLOAD!r});raise SystemExit(3)"],
                    stdout=archive,
                )
            self.assertFalse(archive.closed)
            with self.assertRaisesRegex(ProbeError, "timed out"):
                self.ctx.command(
                    "timed export", [sys.executable, "-c", "import time;time.sleep(1)"], timeout=0.02, stdout=archive
                )
            self.assertFalse(archive.closed)
            self.assertTrue(all(check["status"] == "failed" for check in self.ctx.checks))
        self.assertNotIn("private-synthetic-fixture", json.dumps(self.ctx.checks))

    def test_path_replacement_during_export_is_a_failed_check_not_a_successful_handoff(self) -> None:
        with self.ctx.private_fixture_archive() as archive:
            path = self.ctx.directory / "docker-native-fixture.tar"

            def replace(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
                path.rename(self.ctx.directory / "held-original.tar")
                path.write_bytes(b"replacement")
                return subprocess.CompletedProcess(["fixture"], 0, None, None)

            with (
                patch("scripts.runtime_tests.subprocess.run", side_effect=replace),
                self.assertRaisesRegex(ProbeError, "ownership changed during command"),
            ):
                self.ctx.command("replaced export", ["fixture"], stdout=archive)
            self.assertEqual(self.ctx.checks[-1]["status"], "failed")
            self.assertFalse(archive.closed)

    def test_nested_handoff_rewinds_same_descriptor_and_preserves_legacy_oom_and_mount_controls(self) -> None:
        streams = []
        stop_error = ProbeError("stop after checked stdin handoff")

        def native(name: str, *args: str, **options: object) -> str:
            if name == "save synthetic Docker fixture":
                archive = options["stdout"]
                streams.append(archive)
                os.write(archive.fileno(), PAYLOAD)
                self.assertNotIn("--output", args)
                self.assertEqual(options["timeout"], 180)
            elif name == "load synthetic nested image":
                archive = options["stdin"]
                self.assertIs(archive, streams[0])
                self.assertEqual(archive.tell(), 0)
                self.assertFalse(archive.closed)
                self.assertEqual(args, ("exec", "--interactive", CONTAINER, "docker", "load"))
                self.assertNotIn("timeout", options)
                raise stop_error
            return ""

        def checked(_ctx: RuntimeContext, _budget: object, name: str, *_args: str) -> str:
            return {"read legacy Docker outer OOM score": "0", "inspect inner daemon user": "1000"}.get(name, "20.10.5")

        metadata = json.dumps(
            {
                "Version": "20.10.5",
                "ApiVersion": "1.41",
                "MinAPIVersion": "1.12",
                "Driver": "vfs",
                "SecurityOptions": ["rootless"],
            }
        )
        with (
            patch.object(self.ctx, "podman", side_effect=native),
            patch.object(self.ctx, "start", return_value=CONTAINER) as start,
            patch("scripts.runtime_docker.verify_outer_container_limits"),
            patch("scripts.runtime_docker._checked_exec", side_effect=checked),
            patch("scripts.runtime_docker._docker", return_value=metadata),
            self.assertRaisesRegex(ProbeError, "stop after checked stdin handoff"),
        ):
            _run_nested_docker(self.ctx, {"mode": "rootless", "outerPrivilege": "privileged"}, "1000", MagicMock())
        self.assertTrue(streams[0].closed)
        options = start.call_args.kwargs["options"]
        self.assertEqual(options[options.index("--oom-score-adj") + 1], "0")
        self.assertIn("--privileged", options)
        self.assertIn(
            str(self.ctx.directory / "docker-native-fixture.tar") + ":/tmp/docker-native-fixture.tar:ro", options
        )
        score = next(check for check in self.ctx.checks if check["name"] == "legacy Docker outer OOM score")
        self.assertEqual(
            {key: score[key] for key in ("actual", "expected", "status")},
            {"actual": "0", "expected": "0", "status": "passed"},
        )

    def test_late_stream_completion_still_fails_original_deadline_and_refreshes_root_watchdog(self) -> None:
        self.ctx.backend = DockerBackend(self.ctx.directory, ())
        self.ctx.backend._gnu_timeout_provider = ("/qualified/gnu-timeout", "9.7", "prefixed")
        self.ctx.backend.deadline = 2000
        clock = [1000]

        def late(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            clock[0] = 2001
            return subprocess.CompletedProcess(["fixture"], 0, "private-synthetic-fixture", "private-synthetic-fixture")

        with (
            self.ctx.private_fixture_archive() as archive,
            patch("scripts.runtime_tests.time.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.ctx.backend, "rebudget_command", return_value=["bounded-fixture"]) as rebudget,
            patch("scripts.runtime_tests.subprocess.run", side_effect=late) as run,
            self.assertRaisesRegex(ProbeError, "completed after its original aggregate deadline"),
        ):
            self.ctx.command("late export", ["original-fixture"], timeout=180, stdout=archive)
        rebudget.assert_called_once_with(["original-fixture"], 180)
        self.assertEqual(run.call_args.args[0], ["bounded-fixture"])
        self.assertEqual(self.ctx.checks[-1]["status"], "failed")
        self.assertEqual(self.ctx.backend.deadline, 2000)
        self.assertNotIn("private-synthetic-fixture", json.dumps(self.ctx.checks))

    def test_default_text_output_errors_and_subprocess_options_are_unchanged(self) -> None:
        real_run = subprocess.run
        command = [sys.executable, "-c", "import sys;print('ok');print('detail',file=sys.stderr);sys.exit(3)"]
        with patch("scripts.runtime_tests.subprocess.run", wraps=real_run) as run:
            with self.assertRaisesRegex(ProbeError, "text: exit 3: detail"):
                self.ctx.command("text", command)
            self.assertEqual(self.ctx.command("text unchecked", command, check=False), "ok")
        self.assertEqual(run.call_args.kwargs, {"capture_output": True, "text": True, "check": False, "timeout": 5})
        self.assertEqual(self.ctx.checks[-1]["stdout"], "ok")
        self.assertEqual(self.ctx.checks[-1]["stderr"], "detail")


if __name__ == "__main__":
    unittest.main()
