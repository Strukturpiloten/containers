"""Exercise runtime module-entrypoint failures without launching native workloads."""

from __future__ import annotations

import argparse
import io
import json
import runpy
import signal
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from scripts import runtime_docker, runtime_docker_systemd, runtime_resource_budgets, runtime_tests
from scripts.runtime_errors import ProbeError

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "images/docker/docker-29-conformance-rootless/container.yaml"
CONTAINERS = ["a" * 64, "b" * 64]
_READ_TEXT = Path.read_text


def _fixture_text(path: Path, *, encoding: str | None = None) -> str:
    if path == Path("/proc/self/mountinfo"):
        return ""
    return _READ_TEXT(path, encoding=encoding)


def _failed_workload(ctx: runtime_tests.RuntimeContext, *_args: object, **_kwargs: object) -> None:
    ctx.containers.extend(CONTAINERS)
    ctx.container_launchers.update(dict.fromkeys(CONTAINERS, "systemd"))
    primary = ProbeError("original native startup failure")
    shutdown = ProbeError("workload shutdown failure")
    try:
        raise primary
    except ProbeError as error:
        raise shutdown from error


def _podman_command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
    output = ""
    if "images" in args:
        output = "sha256:fixture"
    elif "{{.Architecture}}" in args:
        output = "amd64"
    elif "--version" in args:
        output = "podman fixture"
    elif "{{.State.Running}}" in args:
        output = "false"
    elif "{{.Id}}" in args:
        output = args[-1]
    elif "{{json .State}}" in args:
        output = json.dumps(
            {
                "Running": False,
                "Status": "exited",
                "ExitCode": 137,
                "OOMKilled": True,
                "Error": "fixture OCI error",
                "Pid": 0,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
            }
        )
    return subprocess.CompletedProcess(args, 0, output, "")


class RuntimeEntrypointTests(unittest.TestCase):
    def test_module_entrypoint_keeps_helper_failures_and_completes_owned_cleanup(self) -> None:
        original_sigterm = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, original_sigterm)
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "owned-store"
            store.mkdir()
            evidence_path = Path(directory) / "evidence.json"
            argv = [
                "scripts.runtime_tests",
                "--metadata",
                str(METADATA),
                "--archive",
                str(Path(directory) / "fixture.tar"),
                "--arch",
                "amd64",
                "--evidence",
                str(evidence_path),
                "--no-sudo",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
                patch("tempfile.mkdtemp", return_value=str(store)),
                patch.object(Path, "read_text", autospec=True, side_effect=_fixture_text) as read_text,
                patch("subprocess.run", side_effect=_podman_command) as command,
                patch("scripts.oci_artifacts.archive_identity", return_value={"configDigest": "sha256:fixture"}),
                patch("scripts.runtime_docker.run_docker", side_effect=_failed_workload) as workload,
                warnings.catch_warnings(),
            ):
                # Other tests import the canonical module; -m still executes a
                # fresh __main__ namespace, precisely the former identity bug.
                warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*scripts.runtime_tests.*")
                with self.assertRaises(SystemExit) as result:
                    runpy.run_module("scripts.runtime_tests", run_name="__main__")
            self.assertEqual(result.exception.code, 1)
            workload.assert_called_once()
            self.assertEqual(read_text.call_args_list.count(call(Path("/proc/self/mountinfo"), encoding="utf-8")), 2)
            entry_error = type(workload.call_args.args[0]).command.__globals__["ProbeError"]
            for helper in (runtime_docker, runtime_docker_systemd, runtime_resource_budgets, runtime_tests):
                self.assertIs(entry_error, helper.ProbeError)
            self.assertFalse(store.exists())
            evidence = json.loads(evidence_path.read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("workload shutdown failure", evidence["error"])
            self.assertIn("original native startup failure", evidence["errorTraceback"])
            self.assertIn("workload shutdown failure", evidence["errorTraceback"])
            self.assertIn("systemd shutdown was abnormal", evidence["cleanupError"])
            failures = [check for check in evidence["checks"] if check["name"] == "cleanup owned systemd shutdown"]
            self.assertEqual([check["container"] for check in failures], list(reversed(CONTAINERS)))
            for failure in failures:
                self.assertEqual(failure["status"], "failed")
                self.assertIn("stop without OOM or OCI error and exit exactly zero", failure["errorTraceback"])
            states = [check for check in evidence["checks"] if check["name"] == "owned systemd orderly lifecycle state"]
            self.assertEqual(len(states), 2)
            self.assertTrue(all(check["status"] == "failed" and check["actual"]["OOMKilled"] for check in states))
            commands = [item.args[0] for item in command.call_args_list]
            for container in CONTAINERS:
                self.assertTrue(
                    any(args[-6:] == ["rm", "--force", "--volumes", "--time", "2", container] for args in commands)
                )
            self.assertTrue(any(args[-2:] == ["unmount", "--all"] for args in commands))
            self.assertTrue(any(args[-3:] == ["ps", "--all", "--quiet"] for args in commands))
            self.assertEqual(evidence["checks"][-1], {"name": "cleanup isolated store", "status": "passed"})

    def test_unexpected_cleanup_exception_still_persists_primary_and_cleanup_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            context = MagicMock()
            context.checks = []
            context.observations = []
            context.load_archive.return_value = {}
            context.podman.return_value = "podman fixture"
            context.cleanup.side_effect = ValueError("unexpected cleanup failure")
            args = argparse.Namespace(
                metadata=str(METADATA),
                archive=str(Path(directory) / "fixture.tar"),
                arch="amd64",
                evidence=str(evidence_path),
                sudo=False,
                no_sudo=True,
                timeout=5,
                allow_privileged=False,
                skip_nested=False,
            )
            original_sigterm = signal.getsignal(signal.SIGTERM)
            with (
                patch("scripts.runtime_tests.RuntimeContext", return_value=context),
                patch("scripts.runtime_tests._docker", side_effect=ProbeError("primary failure")),
            ):
                evidence = runtime_tests.run(args)
            self.assertEqual(signal.getsignal(signal.SIGTERM), original_sigterm)
            self.assertEqual(json.loads(evidence_path.read_text()), evidence)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("primary failure", evidence["error"])
            self.assertIn("primary failure", evidence["errorTraceback"])
            self.assertIn("unexpected cleanup failure", evidence["cleanupError"])
            self.assertIn("unexpected cleanup failure", evidence["cleanupErrorTraceback"])


if __name__ == "__main__":
    unittest.main()
