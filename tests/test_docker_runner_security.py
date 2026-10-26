"""Read-only runner observations must remain bounded, private and non-admitting."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from scripts import docker_runner_security as collector

ROOT = Path(__file__).resolve().parents[1]


class RunnerSecurityTests(unittest.TestCase):
    def test_cli_writes_only_bounded_json_and_reports_output_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observation.json"
            with (
                patch.object(collector.sys, "argv", ["collector", "--output", str(output)]),
                patch.object(collector, "collect", return_value={"state": "unknown"}),
                patch.object(collector, "_cancelled", new=False),
                patch.object(collector.signal, "signal"),
                patch.object(collector.sys, "stderr", new_callable=io.StringIO) as errors,
            ):
                self.assertEqual(collector.main(), 0)
                self.assertEqual(json.loads(output.read_bytes()), {"state": "unknown"})
                self.assertEqual(collector.main(), 1)
                self.assertEqual(errors.getvalue(), "runner security observation unavailable\n")
                self.assertNotIn(str(output), errors.getvalue())
                output.unlink()
                with patch.object(collector, "collect", return_value={"value": "x" * collector.MAX_JSON}):
                    self.assertEqual(collector.main(), 1)
                self.assertFalse(output.exists())

    def test_closed_projection_omits_host_names_paths_uids_and_raw_profiles(self) -> None:
        values = {
            collector.ENABLED: b"Y",
            collector.RESTRICT: b"1",
            collector.USERNS: b"6192125",
            collector.STATUS: b"Name:\tprivate-host\nUid:\t192837\nSeccomp:\t2\nNoNewPrivs:\t0",
            collector.PROFILE: b"/private/profile-sentinel (enforce)",
        }
        kernel = SimpleNamespace(release="6.18.0-generic", machine="x86_64", nodename="hostname-sentinel")
        with (
            patch.object(collector, "_read", side_effect=lambda path: values[path]),
            patch.object(
                collector,
                "_parser",
                return_value={"state": "unknown", "reason": "unavailable", "version": None, "executable": None},
            ),
            patch.object(collector.os, "uname", return_value=kernel),
        ):
            result = collector.collect()
        self.assertEqual(
            set(result),
            {"schemaVersion", "scope", "qualification", "kernel", "apparmor", "userNamespaces", "collectorProcess"},
        )
        self.assertEqual(result["scope"], "ci-validate-host-only")
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(result["apparmor"]["enabled"], {"state": "observed", "value": True})
        self.assertEqual(
            result["collectorProcess"],
            {
                "subject": "collector-process-not-guest",
                "seccomp": {"state": "observed", "value": 2},
                "noNewPrivs": {"state": "observed", "value": 0},
                "profileKind": {"state": "observed", "value": "confined"},
            },
        )
        body = json.dumps(result)
        self.assertLessEqual(len(body.encode()), collector.MAX_JSON)
        for private in ("private-host", "192837", "hostname-sentinel", "profile-sentinel", "/proc/", "/sys/"):
            self.assertNotIn(private, body)

    def test_unavailable_or_malformed_controls_are_explicit_unknown(self) -> None:
        for raw in (b"-1", b"0x1", b"1\n2", b"18446744073709551616", b"private-value"):
            with self.subTest(raw=raw), patch.object(collector, "_read", return_value=raw):
                self.assertEqual(collector._number(collector.RESTRICT, 1), {"state": "unknown", "reason": "malformed"})
        with patch.object(collector, "_read", side_effect=FileNotFoundError("private-path")):
            self.assertEqual(
                collector._number(collector.USERNS, 2**63 - 1), {"state": "unknown", "reason": "unavailable"}
            )
            self.assertEqual(collector._process()["profileKind"]["state"], "unknown")
        with patch.object(collector, "_read", return_value=b"Seccomp:\t2\nSeccomp:\t0\nNoNewPrivs:\t3"):
            result = collector._process()
        self.assertEqual(result["seccomp"]["state"], "unknown")
        self.assertEqual(result["noNewPrivs"]["state"], "unknown")

    def test_bounded_read_refuses_overflow_and_symlink_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned-input"
            path.write_bytes(b"1\n")
            self.assertEqual(collector._read(path), b"1")
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                collector._read(link)
            path.write_bytes(b"x" * (collector.MAX_FILE + 1))
            with self.assertRaisesRegex(collector._ObservationError, "oversized"):
                collector._read(path)

    def test_optional_parser_requires_safe_existing_tool(self) -> None:
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_size=1024)
        self.assertTrue(collector._trusted_parser(info))
        for mode, uid, size in (
            (0o100777, 0, 1024),
            (0o104755, 0, 1024),
            (0o100755, 1000, 1024),
            (0o100755, 0, collector.MAX_BINARY + 1),
        ):
            with self.subTest(mode=mode, uid=uid, size=size):
                self.assertFalse(collector._trusted_parser(SimpleNamespace(st_mode=mode, st_uid=uid, st_size=size)))
        with patch.object(collector.os, "geteuid", return_value=0), patch.object(collector, "_version") as version:
            self.assertEqual(collector._parser(time.monotonic() + 4)["state"], "unknown")
            version.assert_not_called()

    def test_parser_version_snapshot_hashes_actual_bytes_and_rejects_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake-elf"
            data = b"\x7fELF" + b"inert fixture bytes"
            path.write_bytes(data)
            path.chmod(0o755)
            with (
                patch.object(collector, "PARSER", path),
                patch.object(collector.os, "geteuid", return_value=1000),
                patch.object(collector, "_trusted_parser", return_value=True),
                patch.object(collector, "_version", return_value="4.1.6"),
            ):
                result = collector._parser(time.monotonic() + 4)
                self.assertEqual(result["version"], "4.1.6")
                self.assertEqual(result["executable"]["sha256"], hashlib.sha256(data).hexdigest())
                self.assertNotIn("uid", result["executable"])

                def changed(_deadline: float) -> str:
                    path.write_bytes(data + b"changed")
                    return "4.1.6"

                with patch.object(collector, "_version", side_effect=changed):
                    self.assertEqual(collector._parser(time.monotonic() + 4)["reason"], "changed")

    def test_version_query_uses_only_fixed_flag_clean_environment_and_bounded_output(self) -> None:
        process = MagicMock()
        process.returncode = 0
        for version in ("2.13.0", "4.1.6", "5.0.0-beta1"):
            raw = f"AppArmor parser version {version}\n/private/never-published\n".encode()
            with (
                self.subTest(version=version),
                patch.object(collector.subprocess, "Popen", return_value=process) as start,
                patch.object(collector, "_capture", return_value=(raw, 0)),
            ):
                self.assertEqual(collector._version(time.monotonic() + 1), version)
                self.assertEqual(start.call_args.args[0], [str(collector.PARSER), "--version"])
                self.assertEqual(start.call_args.kwargs["env"], {"LC_ALL": "C"})
                self.assertEqual(start.call_args.kwargs["stdin"], collector.subprocess.DEVNULL)
        with (
            patch.object(collector.subprocess, "Popen", return_value=process),
            patch.object(collector, "_capture", return_value=(b"private version output", 0)),
            self.assertRaisesRegex(collector._ObservationError, "malformed"),
        ):
            collector._version(time.monotonic() + 1)
        read, write = os.pipe()
        with os.fdopen(read, "rb") as source:
            os.write(write, b"x" * (collector.MAX_OUTPUT + 1))
            os.close(write)
            process.stdout = source
            with self.assertRaisesRegex(collector._ObservationError, "oversized"):
                collector._capture(process, time.monotonic() + 1)

    def test_timeout_and_cancellation_cleanup_only_owned_version_process(self) -> None:
        process = MagicMock(pid=12345)
        process.returncode = None
        process.wait.return_value = 0
        with (
            patch.object(collector.subprocess, "Popen", return_value=process),
            patch.object(collector, "_capture", side_effect=collector._ObservationError("timeout")),
            patch.object(collector.os, "killpg") as kill,
            self.assertRaisesRegex(collector._ObservationError, "timeout"),
        ):
            collector._version(time.monotonic() + 1)
        kill.assert_called_once_with(process.pid, collector.signal.SIGKILL)
        process.wait.assert_called_once_with(timeout=0.5)
        process.stdout.close.assert_called_once()
        with (
            patch.object(collector, "_cancelled", new=True),
            self.assertRaisesRegex(collector._ObservationError, "cancelled"),
        ):
            collector._check(time.monotonic() + 1)


class RunnerSecurityWorkflowTests(unittest.TestCase):
    def test_capture_and_fixed_artifact_precede_unchanged_mandatory_checks(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        steps = workflow["jobs"]["validate"]["steps"]
        capture = next(step for step in steps if step["name"] == "Observe runner security cohort (read-only)")
        upload = next(step for step in steps if step["name"] == "Retain runner security observation")
        checks = next(step for step in steps if step["name"] == "Validate repository")
        self.assertLess(steps.index(capture), steps.index(upload))
        self.assertLess(steps.index(upload), steps.index(checks))
        self.assertNotIn("continue-on-error", capture)
        self.assertNotIn("continue-on-error", upload)
        self.assertEqual(upload["if"], "${{ always() }}")
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/docker-runner-security.json")
        self.assertEqual(workflow["jobs"]["validate"]["permissions"], {"contents": "read"})
        self.assertIn("unittest discover -s tests", checks["run"])
        self.assertIn("smoke-build", workflow["jobs"]["required-ci"]["needs"])

    def test_reused_artifact_pin_has_existing_template_and_generated_owners(self) -> None:
        config = json.loads((ROOT / ".github/renovate.json").read_text())
        manager = next(
            item
            for item in config["customManagers"]
            if item.get("description", "").startswith("Keep pinned action references")
        )
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        template = (ROOT / ".github/workflow-templates/ci.yml.j2").read_text()
        observed = [
            match.groupdict()
            for match in re.finditer(pattern, template)
            if match.group("depName") == "actions/upload-artifact"
        ]
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0], observed[1])
        self.assertRegex(observed[0]["currentDigest"], r"^[a-f0-9]{40}$")
        self.assertRegex(observed[0]["currentValue"], r"^v\d+\.\d+\.\d+$")
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        upload = next(
            step
            for step in workflow["jobs"]["validate"]["steps"]
            if step["name"] == "Retain runner security observation"
        )
        self.assertEqual(upload["uses"], "actions/upload-artifact@" + observed[0]["currentDigest"])
        self.assertIn("helpers:pinGitHubActionDigests", config["extends"])
        self.assertNotIn(".github/workflows/**", config["ignorePaths"])


if __name__ == "__main__":
    unittest.main()
