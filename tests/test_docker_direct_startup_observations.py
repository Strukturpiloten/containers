"""Earliest native status, exact existing classifiers and original startup clock."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_active as control
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_observations as observations
from scripts import docker_userns_active as active
from scripts import runtime_docker_diagnostics as diagnostics

EPERM = b"[rootlesskit:parent] error: failed to start the child: fork/exec /proc/self/exe: operation not permitted\n"


def port() -> SimpleNamespace:
    """Keep immutable original incarnation separate from mutable readiness results."""
    return SimpleNamespace(
        work_until=300_000_000_000,
        commit=Mock(),
        docker=Mock(return_value=EPERM),
        docker_logs=Mock(return_value=EPERM),
        modules=SimpleNamespace(capture=diagnostics),
        record={
            "directGate": {"released": True},
            "directExecutables": {"engineVersion": "26.1.4"},
            "directReleaseNs": 1_000_000_000,
            "subject": {"pid": 123, "startedAt": "original"},
        },
    )


def api(now: int = 2_000_000_000) -> SimpleNamespace:
    """Use fixed closed checks and a test-local monotonic observation clock."""
    return SimpleNamespace(require=active.require, digest=active.digest, time=SimpleNamespace(monotonic_ns=lambda: now))


class OriginalFailureControls(unittest.TestCase):
    def test_existing_classifier_keeps_exact_nonzero_negative_and_warning_is_not_attribution(self) -> None:
        owned = port()
        owned.docker_logs.return_value = b"rootfs propagation warning /PRIVATE_PATH\n" + EPERM
        result = observations._negative(owned, api(), "a" * 64, 7)
        self.assertEqual(result["kind"], "rootlesskit-child-start-eperm")
        self.assertEqual(result["nativeExitCode"], 7)
        self.assertEqual(result["unclassifiedRecords"], 1)
        self.assertNotIn("PRIVATE_PATH", json.dumps(result))
        self.assertNotIn("kernelAttribution", result)
        self.assertEqual(owned.work_until, 7_000_000_000)

    def test_other_errno_unknown_line_or_zero_exit_is_not_expected_a(self) -> None:
        for raw, code in (
            (EPERM.replace(b"operation not permitted", b"permission denied"), 1),
            (b"[rootlesskit:parent] error: PRIVATE_UNKNOWN\n", 1),
            (EPERM, 0),
        ):
            owned = port()
            owned.docker_logs.return_value = raw
            with self.subTest(raw=raw, code=code):
                result = observations._negative(owned, api(), "a" * 64, code)
                self.assertEqual(result["kind"], "other-failure")
                self.assertEqual(result["nativeExitCode"], code)

    def test_truncation_record_overflow_or_query_failure_preserves_original_status(self) -> None:
        for raw in (
            b"x" * (contract.JOURNAL_BYTES + 1),
            b"x\n" * (contract.JOURNAL_RECORDS + 1),
            b"x" * (contract.RECORD_BYTES + 1),
        ):
            owned = port()
            owned.docker_logs.return_value = raw
            with self.subTest(size=len(raw)):
                result = observations._negative(owned, api(), "a" * 64, 137)
                self.assertEqual(result["kind"], "unknown")
                self.assertIn("diagnosticFailure", result)
            self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 137)
        owned = port()
        owned.docker_logs.side_effect = active.RefusedError
        result = observations._negative(owned, api(), "a" * 64, 1)
        self.assertEqual(result["diagnosticFailure"], "logs-unavailable")
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 1)


class StartupRaceControls(unittest.TestCase):
    def test_stopped_original_task_is_observed_before_any_api_or_postexec_query(self) -> None:
        owned = port()
        state = {"State": {"Pid": 0, "Running": False, "StartedAt": "original", "ExitCode": 1}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness") as readiness,
        ):
            observations.observe(owned, api(), "a" * 64)
        readiness.assert_not_called()
        self.assertEqual(owned.record["directStartup"]["kind"], contract.EXPECTED_A)
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 1)

    def test_fast_exit_during_exec_readiness_preserves_the_rootlesskit_error(self) -> None:
        owned = port()
        before = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        after = {"State": {"Pid": 0, "Running": False, "StartedAt": "original", "ExitCode": 7}}
        with (
            patch.object(control, "inspect_gate", side_effect=[before, after]),
            patch.object(observations, "_readiness", return_value="API_EXEC_UNAVAILABLE"),
        ):
            observations.observe(owned, api(), "a" * 64)
        self.assertEqual(owned.record["directStartup"]["kind"], contract.EXPECTED_A)
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 7)

    def test_ready_running_task_never_invents_zero_native_exit_and_needs_postexec_proof(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness", return_value="26.1.4"),
            patch.object(observations, "_post_exec") as proof,
        ):
            observations.observe(owned, api(), "a" * 64)
        self.assertEqual(owned.record["directStartup"]["kind"], "ready")
        self.assertIsNone(owned.record["directStartup"]["nativeExitCode"])
        proof.assert_called_once()

    def test_original45second_release_deadline_is_not_renewed_and_terminal_observation_is_one_shot(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness") as readiness,
        ):
            observations.observe(owned, api(46_000_000_000), "a" * 64)
        readiness.assert_not_called()
        self.assertEqual(owned.record["directStartup"]["kind"], "other-failure")
        self.assertTrue(owned.record["directObservationTerminal"])
        with self.assertRaises(active.RefusedError):
            observations.observe(owned, api(47_000_000_000), "a" * 64)

    def test_replacement_incarnation_is_not_an_original_startup_result(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "replacement", "ExitCode": 0}}
        with patch.object(control, "inspect_gate", return_value=state), self.assertRaises(active.RefusedError):
            observations.observe(owned, api(), "a" * 64)
        self.assertNotIn("directStartup", owned.record)


if __name__ == "__main__":
    unittest.main()


class ExecutablePreflightControls(unittest.TestCase):
    def test_actual_bounded_file_hash_refuses_modes_caps_and_in_read_source_replacement(self) -> None:
        original_fstat, original_stat = os.fstat, os.stat
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )

        def rooted(value: os.stat_result) -> SimpleNamespace:
            result = {name: getattr(value, name) for name in fields}
            result["st_uid"] = 0
            return SimpleNamespace(**result)

        for fault in (None, "writable", "suid", "capabilities", "replaced"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                image = base / "image"
                binary = image / "usr/local/bin/rootlesskit"
                binary.parent.mkdir(parents=True)
                body = b"original fixed executable bytes"
                binary.write_bytes(body)
                binary.chmod(0o755)
                process = base / "held-proc"
                process.mkdir()
                (process / "root").symlink_to(image, target_is_directory=True)
                if fault == "writable":
                    binary.chmod(0o777)
                if fault == "suid":
                    binary.chmod(0o4755)
                query = api()
                query.mark = active.mark
                query.check = Mock()
                if fault == "replaced":

                    def replace(_deadline: int, *, binary: Path = binary, body: bytes = body) -> None:
                        alternate = binary.with_name("replacement")
                        alternate.write_bytes(body)
                        alternate.chmod(0o755)
                        alternate.replace(binary)

                    query.check.side_effect = replace
                directory = os.open(process, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with (
                        patch.object(observations.os, "fstat", side_effect=lambda fd: rooted(original_fstat(fd))),
                        patch.object(
                            observations.os,
                            "stat",
                            side_effect=lambda *args, **kwargs: rooted(original_stat(*args, **kwargs)),
                        ),
                        patch.object(
                            observations.os,
                            "getxattr",
                            return_value=b"file-capability" if fault == "capabilities" else None,
                            side_effect=None if fault == "capabilities" else OSError(errno.ENODATA, "absent"),
                        ),
                    ):
                        if fault:
                            with self.assertRaises(active.RefusedError):
                                observations._image_file(
                                    port(), query, directory, ("usr", "local", "bin", "rootlesskit"), 4096
                                )
                        else:
                            head, digest = observations._image_file(
                                port(), query, directory, ("usr", "local", "bin", "rootlesskit"), 4096
                            )
                            self.assertEqual(head, body)
                            self.assertEqual(digest, hashlib.sha256(body).hexdigest())
                finally:
                    os.close(directory)

    def test_preflight_requires_actual_native_elf_version_and_original_incarnation_before_release(self) -> None:
        for fault in (None, "architecture", "version", "actor", "exited"):
            with self.subTest(fault=fault):
                owned = port()
                owned.binding = SimpleNamespace(architecture="amd64")
                owned.record["subject"].update(container="a" * 64, startTicks=99, cgroup="exact-scope")
                owned.record["directGate"]["releaseIntent"] = False
                owned.record.pop("directExecutables")
                owned.docker.return_value = (
                    b"rootlesskit version 1.2.3\n" if fault != "version" else b"PRIVATE_UNREVIEWED_PROVIDER"
                )
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                header[18:20] = (183 if fault == "architecture" else 62).to_bytes(2, "little")
                files = [(b"#!/bin/sh\n", "a" * 64), (bytes(header), "b" * 64), (b"4.5.6\n", "c" * 64)]
                task = {"startTicks": 99, "cgroup": "exact-scope"}
                changed = {**task, "startTicks": 100} if fault == "actor" else task
                state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original"}}
                with (
                    patch.object(control, "inspect_gate", return_value=state),
                    patch.object(control, "actor_snapshot", side_effect=[(task, {}), (changed, {})]),
                    patch.object(observations, "_image_file", side_effect=files),
                    patch.object(observations.os, "open", return_value=11),
                    patch.object(observations.os, "pidfd_open", return_value=12, create=True),
                    patch.object(observations.os, "close"),
                    patch.object(
                        observations.select,
                        "select",
                        return_value=([12], [], []) if fault == "exited" else ([], [], []),
                    ),
                ):
                    if fault:
                        with self.assertRaises(active.RefusedError):
                            observations.preflight(owned, api(), "a" * 64)
                        self.assertNotIn("directExecutables", owned.record)
                    else:
                        observations.preflight(owned, api(), "a" * 64)
                        self.assertEqual(owned.record["directExecutables"]["rootlesskitVersion"], "1.2.3")
                        self.assertEqual(owned.record["directExecutables"]["engineVersion"], "4.5.6")
                    self.assertTrue(owned.record["directPreflightIntent"])
                    with self.assertRaises(active.RefusedError):
                        observations.preflight(owned, api(), "a" * 64)
