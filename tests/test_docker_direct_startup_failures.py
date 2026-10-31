"""Real inert log capture and evidence publication failure boundaries; no runtime calls."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_observations as observations
from scripts import docker_direct_startup_runtime as runtime
from scripts import docker_userns_active as active
from scripts import runtime_docker_diagnostics as diagnostics
from scripts import runtime_tests
from tests import test_docker_direct_startup_runtime as coordinator
from tests import test_runtime_oom_lifecycle as publication
from tests.test_docker_direct_startup_observations import EPERM, api


class ActualOwnedLogCapture(unittest.TestCase):
    def owned(self, program: str, *, seconds: float = 5) -> active.RootPort:
        """Replace command argv only; exercise the existing reader/group/watchdog."""
        owned = active.RootPort.__new__(active.RootPort)
        owned.work_until = time.monotonic_ns() + int(seconds * 1_000_000_000)
        owned.binding = SimpleNamespace(deadline_ns=owned.work_until)
        owned.cleanup = False
        owned.provider = "/usr/bin/timeout"
        owned.commit = Mock()
        owned.modules = SimpleNamespace(capture=diagnostics)
        owned.record = {"directExecutables": {"engineVersion": "26.1.4"}}
        owned.docker_arguments = Mock(return_value=[sys.executable, "-c", program])
        return owned

    def negative(self, program: str, code: int = 1, *, seconds: float = 5) -> tuple:
        owned = self.owned(program, seconds=seconds)
        result = observations._negative(owned, api(time.monotonic_ns()), "a" * 64, code)
        owned.docker_arguments.assert_called_once_with("logs", "--tail", "65", "a" * 64)
        return result, owned

    def test_stderr_only_native_fatal_survives_real_query_and_default_query_still_excludes_it(self) -> None:
        program = f"import os; os.write(2, {EPERM!r})"
        result, owned = self.negative(program, 7)
        self.assertEqual(result["kind"], contract.EXPECTED_A)
        self.assertEqual(result["nativeExitCode"], 7)
        self.assertFalse(owned.record["readerPending"])
        unrelated = self.owned(program)
        self.assertEqual(unrelated.query([sys.executable, "-c", program]), b"")

    def test_tail_sentinel_detects_original_overflow_including_hidden_older_fatal(self) -> None:
        older = b"[rootlesskit:parent] error: unexpected earlier fatal\n"
        for records in (63, 64, 65, 80):
            with self.subTest(records=records):
                # Model docker's requested tail while keeping all original records in the fake command.
                lines = ([older] if records > contract.JOURNAL_RECORDS + 1 else []) + [EPERM] * records
                program = f"import os; lines={lines!r}; os.write(2, b''.join(lines[-65:]))"
                result, _owned = self.negative(program)
                self.assertEqual(result["nativeExitCode"], 1)
                if records <= contract.JOURNAL_RECORDS:
                    self.assertEqual(result["kind"], contract.EXPECTED_A)
                    self.assertEqual(result["logRecords"], records)
                else:
                    self.assertEqual(result["kind"], "unknown")
                    self.assertEqual(result["diagnosticFailure"], "logs-record-limit")

    def test_actual_capture_overflow_timeout_and_nonzero_keep_original_native_exit(self) -> None:
        programs = (
            ("import os; os.write(2, b'x' * 70000)", 5),
            ("import time; time.sleep(2)", 0.5),
            ("import sys; sys.exit(3)", 5),
        )
        for code in (1, 137):
            for program, seconds in programs:
                with self.subTest(code=code, program=program):
                    result, owned = self.negative(program, code, seconds=seconds)
                    self.assertEqual(result["kind"], "unknown")
                    self.assertEqual(result["diagnosticFailure"], "logs-unavailable")
                    self.assertEqual(result["nativeExitCode"], code)
                    self.assertEqual(owned.record["directStartup"]["nativeExitCode"], code)
                    self.assertFalse(owned.record["readerPending"])

    def test_unaffirmed_reader_retains_liability_and_native_exit(self) -> None:
        owned = self.owned("pass")
        with patch.object(
            diagnostics, "capture_owned_logs", return_value={"status": "query-unavailable", "teardownVerified": False}
        ):
            result = observations._negative(owned, api(time.monotonic_ns()), "a" * 64, 137)
        self.assertEqual(result["nativeExitCode"], 137)
        self.assertEqual(result["diagnosticFailure"], "logs-unavailable")
        self.assertTrue(owned.record["readerPending"])
        self.assertTrue(owned.record["retained"])

    def work_with_startup(self, startup: dict) -> object:
        original_work = coordinator._work_stub

        def work(state: SimpleNamespace, plan: SimpleNamespace, ctx: object, result: runtime.ArmOutcome) -> None:
            original_work(state, plan, ctx, result)
            observed = coordinator.ActualStartupSequence()._case("A", startup)
            result.summary.update(observed.summary)
            result.failure = observed.failure

        return work

    def test_failed_optional_logs_export_native_code_and_incomplete_facts_without_b(self) -> None:
        for code in (1, 137):
            for pending in (False, True):
                with self.subTest(code=code, pending=pending):
                    owned = self.owned("import sys; sys.exit(3)")
                    if pending:
                        with patch.object(diagnostics, "capture_owned_logs", return_value={"teardownVerified": False}):
                            startup = observations._negative(owned, api(time.monotonic_ns()), "a" * 64, code)
                    else:
                        startup = observations._negative(owned, api(time.monotonic_ns()), "a" * 64, code)
                    with patch.object(coordinator, "_work_stub", side_effect=self.work_with_startup(startup)):
                        record, events, _published, _source = coordinator.PairControls().execute()
                    self.assertEqual(record["status"], "failed")
                    self.assertNotIn("allocate-B", events)
                    self.assertEqual(record["arms"][0]["nativeExitCode"], code)
                    self.assertFalse(record["arms"][0]["factsComplete"])
                    self.assertEqual(record["failures"][0]["reason"], "logs-unavailable")
                    self.assertEqual(owned.record["readerPending"], pending)
                    self.assertEqual(owned.record.get("retained", False), pending)

    def test_recorded_log_failure_precedes_a_later_work_exception(self) -> None:
        original_work = coordinator._work_stub

        def work(state: SimpleNamespace, plan: SimpleNamespace, ctx: object, result: runtime.ArmOutcome) -> None:
            original_work(state, plan, ctx, result)
            result.failure = {**runtime._local_failure(plan, cancelled=False), "reason": "logs-unavailable"}
            message = "later work failure"
            raise RuntimeError(message)

        with patch.object(coordinator, "_work_stub", side_effect=work):
            record, events, _published, _source = coordinator.PairControls().execute()
        self.assertEqual(record["status"], "failed")
        self.assertNotIn("allocate-B", events)
        self.assertEqual(
            [failure["reason"] for failure in record["failures"]], ["logs-unavailable", "operation-unverified"]
        )


class DirectPublicationFailures(unittest.TestCase):
    def evidence(self, *, host: bool) -> dict:
        value = {
            "consumer": contract.CONSUMER,
            "purpose": contract.PURPOSE,
            "qualification": "none",
            "schemaVersion": 1,
        }
        if host:
            value.update(scope="current-job-host-only-not-guest", facts={})
        else:
            value.update(status="diagnostic-complete", conclusion="instrumented-profile-dependent-startup", arms=[])
        return value

    def write(
        self, target: Path, value: dict, fault: str, *, fixture: publication._PairPublicationFault | None = None
    ) -> publication._PairPublicationFault:
        fixture = fixture or publication._PairPublicationFault(target, [1.0], fault)

        def bound_open(path: Path, *arguments: object, **keywords: object) -> object:
            return fixture.open(path, *arguments, **keywords)

        with (
            patch.object(Path, "open", new=bound_open),
            patch.object(runtime_tests.os, "link", side_effect=fixture.link),
            patch.object(runtime_tests.time, "monotonic", side_effect=lambda: fixture.clock[0]),
        ):
            runtime_tests._write_pair_evidence(target, value, 10.0)
        return fixture

    def failed(self, value: dict) -> None:
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["qualification"], "none")
        self.assertEqual(value["publicationFailure"], "evidence-publication-failed")
        self.assertNotIn("cleanupError", value)
        self.assertNotIn("cleanupErrorTraceback", value)

    def test_actual_direct_and_host_publication_failures_invalidate_owned_inode(self) -> None:
        faults = (
            "publication-deadline",
            "publication-error",
            "publication-before-error",
            "close-error",
            "close-deadline",
        )
        for host in (False, True):
            for fault in faults:
                with self.subTest(host=host, fault=fault), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "record.json"
                    value = self.evidence(host=host)
                    if fault.endswith("error"):
                        with self.assertRaises(OSError):
                            self.write(target, value, fault)
                    else:
                        self.write(target, value, fault)
                    self.failed(value)
                    private = next(Path(directory).glob(".runtime-evidence-*/record"))
                    self.failed(json.loads(private.read_text()))
                    if target.exists():
                        self.failed(json.loads(target.read_text()))

    def test_direct_and_host_never_call_systemd_finalizer_or_damage_replacement(self) -> None:
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "record.json"
                value = self.evidence(host=host)
                with patch.object(
                    runtime_tests, "_finish_pair_authority", side_effect=RuntimeError("PRIVATE")
                ) as finalizer:
                    self.write(target, value, "publication-replacement")
                finalizer.assert_not_called()
                self.assertEqual(target.read_bytes(), b"replacement sentinel\n")
                self.failed(json.loads(next(Path(directory).glob(".runtime-evidence-*/record")).read_text()))
                self.assertNotIn("PRIVATE", json.dumps(value))

    def test_throwing_legacy_finalizer_still_invalidates_published_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            value = {"status": "passed", "qualification": "complete", "phases": []}
            with patch.object(runtime_tests, "_finish_pair_authority", side_effect=RuntimeError("semantic failure")):
                self.write(target, value, "publication-deadline")
            self.assertEqual(json.loads(target.read_text())["status"], "failed")
            self.assertEqual(value["publicationFailure"], "authority-finalization-failed")

    def test_retirement_close_is_once_and_never_closes_reused_sentinel_descriptor(self) -> None:
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "record.json"
                sentinel = Path(directory) / "sentinel"
                sentinel.write_bytes(b"replacement sentinel\n")
                fixture = publication._PairRetirementFault(sentinel, "recovery-close")
                try:
                    with (
                        patch.object(runtime_tests.os, "close", side_effect=fixture.close),
                        self.assertRaisesRegex(runtime_tests.ProbeError, "retirement is uncertain"),
                    ):
                        self.write(target, self.evidence(host=host), "recovery-close")
                    self.assertEqual(len(fixture.retired), 1)
                    self.assertEqual(fixture.reused, fixture.retired)
                    self.assertEqual(os.read(fixture.reused[0], 100), b"replacement sentinel\n")
                    self.failed(json.loads(target.read_text()))
                finally:
                    for descriptor in fixture.reused:
                        fixture.real_close(descriptor)

    def test_data_close_error_never_retries_a_reused_descriptor(self) -> None:
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "record.json"
                sentinel = Path(directory) / "sentinel"
                sentinel.write_bytes(b"sentinel")
                fixture = publication._PairPublicationFault(target, [1.0], "close-reused")
                try:
                    with self.assertRaisesRegex(OSError, "after number reuse"):
                        self.write(target, self.evidence(host=host), fixture.fault, fixture=fixture)
                    self.assertEqual(fixture.retired_descriptor, fixture.reused_descriptor)
                    self.assertIsNotNone(fixture.reused_descriptor)
                    self.assertEqual(os.fstat(fixture.reused_descriptor).st_ino, sentinel.stat().st_ino)
                    self.assertFalse(target.exists())
                    self.failed(json.loads(next(Path(directory).glob(".runtime-evidence-*/record")).read_text()))
                finally:
                    if fixture.reused_descriptor is not None:
                        os.close(fixture.reused_descriptor)

    def test_short_failed_inode_write_leaves_no_parseable_success_and_retires_once(self) -> None:
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "record.json"
                fixture = publication._PairRetirementFault(Path(directory) / "sentinel", "recovery-write")
                with (
                    patch.object(runtime_tests.os, "write", side_effect=fixture.write),
                    patch.object(runtime_tests.os, "close", side_effect=fixture.close),
                    self.assertRaisesRegex(runtime_tests.ProbeError, "retirement is uncertain"),
                ):
                    self.write(target, self.evidence(host=host), fixture.fault)
                self.assertEqual(len(fixture.retired), 1)
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(target.read_text())

    def test_host_publisher_rejects_a_failed_return(self) -> None:
        def publish(_path: Path, value: dict, _deadline: float) -> None:
            value.update(status="failed", publicationFailure="evidence-publication-failed")

        plan = SimpleNamespace(
            metadata={"name": "docker-20.10-rootless"},
            architecture="amd64",
            provenance={"candidate": "a" * 40, "run": "1", "attempt": "1", "job": "job"},
            args=SimpleNamespace(evidence=str(Path(tempfile.gettempdir()) / "inert-direct-publication-record.json")),
            services=SimpleNamespace(publish=publish),
            clock=SimpleNamespace(deadline_ns=10),
        )
        with self.assertRaises(contract.DirectDiagnosticError):
            runtime._publish_host(plan, self.evidence(host=True), "before")
