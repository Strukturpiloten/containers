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


class ClosedSubjectFailureTransport(unittest.TestCase):
    def test_all_finite_phases_transport_without_raw_fields_or_authority(self) -> None:
        from scripts import docker_direct_startup_aggregate as aggregate  # noqa: PLC0415
        from scripts import docker_direct_startup_client as client  # noqa: PLC0415

        for phase in active.FAILURE_PHASES:
            with self.subTest(phase=phase):
                progress = {
                    "operation": "bind",
                    "record": {
                        "retained": True,
                        "diagnostic": {
                            "phase": phase,
                            "comparisons": {phase: False, "PRIVATE_PHASE": True},
                            "raw": "PRIVATE_DATA",
                        },
                    },
                }
                receipt = active.failure_receipt(progress, active.RefusedError("PRIVATE_DATA"))
                self.assertEqual(receipt["phase"], phase)
                self.assertEqual(receipt["comparisons"], {phase: False})
                self.assertTrue(active.valid_failure(receipt))
                self.assertNotIn("PRIVATE_", json.dumps(receipt))
                projected = client.project_failure(receipt, "B")
                self.assertEqual(aggregate.validate_failure(projected), projected)
                self.assertEqual(projected["qualification"], "none")
                self.assertFalse(projected["cleanupAuthority"])

    def test_unknown_malformed_and_extra_fields_stay_closed(self) -> None:
        for diagnostic in (
            {},
            {"phase": "PRIVATE_PHASE"},
            {"phase": []},
            {"comparisons": []},
            {"comparisons": {"subject-profile": "PRIVATE_DATA"}},
        ):
            with self.subTest(diagnostic=diagnostic):
                receipt = active.failure_receipt(
                    {"record": {"diagnostic": diagnostic}}, active.RefusedError("PRIVATE_DATA")
                )
                self.assertTrue(active.valid_failure(receipt))
                self.assertEqual(receipt["phase"], "unknown")
                self.assertEqual(receipt["comparisons"], {})
                self.assertNotIn("PRIVATE_", json.dumps(receipt))
        receipt = active.failure_receipt({}, active.RefusedError())
        for mutation in (
            {"raw": "PRIVATE_DATA"},
            {"phase": "subject-private-profile"},
            {"comparisons": {"subject-profile": "PRIVATE_DATA"}},
            {"comparisons": {"subject-profile-private": False}},
            {"cleanupAuthority": True},
        ):
            with self.subTest(mutation=mutation):
                self.assertFalse(active.valid_failure(receipt | mutation))


class ClosedSubjectProfileExtension(unittest.TestCase):
    def test_legacy_extended_child_combinations_and_direct_digest_projection_stay_nonqualifying(self) -> None:
        from scripts import docker_direct_startup_aggregate as aggregate  # noqa: PLC0415
        from scripts import docker_direct_startup_client as client  # noqa: PLC0415
        from scripts import docker_userns_custody_child as child  # noqa: PLC0415
        from tests.test_docker_userns_active import subject_profile_failure  # noqa: PLC0415

        for extended in (False, True):
            for child_build in (False, True):
                with self.subTest(extended=extended, child_build=child_build):
                    receipt = subject_profile_failure()
                    if not extended:
                        receipt.pop("subjectProfile")
                    if child_build:
                        receipt["childBuild"] = {
                            "lifetime": child.Lifetime.UNKNOWN.value,
                            "work": None,
                            "status": None,
                            "guard": None,
                        }
                    self.assertTrue(active.valid_failure(receipt, child=child))
                    projected = client.project_failure(receipt, "B")
                    self.assertEqual(aggregate.validate_failure(projected), projected)
                    self.assertNotIn("subjectProfile", projected)
                    self.assertEqual(projected["rootReceiptSha256"], active.digest(contract.canonical(receipt)))
                    self.assertFalse(projected["cleanupAuthority"])
                    self.assertEqual(projected["qualification"], "none")

    def test_closed_extension_rejects_bad_types_keys_hashes_enums_and_impossible_claims(self) -> None:
        import copy  # noqa: PLC0415

        from tests.test_docker_userns_active import subject_profile_failure  # noqa: PLC0415

        mutations = [
            ("schemaVersion", True),
            ("originOperation", "close"),
            ("source", "PRIVATE"),
            ("bytes", -1),
            ("bytes", 4097),
            ("bytes", True),
            ("sha256", "A" * 64),
            ("framing", "PRIVATE"),
            ("labelKind", "PRIVATE"),
            ("expectedName", "PRIVATE"),
            ("mode", "PRIVATE"),
            ("executableKind", "PRIVATE"),
            ("sameExecutable", "PRIVATE"),
            ("postchecks", []),
            ("postchecksComplete", 1),
            ("foreignLabelMatchesExecutableBasename", 1),
            ("raw", "PRIVATE"),
            ("expectedName", "exact"),
            ("sameExecutable", "mismatch"),
            ("executableKind", "other"),
            ("mode", "other"),
        ]
        for key, bad in mutations:
            with self.subTest(key=key, bad=bad):
                receipt = subject_profile_failure()
                receipt["subjectProfile"][key] = bad
                self.assertFalse(active.valid_failure(receipt))
        for bad in (None, [], "PRIVATE", {"raw": "PRIVATE"}):
            receipt = subject_profile_failure()
            receipt["subjectProfile"] = bad
            self.assertFalse(active.valid_failure(receipt))
        for key in subject_profile_failure()["subjectProfile"]:
            receipt = subject_profile_failure()
            receipt["subjectProfile"].pop(key)
            self.assertFalse(active.valid_failure(receipt))
        for state in ("mismatch", "unavailable", "deadline", "cancelled", "not-attempted", True, "PRIVATE"):
            receipt = subject_profile_failure()
            receipt["subjectProfile"]["postchecks"]["incarnation"] = state
            self.assertFalse(active.valid_failure(receipt))
        receipt = subject_profile_failure()
        receipt["subjectProfile"]["postchecks"]["PRIVATE"] = "match"
        self.assertFalse(active.valid_failure(receipt))
        oversized = copy.deepcopy(receipt)
        oversized["subjectProfile"]["raw"] = "x" * active.MAX_FAILURE
        self.assertFalse(active.valid_failure(oversized))

    def test_stopped_or_identity_unverified_postchecks_cannot_claim_later_task_reads(self) -> None:
        from tests.test_docker_userns_active import subject_profile_failure  # noqa: PLC0415

        for name, state in (
            ("taskAlive", "unavailable"),
            ("taskAlive", "deadline"),
            ("taskReadback", "mismatch"),
            ("profileReadback", "cancelled"),
            ("namespaceReadback", "deadline"),
        ):
            with self.subTest(name=name, state=state):
                receipt = subject_profile_failure()
                facts = receipt["subjectProfile"]
                facts.update(
                    postchecksComplete=False,
                    executableKind="unavailable",
                    sameExecutable="not-attempted",
                    foreignLabelMatchesExecutableBasename=None,
                )
                facts["postchecks"][name] = state
                self.assertFalse(active.valid_failure(receipt))

    def test_provenance_and_original_refusal_are_required_for_every_extended_envelope(self) -> None:
        from tests.test_docker_userns_active import subject_profile_failure  # noqa: PLC0415

        for key, bad in (
            ("actor", "client"),
            ("operation", "prepare"),
            ("phase", "daemon"),
            ("reason", "unexpected"),
            ("comparisons", {"subject-profile": True}),
            ("retained", False),
            ("sourceVerified", False),
            ("bindingVerified", False),
            ("context", None),
            ("reportingLease", None),
            ("reportingLease", "PRIVATE"),
            ("sourceManifestSha256", None),
            ("bindingSha256", None),
            ("cleanupAuthority", True),
        ):
            with self.subTest(key=key):
                self.assertFalse(active.valid_failure(subject_profile_failure() | {key: bad}))
        self.assertTrue(active.valid_failure(subject_profile_failure() | {"operation": "close"}))

    def test_malformed_internal_extension_is_omitted_without_replacing_first_error(self) -> None:
        from tests.test_docker_userns_active import binding, subject_profile_fixture  # noqa: PLC0415

        progress = {
            "actor": "root",
            "operation": "bind",
            "binding": binding(),
            "sourceVerified": True,
            "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
            "lease": "f" * 32,
            "record": {
                "retained": True,
                "diagnostic": {"phase": "subject-profile", "comparisons": {"subject-profile": False}},
            },
        }
        for malformed in (
            None,
            [],
            {"raw": "PRIVATE"},
            subject_profile_fixture() | {"mode": []},
            subject_profile_fixture() | {"postchecks": None},
        ):
            with self.subTest(malformed=malformed):
                progress["record"]["subjectProfile"] = malformed
                receipt = active.failure_receipt(progress, active.RefusedError("PRIVATE"))
                self.assertTrue(active.valid_failure(receipt))
                self.assertEqual((receipt["phase"], receipt["reason"]), ("subject-profile", "refused"))
                self.assertNotIn("subjectProfile", receipt)
                self.assertNotIn("PRIVATE", json.dumps(receipt))
