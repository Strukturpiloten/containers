"""Independent finite pair, source, privacy and nonqualification fault controls."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from functools import cache
from pathlib import Path
from unittest.mock import patch

from scripts import docker_direct_startup_aggregate as aggregate
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts.docker_userns_qualification import context_digest
from tests import test_docker_direct_startup_admission as admission_tests
from tests import test_docker_direct_startup_runtime as runtime_cases
from tests.test_docker_direct_startup_contract import arm

CANDIDATE_RUN = "145"
ATTEMPT = "1"
ROOT = Path(__file__).resolve().parents[1]


@cache
def _pair(image: str = "docker-20.10-rootless", architecture: str = "amd64") -> dict:
    """Create complete source-bound observations with canonical declaration versions."""
    _proof, context, _environment, _event = admission_tests.DirectAdmissionTests().fixture(image, architecture)
    candidate = context["candidate"]
    # The source revision is synthetic; these records cannot qualify a real run.
    context.update(run=CANDIDATE_RUN, attempt=ATTEMPT)
    identity = {
        "manifestDigest": "sha256:" + "1" * 64,
        "configDigest": "sha256:" + "2" * 64,
        "archiveSha256": "3" * 64,
        "architecture": architecture,
        "sourceRevision": candidate,
        "version": next(item["version"] for item in aggregate.declarations() if item["name"] == image),
    }
    source = hashlib.sha256(
        contract.canonical(
            {
                "candidate": candidate,
                "image": image,
                "architecture": architecture,
                "imageIdentity": identity,
                "admissionSha256": context["admissionSha256"],
            }
        )
    ).hexdigest()
    arms = [arm("A"), arm("B")]
    for record in arms:
        record.update(image=image, architecture=architecture, sourceIdentitySha256=source)
        record["guest"]["executables"].update(aggregate.expected_versions(image))
    return {
        "schemaVersion": 1,
        "consumer": "containers-direct-rootless-startup-diagnostic",
        "purpose": "direct-startup-diagnostic",
        "qualification": "none",
        "image": image,
        "architecture": architecture,
        "profile": "docker",
        "status": "diagnostic-complete",
        "candidate": candidate,
        "runId": CANDIDATE_RUN,
        "runAttempt": ATTEMPT,
        "producingJob": "smoke-build",
        "workflowContext": context,
        "workflowContextSha256": context_digest(context),
        "imageIdentity": identity,
        "gateSha256": gate.GATE_SHA256,
        "conclusion": "profile-dependent-startup",
        "arms": arms,
        "namespaceControls": {
            "availability": "unavailable-post-exec-actor-equivalence",
            "controls": ["U", "M", "UM"],
            "attempted": 0,
        },
        "stageDisposed": True,
        "pairStartedNs": 100,
        "pairDeadlineNs": 900_000_000_100,
        "failures": [],
        "bounds": {
            "pairSeconds": 900,
            "armWorkSeconds": 300,
            "cleanupReserveSeconds": 60,
            "storeBytes": 12884901888,
            "startupSeconds": 45,
        },
    }


def pair(image: str = "docker-20.10-rootless", architecture: str = "amd64") -> dict:
    """Copy an independent immutable synthetic record before each fault."""
    return copy.deepcopy(_pair(image, architecture))


def validate(record: dict) -> dict:
    """Validate against independently selected producer identity."""
    return aggregate.validate_pair_report(record, candidate=pair()["candidate"], run=CANDIDATE_RUN, attempt=ATTEMPT)


class PairReportTests(unittest.TestCase):
    def test_both_rows_and_nonremedy_keep_diagnostic_only_status(self) -> None:
        for image, architecture in contract.ROWS:
            record = pair(image, architecture)
            self.assertIs(validate(record), record)
            record["arms"][1].update(startup="rootlesskit-child-start-eperm", nativeExitCode=1)
            record["arms"][1]["guest"]["postExecVerified"] = False
            record["conclusion"] = "profile-not-demonstrated-remedy"
            self.assertEqual(validate(record)["conclusion"], "profile-not-demonstrated-remedy")
            self.assertEqual(record["qualification"], "none")
            self.assertNotEqual(record["status"], "passed")

    def test_bad_identity_source_clock_shape_and_qualification_refuse(self) -> None:
        for field, value in (
            ("schemaVersion", True),
            ("consumer", "native"),
            ("purpose", "maintained-prerequisite"),
            ("qualification", "complete"),
            ("status", "passed"),
            ("status", "skipped"),
            ("status", "cancelled"),
            ("image", "docker-29-conformance-rootless"),
            ("architecture", "arm64"),
            ("candidate", "f" * 40),
            ("runId", "146"),
            ("runAttempt", "2"),
            ("producingJob", "build"),
            ("workflowContextSha256", "f" * 64),
            ("gateSha256", "f" * 64),
            ("stageDisposed", False),
            ("pairStartedNs", True),
            ("pairDeadlineNs", 1 << 64),
            ("pairDeadlineNs", 900_000_000_101),
            ("failures", ["PRIVATE-SECRET"]),
            ("arms", []),
            ("conclusion", "attributed-userns-denial"),
            ("unknown", "PRIVATE-SECRET"),
        ):
            record = pair()
            record[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError) as caught:
                validate(record)
            self.assertNotIn("PRIVATE-SECRET", str(caught.exception))

    def test_claimed_matching_digest_cannot_hide_actor_or_executable_drift(self) -> None:
        for field, key, value in (
            ("actor", "Groups", ["1000", "1001"]),
            ("actor", "CapEff", ["0000000000000001"]),
            ("actor", "NoNewPrivs", ["1"]),
            ("executables", "launcherSha256", "f" * 64),
            ("executables", "rootlesskitSha256", "f" * 64),
        ):
            record = pair()
            record["arms"][1]["guest"][field][key] = value
            with self.subTest(field=field, key=key), self.assertRaises(ValueError):
                validate(record)
        record = pair()
        record["arms"][0]["guest"]["postExecVerified"] = True
        with self.assertRaises(ValueError):
            validate(record)

    def test_missing_every_field_and_nested_wire_mutations_refuse(self) -> None:
        for key in pair():
            record = pair()
            del record[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(record)
        for field, key, value in (
            ("imageIdentity", "sourceRevision", "f" * 40),
            ("imageIdentity", "configDigest", "2" * 64),
            ("imageIdentity", "version", "999.0.0"),
            ("imageIdentity", "unknown", "PRIVATE-SECRET"),
            ("bounds", "pairSeconds", True),
            ("bounds", "storeBytes", 1),
            ("namespaceControls", "attempted", False),
            ("namespaceControls", "attempted", 1),
            ("workflowContext", "expectedUid", "0"),
            ("workflowContext", "ref", "refs/heads/main"),
        ):
            record = pair()
            record[field][key] = value
            with self.subTest(field=field, key=key), self.assertRaises(ValueError):
                validate(record)

    def test_failed_cleanup_source_drift_successful_a_and_unknown_b_refuse(self) -> None:
        for index, field, value in (
            (0, "cleanupVerified", False),
            (1, "cleanupVerified", False),
            (0, "factsComplete", False),
            (1, "factsComplete", False),
            (0, "startup", "ready"),
            (0, "nativeExitCode", 0),
            (1, "startup", "other-failure"),
            (1, "startup", "unknown"),
            (1, "sourceIdentitySha256", "f" * 64),
            (1, "nonPolicyFactsSha256", "f" * 64),
            (1, "qualification", "complete"),
            (0, "profileBound", True),
            (1, "profileBound", False),
        ):
            record = pair()
            record["arms"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                validate(record)
        for key in contract.OWNERSHIP_FIELDS:
            record = pair()
            record["arms"][1]["ownership"][key] = record["arms"][0]["ownership"][key]
            with self.subTest(owner=key), self.assertRaises(ValueError):
                validate(record)
        for key, value in (("postExecVerified", False), ("unknown", "PRIVATE-SECRET")):
            record = pair()
            record["arms"][1]["guest"][key] = value
            with self.subTest(guest=key), self.assertRaises(ValueError):
                validate(record)


def retain_source(source: Path, fault: str, record: dict) -> None:
    """Build independent regular and unsafe report inputs without native execution."""
    if fault == "missing":
        return
    if fault == "symlink":
        secret = source.parent / "private"
        secret.write_text("PRIVATE-SECRET")
        source.symlink_to(secret)
    elif fault == "fifo":
        os.mkfifo(source)
    else:
        contents = {
            "valid": contract.canonical(record),
            "malformed": b"PRIVATE-SECRET",
            "deep": b"[" * 1100 + b"PRIVATE-SECRET",
            "oversized": b"PRIVATE-SECRET" * 1000,
            "private-field": contract.canonical(record | {"nativeValue": "PRIVATE-SECRET"}),
            "wrong-row": contract.canonical(pair("docker-26-rootless", "arm64")),
        }
        source.write_bytes(contents[fault])


class AggregateCliTests(unittest.TestCase):
    def invoke(self, directory: Path, *arguments: str) -> tuple[subprocess.CompletedProcess, dict]:
        output = directory / "result.out"
        command = [
            sys.executable,
            "-m",
            "scripts.docker_direct_startup_aggregate",
            *arguments,
            "--candidate",
            pair()["candidate"],
            "--run",
            CANDIDATE_RUN,
            "--attempt",
            ATTEMPT,
            "--output",
            str(output),
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False, timeout=10)  # noqa: S603 - fixed authored command.
        return result, json.loads(output.read_text())

    def write_pairs(self, directory: Path) -> None:
        for image, architecture in contract.ROWS:
            (directory / f"{image}-{architecture}.json").write_bytes(contract.canonical(pair(image, architecture)))

    def test_complete_directory_and_single_pair_preserve_nonqualification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_pairs(directory)
            result, record = self.invoke(directory, "--directory", temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(record["completeMatrix"])
            self.assertEqual(record["qualification"], "none")
            result, record = self.invoke(
                directory,
                "--pair",
                str(directory / "docker-20.10-rootless-amd64.json"),
                "--image",
                "docker-20.10-rootless",
                "--architecture",
                "amd64",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(record["completeMatrix"])

    def test_swapped_valid_rows_and_wrong_producer_or_artifact_row_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_pairs(directory)
            first = directory / "docker-20.10-rootless-amd64.json"
            second = directory / "docker-26-rootless-arm64.json"
            original_first, original_second = first.read_bytes(), second.read_bytes()
            first.write_bytes(original_second)
            second.write_bytes(original_first)
            result, _record = self.invoke(directory, "--directory", temporary)
            self.assertNotEqual(result.returncode, 0)
            result, _record = self.invoke(
                directory, "--pair", str(first), "--image", "docker-20.10-rootless", "--architecture", "amd64"
            )
            self.assertNotEqual(result.returncode, 0)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_pairs(directory)
            for image, architecture in contract.ROWS:
                source = directory / f"{image}-{architecture}.json"
                artifact = directory / f"direct-startup-pair-{image}-{architecture}"
                artifact.mkdir()
                source.rename(artifact / source.name)
            result, _record = self.invoke(directory, "--directory", temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            (directory / "result.out").unlink()
            artifact = directory / "direct-startup-pair-docker-20.10-rootless-amd64"
            artifact.rename(directory / "direct-startup-pair-docker-26-rootless-amd64")
            result, _record = self.invoke(directory, "--directory", temporary)
            self.assertNotEqual(result.returncode, 0)

    def test_retention_exports_only_closed_records_and_keeps_rejected_source_private(self) -> None:
        for fault in (
            "valid",
            "missing",
            "malformed",
            "oversized",
            "private-field",
            "symlink",
            "fifo",
            "wrong-row",
            "deep",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "source.json"
                record = pair()
                retain_source(source, fault, record)
                original = source.read_bytes() if source.is_file() and not source.is_symlink() else None
                result, retained = self.invoke(
                    directory,
                    "--retain-pair",
                    str(source),
                    "--image",
                    "docker-20.10-rootless",
                    "--architecture",
                    "amd64",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("PRIVATE-SECRET", json.dumps(retained))
                self.assertNotIn("PRIVATE-SECRET", (result.stdout + result.stderr).decode())
                self.assertEqual(retained["qualification"], "none")
                if fault == "valid":
                    self.assertEqual(retained, record)
                else:
                    self.assertEqual(
                        set(retained),
                        {
                            "schemaVersion",
                            "consumer",
                            "purpose",
                            "qualification",
                            "status",
                            "reason",
                            "image",
                            "architecture",
                            "candidate",
                            "runId",
                            "runAttempt",
                            "producingJob",
                        },
                    )
                    self.assertEqual(retained["status"], "failed")
                if original is not None:
                    self.assertEqual(source.read_bytes(), original)
                if fault == "missing":
                    self.assertFalse(source.exists())

    def test_missing_duplicate_unknown_oversized_and_private_errors_fail_closed(self) -> None:
        for fault in ("missing", "duplicate", "unknown", "oversized", "invalid-json", "duplicate-key", "symlink"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.write_pairs(directory)
                target = directory / "docker-26-rootless-arm64.json"
                if fault == "missing":
                    target.unlink()
                elif fault == "duplicate":
                    target.write_bytes(contract.canonical(pair()))
                elif fault == "unknown":
                    (directory / "PRIVATE-SECRET.json").write_text("{}")
                elif fault == "oversized":
                    target.write_text("PRIVATE-SECRET" * 1000)
                elif fault == "invalid-json":
                    target.write_text("PRIVATE-SECRET")
                elif fault == "duplicate-key":
                    target.write_text('{"qualification":"none","qualification":"complete"}')
                else:
                    target.unlink()
                    target.symlink_to(directory / "docker-20.10-rootless-amd64.json")
                result, record = self.invoke(directory, "--directory", temporary)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(record["qualification"], "none")
                self.assertEqual(record["status"], "failed")
                self.assertNotIn("PRIVATE-SECRET", (result.stdout + result.stderr).decode())
                self.assertNotIn("PRIVATE-SECRET", json.dumps(record))


class FailedDiagnosticRetention(unittest.TestCase):
    def setUp(self) -> None:
        self.forbidden = []
        for name in ("Popen", "run", "check_call", "check_output"):
            self.enterContext(patch.object(subprocess, name, side_effect=self.blocked))

    def blocked(self, *_args: object, **_kwargs: object) -> None:
        self.forbidden.append(True)
        message = "unexpected subprocess in diagnostic fixture"
        raise AssertionError(message)

    def tearDown(self) -> None:
        self.assertEqual(self.forbidden, [])

    def record(self) -> dict:
        value = copy.deepcopy(_pair())
        value.update(
            status="failed",
            failures=[aggregate.local_failure("pair", "source-prepare", PermissionError(13, "PRIVATE_MESSAGE"))],
        )
        value["arms"] = []
        return aggregate.failed_report(value)

    def retained(self, value: object, *, row: tuple[str, str] = ("docker-20.10-rootless", "amd64")) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.json"
            path.write_text(json.dumps(value) + "\n")
            return aggregate.retain_pair(
                path, candidate=_pair()["candidate"], run=CANDIDATE_RUN, attempt=ATTEMPT, row=row
            )

    def test_pre_a_failed_record_survives_retention_without_any_success_authority(self) -> None:
        value = self.record()
        self.assertEqual(self.retained(value), value)
        self.assertEqual(value["failures"][0]["phase"], "source-prepare")
        self.assertEqual(value["failures"][0]["reason"], "permission-denied")
        self.assertEqual(value["armOutcomes"], [])
        self.assertEqual(value["qualification"], "none")
        self.assertEqual(value["status"], "failed")
        self.assertNotIn("PRIVATE_", json.dumps(value))
        with self.assertRaises(contract.DirectDiagnosticError):
            aggregate.validate_pair_report(value, candidate=value["candidate"], run=CANDIDATE_RUN, attempt=ATTEMPT)

    def test_local_and_root_cleanup_diagnostics_preserve_order_and_known_native_exit(self) -> None:
        record, _events, published, _source = runtime_cases.PairControls().execute("work-root-cleanup")
        value = published[-1][1]
        self.assertEqual(value["failures"], record["failures"])
        self.assertEqual([item["actor"] for item in value["failures"]], ["coordinator", "root"])
        self.assertEqual(value["armOutcomes"][0]["nativeExitCode"], 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.json"
            path.write_text(json.dumps(value))
            retained = aggregate.retain_pair(
                path,
                candidate=value["candidate"],
                run=value["runId"],
                attempt=value["runAttempt"],
                row=(value["image"], value["architecture"]),
            )
        self.assertEqual(retained, value)
        for key, item in (
            ("cleanupAuthority", True),
            ("reportingLease", "PRIVATE_LOCATOR"),
            ("phase", "PRIVATE_PHASE"),
            ("reason", "PRIVATE_REASON"),
            ("operation", "PRIVATE_OPERATION"),
            ("bindingVerified", "true"),
            ("bindingSha256", "PRIVATE_HASH"),
            ("rootReceiptSha256", "PRIVATE_HASH"),
            ("retained", 1),
            ("sourceVerified", 1),
        ):
            with self.subTest(root_field=key), tempfile.TemporaryDirectory() as directory:
                forged = copy.deepcopy(value)
                forged["failures"][1][key] = item
                path = Path(directory) / "pair.json"
                path.write_text(json.dumps(forged))
                refused = aggregate.retain_pair(
                    path,
                    candidate=value["candidate"],
                    run=value["runId"],
                    attempt=value["runAttempt"],
                    row=(value["image"], value["architecture"]),
                )
                self.assertEqual(refused["reason"], "pair-evidence-refused")
                self.assertNotIn("PRIVATE_", json.dumps(refused))

    def test_forged_private_extra_wrong_source_and_overflow_records_use_fixed_refusal(self) -> None:
        original = self.record()
        mutations = (
            ("candidate", "f" * 40),
            ("runId", "999"),
            ("runAttempt", "2"),
            ("producingJob", "PRIVATE_JOB"),
            ("gateSha256", "0" * 64),
            ("schemaVersion", True),
            ("qualification", "complete"),
            ("status", "diagnostic-complete"),
            ("reason", "PRIVATE_REASON"),
            ("extra", "PRIVATE_EXTRA"),
            ("publicationFailure", "PRIVATE_FAILURE"),
            ("workflowContextSha256", "0" * 64),
            ("workflowContext", {**original["workflowContext"], "admissionSha256": "0" * 64}),
            ("failures", [*original["failures"], original["failures"][0]]),
            ("failures", [{**original["failures"][0], "traceback": "PRIVATE_TRACE"}]),
            ("failures", [{**original["failures"][0], "errorType": "PRIVATE_CLASS"}]),
            ("failures", [{**original["failures"][0], "errorType": "overflow"}]),
            ("failures", [{**original["failures"][0], "errorType": "cancelled"}]),
            ("failures", [{**original["failures"][0], "phase": "PRIVATE_PHASE"}]),
            ("failures", [{**original["failures"][0], "reason": "PRIVATE_REASON"}]),
            ("failures", original["failures"] * (aggregate.FAILURE_LIMIT + 1)),
            ("diagnosticOverflow", True),
            ("armOutcomes", [{"rawEnvironment": "PRIVATE_ENV"}]),
        )
        for key, item in mutations:
            with self.subTest(key=key, item=item):
                value = copy.deepcopy(original)
                value[key] = item
                retained = self.retained(value)
                self.assertEqual(retained["reason"], "pair-evidence-refused")
                self.assertNotIn("PRIVATE_", json.dumps(retained))
        self.assertEqual(
            self.retained(original, row=("docker-26-rootless", "arm64"))["reason"], "pair-evidence-refused"
        )

    def test_bounded_distinct_errors_keep_first_cause_and_explicit_overflow(self) -> None:
        value = copy.deepcopy(_pair())
        value["status"] = "failed"
        value["failures"] = [
            aggregate.local_failure("pair", operation) for operation in sorted(aggregate.LOCAL_OPERATIONS)
        ]
        first = value["failures"][0]
        result = aggregate.failed_report(value)
        self.assertEqual(result["failures"][0], first)
        self.assertEqual(len(result["failures"]), aggregate.FAILURE_LIMIT)
        self.assertEqual(result["failures"][-1]["reason"], "diagnostic-overflow")
        self.assertTrue(result["diagnosticOverflow"])
        self.assertEqual(self.retained(result), result)
        forged = copy.deepcopy(result)
        forged["failures"][-1]["arm"] = "A"
        self.assertEqual(self.retained(forged)["reason"], "pair-evidence-refused")

    def test_fixed_publication_invalidation_preserves_only_otherwise_valid_pair(self) -> None:
        value = copy.deepcopy(_pair())
        value.update(status="failed", conclusion="inconclusive", publicationFailure="evidence-publication-failed")
        retained = self.retained(value)
        self.assertEqual(retained["status"], "failed")
        self.assertEqual(retained["failures"][0]["phase"], "publication")
        self.assertEqual(retained["publicationFailure"], "evidence-publication-failed")
        for key, item in (("gateSha256", "0" * 64), ("publicationFailure", "PRIVATE_CANARY")):
            invalid = copy.deepcopy(value)
            invalid[key] = item
            self.assertEqual(self.retained(invalid)["reason"], "pair-evidence-refused")

    def test_arbitrary_exception_class_names_and_operands_are_never_serialized(self) -> None:
        error = type("PRIVATE_CLASS_CANARY", (Exception,), {})("PRIVATE_MESSAGE_CANARY")
        failure = aggregate.local_failure("pair", "source-prepare", error)
        self.assertEqual(failure["errorType"], "other")
        self.assertEqual(failure["reason"], "operation-unverified")
        self.assertNotIn("PRIVATE_", json.dumps(failure))
