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

from scripts import docker_direct_startup_aggregate as aggregate
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts.docker_userns_qualification import context_digest
from tests import test_docker_direct_startup_admission as admission_tests
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
