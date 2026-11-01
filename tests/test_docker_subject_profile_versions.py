"""Additive private refusal diagnostics: explicit schema dispatch never grants authority."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_aggregate as aggregate
from scripts import docker_direct_startup_client as direct_client
from scripts import docker_direct_startup_contract as direct_contract
from scripts import docker_userns_active as active
from tests import test_docker_userns_active as historical

EXPECTED = b"private-expected-canary"
CHECKS = ("taskAlive", "taskReadback", "profileReadback", "namespaceReadback", "incarnation")


def detail(version: object, *, mode: str = "unconfined", exact: bool = False) -> dict:
    """Build coherent byte/hash/length facts independently of production classifiers."""
    raw = (EXPECTED if exact else b"rootlesskit") + b" (" + mode.encode("ascii") + b")\n"
    return {
        "schemaVersion": version,
        "originOperation": "bind",
        "source": "held-task-attr/apparmor/current",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "framing": "single-ascii-lf",
        "labelKind": "single-named",
        "expectedName": "exact" if exact else "absent",
        "mode": mode,
        "postchecks": dict.fromkeys(CHECKS, "match"),
        "postchecksComplete": True,
        "executableKind": "rootlesskit",
        "sameExecutable": "match",
        "foreignLabelMatchesExecutableBasename": None if exact else True,
    }


def failure(observation: dict) -> dict:
    """Extend the preserved independently bound legacy refusal envelope, never a success receipt."""
    value = historical.subject_profile_failure()
    value["subjectProfile"] = copy.deepcopy(observation)
    return value


def progress(observation: object) -> dict:
    """Supply the existing source/binding/lease/retained refusal journal for internal omission tests."""
    return {
        "actor": "root",
        "operation": "bind",
        "binding": historical.binding(),
        "sourceVerified": True,
        "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
        "lease": "f" * 32,
        "record": {
            "retained": True,
            "diagnostic": {"phase": "subject-profile", "comparisons": {"subject-profile": False}},
            "subjectProfile": observation,
        },
    }


class SubjectProfileDiagnosticVersions(unittest.TestCase):
    def test_historical_validator_bytes_and_independent_four_cell_predicate(self) -> None:
        self.assertEqual(
            hashlib.sha256(inspect.getsource(active.subject_profile_detail).encode()).hexdigest(),
            "7bae99d2cde79d84c77f68c0ab3455b1e4b96e4eb7d275b01106511b7f3a4b82",
        )
        for version, mode, valid in (
            (1, "unconfined", False),
            (1, "enforce", True),
            (2, "unconfined", True),
            (2, "enforce", False),
        ):
            with self.subTest(version=version, mode=mode):
                facts = detail(version, mode=mode, exact=True)
                self.assertEqual(active.subject_profile_diagnostic_detail(facts), facts if valid else None)
                self.assertEqual(active.valid_failure(failure(facts)), valid)
                self.assertIsNone(facts["foreignLabelMatchesExecutableBasename"])
                self.assertEqual(facts["bytes"], len(EXPECTED + b" (" + mode.encode() + b")\n"))
        self.assertIsNone(active.subject_profile_detail(detail(2)))
        self.assertIsNone(active.subject_profile_detail_v2(detail(1)))

    def test_dispatch_uses_only_closed_exact_builtin_integer_versions_without_retry(self) -> None:
        for version in (None, True, False, "1", "2", 1.0, 2.0, 0, -1, 3, 4, [], {}):
            with self.subTest(version=version):
                value = detail(version)
                self.assertIsNone(active.subject_profile_diagnostic_detail(value))
                self.assertFalse(active.valid_failure(failure(value)))
        for value in (
            None,
            [],
            "PRIVATE",
            {},
            {key: item for key, item in detail(1).items() if key != "schemaVersion"},
        ):
            self.assertIsNone(active.subject_profile_diagnostic_detail(value))
        for version, selected, other in (
            (1, "subject_profile_detail", "subject_profile_detail_v2"),
            (2, "subject_profile_detail_v2", "subject_profile_detail"),
        ):
            with (
                patch.object(active, selected, return_value=None) as chosen,
                patch.object(active, other, side_effect=AssertionError("version fallback forbidden")) as forbidden,
            ):
                value = detail(version)
                self.assertIsNone(active.subject_profile_diagnostic_detail(value))
                chosen.assert_called_once_with(value)
                forbidden.assert_not_called()

    def test_neutral_classification_and_all_other_modes_remain_version_independent(self) -> None:
        for raw, framing, kind, relation, mode in historical.SubjectLabelClassification.cases():
            expected = {"framing": framing, "labelKind": kind, "expectedName": relation, "mode": mode}
            self.assertEqual(active.subject_label(raw, EXPECTED), expected)
            for version in (1, 2):
                facts = detail(version)
                facts.update(expected, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                facts["foreignLabelMatchesExecutableBasename"] = None
                valid = not (
                    kind == "single-named" and relation == "exact" and mode == {1: "unconfined", 2: "enforce"}[version]
                )
                with self.subTest(raw=raw[:80], version=version):
                    self.assertEqual(active.subject_profile_diagnostic_detail(facts), facts if valid else None)
        for version in (1, 2):
            for mode in ("unconfined", "enforce", "complain", "kill", "prompt", "allow", "mixed"):
                value = detail(version, mode=mode)
                self.assertEqual(active.subject_profile_diagnostic_detail(value), value)

    def test_both_schemas_retain_closed_types_keys_limits_hashes_and_correlations(self) -> None:
        mutations = (
            ("originOperation", "close"),
            ("source", "PRIVATE"),
            ("bytes", -1),
            ("bytes", 4097),
            ("bytes", True),
            ("bytes", 1.0),
            ("sha256", "A" * 64),
            ("sha256", "a" * 63),
            ("framing", "PRIVATE"),
            ("labelKind", "PRIVATE"),
            ("expectedName", "PRIVATE"),
            ("mode", "PRIVATE"),
            ("mode", []),
            ("executableKind", "PRIVATE"),
            ("sameExecutable", "PRIVATE"),
            ("postchecks", []),
            ("postchecks", None),
            ("postchecksComplete", 1),
            ("foreignLabelMatchesExecutableBasename", 1),
            ("raw", "PRIVATE"),
            ("expectedName", "exact"),
            ("sameExecutable", "mismatch"),
            ("executableKind", "other"),
            ("mode", "other"),
        )
        for version in (1, 2):
            self.assertTrue(active.valid_failure(failure(detail(version))))
            for key, value in mutations:
                with self.subTest(version=version, key=key, value=value):
                    changed = detail(version)
                    changed[key] = value
                    self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
                    self.assertFalse(active.valid_failure(failure(changed)))
            for key in detail(version):
                changed = detail(version)
                changed.pop(key)
                self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
            for postcheck in CHECKS:
                for state in (True, "PRIVATE", "mismatch", "unavailable", "not-attempted"):
                    changed = detail(version)
                    changed["postchecks"][postcheck] = state
                    self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
            changed = detail(version)
            changed["postchecks"]["PRIVATE"] = "match"
            self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
            changed = detail(version)
            changed.update(
                bytes=0,
                sha256="a" * 64,
                framing="other",
                labelKind="unparsed",
                expectedName="unparsed",
                mode="unparsed",
                foreignLabelMatchesExecutableBasename=None,
            )
            self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
            changed["sha256"] = hashlib.sha256(b"").hexdigest()
            self.assertEqual(active.subject_profile_diagnostic_detail(changed), changed)

    def test_postcheck_stop_order_and_task_identity_dependencies_are_preserved(self) -> None:
        for version in (1, 2):
            for index, name in enumerate(CHECKS):
                for stopped in ("deadline", "cancelled"):
                    baseline = detail(version)
                    baseline.update(postchecksComplete=False, foreignLabelMatchesExecutableBasename=None)
                    baseline["postchecks"][name] = stopped
                    for later in CHECKS[index + 1 :]:
                        baseline["postchecks"][later] = "not-attempted"
                    if index < CHECKS.index("profileReadback"):
                        baseline.update(executableKind="unavailable", sameExecutable="not-attempted")
                    self.assertEqual(active.subject_profile_diagnostic_detail(baseline), baseline)
                    for later in CHECKS[index + 1 :]:
                        changed = copy.deepcopy(baseline)
                        changed["postchecks"][later] = "match"
                        self.assertIsNone(active.subject_profile_diagnostic_detail(changed))
            for name, later in (("taskAlive", "taskReadback"), ("taskReadback", "profileReadback")):
                changed = detail(version)
                changed.update(
                    postchecksComplete=False, foreignLabelMatchesExecutableBasename=None, sameExecutable="not-attempted"
                )
                changed["postchecks"][name] = "mismatch"
                changed["postchecks"][later] = "match"
                self.assertIsNone(active.subject_profile_diagnostic_detail(changed))

    def test_each_outer_provenance_dependency_remains_required_and_never_grants_cleanup(self) -> None:
        for version in (1, 2):
            original = failure(detail(version))
            self.assertTrue(active.valid_failure(original))
            for key, value in (
                ("schemaVersion", 2),
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
                with self.subTest(version=version, key=key):
                    self.assertFalse(active.valid_failure(original | {key: value}))
            self.assertTrue(active.valid_failure(original | {"operation": "close"}))
            projected = direct_client.project_failure(original, "B")
            self.assertEqual(aggregate.validate_failure(projected), projected)
            self.assertEqual(projected["rootReceiptSha256"], active.digest(direct_contract.canonical(original)))
            self.assertEqual(projected["qualification"], "none")
            self.assertFalse(projected["cleanupAuthority"])
            self.assertNotIn("subjectProfile", projected)
            self.assertNotIn("reportingLease", projected)

    def test_internal_malformed_detail_is_omitted_but_external_malformed_detail_refuses(self) -> None:
        for version, inconsistent in ((1, "unconfined"), (2, "enforce")):
            valid = detail(version)
            receipt = active.failure_receipt(progress(valid), active.RefusedError("PRIVATE"))
            self.assertEqual(receipt["subjectProfile"], valid)
            self.assertEqual(receipt["schemaVersion"], 1)
            self.assertFalse(receipt["cleanupAuthority"])
            for value in (
                None,
                [],
                {"raw": "PRIVATE"},
                detail(version, mode=inconsistent, exact=True),
                detail("2"),
                valid | {"postchecks": None},
                valid | {"mode": []},
            ):
                with self.subTest(version=version, value=value):
                    internal = active.failure_receipt(progress(value), active.RefusedError("PRIVATE"))
                    self.assertTrue(active.valid_failure(internal))
                    self.assertNotIn("subjectProfile", internal)
                    self.assertEqual((internal["phase"], internal["reason"]), ("subject-profile", "refused"))
                    self.assertNotIn("PRIVATE", json.dumps(internal))
                    external = failure(valid)
                    external["subjectProfile"] = value
                    self.assertFalse(active.valid_failure(external))
            oversized = failure(valid)
            oversized["subjectProfile"]["raw"] = "x" * active.MAX_FAILURE
            self.assertFalse(active.valid_failure(oversized))

    def test_real_client_transports_both_versions_as_redacted_retained_refusals(self) -> None:
        for version in (1, 2):
            for operation in ("bind", "close"):
                with self.subTest(version=version, operation=operation), tempfile.TemporaryDirectory() as temporary:
                    client = historical.client_fixture(Path(temporary))
                    value = failure(detail(version)) | {"operation": operation}

                    def command(
                        _name: str, _argv: list, *, client: object = client, value: dict = value, **_kwargs: object
                    ) -> str:
                        client.ctx.checks.append(
                            {"exitCode": 1, "stdout": "PRIVATE", "stderr": "PRIVATE", "error": "PRIVATE"}
                        )
                        return json.dumps(value)

                    client.ctx.command = Mock(side_effect=command)
                    with self.assertRaises(ValueError):
                        client.rpc(operation, {})
                    self.assertEqual(client.failures, [value])
                    self.assertEqual(client.evidence["failures"][0]["subjectProfile"], detail(version))
                    self.assertFalse(client.evidence["cleanupAuthority"])
                    self.assertNotIn("PRIVATE", client.ctx.scoped_failure_output.read_text())
                    self.assertNotIn("PRIVATE", json.dumps(client.ctx.checks))

    def test_real_client_rejects_unknown_and_version_mixed_details_without_raw_capture(self) -> None:
        for observation in (
            detail(1, exact=True),
            detail(2, mode="enforce", exact=True),
            detail(version=True),
            detail(3),
            detail(2) | {"raw": "PRIVATE"},
        ):
            with self.subTest(observation=observation), tempfile.TemporaryDirectory() as temporary:
                client = historical.client_fixture(Path(temporary))
                value = failure(observation)
                client.ctx.command = Mock(return_value=json.dumps(value))
                with self.assertRaises(ValueError):
                    client.rpc("bind", {})
                self.assertNotIn("subjectProfile", client.failures[0])
                self.assertEqual(client.failures[0]["reason"], "receipt-mismatch")
                self.assertNotIn("PRIVATE", client.ctx.scoped_failure_output.read_text())

    def test_current_trusted_collector_emits_only_enforce_schema2(self) -> None:
        collector = historical.SubjectRefusalObservation()
        for raw in (b"rootlesskit (unconfined)\n", EXPECTED + b" (unconfined)\n"):
            with self.subTest(raw=raw), collector.fixture(raw) as case:
                value = collector.refuse(case)
                self.assertEqual(value["subjectProfile"]["schemaVersion"], 2)
                self.assertEqual(case.port.record["subjectProfile"]["schemaVersion"], 2)
                self.assertFalse(value["cleanupAuthority"])
