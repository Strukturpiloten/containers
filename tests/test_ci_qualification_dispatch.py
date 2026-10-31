"""Bounded ordinary CI selects exact work without emitting the protected full check."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts import ci_validation_scope as scope
from scripts import container_engine as engine
from scripts import docker_userns_qualification as qualification
from scripts.evidence_gate import EvidenceError, require_ordinary_runtime_authority, verify_architecture
from tests import test_ci_diagnostic_dispatch as workflow_tests
from tests import test_docker_userns_active as root_tests
from tests import test_runtime_oom_lifecycle as lifecycle_tests
from tests.test_docker_userns_qualification import scoped_receipt, workflow_context
from tests.test_evidence_gate import maintained_runtime

PROFILE = "docker-rootless-qualification"


def selection() -> dict:
    """Build the pending ordinary request independently of the shell selector."""
    return {
        "validationProfile": PROFILE,
        "focusedRuntimeRequested": "witness-diagnostic",
        "focusedRuntime": "none",
        "oomAccountingMode": "qualification",
        "qualification": "pending",
    }


def plan() -> dict:
    """Use the existing planner; assert exact expected results independently below."""
    return engine._build_plan(
        engine._load_images(),
        engine.PlanOptions(
            "workflow_dispatch", "reviewed", "main", None, "a" * 40, None, "image", "docker-29-conformance-rootless"
        ),
    )


def context() -> scope.Context:
    """Keep trusted workflow fields independent from the plan under test."""
    return scope.Context("workflow_dispatch", PROFILE, PROFILE, "reviewed", "a" * 40, "main")


class BoundedPlanTests(unittest.TestCase):
    def test_exact_declared_pair_passes_before_outputs_with_actual_profile_preserved(self) -> None:
        result = scope.validate_plan(plan(), selection(), context())
        self.assertEqual(result["validationProfile"], PROFILE)
        self.assertEqual([image["name"] for image in result["images"]], ["docker-29-conformance-rootless"])
        self.assertEqual(
            [(item["name"], item["arch"], item["runner"]) for item in result["smokeBuildMatrix"]["include"]],
            [
                ("docker-29-conformance-rootless", "amd64", "ubuntu-26.04"),
                ("docker-29-conformance-rootless", "arm64", "ubuntu-26.04-arm"),
            ],
        )
        self.assertEqual(
            [(item["name"], item["arch"]) for item in result["payloadMatrix"]["include"]],
            [("docker-29-payload", "amd64"), ("docker-29-payload", "arm64")],
        )
        self.assertEqual(result["selection"]["reverseDependencies"], [])
        self.assertIs(type(result["selection"]["noCache"]), bool)
        self.assertTrue(result["selection"]["noCache"])

    def test_missing_corrupt_and_widened_plans_never_release_outputs(self) -> None:
        original = plan()
        smoke = original["smokeBuildMatrix"]["include"]
        payloads = original["payloadMatrix"]["include"]
        mutations = (
            (("images",), []),
            (("images",), [*original["images"], copy.deepcopy(original["images"][0])]),
            (("selection", "reverseDependencies"), ["unexpected-consumer"]),
            (("smokeBuildMatrix", "include"), [*smoke, copy.deepcopy(smoke[0])]),
            (("smokeBuildMatrix", "include"), smoke[:1]),
            (("smokeBuildMatrix", "include", 1, "runner"), "ubuntu-latest"),
            (("payloadMatrix", "include"), [*payloads, copy.deepcopy(payloads[0])]),
            (("payloadMatrix", "include"), payloads[:1]),
            (("payloadMatrix", "include", 0, "name"), "unexpected-payload"),
            (("sourceRevision",), "f" * 40),
            (("eventName",), "push"),
            (("refName",), "unexpected"),
            (("selection", "scope"), "all"),
            (("selection", "target"), "unexpected"),
            (("selection", "noCache"), False),
            (("stageMatrices", 0, "publishMatrix", "include", 0, "stage"), False),
            (("validationProfile",), "full"),
            (("unknown",), True),
        )
        for path, value in mutations:
            changed = copy.deepcopy(original)
            parent = changed
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(scope.ScopeError):
                scope.validate_plan(changed, selection(), context())
        for key in ("selection", "images", "smokeBuildMatrix", "payloadMatrix"):
            changed = copy.deepcopy(original)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(scope.ScopeError):
                scope.validate_plan(changed, selection(), context())

    def test_changed_trusted_fixture_cannot_disable_its_original_native_workload(self) -> None:
        declared = next(image for image in engine._load_images() if image["name"] == "docker-29-conformance-rootless")
        changed = copy.deepcopy(declared)
        changed["tests"]["docker"]["nestedRuntime"] = False
        changed_plan = plan()
        changed_plan["images"] = [engine._normalize_image(changed, 0)]
        with (
            patch.object(scope.container_engine, "_load_images", return_value=[changed]),
            self.assertRaises(scope.ScopeError),
        ):
            scope.validate_plan(changed_plan, selection(), context())

    def test_unknown_missing_and_conflicting_selector_artifacts_refuse(self) -> None:
        for key, value in (
            ("validationProfile", "full"),
            ("focusedRuntime", "witness-diagnostic"),
            ("focusedRuntimeRequested", "mandatory-accounting"),
            ("qualification", "complete"),
            ("unexpected", True),
        ):
            changed = {**selection(), key: value}
            with self.subTest(key=key), self.assertRaises(scope.ScopeError):
                scope.validate_plan(plan(), changed, context())
        for changed in (
            replace(context(), selected_profile=""),
            replace(context(), selected_profile="full"),
            replace(context(), requested_profile="unknown"),
            replace(context(), event_name="pull_request"),
        ):
            with self.subTest(context=changed), self.assertRaises((scope.ScopeError, qualification.QualificationError)):
                scope.validate_plan(plan(), selection(), changed)

    def test_actual_cli_rejects_corruption_without_annotating_or_releasing_a_plan(self) -> None:
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original = json.dumps(plan())
                (root / "plan.json").write_text(original)
                selected = selection()
                if corrupt:
                    selected["validationProfile"] = "full"
                (root / "selection.json").write_text(json.dumps(selected))
                result = subprocess.run(  # noqa: S603 - data-only repository validator; no builder or runtime operation.
                    [
                        os.sys.executable,
                        "-m",
                        "scripts.ci_validation_scope",
                        "--plan",
                        str(root / "plan.json"),
                        "--selection",
                        str(root / "selection.json"),
                        "--event-name",
                        "workflow_dispatch",
                        "--requested-profile",
                        PROFILE,
                        "--selected-profile",
                        PROFILE,
                        "--ref-name",
                        "reviewed",
                        "--source-revision",
                        "a" * 40,
                        "--default-branch",
                        "main",
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, not corrupt, result.stderr)
                if corrupt:
                    self.assertEqual((root / "plan.json").read_text(), original)
                else:
                    self.assertEqual(json.loads((root / "plan.json").read_text())["validationProfile"], PROFILE)


class BoundedWorkflowTests(unittest.TestCase):
    select = workflow_tests.DiagnosticDispatchTests.select

    @classmethod
    def setUpClass(cls) -> None:
        workflow_tests.DiagnosticDispatchTests.setUpClass.__func__(cls)

    def test_bounded_ascii_variants_select_ordinary_work_and_reject_focused_accounting(self) -> None:
        for raw in (PROFILE, PROFILE.upper(), "Docker-Rootless-Qualification"):
            with self.subTest(raw=raw):
                result, outputs = self.select("workflow_dispatch", raw, ref="refs/heads/reviewed")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    outputs,
                    {
                        "scope": "image",
                        "target": "docker-29-conformance-rootless",
                        "diagnostic_only": "false",
                        "runtime_mode": "qualification",
                        "focused_runtime": "none",
                        "validation_profile": PROFILE,
                    },
                )
                self.assertEqual(self.selection, selection())
                bad, outputs = self.select("workflow_dispatch", raw, "mandatory-accounting")
                self.assertNotEqual(bad.returncode, 0)
                self.assertEqual(outputs, {})
        for raw in (
            " " + PROFILE,
            PROFILE + " ",
            "\uff24ocker-rootless-qualification",
            "unknown",
            PROFILE + "\nscope=all",
        ):
            with self.subTest(raw=raw):
                result, outputs = self.select("workflow_dispatch", raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs, {})

    def test_scope_assertion_precedes_outputs_and_no_budget_or_publish_expansion_exists(self) -> None:
        steps = self.jobs["plan"]["steps"]
        guard = next(item for item in steps if item["name"] == "Assert selected CI scope")
        outputs = next(item for item in steps if item.get("id") == "outputs")
        self.assertLess(steps.index(guard), steps.index(outputs))
        self.assertIn("scripts.ci_validation_scope", guard["run"])
        self.assertEqual(
            self.jobs["plan"]["outputs"]["validation_profile"], "${{ steps.mode.outputs.validation_profile }}"
        )
        self.assertEqual(self.jobs["smoke-build"]["strategy"]["max-parallel"], 8)
        self.assertEqual(self.jobs["payloads"]["strategy"]["max-parallel"], 4)
        self.assertEqual(self.jobs["smoke-build"]["timeout-minutes"], 120)

    def test_partial_names_never_become_protected_checks_and_unknown_fallback_fails(self) -> None:
        aggregate = self.jobs["required-ci"]
        self.assertEqual(aggregate["if"], "${{ always() }}")
        self.assertNotIn("needs.", aggregate["name"])
        self.assertEqual(sum(job.get("name", "") == "Required CI" for job in self.jobs.values()), 0)
        for raw, expected in (
            (PROFILE, "Docker fixture qualification (bounded)"),
            (PROFILE.upper(), "Docker fixture qualification (bounded)"),
            ("docker-rootless-diagnostic", "Docker fixture diagnostic (not Required CI)"),
            ("full", "Required CI"),
            ("unknown", "Required CI"),
        ):
            self.assertEqual(
                workflow_tests.render_workflow_value(aggregate["name"], event="workflow_dispatch", profile=raw),
                expected,
            )
        script = aggregate["steps"][0]["run"]
        baseline = {
            "SELECTED_PROFILE": PROFILE,
            "REQUESTED_PROFILE": PROFILE,
            "DIAGNOSTIC_ONLY": "false",
            "REQUESTED_DIAGNOSTIC_ONLY": "false",
            "HAS_BUILDS": "true",
            "HAS_PAYLOADS": "true",
            "PAYLOAD_RESULT": "success",
            "PLAN_RESULT": "success",
            "SMOKE_RESULT": "success",
            "VALIDATE_RESULT": "success",
        }
        changes = [
            {},
            {"SELECTED_PROFILE": "full"},
            {"SELECTED_PROFILE": ""},
            {"REQUESTED_PROFILE": "invalid"},
            {"DIAGNOSTIC_ONLY": "true"},
            {"HAS_BUILDS": "false"},
            {"HAS_PAYLOADS": "false"},
        ]
        changes.extend(
            {key: value}
            for key in ("PLAN_RESULT", "VALIDATE_RESULT", "SMOKE_RESULT", "PAYLOAD_RESULT")
            for value in ("failure", "cancelled", "skipped", "")
        )
        for change in changes:
            with self.subTest(change=change):
                result = subprocess.run(  # noqa: S603 - execute only the repository-owned aggregate shell.
                    ["/bin/bash", "-c", script],
                    env={**os.environ, **baseline, **change},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, not change, result.stderr)
                self.assertNotIn("Required repository checks passed", result.stdout)


class BoundedAdmissionTests(unittest.TestCase):
    def test_root_and_producer_preserve_actual_profile_on_both_architectures(self) -> None:
        from scripts.docker_userns_active_bootstrap_bundle import context as produce  # noqa: PLC0415

        fixture = root_tests.MaintainedBootstrapContract()
        for architecture, image_os, runner_arch in (("amd64", "ubuntu26", "X64"), ("arm64", "ubuntu26-arm64", "ARM64")):
            with self.subTest(architecture=architecture):
                proof = root_tests.SyntheticProof()
                proof.context = workflow_context(
                    purpose="maintained-prerequisite",
                    candidate=proof.candidate,
                    architecture=architecture,
                    profile=PROFILE,
                    requested=PROFILE.upper(),
                )
                event = fixture.event(proof.context)
                environment = {
                    **root_tests.candidate_environment(proof.candidate),
                    "GITHUB_REF": proof.context["ref"],
                    "GITHUB_WORKFLOW_REF": proof.context["workflowRef"],
                    "ImageOS": image_os,
                    "ImageVersion": proof.context["imageVersion"],
                    "RUNNER_ARCH": runner_arch,
                }
                with root_tests.event_payload(json.dumps(event).encode()):
                    self.assertEqual(produce(environment, architecture), proof.context)
                _literal, mkdir = fixture.root(proof, event, architecture=architecture)
                mkdir.assert_called_once_with(mode=0o700)
                event["inputs"]["validation_profile"] = "full"
                _literal, mkdir = fixture.root(proof, event, architecture=architecture)
                mkdir.assert_not_called()

    def test_exact_allowset_schema_and_revision_cannot_be_replayed(self) -> None:
        path = Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json"
        document = json.loads(path.read_bytes())
        self.assertEqual(document["schemaVersion"], 6)
        self.assertEqual(document["revision"], "containers553-exact-conformance-images-v1")
        self.assertEqual(qualification.admission_document(path.read_bytes()), document)
        self.assertEqual(
            document["maintainedContext"]["images"],
            ["docker-29-conformance-rootless", "docker-29-8-1-conformance-rootless"],
        )
        self.assertEqual(document["context"]["image"], "docker-29-conformance-rootless")
        self.assertEqual(document["maintainedContext"]["validationProfiles"], ["full", PROFILE])
        for values in (
            ["full"],
            [PROFILE],
            ["full", PROFILE, "docker-rootless-diagnostic"],
            ["full", "full"],
            "full," + PROFILE,
            None,
        ):
            changed = copy.deepcopy(document)
            changed["maintainedContext"]["validationProfiles"] = values
            with self.subTest(values=values), self.assertRaises(qualification.QualificationError):
                qualification.admission_document(json.dumps(changed).encode())
        for key, value in (
            ("schemaVersion", 2),
            ("schemaVersion", 4),
            ("schemaVersion", True),
            ("revision", "containers527-maintained-native-v1"),
            ("revision", "unknown-revision"),
            ("unknownField", "unrecognized"),
        ):
            with self.subTest(key=key), self.assertRaises(qualification.QualificationError):
                qualification.admission_document(json.dumps({**document, key: value}).encode())

    def test_fixed_root_independently_rejects_malformed_connected_admission_allowset(self) -> None:
        fixture = root_tests.MaintainedBootstrapContract()
        raw = (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_bytes()
        for values in (
            ["full"],
            [PROFILE],
            ["full", PROFILE, "docker-rootless-diagnostic"],
            ["full", "full"],
            "full," + PROFILE,
        ):
            document = json.loads(raw)
            document["maintainedContext"]["validationProfiles"] = values
            proof = root_tests.SyntheticProof(admission_raw=json.dumps(document).encode())
            proof.context = workflow_context(
                purpose="maintained-prerequisite", candidate=proof.candidate, profile=PROFILE
            )
            proof.context["admissionSha256"] = root_tests.active.digest(proof.files[root_tests.producer.ADMISSION])
            with self.subTest(values=values):
                _literal, mkdir = fixture.root(proof, fixture.event(proof.context))
                mkdir.assert_not_called()

    def test_ordinary_archived_facts_stay_intrinsic_and_cross_profile_relabelling_refuses(self) -> None:
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture), patch.dict(os.environ, {}, clear=True):
                record = maintained_runtime(architecture, PROFILE)
                require_ordinary_runtime_authority(record, "docker", {"launcher": "systemd", "mode": "rootless"})
                for phase in record["phases"]:
                    phase["scopedProfile"]["workflowContext"]["validationProfile"] = "full"
                    phase["scopedProfile"]["workflowContext"]["validationProfileRequested"] = "full"
                with self.assertRaises(EvidenceError):
                    require_ordinary_runtime_authority(record, "docker", {"launcher": "systemd", "mode": "rootless"})

    def test_architecture_gate_recognizes_bounded_native_facts_but_keeps_scan_and_source_contracts(self) -> None:
        for architecture in ("amd64", "arm64"):
            runtime = maintained_runtime(architecture, PROFILE)
            identity = runtime["imageIdentity"]
            scan = {
                "image": "ghcr.io/strukturpiloten/docker-29-conformance-rootless",
                "architecture": architecture,
                "admission": "isolated-test",
                "decision": "passed",
                "sourceRevision": "a" * 40,
                "runId": "1",
                "runAttempt": "2",
                "candidateDigest": identity["manifestDigest"],
                "candidateSource": {**identity, "archiveSha256": "sha256:" + identity["archiveSha256"]},
                "baselineStatus": "absent",
                "baselineDigest": None,
                "baselineSource": {"status": "absent"},
                "scanner": {"version": "0.119.0"},
                "database": {"schemaVersion": "6"},
            }
            with (
                patch(
                    "scripts.evidence_gate.image_policy",
                    return_value={
                        "image": scan["image"],
                        "admission": "isolated-test",
                        "requiredRuntimeProfile": "docker",
                    },
                ),
                patch("scripts.evidence_gate.archive_identity", return_value=identity),
            ):
                for fault in (None, "scan", "source", "missing-native"):
                    selected = copy.deepcopy(runtime)
                    scan_record = copy.deepcopy(scan)
                    if fault == "scan":
                        scan_record["candidateSource"]["manifestDigest"] = "sha256:" + "f" * 64
                    elif fault == "source":
                        selected["runId"] = "999"
                    elif fault == "missing-native":
                        del selected["phases"][1]["scopedProfile"]
                    arguments = {
                        "name": runtime["image"],
                        "architecture": architecture,
                        "source_revision": "a" * 40,
                        "version": "1.0.0",
                        "run_id": "1",
                        "execution_attempt": 2,
                        "archive": Path("unused.tar"),
                        "runtime": selected,
                        "scan": scan_record,
                    }
                    with self.subTest(architecture=architecture, fault=fault):
                        if fault is None:
                            verify_architecture(**arguments)
                        else:
                            with self.assertRaises(EvidenceError):
                                verify_architecture(**arguments)

    def test_actual_bounded_phase_requires_real_prerequisite_facts_before_completion(self) -> None:
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                result, *_rest = lifecycle_tests.PhaseExecutionTests().execute(
                    lifecycle_tests._PhaseCase(
                        engine="docker",
                        ledger=True,
                        stage="owned-stage",
                        architecture=architecture,
                        scoped_receipt=scoped_receipt(
                            purpose="maintained-prerequisite",
                            architecture=architecture,
                            phase="enforcement",
                            requested=PROFILE,
                        ),
                    )
                )
                self.assertEqual(result["qualification"], "complete")
                self.assertEqual(result["scopedProfile"]["workflowContext"]["validationProfile"], PROFILE)
                self.assertEqual(result["focusedRuntime"], "none")

    def test_actual_bounded_pair_requires_both_native_phases_and_no_missing_stage_fallback(self) -> None:
        original = lifecycle_tests.scoped_receipt

        def bounded(**kwargs: object) -> dict:
            return original(**kwargs, requested=PROFILE)

        for architecture in ("amd64", "arm64"):
            with (
                self.subTest(architecture=architecture),
                patch.object(lifecycle_tests, "scoped_receipt", side_effect=bounded),
            ):
                result, _events = lifecycle_tests.PairAuthorityTests().pair(architecture=architecture, maintained=True)
                self.assertEqual(result["qualification"], "complete")
                self.assertEqual(result["workflowContext"]["validationProfile"], PROFILE)
            result, ctx, *_rest = lifecycle_tests.PhaseExecutionTests().execute(
                lifecycle_tests._PhaseCase(engine="docker", ledger=True, architecture=architecture)
            )
            self.assertEqual(result["qualification"], "none")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(ctx.probe_calls, 0)
