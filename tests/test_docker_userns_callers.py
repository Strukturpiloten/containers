"""Independent original-event/caller facts; no hosted operation or privileged workload."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import subprocess
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import docker_userns_active as active
from scripts import docker_userns_active_bootstrap_bundle as producer
from scripts import docker_userns_qualification as qualification
from scripts.evidence_gate import EvidenceError, require_ordinary_runtime_authority, verify_architecture
from scripts.maintenance import catalogue
from scripts.release_evidence import ReleaseEvidenceError
from tests import test_docker_userns_active as active_tests
from tests import test_maintenance as maintenance_tests
from tests import test_release_evidence as release_tests
from tests import test_runtime_oom_lifecycle as lifecycle_tests
from tests.test_docker_userns_qualification import scoped_receipt, stage_disposal, workflow_context
from tests.test_evidence_gate import maintained_runtime

REPOSITORY = "Strukturpiloten/containers"
CI = ".github/workflows/ci.yml"
PUBLICATION = ".github/workflows/publish-images.yml"
KINDS = (
    "ci-pr",
    "ci-merge-group",
    "ci-manual-full",
    "ci-manual-bounded",
    "ci-diagnostic",
    "publication-push",
    "publication-schedule",
    "publication-manual-all",
    "publication-manual-image",
    "publication-manual-family",
)


def caller_case(kind: str, architecture: str, candidate: str = "a" * 40) -> tuple[dict, dict, dict]:
    """Build expected caller/event facts independently from production classifiers."""
    purpose = "experimental-candidate" if kind == "ci-diagnostic" else "maintained-prerequisite"
    profile = "docker-rootless-qualification" if kind == "ci-manual-bounded" else "full"
    context = workflow_context(purpose=purpose, candidate=candidate, architecture=architecture, profile=profile)
    event = {"repository": {"full_name": REPOSITORY, "default_branch": "main"}}
    if kind in {"ci-manual-full", "ci-manual-bounded", "ci-diagnostic"}:
        event.update(
            workflow=CI, ref=context["ref"], inputs={"validation_profile": context["validationProfileRequested"]}
        )
    else:
        context.update(validationProfile="full", validationProfileRequested="", caller=kind)
        if kind == "ci-pr":
            context.update(
                event="pull_request",
                ref="refs/pull/17/merge",
                eventAction="synchronize",
                pullRequestNumber="17",
                eventHeadSha="b" * 40,
                eventBaseSha="c" * 40,
                eventHeadRef="refs/heads/TheRealBecks/feature",
                eventBaseRef="refs/heads/main",
                headRepository=REPOSITORY,
                baseRepository=REPOSITORY,
            )
            event.update(
                action="synchronize",
                number=17,
                pull_request={
                    "number": 17,
                    "merge_commit_sha": candidate,
                    "head": {"repo": {"full_name": REPOSITORY}, "sha": "b" * 40, "ref": "TheRealBecks/feature"},
                    "base": {"repo": {"full_name": REPOSITORY}, "sha": "c" * 40, "ref": "main"},
                },
            )
        elif kind == "ci-merge-group":
            context.update(
                event="merge_group",
                ref="refs/heads/gh-readonly-queue/main/opaque-group-17",
                eventAction="checks_requested",
                eventHeadSha=candidate,
                eventBaseSha="c" * 40,
                eventHeadRef="refs/heads/gh-readonly-queue/main/opaque-group-17",
                eventBaseRef="refs/heads/main",
            )
            event.update(
                action="checks_requested",
                merge_group={
                    "head_sha": candidate,
                    "base_sha": "c" * 40,
                    "head_ref": context["ref"],
                    "base_ref": "refs/heads/main",
                },
            )
        else:
            publication_case(kind, candidate, event, context)
    context["workflowRef"] = REPOSITORY + "/" + context["workflowPath"] + "@" + context["ref"]
    environment = {
        **active_tests.candidate_environment(candidate),
        "IMAGE_NAME": context["image"],
        "GITHUB_EVENT_NAME": context["event"],
        "GITHUB_REF": context["ref"],
        "GITHUB_WORKFLOW_REF": context["workflowRef"],
        "GITHUB_JOB": context["job"],
        "RUNNER_ARCH": "X64" if architecture == "amd64" else "ARM64",
        "ImageOS": context["imageOS"],
        "ImageVersion": context["imageVersion"],
    }
    return event, environment, context


def publication_case(kind: str, candidate: str, event: dict, context: dict) -> None:
    """Keep original publication events and leaf build identity explicit in fixtures."""
    context.update(workflowPath=PUBLICATION, job="build", defaultBranch="main", publicationScope="all")
    if kind == "publication-push":
        context.update(event="push", ref="refs/heads/main", eventHeadSha=candidate)
        event.update(ref="refs/heads/main", after=candidate, deleted=False)
    elif kind == "publication-schedule":
        context.update(event="schedule", ref="refs/heads/main", eventSchedule="47 3 * * *")
        event["schedule"] = "47 3 * * *"
    else:
        scope = kind.removeprefix("publication-manual-")
        target = {"all": "", "image": "docker-29-conformance-rootless", "family": "docker"}[scope]
        context.update(
            caller="publication-manual",
            event="workflow_dispatch",
            ref="refs/tags/reviewed-native-v1",
            publicationScope=scope,
            publicationTarget=target,
        )
        event.update(workflow=PUBLICATION, ref=context["ref"], inputs={"scope": scope, "target": target})


def caller_receipt(context: dict, phase: str) -> dict:
    """Join independent actual host/cleanup facts to the expected caller binding."""
    receipt = scoped_receipt(
        purpose=context["purpose"],
        phase=phase,
        candidate=context["candidate"],
        architecture=context["architecture"],
        requested=context["validationProfileRequested"],
    )
    binding = replace(
        qualification.NativeBinding(**receipt["binding"]),
        job=context["job"],
        run=context["run"],
        attempt=context["attempt"],
        workflow_context_sha256=qualification.context_digest(context),
    )
    receipt.update(
        workflowContext=copy.deepcopy(context),
        binding=asdict(binding),
        bindingSha256=binding.digest(),
        validationProfile=context["validationProfile"],
        validationProfileRequested=context["validationProfileRequested"],
    )
    receipt["profileName"] = f"dockerlens-127-upstream-rootless-{binding.run}-{binding.attempt}-{receipt['lease']}"
    observed = (receipt["profileName"] + " (unconfined)\n").encode()
    receipt["profileObservation"].update(bytes=len(observed), sha256=hashlib.sha256(observed).hexdigest())
    return receipt


def caller_record(context: dict) -> dict:
    """Produce a complete authored archived record without ambient consumer identity."""
    result = maintained_runtime(context["architecture"])
    result.update(
        producingJob=context["job"],
        runId=context["run"],
        runAttempt=context["attempt"],
        workflowContext=copy.deepcopy(context),
    )
    for phase in result["phases"]:
        phase["scopedProfile"] = caller_receipt(context, phase["phase"])
    result["stageDisposal"] = stage_disposal(result["phases"][1]["scopedProfile"])
    result["phases"][1]["stageDisposal"] = copy.deepcopy(result["stageDisposal"])
    return result


class CallerContextTests(unittest.TestCase):
    def test_every_finite_tuple_agrees_across_producer_fixed_root_and_archive_both_architectures(self) -> None:
        root = active_tests.MaintainedBootstrapContract()
        raw = (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_bytes()
        admission = qualification.admission_document(raw)
        for kind in KINDS:
            for architecture in ("amd64", "arm64"):
                with self.subTest(kind=kind, architecture=architecture):
                    proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40) if kind == "ci-pr" else ())
                    event, environment, expected = caller_case(kind, architecture, proof.candidate)
                    with (
                        patch.dict(os.environ, environment, clear=True),
                        active_tests.event_payload(json.dumps(event).encode()),
                    ):
                        actual = producer.context(environment, architecture)
                    self.assertEqual(actual, expected)
                    qualification.validate_workflow_context(actual, admission, expected["admissionSha256"])
                    proof.context = actual
                    _literal, mkdir = root.root(proof, event, architecture=architecture)
                    mkdir.assert_called_once_with(mode=0o700)
                    self.assertEqual(actual["candidate"], actual["workflow"])
                    self.assertEqual(actual["candidate"], actual["checkout"])

    def test_historical_fixture_is_bound_for_full_ordinary_callers_only(self) -> None:
        root = active_tests.MaintainedBootstrapContract()
        raw = (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_bytes()
        admission = qualification.admission_document(raw)
        for kind in KINDS:
            if kind in {"ci-manual-bounded", "ci-diagnostic"}:
                continue
            for architecture in ("amd64", "arm64"):
                with self.subTest(kind=kind, architecture=architecture):
                    proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40) if kind == "ci-pr" else ())
                    event, environment, expected = caller_case(kind, architecture, proof.candidate)
                    environment["IMAGE_NAME"] = expected["image"] = "docker-29-8-1-conformance-rootless"
                    if kind == "publication-manual-image":
                        event["inputs"]["target"] = expected["publicationTarget"] = expected["image"]
                    with (
                        patch.dict(os.environ, environment, clear=True),
                        active_tests.event_payload(json.dumps(event).encode()),
                    ):
                        actual = producer.context(environment, architecture)
                    self.assertEqual(actual, expected)
                    qualification.validate_workflow_context(actual, admission, expected["admissionSha256"])
                    proof.context = actual
                    _literal, mkdir = root.root(proof, event, architecture=architecture, environment=environment)
                    mkdir.assert_called_once_with(mode=0o700)
        for kind in ("ci-manual-bounded", "ci-diagnostic"):
            with self.subTest(kind=kind):
                self.refused(
                    kind,
                    lambda _event, environment, context: (
                        environment.update(IMAGE_NAME="docker-29-8-1-conformance-rootless"),
                        context.update(image="docker-29-8-1-conformance-rootless"),
                    ),
                )
        self.refused(
            "publication-manual-image",
            lambda _event, environment, context: (
                environment.update(IMAGE_NAME="docker-29-8-1-conformance-rootless"),
                context.update(image="docker-29-8-1-conformance-rootless"),
            ),
        )
        self.refused(
            "publication-manual-family",
            lambda event, environment, context: (
                event["inputs"].update(target="podman"),
                environment.update(IMAGE_NAME="docker-29-8-1-conformance-rootless"),
                context.update(image="docker-29-8-1-conformance-rootless", publicationTarget="podman"),
            ),
        )
        proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40))
        event, environment, expected = caller_case("ci-pr", "amd64", proof.candidate)
        environment["IMAGE_NAME"] = expected["image"] = "docker-29-8-1-conformance-rootless"
        proof.context = expected
        _literal, mkdir = root.root(
            proof, event, environment={**environment, "IMAGE_NAME": "docker-29-conformance-rootless"}
        )
        mkdir.assert_not_called()
        for image in ("", "unknown", "docker-29-8-2-conformance-rootless"):
            with self.subTest(image=image):
                self.refused(
                    "ci-pr",
                    lambda _event, environment, context, image=image: (
                        environment.update(IMAGE_NAME=image),
                        context.update(image=image),
                    ),
                )
        event, environment, _expected = caller_case("ci-pr", "amd64")
        environment.pop("IMAGE_NAME")
        with (
            patch.dict(os.environ, environment, clear=True),
            active_tests.event_payload(json.dumps(event).encode()),
            self.assertRaises(ValueError),
        ):
            producer.context(environment, "amd64")

    def refused(self, kind: str, mutate: object) -> None:
        proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40) if kind == "ci-pr" else ())
        event, environment, context = caller_case(kind, "amd64", proof.candidate)
        mutate(event, environment, context)
        with (
            patch.dict(os.environ, environment, clear=True),
            active_tests.event_payload(json.dumps(event).encode()),
            self.assertRaises((ValueError, qualification.QualificationError)),
        ):
            producer.context(environment, "amd64")
        proof.context = context
        root = active_tests.MaintainedBootstrapContract()
        _literal, mkdir = root.root(proof, event)
        mkdir.assert_not_called()

    def test_pr_forks_missing_heads_and_synthetic_merge_substitution_refuse_before_stage(self) -> None:
        mutations = {
            "fork": lambda event, _env, _ctx: event["pull_request"]["head"]["repo"].update(full_name="fork/containers"),
            "wrong-base": lambda event, _env, _ctx: event["pull_request"]["base"]["repo"].update(
                full_name="fork/containers"
            ),
            "missing-head": lambda event, _env, _ctx: event["pull_request"].update(head=None),
            "number": lambda event, _env, _ctx: event.update(number=18),
            "head-substitution": lambda event, _env, context: event["pull_request"]["head"].update(
                sha=context["candidate"]
            ),
        }
        for fault, mutation in mutations.items():
            with self.subTest(fault=fault):
                self.refused("ci-pr", mutation)

    def test_queue_and_publication_payload_contradictions_refuse(self) -> None:
        cases = (
            ("ci-merge-group", "head", lambda event, _env, _ctx: event["merge_group"].update(head_sha="f" * 40)),
            (
                "ci-merge-group",
                "ref",
                lambda event, _env, _ctx: event["merge_group"].update(head_ref="refs/heads/main"),
            ),
            ("ci-merge-group", "action", lambda event, _env, _ctx: event.update(action="destroyed")),
            ("publication-push", "delete", lambda event, _env, _ctx: event.update(deleted=True)),
            ("publication-push", "after", lambda event, _env, _ctx: event.update(after="f" * 40)),
            ("publication-push", "branch", lambda event, _env, _ctx: event.update(ref="refs/heads/other")),
            (
                "publication-schedule",
                "default",
                lambda event, _env, _ctx: event["repository"].update(default_branch="other"),
            ),
            ("publication-schedule", "missing", lambda event, _env, _ctx: event.pop("schedule")),
            (
                "publication-manual-image",
                "CI-input",
                lambda event, _env, _ctx: event["inputs"].update(validation_profile="docker-rootless-diagnostic"),
            ),
            ("publication-manual-all", "target", lambda event, _env, _ctx: event["inputs"].update(target="docker")),
        )
        for kind, fault, mutation in cases:
            with self.subTest(kind=kind, fault=fault):
                self.refused(kind, mutation)

    def test_missing_or_contradictory_original_event_facts_refuse_both_admission_actors(self) -> None:
        cases = (
            ("ci-pr", "base-missing", lambda event, _env, _ctx: event["pull_request"].pop("base")),
            ("ci-pr", "head-repo-missing", lambda event, _env, _ctx: event["pull_request"]["head"].pop("repo")),
            ("ci-pr", "base-sha", lambda event, _env, _ctx: event["pull_request"]["base"].update(sha="0" * 40)),
            ("ci-pr", "head-ref", lambda event, _env, _ctx: event["pull_request"]["head"].update(ref="../main")),
            ("ci-pr", "base-ref", lambda event, _env, _ctx: event["pull_request"]["base"].update(ref="")),
            ("ci-pr", "action", lambda event, _env, _ctx: event.update(action="closed")),
            ("ci-pr", "request-number", lambda event, _env, _ctx: event["pull_request"].update(number=18)),
            ("ci-pr", "number-type", lambda event, _env, _ctx: event.update(number="17")),
            ("ci-merge-group", "missing-group", lambda event, _env, _ctx: event.pop("merge_group")),
            (
                "ci-merge-group",
                "base-sha",
                lambda event, _env, ctx: event["merge_group"].update(base_sha=ctx["candidate"]),
            ),
            (
                "ci-merge-group",
                "base-ref",
                lambda event, _env, _ctx: event["merge_group"].update(base_ref="refs/tags/v1"),
            ),
            ("publication-push", "missing-delete", lambda event, _env, _ctx: event.pop("deleted")),
            ("publication-push", "delete-type", lambda event, _env, _ctx: event.update(deleted="false")),
            ("publication-push", "default-branch", lambda event, _env, _ctx: event["repository"].pop("default_branch")),
            ("publication-schedule", "cron-type", lambda event, _env, _ctx: event.update(schedule=["47 3 * * *"])),
            ("publication-schedule", "cron-shape", lambda event, _env, _ctx: event.update(schedule="@daily")),
            ("publication-schedule", "cron-size", lambda event, _env, _ctx: event.update(schedule="1" * 97)),
            ("publication-schedule", "ref", lambda event, _env, _ctx: event.update(ref="refs/heads/other")),
            ("publication-manual-image", "empty-target", lambda event, _env, _ctx: event["inputs"].update(target="")),
            (
                "publication-manual-family",
                "unsafe-target",
                lambda event, _env, _ctx: event["inputs"].update(target="../docker"),
            ),
            ("publication-manual-all", "scope", lambda event, _env, _ctx: event["inputs"].update(scope="diagnostic")),
            ("publication-manual-all", "workflow", lambda event, _env, _ctx: event.update(workflow=CI)),
            ("publication-manual-all", "ref", lambda event, _env, _ctx: event.update(ref="refs/heads/other")),
            ("publication-manual-all", "inputs-type", lambda event, _env, _ctx: event.update(inputs=[])),
        )
        for kind, fault, mutation in cases:
            with self.subTest(kind=kind, fault=fault):
                self.refused(kind, mutation)
        for kind in ("ci-pr", "ci-merge-group", "publication-push", "publication-schedule", "publication-manual-all"):
            with self.subTest(kind=kind, fault="repository"):
                self.refused(kind, lambda event, _env, _ctx: event["repository"].update(full_name="fork/containers"))

    def test_each_caller_scalar_is_independently_bound_before_root_stage_write(self) -> None:
        for kind in ("ci-pr", "ci-merge-group", "publication-push", "publication-schedule", "publication-manual-all"):
            for key, value in (
                ("GITHUB_SHA", "f" * 40),
                ("GITHUB_WORKFLOW_SHA", "f" * 40),
                ("GITHUB_REF", "refs/heads/other"),
                ("GITHUB_WORKFLOW_REF", REPOSITORY + "/.github/workflows/unrelated.yml@refs/heads/main"),
                ("GITHUB_JOB", "finalize"),
                ("GITHUB_EVENT_NAME", "workflow_call"),
            ):
                proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40) if kind == "ci-pr" else ())
                event, environment, proof.context = caller_case(kind, "amd64", proof.candidate)
                changed = {**environment, key: value}
                with (
                    self.subTest(kind=kind, key=key),
                    active_tests.event_payload(json.dumps(event).encode()),
                    self.assertRaises((ValueError, qualification.QualificationError)),
                ):
                    producer.context(changed, "amd64")
                _literal, mkdir = active_tests.MaintainedBootstrapContract().root(proof, event, environment=changed)
                mkdir.assert_not_called()

    def test_prior_protocol_or_changed_finite_policy_cannot_reach_root_stage(self) -> None:
        raw = (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_bytes()
        baseline = json.loads(raw)
        variants = [(f"schema-{version}", {**baseline, "schemaVersion": version}) for version in (1, 2, 3, 4, 5, True)]
        for fault in ("missing", "extra", "job", "event", "workflow", "refPolicy", "selector"):
            admission = copy.deepcopy(baseline)
            if fault == "missing":
                admission["maintainedCallers"].pop("publication-push")
            elif fault == "extra":
                admission["maintainedCallers"]["unrelated"] = admission["maintainedCallers"]["ci-pr"]
            else:
                admission["maintainedCallers"]["publication-push"][fault] = "unrelated"
            variants.append((fault, admission))
        for fault, admission in variants:
            raw = json.dumps(admission).encode()
            proof = active_tests.SyntheticProof(admission_raw=raw)
            event, environment, proof.context = caller_case("publication-push", "amd64", proof.candidate)
            proof.context["admissionSha256"] = hashlib.sha256(raw).hexdigest()
            with self.subTest(fault=fault):
                with self.assertRaises(qualification.QualificationError):
                    qualification.admission_document(raw)
                _literal, mkdir = active_tests.MaintainedBootstrapContract().root(proof, event, environment=environment)
                mkdir.assert_not_called()

    def test_automatic_inputs_cannot_switch_into_ci_diagnostic_or_bounded_scope(self) -> None:
        for kind in ("ci-pr", "ci-merge-group", "publication-push", "publication-schedule"):
            event, environment, expected = caller_case(kind, "amd64")
            event["inputs"] = {
                "validation_profile": "docker-rootless-diagnostic",
                "focused_runtime": "mandatory-accounting",
            }
            with self.subTest(kind=kind), active_tests.event_payload(json.dumps(event).encode()):
                actual = producer.context(environment, "amd64")
                self.assertEqual(actual, expected)
                self.assertEqual(actual["purpose"], "maintained-prerequisite")
                self.assertEqual(actual["validationProfileRequested"], "")

    def test_unknown_callee_job_event_workflow_runner_and_source_are_not_callers(self) -> None:
        for key, value in (
            ("GITHUB_WORKFLOW_REF", REPOSITORY + "/.github/workflows/publish-one-image.yml@refs/heads/main"),
            ("GITHUB_JOB", "publish-stage-0"),
            ("GITHUB_JOB", "publish"),
            ("GITHUB_EVENT_NAME", "workflow_call"),
            ("GITHUB_EVENT_NAME", "pull_request_target"),
            ("GITHUB_REPOSITORY", "fork/containers"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_WORKFLOW_SHA", "f" * 40),
        ):
            event, environment, _expected = caller_case("publication-push", "amd64")
            with (
                self.subTest(key=key, value=value),
                active_tests.event_payload(json.dumps(event).encode()),
                self.assertRaises((ValueError, qualification.QualificationError)),
            ):
                producer.context({**environment, key: value}, "amd64")
            if key != "RUNNER_ENVIRONMENT":
                proof = active_tests.SyntheticProof()
                event, environment, proof.context = caller_case("publication-push", "amd64", proof.candidate)
                _literal, mkdir = active_tests.MaintainedBootstrapContract().root(
                    proof, event, environment={**environment, key: value}
                )
                mkdir.assert_not_called()


class CallerNativeEvidenceTests(unittest.TestCase):
    def test_every_maintained_archived_tuple_is_intrinsic_in_other_consumer_jobs(self) -> None:
        for kind in KINDS:
            if kind == "ci-diagnostic":
                continue
            for architecture in ("amd64", "arm64"):
                _event, _environment, context = caller_case(kind, architecture)
                record = caller_record(context)
                with (
                    self.subTest(kind=kind, architecture=architecture),
                    patch.dict(
                        os.environ,
                        {
                            "GITHUB_JOB": "finalize",
                            "GITHUB_EVENT_NAME": "workflow_call",
                            "GITHUB_SHA": "f" * 40,
                            "GITHUB_RUN_ID": "999",
                            "GITHUB_RUN_ATTEMPT": "9",
                            "ImageVersion": "20270101.999.9",
                        },
                        clear=True,
                    ),
                ):
                    require_ordinary_runtime_authority(record, "docker", {"launcher": "systemd", "mode": "rootless"})

    def test_job_bindings_failure_projection_and_detached_ack_remain_closed(self) -> None:
        _event, _environment, context = caller_case("publication-push", "arm64")
        record = caller_record(context)
        binding = qualification.NativeBinding(**record["phases"][0]["scopedProfile"]["binding"])
        self.assertEqual(binding.job, "build")
        failure = active.failure_receipt(
            {"actor": "root", "operation": "prepare", "binding": binding}, PermissionError(13, "private")
        )
        self.assertTrue(active.valid_failure(failure))
        self.assertEqual(failure["context"]["job"], "build")
        for key, value in (("producingJob", "smoke-build"), ("runId", "999"), ("stageDisposal", {})):
            changed = copy.deepcopy(record)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(changed, "docker", {"launcher": "systemd", "mode": "rootless"})
        with self.assertRaises(qualification.QualificationError):
            replace(binding, job="publish-stage-0").validate()


def activation_expression(
    context: dict, event: dict, *, runner_environment: str = "github-hosted", runner_os: str = "Linux"
) -> bool:
    """Evaluate only the inert Boolean grammar used by the real Action expression."""
    action = Path(__file__).resolve().parents[1] / ".github/actions/build-arch-image/action.yml"
    document = yaml.safe_load(action.read_text())
    expression = next(
        step["env"]["ACTIVE_USERNS_CONTEXT"]
        for step in document["runs"]["steps"]
        if "ACTIVE_USERNS_CONTEXT" in step.get("env", {})
    )
    source = expression.removeprefix("${{").removesuffix("}}").replace("&&", " and ").replace("||", " or ")
    values = {
        "github": {
            "repository": context["repository"],
            "event_name": context["event"],
            "workflow_ref": context["workflowRef"],
            "job": context["job"],
            "ref": context["ref"],
            "event": event,
        },
        "runner": {"os": runner_os, "environment": runner_environment},
        "inputs": {"entry": json.dumps({"arch": context["architecture"]})},
        "false": False,
    }
    return bool(_expression_value(ast.parse(source.strip(), mode="eval").body, values))


def _expression_value(node: ast.AST, values: dict) -> object:
    """Interpret explicit expression nodes without executing generated source."""
    match node:
        case ast.Constant(value=value):
            result = value
        case ast.Name(id=name):
            result = values[name]
        case ast.Attribute(value=parent, attr=attribute):
            container = _expression_value(parent, values)
            result = container.get(attribute, "") if isinstance(container, dict) else ""
        case ast.BoolOp(op=ast.And(), values=children):
            result = all(_expression_value(child, values) for child in children)
        case ast.BoolOp(op=ast.Or(), values=children):
            result = any(_expression_value(child, values) for child in children)
        case ast.Compare(left=left, ops=[ast.Eq()], comparators=[right]):
            result = _expression_value(left, values) == _expression_value(right, values)
        case ast.Call(func=ast.Name(id="startsWith"), args=[left, right], keywords=[]):
            result = str(_expression_value(left, values)).startswith(str(_expression_value(right, values)))
        case ast.Call(func=ast.Name(id="fromJSON"), args=[child], keywords=[]):
            result = json.loads(_expression_value(child, values))
        case _:
            raise AssertionError(ast.dump(node))

    return result


class CallerActivationTests(unittest.TestCase):
    def test_real_action_expression_activates_every_supported_original_tuple(self) -> None:
        for kind in KINDS:
            for architecture in ("amd64", "arm64"):
                event, _environment, context = caller_case(kind, architecture)
                with self.subTest(kind=kind, architecture=architecture):
                    self.assertTrue(activation_expression(context, event))

    def test_real_action_expression_refuses_unknown_scalar_and_fork_contexts(self) -> None:
        event, _environment, context = caller_case("publication-push", "amd64")
        for field, value in (
            ("repository", "fork/containers"),
            ("job", "publish-stage-0"),
            ("job", "publish"),
            ("event", "workflow_call"),
            ("architecture", "riscv64"),
            ("workflowRef", REPOSITORY + "/.github/workflows/publish-one-image.yml@refs/heads/main"),
            ("ref", "refs/heads/other"),
        ):
            with self.subTest(field=field):
                self.assertFalse(activation_expression({**context, field: value}, event))
        self.assertFalse(activation_expression(context, event, runner_environment="self-hosted"))
        self.assertFalse(activation_expression(context, event, runner_os="Windows"))
        for field in ("head", "base"):
            event, _environment, context = caller_case("ci-pr", "amd64")
            event["pull_request"][field]["repo"]["full_name"] = "fork/containers"
            self.assertFalse(activation_expression(context, event))

    def test_activation_boolean_does_not_replace_root_source_or_event_checks(self) -> None:
        proof = active_tests.SyntheticProof(parents=("c" * 40, "d" * 40))
        event, environment, context = caller_case("ci-pr", "amd64", proof.candidate)
        self.assertTrue(activation_expression(context, event))
        proof.context = context
        _literal, mkdir = active_tests.MaintainedBootstrapContract().root(proof, event, environment=environment)
        mkdir.assert_not_called()


class CallerPhaseAndConsumerTests(unittest.TestCase):
    execute = lifecycle_tests.PhaseExecutionTests.execute
    pair = lifecycle_tests.PairAuthorityTests.pair

    def test_actual_phase_pair_accepts_all_maintained_callers_and_binds_leaf_job(self) -> None:
        for kind in KINDS:
            if kind == "ci-diagnostic":
                continue
            for architecture in ("amd64", "arm64"):
                _event, _environment, context = caller_case(kind, architecture)

                def authored_receipt(*, phase: str, fixture_context: dict = context, **_unused: object) -> dict:
                    return caller_receipt(fixture_context, phase)

                with (
                    self.subTest(kind=kind, architecture=architecture),
                    patch.object(lifecycle_tests, "scoped_receipt", side_effect=authored_receipt),
                    patch.dict(os.environ, {"GITHUB_JOB": "unrelated", "GITHUB_SHA": "f" * 40}, clear=True),
                ):
                    result, _events = self.pair(maintained=True, architecture=architecture)
                    self.assertEqual(result["status"], "passed")
                    self.assertEqual(result["qualification"], "complete")
                    self.assertEqual(result["producingJob"], context["job"])
                    self.assertEqual(result["workflowContext"], context)
                    require_ordinary_runtime_authority(result, "docker", {"launcher": "systemd", "mode": "rootless"})

    def verify_archive(self, runtime: dict, architecture: str, *, missing_scan: bool = False) -> None:
        identity = runtime["imageIdentity"]
        scan = {
            "image": "ghcr.io/strukturpiloten/docker-29-conformance-rootless",
            "architecture": architecture,
            "admission": "isolated-test",
            "decision": "passed",
            "sourceRevision": "a" * 40,
            "runId": "1",
            "runAttempt": "2",
            "candidateSource": copy.deepcopy(identity),
            "baselineStatus": "absent",
            "baselineDigest": None,
            "baselineSource": {"status": "absent"},
            "scanner": {"version": "fixture"},
            "database": {"version": "fixture"},
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
            patch(
                "scripts.evidence_gate.archive_identity", return_value=maintained_runtime(architecture)["imageIdentity"]
            ),
            patch(
                "scripts.evidence_gate.container_engine._load_images",
                return_value=[
                    {
                        "name": "docker-29-conformance-rootless",
                        "tests": {"docker": {"launcher": "systemd", "mode": "rootless"}},
                    }
                ],
            ),
        ):
            verify_architecture(
                name="docker-29-conformance-rootless",
                architecture=architecture,
                source_revision="a" * 40,
                version="1.0.0",
                run_id="1",
                execution_attempt=2,
                archive=Path("fixture.tar"),
                runtime=runtime,
                scan={} if missing_scan else scan,
            )

    def test_publisher_release_and_catalogue_accept_original_build_job_and_prior_attempt(self) -> None:
        for kind in ("publication-push", "publication-schedule", "publication-manual-image"):
            for architecture in ("amd64", "arm64"):
                _event, _environment, context = caller_case(kind, architecture)
                for attempt in ("1", "2"):
                    record = caller_record({**context, "attempt": attempt})
                    with (
                        self.subTest(kind=kind, architecture=architecture, attempt=attempt),
                        patch.dict(
                            os.environ, {"GITHUB_JOB": "finalize", "GITHUB_EVENT_NAME": "workflow_call"}, clear=True
                        ),
                    ):
                        self.verify_archive(record, architecture)
                        release_tests.MaintainedPrerequisiteReleaseConsumerTests().validate(record, architecture)
                        image = maintenance_tests.MaintainedPrerequisiteCatalogueTests().image(architecture)
                        row = catalogue([image], runtime_results={image["name"]: [record]})["images"][0]
                        self.assertEqual(row["runtimeCoverage"][architecture]["docker"]["nativeAuthority"], "ordinary")
                        self.assertEqual(row["registry"]["status"], "unknown")

    def test_consumers_refuse_missing_scan_publication_or_future_cross_build_facts(self) -> None:
        for architecture in ("amd64", "arm64"):
            _event, _environment, context = caller_case("publication-push", architecture)
            baseline = caller_record(context)
            with self.assertRaises(EvidenceError):
                self.verify_archive(baseline, architecture, missing_scan=True)
            for missing in ("scan", "publication"):
                with self.subTest(missing=missing), self.assertRaises(ReleaseEvidenceError):
                    release_tests.MaintainedPrerequisiteReleaseConsumerTests().validate(baseline, architecture, missing)
            changes = {
                "future-attempt": {**context, "attempt": "3"},
                "cross-run": {**context, "run": "999"},
            }
            records = [(key, caller_record(value)) for key, value in changes.items()]
            for field in ("sourceRevision", "archiveSha256", "configDigest"):
                changed = copy.deepcopy(baseline)
                changed["imageIdentity"][field] = "f" * 40 if field == "sourceRevision" else "f" * 64
                records.append((field, changed))
            for part in ("receipt", "acknowledgment"):
                changed = copy.deepcopy(baseline)
                if part == "receipt":
                    changed["phases"][0]["scopedProfile"]["schemaVersion"] = 2
                else:
                    changed["stageDisposal"]["schemaVersion"] = 2
                records.append(("prior-" + part + "-protocol", changed))
            changed = copy.deepcopy(baseline)
            changed["stageDisposal"]["bootstrapSha256"] = "f" * 64
            records.append(("forged-disposal", changed))
            for fault, record in records:
                with self.subTest(fault=fault, architecture=architecture):
                    with self.assertRaises(EvidenceError):
                        self.verify_archive(record, architecture)
                    with self.assertRaises(ReleaseEvidenceError):
                        release_tests.MaintainedPrerequisiteReleaseConsumerTests().validate(record, architecture)


def collect_proof(proof: active_tests.SyntheticProof, reads: list[tuple[str, str]]) -> list[dict]:
    """Mock external Git reads while retaining its real size/hash validation."""

    def read(command: list[str], **_options: object) -> subprocess.CompletedProcess:
        identifier = command[-1]
        item = proof.objects[identifier]
        raw = base64.b64decode(item["data"])
        if command[-2] == "-s":
            result = str(len(raw)).encode() + b"\n"
        else:
            reads.append((command[-2], identifier))
            if command[-2] != item["kind"]:
                raise AssertionError(command)
            result = raw
        return subprocess.CompletedProcess(command, 0, stdout=result)

    with patch.object(producer.git.subprocess, "run", side_effect=read):
        return producer.proof(proof.candidate, proof.context)


class PullRequestParentProofTests(unittest.TestCase):
    def root(self, proof: active_tests.SyntheticProof, event: dict, environment: dict) -> tuple[object, object]:
        literal = active_tests.literal_namespace()
        with patch.dict(literal, {"tree": unittest.mock.Mock(wraps=literal["tree"])}) as namespace:
            tree_reader = namespace["tree"]
            with patch.object(active_tests, "literal_namespace", return_value=literal):
                _literal, mkdir = active_tests.MaintainedBootstrapContract().root(
                    proof, event, architecture=proof.context["architecture"], environment=environment
                )
        return tree_reader, mkdir

    def test_null_absent_matching_and_stale_caches_are_advisory_for_real_parent_proof(self) -> None:
        for architecture in ("amd64", "arm64"):
            proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40))
            for action in ("opened", "synchronize", "reopened"):
                for cache in ("absent", None, proof.candidate, "f" * 40, "b" * 40, "c" * 40):
                    event, environment, expected = caller_case("ci-pr", architecture, proof.candidate)
                    event["action"] = expected["eventAction"] = action
                    if cache == "absent":
                        event["pull_request"].pop("merge_commit_sha")
                    else:
                        event["pull_request"]["merge_commit_sha"] = cache
                    with (
                        self.subTest(architecture=architecture, action=action, cache=cache),
                        active_tests.event_payload(json.dumps(event).encode()),
                    ):
                        proof.context = producer.context(environment, architecture)
                        self.assertEqual(proof.context, expected)
                        reads = []
                        objects = collect_proof(proof, reads)
                        self.assertEqual({item["oid"] for item in objects}, set(proof.objects))
                        self.assertEqual(reads[0], ("commit", proof.candidate))
                        tree_reader, mkdir = self.root(proof, event, environment)
                        self.assertTrue(tree_reader.called)
                        mkdir.assert_called_once_with(mode=0o700)

    def test_malformed_nonnull_cache_is_refused_by_both_original_event_classifiers(self) -> None:
        for cache in (True, False, 1, 0, {}, [], "", " ", "a" * 39, "g" * 40, "0" * 40, "a" * 41):
            proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40))
            event, environment, proof.context = caller_case("ci-pr", "amd64", proof.candidate)
            event["pull_request"]["merge_commit_sha"] = cache
            with (
                self.subTest(cache=cache),
                active_tests.event_payload(json.dumps(event).encode()),
                self.assertRaises((ValueError, qualification.QualificationError)),
            ):
                producer.context(environment, "amd64")
            tree_reader, mkdir = self.root(proof, event, environment)
            tree_reader.assert_not_called()
            mkdir.assert_not_called()

    def assert_bad_parents(self, proof: active_tests.SyntheticProof) -> None:
        event, environment, proof.context = caller_case("ci-pr", "amd64", proof.candidate)
        with active_tests.event_payload(json.dumps(event).encode()):
            self.assertEqual(producer.context(environment, "amd64"), proof.context)
        self.assertTrue(activation_expression(proof.context, event))
        # This independently computed identifier remains coherent in all selected scalars.
        raw = base64.b64decode(proof.objects[proof.candidate]["data"])
        actual = hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
        self.assertEqual(proof.candidate, actual)
        reads = []
        with self.assertRaises((ValueError, qualification.QualificationError)):
            collect_proof(proof, reads)
        self.assertEqual(reads, [("commit", proof.candidate)])
        tree_reader, mkdir = self.root(proof, event, environment)
        tree_reader.assert_not_called()
        mkdir.assert_not_called()

    def test_hash_valid_wrong_missing_reversed_extra_and_other_pr_parents_refuse_before_tree(self) -> None:
        for parents in (
            (),
            ("c" * 40,),
            ("b" * 40,),
            ("b" * 40, "c" * 40),
            ("c" * 40, "c" * 40),
            ("d" * 40, "b" * 40),
            ("c" * 40, "d" * 40),
            ("d" * 40, "e" * 40),
            ("c" * 40, "b" * 40, "d" * 40),
            ("c" * 40 + " trailing", "b" * 40),
        ):
            with self.subTest(parents=parents):
                self.assert_bad_parents(active_tests.SyntheticProof(parents=parents))

    def test_message_and_signed_continuations_are_not_top_level_parents(self) -> None:
        suffix = (
            b"author Fixture <fixture@example.invalid> 1 +0000\n"
            b"committer Fixture <fixture@example.invalid> 1 +0000\n"
            b"gpgsig -----BEGIN FIXTURE-----\n parent "
            + b"f" * 40
            + b"\n -----END FIXTURE-----\n\nparent "
            + b"e" * 40
            + b"\n"
        )
        proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40), commit_suffix=suffix)
        event, environment, proof.context = caller_case("ci-pr", "amd64", proof.candidate)
        objects = collect_proof(proof, [])
        self.assertEqual({item["oid"] for item in objects}, set(proof.objects))
        _tree_reader, mkdir = self.root(proof, event, environment)
        mkdir.assert_called_once_with(mode=0o700)

    def test_late_or_malformed_top_level_parent_headers_and_missing_separator_refuse(self) -> None:
        for header in (b"parent " + b"d" * 40, b"parent", b"parent\t" + b"d" * 40, b"parentish wrong"):
            suffix = b"author Fixture <fixture@example.invalid> 1 +0000\n" + header + b"\n\nfixture\n"
            with self.subTest(header=header):
                self.assert_bad_parents(active_tests.SyntheticProof(parents=("c" * 40, "b" * 40), commit_suffix=suffix))
        self.assert_bad_parents(
            active_tests.SyntheticProof(parents=("c" * 40, "b" * 40), commit_suffix=b"author Fixture\n")
        )

    def test_existing_hash_authentication_still_refuses_changed_candidate_bytes(self) -> None:
        proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40))
        item = proof.objects[proof.candidate]
        item["data"] = base64.b64encode(base64.b64decode(item["data"]) + b"tampered").decode()
        event, environment, proof.context = caller_case("ci-pr", "amd64", proof.candidate)
        reads = []
        with self.assertRaises(ValueError):
            collect_proof(proof, reads)
        self.assertEqual(reads, [("commit", proof.candidate)])
        tree_reader, mkdir = self.root(proof, event, environment)
        tree_reader.assert_not_called()
        mkdir.assert_not_called()

    def test_actual_head_and_base_selection_refuse_despite_advisory_cache(self) -> None:
        for role in ("head", "base"):
            for cache in (None, "f" * 40):
                proof = active_tests.SyntheticProof(parents=("c" * 40, "b" * 40))
                event, environment, proof.context = caller_case("ci-pr", "amd64", proof.candidate)
                event["pull_request"][role]["sha"] = proof.candidate
                event["pull_request"]["merge_commit_sha"] = cache
                with (
                    self.subTest(role=role, cache=cache),
                    active_tests.event_payload(json.dumps(event).encode()),
                    self.assertRaises((ValueError, qualification.QualificationError)),
                ):
                    producer.context(environment, "amd64")
                tree_reader, mkdir = self.root(proof, event, environment)
                tree_reader.assert_not_called()
                mkdir.assert_not_called()

    def test_other_callers_keep_their_own_commit_shape_and_archives_invent_no_cache(self) -> None:
        for kind in KINDS:
            if kind == "ci-pr":
                continue
            proof = active_tests.SyntheticProof()
            _event, _environment, proof.context = caller_case(kind, "amd64", proof.candidate)
            with self.subTest(kind=kind):
                self.assertEqual({item["oid"] for item in collect_proof(proof, [])}, set(proof.objects))
        _event, _environment, context = caller_case("ci-pr", "amd64")
        self.assertNotIn("merge_commit_sha", qualification._archived_event(context)["pull_request"])
        record = caller_record(context)
        require_ordinary_runtime_authority(record, "docker", {"launcher": "systemd", "mode": "rootless"})
        for key in ("eventHeadSha", "eventBaseSha"):
            changed = copy.deepcopy(record)
            changed["workflowContext"][key] = "d" * 40
            for phase in changed["phases"]:
                phase["scopedProfile"]["workflowContext"][key] = "d" * 40
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(changed, "docker", {"launcher": "systemd", "mode": "rootless"})

    def test_public_current_protocol_versions_match_accepted_artifacts(self) -> None:
        document = (Path(__file__).resolve().parents[1] / "docs/runtime-backends.md").read_text()
        self.assertIn(
            f"acknowledgments use schema {qualification.PREREQUISITE_SCHEMA}. "
            f"Admission uses schema {qualification.ADMISSION_SCHEMA}:",
            document,
        )
        _event, _environment, context = caller_case("ci-pr", "amd64")
        self.assertEqual(len(context), 34)
