"""Independent direct-only source, caller and policy-discriminator controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import asdict, replace

from scripts import docker_direct_startup_contract as direct
from scripts import docker_userns_active_bootstrap_bundle as producer
from scripts import docker_userns_qualification as qualification
from tests import test_docker_userns_active as active_tests
from tests.test_docker_direct_startup_contract import binding
from tests.test_docker_userns_qualification import workflow_context


class DirectAdmissionTests(unittest.TestCase):
    def fixture(self, image: str, architecture: str) -> tuple:
        """Derive independently expected fields from the original manual event."""
        proof = active_tests.SyntheticProof()
        context = workflow_context(
            purpose="maintained-prerequisite",
            candidate=proof.candidate,
            architecture=architecture,
            profile="docker-direct-rootless-diagnostic",
        )
        context.update(
            ref="refs/heads/TheRealBecks/issue442-direct-startup-20261031",
            workflowRef=(
                "Strukturpiloten/containers/.github/workflows/ci.yml@"
                "refs/heads/TheRealBecks/issue442-direct-startup-20261031"
            ),
            purpose="direct-startup-diagnostic",
            image=image,
            diagnosticVariant="direct-uid1000-profiled-b",
            launcher="direct",
            expectedUid="1000",
            diagnosticArm="B",
        )
        context["imageVersion"] = "20261026.180.1"
        proof.context = context
        environment = {
            **active_tests.candidate_environment(proof.candidate),
            "GITHUB_REF": context["ref"],
            "GITHUB_WORKFLOW_REF": context["workflowRef"],
            "RUNNER_ARCH": {"amd64": "X64", "arm64": "ARM64"}[architecture],
            "ImageOS": {"amd64": "ubuntu26", "arm64": "ubuntu26-arm64"}[architecture],
            "IMAGE_NAME": image,
        }
        event = {
            "inputs": {"validation_profile": "docker-direct-rootless-diagnostic"},
            "repository": {"full_name": "Strukturpiloten/containers"},
            "workflow": ".github/workflows/ci.yml",
            "ref": context["ref"],
        }
        return proof, context, environment, event

    def test_exact_pairs_agree_between_producer_fixed_root_and_archived_context(self) -> None:
        for image, architecture in (("docker-20.10-rootless", "amd64"), ("docker-26-rootless", "arm64")):
            with self.subTest(image=image, architecture=architecture):
                proof, context, environment, event = self.fixture(image, architecture)
                with active_tests.event_payload(json.dumps(event).encode()):
                    self.assertEqual(producer.context(environment, architecture), context)
                literal, writes = active_tests.MaintainedBootstrapContract().root(
                    proof,
                    event,
                    architecture=architecture,
                )
                writes.assert_called_once()
                self.assertEqual(literal["DIAGNOSTIC"]["context"]["image"], image)
                raw = (active_tests.ROOT / producer.ADMISSION).read_bytes()
                qualification.validate_workflow_context(
                    context,
                    qualification.admission_document(raw),
                    hashlib.sha256(raw).hexdigest(),
                )
                self.assertEqual(len(context), 38)

    def test_wrong_caller_source_image_architecture_uid_arm_and_shape_stop_before_root_write(self) -> None:
        for field, value in (
            ("image", "docker-29-conformance-rootless"),
            ("image", "docker-26-rootless"),
            ("architecture", "arm64"),
            ("expectedUid", "0"),
            ("expectedUid", 1000),
            ("diagnosticArm", "A"),
            ("launcher", "systemd"),
            ("diagnosticVariant", "native29"),
            ("job", "build"),
            ("candidate", "f" * 40),
            ("qualification", "complete"),
        ):
            proof, _context, _environment, event = self.fixture("docker-20.10-rootless", "amd64")
            proof.context[field] = value
            with self.subTest(field=field, value=value):
                _literal, writes = active_tests.MaintainedBootstrapContract().root(proof, event)
                writes.assert_not_called()
        for field, value in (
            ("ref", "refs/heads/main"),
            ("workflow", ".github/workflows/publish-images.yml"),
            ("repository", {"full_name": "attacker/containers"}),
            (
                "inputs",
                {"validation_profile": "docker-direct-rootless-diagnostic", "focused_runtime": "mandatory-accounting"},
            ),
        ):
            proof, _context, _environment, event = self.fixture("docker-20.10-rootless", "amd64")
            event[field] = value
            with self.subTest(field=field):
                _literal, writes = active_tests.MaintainedBootstrapContract().root(proof, event)
                writes.assert_not_called()

    def test_control_has_its_actual_a_identity_and_cannot_enter_policy_factory(self) -> None:
        values = asdict(binding())
        values.update(variant="direct-uid1000-unprofiled-a", phase="direct-control", arm="A")
        control = direct.DirectControlBinding(**values)
        control.validate()
        self.assertEqual(control.arm, "A")
        with self.assertRaises(qualification.QualificationError):
            qualification.native_binding(asdict(control))
        self.assertIs(type(qualification.native_binding(asdict(binding()))), direct.DirectDiagnosticBinding)
        for values in ({"arm": "A"}, {"expected_uid": "0"}, {"phase": "enforcement"}):
            with self.subTest(values=values), self.assertRaises(qualification.QualificationError):
                qualification.native_binding(asdict(replace(binding(), **values)))

    def test_direct_admission_neither_relabels_nor_widens_old_arm_observation(self) -> None:
        proof, context, _environment, _event = self.fixture("docker-26-rootless", "arm64")
        raw = proof.files[producer.ADMISSION]
        admission = qualification.admission_document(raw)
        self.assertEqual(admission["architectures"]["arm64"], "compile-only-refuse-load")
        self.assertEqual(qualification.active_cohort(admission, context), admission["cohorts"]["arm64"])
        legacy = workflow_context(purpose="experimental-candidate", architecture="arm64")
        with self.assertRaises(qualification.QualificationError):
            qualification.active_cohort(admission, legacy)
        widened = copy.deepcopy(admission)
        widened["directContext"]["rows"].append({"image": "docker-23-rootless", "architecture": "amd64"})
        with self.assertRaises(qualification.QualificationError):
            qualification.admission_document(json.dumps(widened).encode())


if __name__ == "__main__":
    unittest.main()
