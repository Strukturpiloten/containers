"""Independent finite ARM admission controls; no policy, guest or host mutation."""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import json
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_runner_security as reader
from scripts import docker_userns_active as active
from scripts import docker_userns_custody_child as child
from scripts import docker_userns_dryparse as compiler
from scripts import docker_userns_policy_source as policy_source
from scripts import docker_userns_qualification as qualification
from scripts.evidence_gate import EvidenceError, require_ordinary_runtime_authority
from scripts.runtime_docker import DockerProbePhase
from tests import test_docker_userns_active as active_tests
from tests import test_runtime_oom_lifecycle as lifecycle_tests
from tests.test_docker_userns_active import (
    SyntheticProof,
    candidate_environment,
    event_payload,
    failure_port,
)
from tests.test_docker_userns_qualification import scoped_receipt, workflow_context
from tests.test_evidence_gate import maintained_mutations, maintained_runtime
from tests.test_runtime_oom_lifecycle import _PhaseCase

ROOT = Path(__file__).resolve().parents[1]
ARM = {
    "osID": "ubuntu",
    "osVersion": "26.04",
    "machine": "aarch64",
    "kernel": "7.0.0-1017-azure",
    "parserVersion": "5.0.2",
    "parserSha256": "51d0cac5d322d688892e5bfd9283262bab55fdced1c85a107cb2a92bc71e0e36",
    "interpreter": "/usr/bin/python3.14",
    "interpreterSha256": "d1b87c365d0cf5a985cfedfc227ff613a5bc6ff56e841202eb9330d263bbeee9",
    "abiSha256": "e510bb8f6788b45e48de2f859a6f94a7b8416cbac5a1051814cfce925fa911bd",
    "namespaceMaskSha256": "9513df1bb68dc257a9a12db6b9ff4bd46b379113ca37438a2426577e362318d8",
    "policyVersion9Sha256": "5040625b1fb6fa4af07226683f6e6003b29e5e70b16f8cfb24be7a752393f0ee",
    "pythonVersion": [3, 14, 4, "final", 0],
}


def admission() -> dict:
    """Load actual attempt policy separately from independent expected ARM facts."""
    return qualification.admission_document((ROOT / ".github/docker-userns-active-admission.json").read_bytes())


def host_controls(fault: str | None) -> dict:
    """Keep independent host-control fixtures separate from the active observer."""
    controls = {
        reader.ENABLED: b"Y",
        reader.RESTRICT: b"1",
        reader.USERNS: b"58304",
        qualification.LEGACY_CLONE: b"1",
    }
    if fault in {"disabled", "restriction", "zero-userns"}:
        controls[{"disabled": reader.ENABLED, "restriction": reader.RESTRICT, "zero-userns": reader.USERNS}[fault]] = (
            b"0"
        )
    if fault == "legacy-disabled":
        controls[qualification.LEGACY_CLONE] = b"0"
    if fault == "legacy-malformed":
        controls[qualification.LEGACY_CLONE] = b"unknown"
    return controls


class ArmRootAdmissionTests(unittest.TestCase):
    def preflight(self, fault: str | None) -> dict:
        context = workflow_context(purpose="maintained-prerequisite", architecture="arm64")
        if fault == "ImageOS":
            context["imageOS"] = "ubuntu26"
        controls = host_controls(fault)
        raw = (ROOT / ".github/docker-userns-active-admission.json").read_bytes()
        manifest = (ROOT / ".github/docker-userns-policy-source.json").read_bytes()
        expected = {key: value for key, value in ARM.items() if key.endswith("Sha256")}
        observed = dict(expected)
        if fault in expected:
            observed[fault] = (
                admission()["cohorts"]["amd64"][fault] if fault in {"parserSha256", "interpreterSha256"} else "0" * 64
            )

        def files(_modules: object, _progress: dict, result: dict, evaluate: object) -> None:
            for key in expected:
                if fault == "missing-" + key:
                    raise FileNotFoundError(errno.ENOENT, "inert missing fixed host fact")
                evaluate(
                    key,
                    key.encode(),
                    "preflight-python-hash" if key == "interpreterSha256" else "preflight-parser-hash",
                )
                result[key] = {"sha256": observed[key]}

        def digest(raw: bytes) -> str:
            # Opaque held-host bytes are represented only by independently authored observed digests.
            return observed.get(raw.decode(errors="ignore"), hashlib.sha256(raw).hexdigest())

        def control(path: Path) -> bytes:
            if path == qualification.LEGACY_CLONE and fault in {"legacy-absent", "legacy-unreadable"}:
                raise OSError(
                    errno.ENOENT if fault == "legacy-absent" else errno.EACCES, "inert host control unavailable"
                )
            return controls[path]

        modules = SimpleNamespace(
            qualification=qualification,
            host=SimpleNamespace(
                safe_path=lambda path: path,
                read_root=lambda *_args: (b'ID=ubuntu\nVERSION_ID="26.04"\n', None),
            ),
        )
        with (
            patch.object(
                active, "root_bytes", side_effect=lambda path: raw if path.name.endswith("admission.json") else manifest
            ),
            patch.object(
                active.os,
                "uname",
                return_value=SimpleNamespace(
                    machine="x86_64" if fault == "machine" else "aarch64",
                    release="unknown" if fault == "kernel" else ARM["kernel"],
                ),
            ),
            patch.object(active, "collect_cohort_files", side_effect=files),
            patch.object(active, "digest", side_effect=digest),
            patch.object(reader, "_read", side_effect=control),
            patch.object(qualification.time, "monotonic_ns", return_value=1),
            patch.object(active, "check"),
        ):
            return active.root_preflight(ROOT, {"context": context, "deadlineNs": 180_000_000_000}, modules)

    def test_exact_arm_predicate_is_complete_and_both_architectures_stay_distinct(self) -> None:
        policy = admission()
        self.assertEqual(policy["cohorts"]["arm64"], ARM)
        observed = self.preflight(None)
        self.assertEqual(observed["machine"], "aarch64")
        self.assertEqual(observed["controls"]["maximum_userns"], 58304)
        self.assertIsNone(self.preflight("legacy-absent")["controls"]["legacy_clone"])
        self.assertEqual(
            {key: value["sha256"] for key, value in observed["files"].items()},
            {key: value for key, value in ARM.items() if key.endswith("Sha256")},
        )
        self.assertNotEqual(policy["cohorts"]["amd64"]["parserSha256"], ARM["parserSha256"])
        self.assertNotEqual(policy["cohorts"]["amd64"]["interpreterSha256"], ARM["interpreterSha256"])

    def test_crossed_tools_platform_missing_features_and_controls_refuse_before_load(self) -> None:
        for fault in (
            "ImageOS",
            "kernel",
            "machine",
            "parserSha256",
            "interpreterSha256",
            "abiSha256",
            "namespaceMaskSha256",
            "policyVersion9Sha256",
            "missing-namespaceMaskSha256",
            "missing-policyVersion9Sha256",
            "disabled",
            "restriction",
            "zero-userns",
            "legacy-disabled",
            "legacy-malformed",
            "legacy-unreadable",
            "missing-interpreterSha256",
        ):
            with (
                self.subTest(fault=fault),
                self.assertRaises((active.RefusedError, qualification.QualificationError, OSError)),
            ):
                self.preflight(fault)

    def test_missing_cohort_and_observation_context_never_select_active_arm(self) -> None:
        policy = admission()
        for purpose in ("experimental-candidate", "unknown"):
            with self.subTest(purpose=purpose), self.assertRaises(qualification.QualificationError):
                qualification.active_cohort(policy, {"purpose": purpose, "architecture": "arm64"})
        for missing in ("arm64", "amd64"):
            changed = copy.deepcopy(policy)
            del changed["cohorts"][missing]
            with self.subTest(missing=missing), self.assertRaises(qualification.QualificationError):
                qualification.admission_document(json.dumps(changed).encode())

    def test_root_and_producer_reach_same_full_arm_proof_but_do_not_claim_qualification(self) -> None:
        case = active_tests.MaintainedBootstrapContract()
        proof = SyntheticProof()
        proof.context = workflow_context(
            purpose="maintained-prerequisite", candidate=proof.candidate, architecture="arm64"
        )
        event = case.event(proof.context)
        environment = {
            **candidate_environment(proof.candidate),
            "GITHUB_REF": proof.context["ref"],
            "GITHUB_WORKFLOW_REF": proof.context["workflowRef"],
            "RUNNER_ARCH": "ARM64",
            "ImageOS": "ubuntu26-arm64",
            "ImageVersion": proof.context["imageVersion"],
        }
        with event_payload(json.dumps(event).encode()):
            self.assertEqual(active_context(environment), proof.context)
        literal, mkdir = case.root(proof, event, architecture="arm64")
        mkdir.assert_called_once_with(mode=0o700)
        self.assertTrue(literal["DIAGNOSTIC"]["sourceVerified"])
        self.assertEqual(admission()["qualification"], "none")

    def test_maintained_arm_admission_reaches_existing_guarded_stage_after_preflight(self) -> None:
        port = failure_port()
        expected = scoped_receipt(purpose="maintained-prerequisite", architecture="arm64")
        port.binding = qualification.NativeBinding(**expected["binding"])
        port.record["bindingSha256"] = port.binding.digest()
        port.bootstrap = {"context": expected["workflowContext"], "deadlineNs": port.binding.deadline_ns}
        port.admission = admission()
        port.preflight = Mock(return_value=self.preflight(None))
        stop = RuntimeError("stop before existing daemon/builder/owner/load effects")
        port.modules.host = SimpleNamespace(safe_path=Mock(side_effect=stop))
        port.provider = "/usr/bin/timeout"
        with self.assertRaises(RuntimeError) as raised:
            port.admit(port.binding)
        self.assertIs(raised.exception, stop)
        self.assertTrue(port.record["diagnostic"]["comparisons"]["admission"])
        port.load.assert_not_called()


def active_context(environment: dict) -> dict:
    """Use actual unprivileged context producer; no tool or root operation runs."""
    from scripts.docker_userns_active_bootstrap_bundle import context  # noqa: PLC0415

    return context(environment, "arm64")


class ArmInterpreterTests(unittest.TestCase):
    def test_version_and_pure_builder_use_actual_selected_arm_interpreter_digest(self) -> None:
        port = failure_port()
        expected = scoped_receipt(purpose="maintained-prerequisite", architecture="arm64")
        port.binding = qualification.NativeBinding(**expected["binding"])
        port.admission = admission()
        port.bootstrap = {"context": expected["workflowContext"], "uid": 1000, "gid": 1000}
        port.record["profileName"] = expected["profileName"]
        port.work_until = 10**18
        port.stage = ROOT
        port.cleanup = False
        port.modules.child = child
        outcome = SimpleNamespace(dead=True, policy=b"AppArmor parser version 5.0.2\nfixture\n")
        with (
            patch.object(active, "root_preflight", return_value={}),
            patch.object(active.os, "open", return_value=91),
            patch.object(active.os, "close"),
            patch.object(active, "check"),
            patch.object(child, "probe", return_value=outcome) as probe,
            patch.object(child, "build", return_value=outcome) as build,
        ):
            port.preflight()
            self.assertIs(port.build_policy(91, (), port.binding), outcome)
        self.assertEqual(probe.call_args.args[0].sha256, ARM["interpreterSha256"])
        self.assertEqual(build.call_args.args[0].sha256, ARM["interpreterSha256"])

    def test_unsupported_fd_execution_refuses_without_path_fallback(self) -> None:
        parsed = ast.parse(child.PROBE_CODE)
        guarded = next(
            node
            for node in ast.walk(parsed)
            if isinstance(node, ast.If) and ast.unparse(node.test) == "kind == 'parser-version'"
        )
        executable = Mock()
        system = SimpleNamespace(supports_fd=set(), execve=executable, set_inheritable=Mock())
        with self.assertRaises(SystemExit) as raised:
            exec(  # noqa: S102 - execute only the fixed FD refusal guard with inert OS methods.
                compile(ast.Module(body=[guarded], type_ignores=[]), "fixed-probe-fd-guard", "exec"),
                {"kind": "parser-version", "os": system, "target": 91},
            )
        self.assertEqual(raised.exception.code, 1)
        executable.assert_not_called()
        system.set_inheritable.assert_not_called()

    def test_compile_and_load_use_selected_arm_parser_before_any_effect(self) -> None:
        expected = scoped_receipt(purpose="maintained-prerequisite", architecture="arm64")
        policy = b"inert policy fixture"
        for digest in (ARM["parserSha256"], admission()["cohorts"]["amd64"]["parserSha256"]):
            with self.subTest(digest=digest):
                parser = SimpleNamespace(
                    file=SimpleNamespace(public=lambda digest=digest: {"sha256": digest}), descriptor=91, check=Mock()
                )
                source = SimpleNamespace(
                    hold_executable=Mock(return_value=nullcontext(parser)),
                    ExecutableCall=policy_source.ExecutableCall,
                    bounded_child=Mock(return_value=(b"", 0)),
                )
                state = {"binding": {"deadline_ns": 10**18}, "policySha256": hashlib.sha256(policy).hexdigest()}
                bootstrap = {"context": expected["workflowContext"], "uid": 1000, "gid": 1000}

                def read(path: Path, *_args: object, state: dict = state) -> bytes:
                    if path.name == "state.json":
                        return json.dumps(state).encode()
                    if path.name.endswith("admission.json"):
                        return json.dumps(admission()).encode()
                    return policy

                with (
                    patch.object(active, "root_bytes", side_effect=read),
                    patch.object(active, "namespace_snapshot", return_value={}),
                    patch.object(active, "check"),
                    patch.object(active.os, "setgroups") as groups,
                    patch.object(active.os, "setresgid"),
                    patch.object(active.os, "setresuid"),
                ):
                    modules = SimpleNamespace(qualification=qualification, source=source, compiler=compiler)
                    if digest == ARM["parserSha256"]:
                        result = active.compile_worker(bootstrap, modules, Path("/inert/stage/leases/fixture"))
                        self.assertFalse(result["loadRun"])
                        self.assertEqual(result["qualification"], "none")
                        source.bounded_child.assert_called_once()
                    else:
                        with self.assertRaises(active.RefusedError):
                            active.compile_worker(bootstrap, modules, Path("/inert/stage/leases/fixture"))
                        groups.assert_not_called()
                        source.bounded_child.assert_not_called()
                port = failure_port()
                port.binding = qualification.NativeBinding(**expected["binding"])
                port.admission = admission()
                port.modules.source = source
                port.modules.compiler = compiler
                port.record.update(compiled=True, namespace={}, policySha256=state["policySha256"])
                port.store.path = Path("/inert/stage/leases/fixture")
                port.verify_owner, port.query = Mock(), Mock(return_value=b"")
                with (
                    patch.object(active, "namespace_snapshot", return_value={}),
                    patch.object(active, "root_bytes", return_value=policy),
                    patch.object(active.os, "open", return_value=92),
                    patch.object(active.os, "close"),
                ):
                    if digest == ARM["parserSha256"]:
                        port.parser("--add")
                        port.query.assert_called_once()
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.parser("--add")
                        port.query.assert_not_called()


class ArmNativeAuthorityTests(unittest.TestCase):
    execute = lifecycle_tests.PhaseExecutionTests.execute
    pair = lifecycle_tests.PairAuthorityTests.pair

    def test_actual_arm_maintained_phases_and_pair_require_complete_context_and_disposal(self) -> None:
        result, _events = self.pair(architecture="arm64", maintained=True)
        self.assertEqual(result["qualification"], "complete")
        require_ordinary_runtime_authority(result, "docker", {"mode": "rootless", "launcher": "systemd"})
        for phase in result["phases"]:
            self.assertEqual(phase["architecture"], "arm64")
            self.assertEqual(phase["scopedProfile"]["preflight"]["machine"], "aarch64")

    def test_arm_late_phase_pair_and_publication_failures_retain_none(self) -> None:
        for late in ("export", "deadline", "check", "disposal", "disposal-cancel"):
            with self.subTest(late=late):
                result, *_rest = self.execute(
                    _PhaseCase(
                        engine="docker",
                        ledger=True,
                        stage="owned-stage",
                        architecture="arm64",
                        late=late,
                        phase=DockerProbePhase.ENFORCEMENT,
                        scoped_receipt=scoped_receipt(
                            purpose="maintained-prerequisite", architecture="arm64", phase="enforcement"
                        ),
                    )
                )
                self.assertEqual(result["qualification"], "none")
                self.assertNotEqual(result["status"], "passed")
        for late in ("verify", "close", "deadline", "write"):
            with self.subTest(pair=late):
                result, _events = self.pair(architecture="arm64", maintained=True, late=late)
                self.assertEqual(result["qualification"], "none")

    def test_arm_importer_rejects_borrowed_hashes_namespace_drift_and_observations(self) -> None:
        for key in ("parserSha256", "interpreterSha256", "abiSha256", "namespaceMaskSha256", "policyVersion9Sha256"):
            record = maintained_runtime("arm64")
            record["phases"][1]["scopedProfile"]["preflight"]["files"][key]["sha256"] = (
                admission()["cohorts"]["amd64"][key] if key in {"parserSha256", "interpreterSha256"} else "0" * 64
            )
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(record, "docker", {"mode": "rootless", "launcher": "systemd"})
        for key in ("name", "level", "stacked"):
            record = maintained_runtime("arm64")
            record["phases"][1]["scopedProfile"]["namespace"][key] = "0" * 64
            with self.subTest(namespace=key), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(record, "docker", {"mode": "rootless", "launcher": "systemd"})
        for mode in ("enforce", "complain", "default_allow", "stacked//label"):
            record = maintained_runtime("arm64")
            scoped = record["phases"][1]["scopedProfile"]
            label = (scoped["profileName"] + " (" + mode + ")\n").encode()
            scoped["profileObservation"].update(bytes=len(label), sha256=hashlib.sha256(label).hexdigest())
            with self.subTest(mode=mode), self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(record, "docker", {"mode": "rootless", "launcher": "systemd"})
        for fault, record in maintained_mutations("arm64"):
            self.assertIsInstance(fault, str)
            with self.assertRaises(EvidenceError):
                require_ordinary_runtime_authority(record, "docker", {"mode": "rootless", "launcher": "systemd"})
