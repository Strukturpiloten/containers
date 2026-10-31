"""Independent event-order and failure controls with all native effects simulated."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_aggregate as aggregate
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_plan as planner
from scripts import docker_direct_startup_runtime as runtime
from scripts.docker_userns_active_client import ActiveClient
from scripts.runtime_docker_backend import DockerBackend, DockerBackendError
from tests import test_docker_direct_startup_admission as admission_tests
from tests import test_docker_direct_startup_client as client_tests
from tests.test_docker_direct_startup_contract import arm


class Cancellation:
    """Latch only test-local cancellation, without changing native resources."""

    def __init__(self) -> None:
        """Start with no pending test cancellation."""
        self.cancelled = False
        self.defer_interrupts = False

    def __call__(self, _number: int, _frame: object) -> None:
        self.cancelled = True
        if not self.defer_interrupts:
            raise KeyboardInterrupt


def _archive_class(state: SimpleNamespace) -> type:
    class Archive:
        def __init__(self, path: Path, _supplied: Path) -> None:
            self.path = path
            self.identity = None

        def verify(self) -> None:
            state.events.append("archive-verify")

        def close(self) -> None:
            state.events.append("archive-close")

    return Archive


def _context_class(state: SimpleNamespace) -> type:
    class Context:
        def __init__(self, **kwargs: object) -> None:
            self.arm = "A" if "allocate-A" not in state.events else "B"
            self.name, self.architecture = kwargs["image"], kwargs["architecture"]
            self.backend = SimpleNamespace(direct_gate=None, scoped_profile=None)
            state.events.append("allocate-" + self.arm)
            self.runtime_disk_budget = None

        def bind_guest_profile(self, _profile: dict) -> None:
            pass

        def prepare(self) -> dict:
            state.events.append("services-network-" + self.arm)
            return {"engine": "docker", "serverVersion": "29.0.0"}

        def cleanup(self) -> None:
            state.events.append("cleanup-start-" + self.arm)
            if state.fault in {"work-root-cleanup", "cancel-root-cleanup"} and self.arm == "A":
                client, _ctx, _response = client_tests.DirectGateClientTests().fixture()
                receipt = client_tests.DirectRootFailureTests().receipt(client)
                receipt["operation"] = "direct-control-close"
                self.backend.direct_gate.failure = client_tests.client_module.project_failure(receipt, "A")
                self.backend.direct_gate.failures = [receipt]
                raise contract.DirectDiagnosticError
            if state.fault == "a-cleanup" and self.arm == "A":
                raise contract.DirectDiagnosticError
            if self.arm == "A":
                self.backend.direct_gate.evidence.update(disposed=True, state="closed")
            else:
                self.backend.scoped_profile.evidence.update(state="closed", custodyDisposed=True)
            if state.fault == "b-budget" and self.arm == "A":
                state.clock.now = 580_000_000_000
            state.events.append("cleanup-complete-" + self.arm)

    return Context


def _late_work_failure(state: SimpleNamespace, plan: SimpleNamespace) -> None:
    if state.fault in {"work-root-cleanup", "cancel-root-cleanup"} and plan.arm == "A":
        plan.operation = "startup-observation"
        if state.fault == "cancel-root-cleanup":
            raise KeyboardInterrupt
        message = "PRIVATE_SOURCE_CANARY"
        raise RuntimeError(message)


def _work_stub(state: SimpleNamespace, plan: SimpleNamespace, ctx: object, outcome: runtime.ArmOutcome) -> None:
    state.events.append("work-" + plan.arm)
    if plan.arm == "B":
        state.events.append("profile-B")
        ctx.backend.scoped_profile = SimpleNamespace(
            evidence={}, failures=[], dispose_stage=lambda: {"stageDisposed": True}
        )
    ctx.backend.direct_gate = SimpleNamespace(failure=None, evidence={"disposed": False, "state": "direct-control"})
    summary = arm(plan.arm)
    summary["guest"]["executables"].update(state.versions)
    summary["sourceIdentitySha256"] = state.source_digest
    summary["cleanupVerified"] = False
    if state.fault == "a-other" and plan.arm == "A":
        summary["startup"] = "other-failure"
    if state.fault == "same-negative" and plan.arm == "B":
        summary.update(startup=contract.EXPECTED_A, nativeExitCode=1)
        summary["guest"]["postExecVerified"] = False
    if state.fault == "b-other" and plan.arm == "B":
        summary.update(startup="other-failure", nativeExitCode=125)
        summary["guest"]["postExecVerified"] = False
    if state.fault == "reuse" and plan.arm == "B":
        summary["ownership"] = copy.deepcopy(arm("A")["ownership"])
    if state.fault == "source-drift" and plan.arm == "B":
        summary["sourceIdentitySha256"] = "f" * 64
    outcome.summary.update(summary)
    outcome.identity = state.identity
    _late_work_failure(state, plan)
    if state.fault == "a-late-generic" and plan.arm == "A":
        reason = "PRIVATE_SOURCE_CANARY"
        raise RuntimeError(reason)
    if state.fault == "cancel" and plan.arm == "A":
        raise KeyboardInterrupt


class PairControls(unittest.TestCase):
    def execute(self, fault: str | None = None) -> tuple:
        """Run the real coordinator and arm cleanup with inert contexts and archive."""
        events = []
        clock = SimpleNamespace(now=250_000_000_000 if fault == "b-budget" else 2_000_000_000)
        _proof, provenance, _environment, _event = admission_tests.DirectAdmissionTests().fixture(
            "docker-20.10-rootless", "amd64"
        )
        versions = planner.expected_versions("docker-20.10-rootless")
        identity = {
            "manifestDigest": "sha256:" + "a" * 64,
            "configDigest": "sha256:" + "b" * 64,
            "archiveSha256": "c" * 64,
            "architecture": "amd64",
            "sourceRevision": provenance["candidate"],
            "version": versions["engineVersion"],
        }
        source_digest = runtime._sha(
            {
                "candidate": provenance["candidate"],
                "image": "docker-20.10-rootless",
                "architecture": "amd64",
                "imageIdentity": identity,
                "admissionSha256": provenance["admissionSha256"],
            }
        )
        cancellation = Cancellation()

        state = SimpleNamespace(
            events=events, clock=clock, fault=fault, versions=versions, source_digest=source_digest, identity=identity
        )
        archive_class, context_class = _archive_class(state), _context_class(state)
        with tempfile.TemporaryDirectory() as output:
            args = SimpleNamespace(
                allow_privileged=True,
                skip_nested=False,
                archive="/unused-archive",
                focused_runtime=contract.PURPOSE,
                oom_accounting_mode="qualification",
                outer_engine="docker",
                active_userns_stage="/run/containers-userns-active." + "f" * 32,
                timeout=180,
                direct_started_ns=1_000_000_000,
                direct_deadline_ns=901_000_000_000,
                evidence=str(Path(output) / "docker-20.10-rootless-amd64.json"),
            )
            metadata = {
                "name": "docker-20.10-rootless",
                "tests": {"docker": {"mode": "rootless", "outerPrivilege": "privileged", "nestedRuntime": True}},
            }
            published = []

            def publish(path: Path, value: dict, deadline: float) -> None:
                published.append((path.name, copy.deepcopy(value), deadline))

            services = SimpleNamespace(
                Context=context_class, Archive=archive_class, Cancellation=lambda: cancellation, publish=publish
            )
            if fault == "diagnostic-mode":
                args.oom_accounting_mode = "diagnostic"
            with (
                patch.object(runtime, "context", return_value=provenance),
                patch.object(runtime, "_host_observation", return_value=({"qualification": "none"}, {"fixed": "host"})),
                patch.object(
                    runtime, "_work", side_effect=lambda plan, ctx, result: _work_stub(state, plan, ctx, result)
                ),
                patch.object(runtime.time, "monotonic_ns", side_effect=lambda: clock.now),
            ):
                if fault == "diagnostic-mode":
                    with self.assertRaises(contract.DirectDiagnosticError):
                        runtime.run_pair(args, metadata, "amd64", use_sudo=True, services=services)
                    record = None
                else:
                    record = runtime.run_pair(args, metadata, "amd64", use_sudo=True, services=services)
        return record, events, published, provenance

    def test_a_native_negative_and_complete_cleanup_precede_every_b_resource(self) -> None:
        record, events, published, source = self.execute()
        self.assertEqual(record["status"], "diagnostic-complete")
        self.assertEqual(record["qualification"], "none")
        self.assertEqual(record["arms"][0]["nativeExitCode"], 1)
        self.assertIsNone(record["arms"][1]["nativeExitCode"])
        for action in ("allocate-B", "services-network-B", "profile-B"):
            self.assertLess(events.index("cleanup-complete-A"), events.index(action))
        self.assertEqual(len([event for event in events if event.startswith("allocate-")]), 2)
        self.assertEqual([name for name, _value, _deadline in published][-1], "docker-20.10-rootless-amd64.json")
        aggregate.validate_pair_report(
            record, candidate=source["candidate"], run=source["run"], attempt=source["attempt"]
        )

    def test_generic_a_cleanup_cancellation_or_insufficient_b_budget_never_construct_b(self) -> None:
        for fault in ("a-other", "a-cleanup", "a-late-generic", "cancel", "b-budget"):
            with self.subTest(fault=fault):
                record, events, _published, _source = self.execute(fault)
                self.assertEqual(record["status"], "failed")
                self.assertNotIn("allocate-B", events)
                self.assertEqual(record["arms"][0]["nativeExitCode"], 1)
                self.assertNotIn("PRIVATE_SOURCE_CANARY", json.dumps(record))

    def test_first_local_work_or_cancellation_failure_survives_distinct_validated_root_cleanup_failure(self) -> None:
        for fault in ("work-root-cleanup", "cancel-root-cleanup"):
            with self.subTest(fault=fault):
                record, events, _published, _source = self.execute(fault)
                self.assertEqual(record["status"], "failed")
                self.assertNotIn("allocate-B", events)
                first, cleanup = record["failures"]
                self.assertEqual(first["actor"], "coordinator")
                self.assertEqual(first["operation"], "startup-observation")
                self.assertEqual(
                    first["reason"], "cancelled" if fault == "cancel-root-cleanup" else "operation-unverified"
                )
                self.assertEqual(cleanup["actor"], "root")
                self.assertEqual(cleanup["operation"], "direct-control-close")
                self.assertTrue(cleanup["bindingVerified"])
                self.assertTrue(cleanup["retained"])
                self.assertIn("rootReceiptSha256", cleanup)
                self.assertNotIn("PRIVATE_SOURCE_CANARY", json.dumps(record))

    def test_b_same_failure_is_complete_negative_collection_and_other_or_drift_is_not_complete(self) -> None:
        record, _events, _published, _source = self.execute("same-negative")
        self.assertEqual(record["status"], "diagnostic-complete")
        self.assertEqual(record["conclusion"], "profile-not-demonstrated-remedy")
        self.assertEqual(record["arms"][1]["nativeExitCode"], 1)
        for fault in ("b-other", "reuse", "source-drift"):
            with self.subTest(fault=fault):
                record, _events, _published, _source = self.execute(fault)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(record["qualification"], "none")

    def test_direct_dispatch_does_not_bypass_the_oom_diagnostic_restriction(self) -> None:
        record, events, published, _source = self.execute("diagnostic-mode")
        self.assertIsNone(record)
        self.assertEqual(events, [])
        self.assertEqual(published, [])

    def test_nonce_namespace_hashes_are_not_configuration_drift_but_actual_capability_drift_is(self) -> None:
        first = arm("A")["guest"]
        second = arm("B")["guest"]
        second["actor"]["namespaces"]["mnt"]["sha256"] = "f" * 64
        second["actor"]["namespaces"]["pid"]["sha256"] = "e" * 64
        self.assertEqual(runtime._nonpolicy(first, {}, {}), runtime._nonpolicy(second, {}, {}))
        second["actor"]["CapEff"] = ["0000000000000001"]
        self.assertNotEqual(runtime._nonpolicy(first, {}, {}), runtime._nonpolicy(second, {}, {}))


class BackendGateCleanupControls(unittest.TestCase):
    def test_a_gate_custody_must_close_before_network_or_image_cleanup(self) -> None:
        for fault in (False, True):
            with self.subTest(fault=fault):
                events = []
                backend = DockerBackend(Path("/unused-direct-runtime"), ())
                backend.ready = True
                backend._remove_containers = lambda _ctx, events=events: events.append("guest")
                backend._remove_network = lambda _ctx, events=events: events.append("network")
                backend._remove_images = lambda _ctx, events=events: events.append("images")

                def close(*, events: list = events, fault: bool = fault) -> None:
                    events.append("gate")
                    if fault:
                        raise contract.DirectDiagnosticError

                backend.direct_gate = SimpleNamespace(arm="A", close_control=close)
                if fault:
                    with self.assertRaises(DockerBackendError):
                        backend._cleanup_resources(Mock())
                    self.assertEqual(events, ["guest", "gate"])
                else:
                    self.assertEqual(backend._cleanup_resources(Mock()), [])
                    self.assertEqual(events, ["guest", "gate", "network", "images"])


class ActualStartupSequence(unittest.TestCase):
    def test_original_gated_work_binds_effective_subject_before_one_release(self) -> None:
        for name in ("A", "B"):
            with self.subTest(arm=name):
                self._case(name)

    def _case(self, name: str, startup: dict | None = None) -> runtime.ArmOutcome:
        events = []
        versions = planner.expected_versions("docker-20.10-rootless")
        base = arm(name)
        base["guest"]["executables"].update(versions)
        backend = SimpleNamespace(
            owner=("a" if name == "A" else "b") * 32,
            directory=Path("/unused-" + name),
            slice="private.slice",
            slice_identity="1:2",
            network_id=("c" if name == "A" else "d") * 64,
            scoped_profile=None,
            direct_gate=None,
            scoped_run_options=lambda options: (*options, "--security-opt", "apparmor=owned"),
        )

        def profile(_ctx: object, _stage: str, _identity: dict) -> None:
            events.append("profile")
            backend.scoped_profile = SimpleNamespace(bind=lambda _cid: events.append("bind-B"))

        backend.prepare_scoped_profile = profile
        ctx = SimpleNamespace(
            backend=backend,
            name="docker-20.10-rootless",
            architecture="amd64",
            start=lambda *_args, **_kwargs: events.append("create") or "e" * 64,
            exec=lambda *_args, **_kwargs: "200000 100000\n4294967296\n512",
            checks=[],
            podman=lambda *_args, **_kwargs: json.dumps(
                [
                    {
                        "Type": "volume",
                        "Name": "f" * 64,
                        "Destination": "/home/docker/.local/share/docker",
                        "RW": True,
                    }
                ]
            ),
        )

        class Gate:
            def __init__(self, *_args: object) -> None:
                self.evidence = {**copy.deepcopy(base["guest"]), "disposed": False}

            def prepare(self) -> None:
                events.append("gate")

            def create(self) -> tuple:
                return ()

            def bind_control(self, _cid: str) -> None:
                events.append("bind-A")

            def preflight(self, _cid: str) -> None:
                events.append("preflight")

            def release(self, _cid: str) -> None:
                events.append("release")

            def observe(self, _cid: str) -> dict:
                events.append("observe")
                return (
                    startup
                    if startup is not None
                    else {"kind": base["startup"], "nativeExitCode": base["nativeExitCode"]}
                )

        outcome = runtime.ArmOutcome({"profileBound": False})
        plan = SimpleNamespace(
            args=SimpleNamespace(active_userns_stage="/unused-stage"),
            arm=name,
            stable_host={},
            outer_runtime={},
            cancellation=SimpleNamespace(cancelled=False),
        )
        with patch.object(runtime, "GateClient", Gate):
            runtime._gated_start(plan, ctx, outcome, {}, SimpleNamespace(checkpoint=Mock()))
        self.assertEqual(events.count("release"), 1)
        self.assertLess(events.index("bind-" + name), events.index("preflight"))
        self.assertLess(events.index("preflight"), events.index("release"))
        self.assertLess(events.index("release"), events.index("observe"))
        self.assertEqual(outcome.summary["profileBound"], name == "B")
        self.assertEqual(
            outcome.summary["nativeExitCode"], startup["nativeExitCode"] if startup else (1 if name == "A" else None)
        )
        if name == "A":
            self.assertNotIn("profile", events)
        return outcome


class RootFailureComposition(unittest.TestCase):
    def receipt(self, client: object, operation: str, phase: str, lease: str = "c" * 32) -> dict:
        """Create closed, bound root evidence; private error text never leaves projection."""
        protocol = client_tests.client_module.protocol
        return protocol.failure_receipt(
            {
                "actor": "root",
                "operation": operation,
                "binding": client.binding,
                "sourceVerified": True,
                "sourceManifestSha256": protocol.SOURCE_MANIFEST_SHA256,
                "lease": lease,
                "record": {"state": "attached", "retained": True, "diagnostic": {"phase": phase}},
            },
            PermissionError(13, "PRIVATE_ROOT_FAILURE_CANARY"),
        )

    def clients(self) -> tuple:
        """Compose the real independent gate/profile clients over one inert B context."""
        gate, ctx, _response = client_tests.DirectGateClientTests().fixture("B")
        profile = ActiveClient.__new__(ActiveClient)
        profile.binding, profile.stage, profile.name = gate.binding, gate.stage, gate.name
        profile.ctx, profile.evidence, profile.failures = ctx, {}, []
        ctx.backend.direct_gate, ctx.backend.scoped_profile = gate, profile
        return gate, profile, ctx

    def execute(self, mode: str) -> tuple:
        """Exercise coordinator snapshots around real client RPC and backend cleanup."""
        state = SimpleNamespace()
        original_context, original_work = _context_class, _work_stub
        case = self

        def context(test_state: SimpleNamespace) -> type:
            base = original_context(test_state)

            class Context(base):
                def cleanup(self) -> None:
                    if self.arm == "A":
                        super().cleanup()
                        return
                    test_state.events.append("cleanup-start-B")
                    if mode == "local-cleanup":
                        message = "PRIVATE_LOCAL_CLEANUP_CANARY"
                        raise RuntimeError(message)
                    state.transport.command.return_value = json.dumps(state.cleanup_receipt)
                    self.backend.ready = True
                    self.backend._remove_containers = Mock()
                    DockerBackend._cleanup_resources(self.backend, self)

            return Context

        def work(test_state: SimpleNamespace, plan: SimpleNamespace, ctx: object, result: runtime.ArmOutcome) -> None:
            original_work(test_state, plan, ctx, result)
            if plan.arm == "A":
                return
            gate, profile, transport = case.clients()
            state.gate, state.profile, state.transport = gate, profile, transport
            state.cleanup_receipt = case.receipt(profile, "close", "profile-absence")
            ctx.backend.scoped_profile = profile
            ctx.backend.direct_gate = None if mode == "same-profile" else gate
            client = profile if mode == "same-profile" else gate
            operation = "bind" if mode == "same-profile" else "direct-observe"
            state.work_receipt = case.receipt(client, operation, "subject")
            transport.command.return_value = json.dumps(state.work_receipt)
            plan.operation = "startup-observation"
            if mode == "same-profile":
                profile.bind("a" * 64)
            else:
                gate.observe("a" * 64)

        with patch.dict(globals(), _context_class=context, _work_stub=work):
            record, events, published, _source = PairControls().execute()
        return record, events, published, state

    def test_gate_root_work_then_independent_profile_close_root_failure_are_both_exported(self) -> None:
        record, events, published, state = self.execute("gate-profile")
        self.assert_failures(record, events, published, ("direct-observe", "close"))
        self.assertEqual(state.gate.failures, [state.work_receipt])
        self.assertEqual(state.profile.failures, [state.cleanup_receipt])
        self.assertEqual(state.gate.failure, record["failures"][0])
        self.assertEqual(state.transport.command.call_count, 2)

    def test_same_profile_first_work_and_second_cleanup_receipts_are_both_exported(self) -> None:
        record, events, published, state = self.execute("same-profile")
        self.assert_failures(record, events, published, ("bind", "close"))
        self.assertEqual(state.profile.failures, [state.work_receipt, state.cleanup_receipt])
        self.assertEqual(state.transport.command.call_count, 2)

    def test_old_gate_receipt_cannot_hide_later_local_cleanup_failure(self) -> None:
        record, events, published, state = self.execute("local-cleanup")
        self.assertEqual(record["status"], "failed")
        self.assertEqual(published[-1][1], record)
        first, cleanup = record["failures"]
        self.assertEqual(first, state.gate.failure)
        self.assertEqual(first["operation"], "direct-observe")
        self.assertEqual(cleanup["actor"], "coordinator")
        self.assertEqual(cleanup["operation"], "cleanup")
        self.assertEqual(cleanup["reason"], "operation-unverified")
        self.assertEqual(state.profile.failures, [])
        self.assertIn("cleanup-start-B", events)
        self.assertNotIn("PRIVATE_", json.dumps(record))

    def assert_failures(self, record: dict, events: list, published: list, operations: tuple[str, str]) -> None:
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["qualification"], "none")
        self.assertEqual(published[-1][1], record)
        self.assertFalse(record["arms"][1]["cleanupVerified"])
        self.assertFalse(record["arms"][1]["factsComplete"])
        self.assertIn("cleanup-start-B", events)
        self.assertEqual([failure["operation"] for failure in record["failures"]], list(operations))
        self.assertEqual([failure["phase"] for failure in record["failures"]], ["subject", "profile-absence"])
        for failure in record["failures"]:
            self.assertEqual(failure["actor"], "root")
            self.assertEqual(failure["arm"], "B")
            self.assertTrue(failure["bindingVerified"])
            self.assertTrue(failure["retained"])
            self.assertFalse(failure["cleanupAuthority"])
            self.assertIn("rootReceiptSha256", failure)
        self.assertNotIn("PRIVATE_", json.dumps(record))

    def test_all_four_retained_receipts_from_each_journal_are_projected_and_duplicates_suppressed(self) -> None:
        gate, profile, ctx = self.clients()
        for index in range(4):
            gate.capture_failure(self.receipt(gate, "direct-observe", "subject", f"{index:032x}"))
            profile.capture_failure(self.receipt(profile, "close", "profile-absence", f"{index + 4:032x}"))
        result = runtime.ArmOutcome({})
        self.assertTrue(runtime._capture_failures(result, ctx, "B"))
        retained = [result.failure, *result.secondary_failures]
        self.assertEqual(len(retained), 8)
        self.assertEqual(
            retained,
            [
                client_tests.client_module.project_failure(receipt, "B")
                for receipt in (*gate.failures, *profile.failures)
            ],
        )
        self.assertFalse(runtime._capture_failures(result, ctx, "B"))
        self.assertEqual([result.failure, *result.secondary_failures], retained)
        profile.failures = [gate.failures[0], profile.failures[-1]]
        self.assertFalse(runtime._capture_failures(result, ctx, "B"))
        self.assertEqual([result.failure, *result.secondary_failures], retained)

    def test_unvalidated_private_receipt_is_refused_before_projection(self) -> None:
        gate, _profile, ctx = self.clients()
        gate.failures = [{"private": "PRIVATE_RAW_CANARY"}]
        result = runtime.ArmOutcome({})
        with self.assertRaises(contract.DirectDiagnosticError):
            runtime._capture_failures(result, ctx, "B")
        self.assertIsNone(result.failure)
        self.assertEqual(result.secondary_failures, [])
