"""Inert closed transport, actual arm identity and protected-output regressions."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_client as client_module
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from tests import test_docker_direct_startup_admission as admission_tests
from tests.test_docker_direct_startup_contract import binding


def actor() -> dict:
    """Build independent finite actor facts without raw process or environment data."""
    return {
        "Uid": ["1000"] * 4,
        "Gid": ["1000"] * 4,
        "Groups": ["1000"],
        "CapInh": ["0000000000000000"],
        "CapPrm": ["0000000000000000"],
        "CapEff": ["0000000000000000"],
        "CapBnd": ["000001ffffffffff"],
        "CapAmb": ["0000000000000000"],
        "NoNewPrivs": ["0"],
        "Seccomp": ["0"],
        "Seccomp_filters": ["0"],
        "uid_mapSha256": "1" * 64,
        "gid_mapSha256": "2" * 64,
        "namespaceDepth": 2,
        "guestPid": 1,
        "namespaces": {
            kind: {"sha256": token * 64, "relationship": relationship}
            for kind, token, relationship in (
                ("user", "3", "same-host"),
                ("mnt", "4", "owned-distinct"),
                ("pid", "5", "owned-distinct"),
            )
        },
    }


class DirectGateClientTests(unittest.TestCase):
    def fixture(self, arm: str = "A") -> tuple:
        """Construct an inert native context and mocked bounded command transport."""
        native = binding()
        backend = SimpleNamespace(
            owner=native.owner,
            slice=native.runtime_slice,
            slice_identity=native.slice_identity,
            directory=Path("/unused-direct-runtime"),
            timeout_executable=lambda: "/usr/bin/gnutimeout",
            privileged=lambda command, _seconds: command,
            scoped_profile=SimpleNamespace(binding=native, name="e" * 32) if arm == "B" else None,
        )
        ctx = SimpleNamespace(
            name="docker-20.10-rootless",
            architecture="amd64",
            runtime_deadline=native.deadline_ns / 1_000_000_000,
            runtime_phase="direct-control" if arm == "A" else "direct-profiled",
            backend=backend,
            checks=[{"exitCode": 0, "stdout": "PRIVATE_CANARY", "stderr": "PRIVATE_CANARY"}],
            command=Mock(),
        )
        _proof, source, _environment, _event = admission_tests.DirectAdmissionTests().fixture(
            ctx.name, ctx.architecture
        )
        with patch.object(client_module, "context", return_value=source):
            client = client_module.GateClient(
                ctx,
                "/run/containers-userns-active." + "f" * 32,
                asdict(native)
                | {
                    "archiveSha256": native.archive_sha256,
                    "manifestDigest": native.manifest_digest,
                    "configDigest": native.config_digest,
                },
                arm,
            )
        response = {
            "schemaVersion": 1,
            "consumer": "containers-direct-rootless-startup-diagnostic",
            "purpose": "direct-startup-diagnostic",
            "qualification": "none",
            "bindingSha256": client.binding.digest(),
            "arm": arm,
            "lease": "e" * 32,
            "state": "direct-control" if arm == "A" else "loaded",
            "gateSha256": gate.GATE_SHA256,
            "released": False,
            "disposed": False,
            "actor": None,
            "executables": None,
            "startup": None,
            "postExecVerified": False,
        }
        ctx.command.return_value = json.dumps(response)
        return client, ctx, response

    def test_actual_a_and_b_bindings_cannot_be_swapped_or_relabelled_native29(self) -> None:
        for arm, expected in (("A", contract.DirectControlBinding), ("B", contract.DirectDiagnosticBinding)):
            client, ctx, _response = self.fixture(arm)
            self.assertIs(type(client.binding), expected)
            self.assertEqual(client.binding.arm, arm)
            self.assertEqual(client.binding.image, "docker-20.10-rootless")
            client.prepare()
            command = ctx.command.call_args.args[1]
            self.assertEqual(command[:4], ["/usr/bin/python3.14", "-I", "-B", "-S"])
            self.assertIn("direct-control-prepare" if arm == "A" else "direct-gate-prepare", command)
            self.assertNotIn("PRIVATE_CANARY", str(ctx.checks))

    def test_optional_log_failure_is_closed_and_retains_authenticated_native_exit(self) -> None:
        for code in (1, 137):
            for reason in (
                "logs-unavailable",
                "logs-byte-limit",
                "logs-record-limit",
                "logs-record-byte-limit",
                "logs-invalid-encoding",
                "PRIVATE_CANARY",
            ):
                client, ctx, response = self.fixture()
                response["startup"] = {
                    "kind": "unknown",
                    "nativeExitCode": code,
                    "engineVersion": None,
                    "diagnosticFailure": reason,
                }
                ctx.command.return_value = json.dumps(response)
                with self.subTest(code=code, reason=reason):
                    if reason == "PRIVATE_CANARY":
                        with self.assertRaises(contract.DirectDiagnosticError):
                            client.prepare()
                    else:
                        client.prepare()
                        self.assertEqual(client.evidence["startup"]["nativeExitCode"], code)
                        self.assertEqual(client.evidence["startup"]["diagnosticFailure"], reason)
                self.assertNotIn("PRIVATE_CANARY", str(ctx.checks))

    def test_unknown_extra_wrong_source_arm_boolean_and_private_values_never_escape(self) -> None:
        for key, value in (
            ("schemaVersion", True),
            ("qualification", "complete"),
            ("bindingSha256", "9" * 64),
            ("arm", "B"),
            ("lease", "PRIVATE_CANARY"),
            ("state", "PRIVATE_CANARY"),
            ("released", 1),
            ("disposed", "false"),
            ("extra", "PRIVATE_CANARY"),
        ):
            client, ctx, response = self.fixture()
            response[key] = value
            ctx.command.return_value = json.dumps(response)
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(contract.DirectDiagnosticError, "^direct startup diagnostic contract refused$"),
            ):
                client.prepare()
            self.assertTrue(client.failed)
            self.assertNotIn("PRIVATE_CANARY", str(ctx.checks))
            with self.assertRaises(contract.DirectDiagnosticError):
                client.prepare()
            self.assertEqual(ctx.command.call_count, 1)

    def test_nonzero_native_transport_and_overflow_or_duplicate_records_are_refused(self) -> None:
        for kind in ("exit", "overflow", "duplicate", "invalid-json", "exception"):
            client, ctx, _response = self.fixture()
            if kind == "exit":
                ctx.checks[-1]["exitCode"] = 1
            if kind == "overflow":
                ctx.command.return_value = "PRIVATE_CANARY" * 400
            if kind == "duplicate":
                ctx.command.return_value = '{"schemaVersion":1,"schemaVersion":1}'
            if kind == "invalid-json":
                ctx.command.return_value = "PRIVATE_CANARY"
            if kind == "exception":
                ctx.command.side_effect = PermissionError("PRIVATE_CANARY")
            with self.subTest(kind=kind), self.assertRaises(contract.DirectDiagnosticError):
                client.prepare()
            self.assertNotIn("PRIVATE_CANARY", str(ctx.checks))

    def test_running_release_keeps_unknown_native_exit_and_requires_complete_actor_facts(self) -> None:
        client, ctx, response = self.fixture()
        client.prepare()
        response.update(released=True, actor=actor())
        ctx.command.return_value = json.dumps(response)
        client.release("a" * 64)
        self.assertEqual(client.evidence["qualification"], "none")
        self.assertNotIn("nativeExitCode", client.evidence)
        for key, value in (
            ("guestPid", True),
            ("namespaceDepth", True),
            ("Uid", ["0"] * 4),
            ("rawEnvironment", "PRIVATE_CANARY"),
        ):
            facts = copy.deepcopy(actor())
            facts[key] = value
            with self.subTest(key=key), self.assertRaises(contract.DirectDiagnosticError):
                client_module.validate_actor(facts)


if __name__ == "__main__":
    unittest.main()


class DirectRootFailureTests(unittest.TestCase):
    def receipt(self, client: client_module.GateClient) -> dict:
        """Create an existing closed root failure after durable create intent."""
        return client_module.protocol.failure_receipt(
            {
                "actor": "root",
                "operation": "direct-control-prepare",
                "phase": "coordinator-proof",
                "binding": client.binding,
                "sourceVerified": True,
                "sourceManifestSha256": client_module.protocol.SOURCE_MANIFEST_SHA256,
                "lease": "c" * 32,
                "record": {"state": "prepared", "retained": True, "diagnostic": {"phase": "coordinator-proof"}},
            },
            PermissionError(13, "PRIVATE_FAILURE_CANARY"),
        )

    def test_nonzero_closed_root_failure_keeps_binding_phase_reporting_and_liability(self) -> None:
        client, ctx, _response = DirectGateClientTests().fixture()
        receipt = self.receipt(client)
        self.assertTrue(client_module.protocol.valid_failure(receipt))
        ctx.checks[-1]["exitCode"] = 1
        ctx.command.return_value = json.dumps(receipt)
        with self.assertRaises(contract.DirectDiagnosticError):
            client.prepare()
        self.assertTrue(client.failed)
        self.assertEqual(client.failures, [receipt])
        self.assertEqual(client.name, "new")
        self.assertEqual(client.failure["bindingSha256"], client.binding.digest())
        self.assertEqual(client.failure["phase"], "coordinator-proof")
        self.assertTrue(client.failure["retained"])
        self.assertFalse(client.failure["cleanupAuthority"])
        self.assertEqual(client.failure["reportingLeaseSha256"], client_module.protocol.digest(("c" * 32).encode()))
        self.assertNotIn("PRIVATE_FAILURE_CANARY", json.dumps(client.failure))
        self.assertNotIn("PRIVATE_FAILURE_CANARY", str(ctx.checks))

    def test_wrong_binding_source_phase_and_private_payloads_never_become_root_evidence(self) -> None:
        for key, value in (
            ("bindingSha256", "9" * 64),
            ("sourceManifestSha256", "9" * 64),
            ("operation", "prepare"),
            ("phase", "PRIVATE_FAILURE_CANARY"),
            ("reportingLease", "/PRIVATE_FAILURE_CANARY"),
            ("cleanupAuthority", True),
        ):
            client, ctx, _response = DirectGateClientTests().fixture()
            receipt = self.receipt(client)
            receipt[key] = value
            ctx.checks[-1]["exitCode"] = 1
            ctx.command.return_value = json.dumps(receipt)
            with self.subTest(key=key), self.assertRaises(contract.DirectDiagnosticError):
                client.prepare()
            self.assertEqual(client.failures, [])
            self.assertIsNone(client.failure)
            self.assertEqual(client.name, "new")
            self.assertNotIn("PRIVATE_FAILURE_CANARY", str(ctx.checks))

    def test_first_valid_failure_is_preserved_and_no_second_root_attempt_can_run(self) -> None:
        client, ctx, _response = DirectGateClientTests().fixture()
        first = self.receipt(client)
        ctx.checks[-1]["exitCode"] = 1
        ctx.command.return_value = json.dumps(first)
        with self.assertRaises(contract.DirectDiagnosticError):
            client.prepare()
        captured = copy.deepcopy(client.failure)
        with self.assertRaises(contract.DirectDiagnosticError):
            client.prepare()
        self.assertEqual(ctx.command.call_count, 1)
        second = copy.deepcopy(first)
        second["reason"] = "cancelled"
        client.capture_failure(second)
        self.assertEqual(client.failures[0], first)
        self.assertEqual(client.failure, captured)
