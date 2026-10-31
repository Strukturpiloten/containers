"""Bounded unprivileged gate transport for the two nonqualifying direct arms."""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts import docker_userns_active as protocol
from scripts import docker_userns_custody_child as child
from scripts.docker_direct_startup_active import OPERATIONS
from scripts.docker_userns_active_bootstrap_bundle import context
from scripts.docker_userns_qualification import context_digest

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext


RECEIPT_KEYS = (
    "schemaVersion",
    "consumer",
    "purpose",
    "qualification",
    "bindingSha256",
    "arm",
    "lease",
    "state",
    "gateSha256",
    "released",
    "disposed",
    "actor",
    "executables",
    "startup",
    "postExecVerified",
)


validate_actor = contract.validate_actor


def project_failure(value: dict, arm: str) -> dict:
    """Project only an existing validated closed failure, without locator authority."""
    contract.require(protocol.valid_failure(value, child=child) and type(arm) is str and arm in {"A", "B"})
    locator = value["reportingLease"]
    result = {
        "schemaVersion": 1,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "arm": arm,
        "actor": value["actor"],
        "operation": value["operation"],
        "phase": value["phase"],
        "reason": value["reason"],
        "bindingVerified": value["bindingVerified"],
        "bindingSha256": value["bindingSha256"],
        "sourceVerified": value["sourceVerified"],
        "retained": value["retained"],
        "cleanupAuthority": False,
        "rootReceiptSha256": protocol.digest(contract.canonical(value)),
        "reportingLeaseSha256": protocol.digest(locator.encode("ascii")) if locator is not None else None,
    }
    contract.require(len(contract.canonical(result)) <= contract.RECORD_BYTES)
    return result


class GateClient:
    """Own one exact gate attempt without granting control A policy authority."""

    def __init__(self, ctx: RuntimeContext, stage: str, identity: dict[str, str], arm: str) -> None:
        """Bind actual A identity, or reuse B's already admitted profile binding."""
        contract.require(
            type(stage) is str and re.fullmatch(r"/run/containers-userns-active\.[0-9a-f]{32}", stage) is not None
        )
        contract.require(type(arm) is str and arm in {"A", "B"})
        contract.finite_tuple(ctx.name, ctx.architecture)
        contract.require(ctx.runtime_phase == ("direct-control" if arm == "A" else "direct-profiled"))
        self.ctx, self.stage, self.arm = ctx, Path(stage), arm
        self.evidence: dict = {}
        self.failed = False
        self.failures: list[dict] = []
        self.failure: dict | None = None
        self.name = "new"
        if arm == "B":
            profile = ctx.backend.scoped_profile
            contract.require(profile is not None and type(profile.binding) is contract.DirectDiagnosticBinding)
            self.binding = profile.binding
            contract.require(
                self.binding.image == ctx.name
                and self.binding.architecture == ctx.architecture
                and self.binding.owner == ctx.backend.owner
                and self.binding.runtime_slice == ctx.backend.slice
                and self.binding.slice_identity == ctx.backend.slice_identity
                and self.binding.deadline_ns == int(ctx.runtime_deadline * 1_000_000_000)
            )
            self.name = profile.name
        else:
            source = context(dict(os.environ), ctx.architecture)
            contract.require(source["purpose"] == contract.PURPOSE and source["image"] == ctx.name)
            self.binding = contract.DirectControlBinding(
                candidate=source["candidate"],
                run=source["run"],
                attempt=source["attempt"],
                job=source["job"],
                architecture=ctx.architecture,
                image=ctx.name,
                phase="direct-control",
                archive_sha256=identity["archiveSha256"],
                manifest_digest=identity["manifestDigest"],
                config_digest=identity["configDigest"],
                owner=ctx.backend.owner,
                runtime_slice=ctx.backend.slice,
                slice_identity=ctx.backend.slice_identity,
                deadline_ns=int(ctx.runtime_deadline * 1_000_000_000),
                purpose=contract.PURPOSE,
                admission_sha256=source["admissionSha256"],
                workflow_context_sha256=context_digest(source),
                variant=contract.CONTROL_VARIANT,
                launcher="direct",
                expected_uid="1000",
                arm="A",
            )
        self.binding.validate()

    def _redact(self) -> None:
        checks = getattr(self.ctx, "checks", [])
        if checks:
            checks[-1].pop("stdout", None)
            checks[-1].pop("stderr", None)
            checks[-1].pop("error", None)

    def matches_failure(self, value: dict, operation: str) -> bool:
        """Cross-bind only the existing closed failure protocol, never its cleanup locator."""
        if (
            not protocol.valid_failure(value, child=child)
            or value["actor"] != "root"
            or value["operation"] != operation
        ):
            return False
        expected = protocol.failure_context(asdict(self.binding), self.binding.phase)
        if value["bindingVerified"]:
            if value["bindingSha256"] != self.binding.digest() or value["context"] != expected:
                return False
        elif value["bindingSha256"] is not None or value["reportingLease"] is not None:
            return False
        if value["context"] is not None and any(
            value["context"][key] != expected[key] for key in expected if key != "phase"
        ):
            return False
        return not value["sourceVerified"] or value["sourceManifestSha256"] == protocol.SOURCE_MANIFEST_SHA256

    def capture_failure(self, value: dict) -> None:
        """Retain the first closed root receipt without adopting reporting authority."""
        self.failures = [*self.failures[:1], *self.failures[1:3], value]
        if self.failure is None:
            self.failure = project_failure(value, self.arm)

    def _response(self, value: object) -> dict:
        record = contract.exact_keys(value, RECEIPT_KEYS)
        contract.require(type(record["schemaVersion"]) is int and record["schemaVersion"] == contract.SCHEMA)
        contract.require(record["consumer"] == contract.CONSUMER and record["purpose"] == contract.PURPOSE)
        contract.require(record["qualification"] == "none" and record["bindingSha256"] == self.binding.digest())
        contract.require(record["arm"] == self.arm and record["gateSha256"] == gate.GATE_SHA256)
        contract.require(type(record["lease"]) is str and re.fullmatch(r"[0-9a-f]{32}", record["lease"]) is not None)
        contract.require(self.name == "new" or record["lease"] == self.name)
        contract.require(
            type(record["state"]) is str and record["state"] in {"direct-control", "loaded", "attached", "closed"}
        )
        contract.require(all(type(record[key]) is bool for key in ("released", "disposed", "postExecVerified")))
        if record["actor"] is not None:
            validate_actor(record["actor"])
        contract.require(not record["released"] or record["actor"] is not None)
        if record["executables"] is not None:
            contract.validate_executables(record["executables"])
        if record["startup"] is not None:
            startup = record["startup"]
            keys = {"kind", "nativeExitCode", "engineVersion"}
            contract.require(
                type(startup) is dict
                and set(startup)
                in (
                    keys,
                    keys | {"logRecords", "unclassifiedRecords", "logSha256"},
                    keys | {"diagnosticFailure"},
                )
            )
            if "diagnosticFailure" in startup:
                contract.require(
                    startup["kind"] == "unknown"
                    and startup["diagnosticFailure"]
                    in {
                        "logs-unavailable",
                        "logs-byte-limit",
                        "logs-record-limit",
                        "logs-record-byte-limit",
                        "logs-invalid-encoding",
                    }
                )
            contract.require(type(startup["kind"]) is str and startup["kind"] in {"pending", *contract.STARTUP_KINDS})
            code = startup["nativeExitCode"]
            contract.require(code is None or (type(code) is int and 0 <= code <= contract.MAX_NATIVE_EXIT))
            if startup["kind"] == "ready":
                contract.require(
                    code is None and record["postExecVerified"] is True and record["executables"] is not None
                )
                contract.require(startup["engineVersion"] == record["executables"]["engineVersion"])
            else:
                contract.require(startup["engineVersion"] is None)
            if "logRecords" in startup:
                contract.require(
                    type(startup["logRecords"]) is int and 0 <= startup["logRecords"] <= contract.JOURNAL_RECORDS
                )
                contract.require(
                    type(startup["unclassifiedRecords"]) is int
                    and 0 <= startup["unclassifiedRecords"] <= startup["logRecords"]
                )
                contract.require(
                    type(startup["logSha256"]) is str
                    and re.fullmatch(r"[0-9a-f]{64}", startup["logSha256"]) is not None
                )

        contract.require(len(contract.canonical(record)) <= contract.RECORD_BYTES)
        return record

    def rpc(self, operation: str, request: dict) -> dict:
        """Use only the staged source and original bounded private-root command path."""
        contract.require(not self.failed and type(operation) is str and operation in OPERATIONS)
        raw = base64.b64encode(contract.canonical(request)).decode("ascii")
        command = [
            "/usr/bin/python3.14",
            "-I",
            "-B",
            "-S",
            str(self.stage / "scripts/docker_userns_active.py"),
            operation,
            str(self.stage),
            self.name,
            "--request",
            raw,
        ]
        try:
            output = self.ctx.command(
                "direct startup gate " + operation,
                self.ctx.backend.privileged(command, 45),
                timeout=45,
                check=False,
            )
            contract.require(type(output) is str and len(output.encode("utf-8")) <= protocol.MAX_FAILURE)
            value = json.loads(output, object_pairs_hook=protocol.unique)
            if type(value) is dict and value.get("kind") == "active-qualification-failure":
                contract.require(self.matches_failure(value, operation))
                self.capture_failure(value)
                contract.require(condition=False)
            contract.require(self.ctx.checks and self.ctx.checks[-1].get("exitCode") == 0)
            result = self._response(value)
        except Exception, KeyboardInterrupt:  # noqa: BLE001 - never expose private transport errors.
            self.failed = True
            raise contract.DirectDiagnosticError from None
        finally:
            self._redact()
        self.name, self.evidence = result["lease"], result
        return result

    def prepare(self) -> None:
        """Register the pending client before this one root allocation attempt."""
        if self.arm == "A":
            self.rpc(
                "direct-control-prepare",
                {
                    "binding": asdict(self.binding),
                    "daemonDirectory": str(self.ctx.backend.directory),
                    "timeoutExecutable": self.ctx.backend.timeout_executable(),
                    "coordinatorPid": os.getpid(),
                },
            )
        else:
            self.rpc("direct-gate-prepare", {"bindingSha256": self.binding.digest(), "container": None})

    def create(self) -> tuple[str, ...]:
        """Return fixed gate mounts/entrypoint only after A's durable create intent."""
        contract.require(self.evidence and not self.failed and self.evidence["state"] != "closed")
        if self.arm == "A":
            self.rpc("direct-control-create", {"bindingSha256": self.binding.digest(), "container": None})
        return (
            "--entrypoint",
            "/bin/sh",
            "--mount",
            "type=bind,src="
            + str(self.stage / "leases" / self.name / "direct-gate")
            + ",dst="
            + gate.GUEST_DIRECTORY
            + ",readonly",
        )

    def bind_control(self, container: str) -> None:
        """Bind A separately; B uses the unchanged policy lease bind lifecycle."""
        contract.require(self.arm == "A")
        self.rpc("direct-control-bind", {"bindingSha256": self.binding.digest(), "container": container})

    def preflight(self, container: str) -> None:
        """Bind actual image executables under one fixed read-only preflight."""
        value = self.rpc("direct-preflight", {"bindingSha256": self.binding.digest(), "container": container})
        contract.require(value["executables"] is not None and value["actor"] is not None)

    def observe(self, container: str) -> dict:
        """Read one bounded startup sample under the original release deadline."""
        value = self.rpc("direct-observe", {"bindingSha256": self.binding.digest(), "container": container})
        contract.require(value["startup"] is not None)
        return value["startup"]

    def release(self, container: str) -> None:
        """Request one inert release after the actual live actor has been bound."""
        value = self.rpc("direct-release", {"bindingSha256": self.binding.digest(), "container": container})
        contract.require(value["released"] is True and value["disposed"] is False)

    def close_control(self) -> None:
        """Require A's verified original task/store gate cleanup before B can start."""
        contract.require(self.arm == "A" and self.name != "new")
        value = self.rpc("direct-control-close", {"bindingSha256": self.binding.digest(), "container": None})
        contract.require(value["state"] == "closed" and value["disposed"] is True)
