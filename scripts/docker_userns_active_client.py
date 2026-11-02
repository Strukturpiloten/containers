"""Unprivileged native client for the isolated issue527 qualification candidate."""

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from scripts import docker_direct_startup_contract as direct
from scripts import docker_userns_active as protocol
from scripts import docker_userns_custody_child as child
from scripts.docker_userns_active_bootstrap_bundle import context
from scripts.docker_userns_qualification import (
    PREREQUISITE_SCHEMA,
    SCOPED_RECEIPT_KEYS,
    MaintainedDirectBinding,
    QualificationError,
    admitted_deadline_ns,
    context_digest,
    native_binding,
    postexec_witness_valid,
    validate_stage_disposal,
)

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext

STAGE_PATTERN = r"/run/containers-userns-active\.[0-9a-f]{32}"


class ActiveClient:
    """Bind native phase evidence to a separately admitted root-private helper."""

    def __init__(self, ctx: RuntimeContext, stage: str, identity: dict[str, str]) -> None:
        """Prepare one lease only after the archive and private runtime are proven."""
        if not re.fullmatch(STAGE_PATTERN, stage):
            reason = "invalid active qualification stage"
            raise ValueError(reason)
        self.ctx, self.stage = ctx, Path(stage)
        self.provenance = context(dict(os.environ), ctx.architecture)
        backend = ctx.backend
        fields = {
            "candidate": os.environ.get("GITHUB_SHA", ""),
            "run": os.environ.get("GITHUB_RUN_ID", ""),
            "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "job": os.environ.get("GITHUB_JOB", ""),
            "architecture": ctx.architecture,
            "phase": ctx.runtime_phase,
            "image": ctx.name,
            "archive_sha256": identity["archiveSha256"],
            "manifest_digest": identity["manifestDigest"],
            "config_digest": identity["configDigest"],
            "owner": backend.owner,
            "runtime_slice": backend.slice,
            "slice_identity": backend.slice_identity,
            "deadline_ns": admitted_deadline_ns(ctx.runtime_deadline_ns),
            "purpose": self.provenance["purpose"],
            "admission_sha256": self.provenance["admissionSha256"],
            "workflow_context_sha256": context_digest(self.provenance),
        }
        if self.provenance["purpose"] == direct.PURPOSE:
            fields.update(variant=direct.VARIANT, launcher="direct", expected_uid="1000", arm="B")
        self.binding = native_binding(fields)
        self.binding.validate()
        self.name = "new"
        self.evidence: dict[str, Any] = {}
        self.failures: list[dict[str, Any]] = []
        self._bootstrap_anchor: tuple[Path, str, str, str] | None = None
        self._close_receipt: dict[str, Any] | None = None

    def prepare(self) -> None:
        """Acquire authority only after the backend records this pending client."""
        backend = self.ctx.backend
        value = self.rpc(
            "prepare",
            {
                "binding": asdict(self.binding),
                "daemonDirectory": str(backend.directory),
                "timeoutExecutable": backend.timeout_executable(),
                "coordinatorPid": os.getpid(),
            },
        )
        self._bootstrap_anchor = (self.stage, self.binding.digest(), value["lease"], value["bootstrapSha256"])
        self.evidence = value
        self.name = value["lease"]

    def rpc(self, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        """Use the native bounded command path and closed root-side JSON protocol."""
        self._close_response_phase = None
        raw = base64.b64encode(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
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
            result = self.ctx.command(
                "scoped userns profile " + operation, self.ctx.backend.privileged(command, 45), timeout=45, check=False
            )
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve only bounded classification.
            self.redact_command()
            self.capture_failure(self.local_failure(operation, protocol.failure_reason(error)))
            reason = "active qualification command unavailable; runtime retained"
            raise ValueError(reason) from None
        self.redact_command()
        if type(result) is not str:
            self.refuse_response(operation, "malformed-receipt")
        if len(result.encode("utf-8")) > protocol.MAX_STATE:
            self.refuse_response(operation, "oversized-receipt")
        try:
            value = json.loads(result, object_pairs_hook=protocol.unique)
        except ValueError, TypeError, protocol.RefusedError:
            self.refuse_response(operation, "malformed-receipt")
        if type(value) is not dict:
            self.refuse_response(operation, "malformed-receipt")
        if value.get("kind") == "active-qualification-failure":
            if self.response_invalid(
                operation, "client-close-failure-envelope", not self.matches_failure(value, operation)
            ):
                self.refuse_response(operation, "receipt-mismatch")
            self.capture_failure(value)
            reason = "active qualification root refusal; runtime retained"
            raise ValueError(reason)
        checks = getattr(self.ctx, "checks", [])
        if (
            (self.response_invalid(operation, "client-close-command", checks and checks[-1].get("exitCode") != 0))
            or self.response_invalid(operation, "client-close-schema", set(value) != SCOPED_RECEIPT_KEYS)
            or self.response_invalid(operation, "client-close-schema", type(value.get("schemaVersion")) is not int)
            or self.response_invalid(
                operation, "client-close-schema", value.get("schemaVersion") != PREREQUISITE_SCHEMA
            )
            or self.response_invalid(operation, "client-close-schema", value.get("consumer") != protocol.CONSUMER)
            or self.response_invalid(operation, "client-close-binding", value.get("binding") != asdict(self.binding))
            or self.response_invalid(
                operation, "client-close-binding", value.get("bindingSha256") != self.binding.digest()
            )
            or self.response_invalid(operation, "client-close-binding", value.get("purpose") != self.binding.purpose)
            or self.response_invalid(
                operation, "client-close-binding", value.get("admissionSha256") != self.binding.admission_sha256
            )
            or self.response_invalid(
                operation,
                "client-close-provenance",
                value.get("admissionRevision") != self.provenance["admissionRevision"],
            )
            or self.response_invalid(
                operation, "client-close-provenance", value.get("workflowContext") != self.provenance
            )
            or self.response_invalid(operation, "client-close-bootstrap", type(value.get("bootstrapSha256")) is not str)
            or self.response_invalid(
                operation, "client-close-bootstrap", re.fullmatch(r"[0-9a-f]{64}", value["bootstrapSha256"]) is None
            )
            or (
                self.response_invalid(
                    operation,
                    "client-close-bootstrap",
                    not self.bootstrap_matches(operation, value),
                )
            )
            or self.response_invalid(
                operation,
                "client-close-qualification",
                value.get("qualification")
                != (
                    "none"
                    if type(self.binding) is direct.DirectDiagnosticBinding
                    else "maintained-prerequisite"
                    if self.binding.purpose == "maintained-prerequisite"
                    else "experimental-candidate-only"
                ),
            )
            or self.response_invalid(operation, "client-close-retention", value.get("retained") is not False)
            or self.response_invalid(
                operation,
                "client-close-provenance",
                value.get("validationProfile") != self.provenance["validationProfile"],
            )
            or self.response_invalid(
                operation,
                "client-close-provenance",
                value.get("validationProfileRequested") != self.provenance["validationProfileRequested"],
            )
            or self.response_invalid(
                operation, "client-close-witness", not postexec_witness_valid(value.get("postExecWitness"), value)
            )
        ):
            self.refuse_response(operation, "receipt-mismatch")
        return value

    def bootstrap_matches(self, operation: str, value: dict[str, Any]) -> bool:
        """Compare later replies with only the original acknowledged prepare identity."""
        lease = value["lease"]
        if type(lease) is not str or re.fullmatch(r"[0-9a-f]{32}", lease) is None:
            return False
        if self._bootstrap_anchor is None:
            return operation == "prepare" and self.name == "new" and not self.evidence and not self.failures
        return (
            self._bootstrap_anchor == (self.stage, self.binding.digest(), lease, value["bootstrapSha256"])
            and lease == self.name
        )

    def response_invalid(self, operation: str, phase: str, value: object) -> bool:
        """Name only the first existing close validation predicate, evaluated once."""
        if value:
            if operation == "close":
                self._close_response_phase = phase
            return True
        return False

    def matches_failure(self, value: dict[str, Any], operation: str) -> bool:
        """Accept diagnostics only when their claimed verification matches this exact request."""
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

    def redact_command(self) -> None:
        """Replace raw root transport output with the separately validated diagnostic protocol."""
        checks = getattr(self.ctx, "checks", [])
        if checks:
            checks[-1].pop("stdout", None)
            checks[-1].pop("stderr", None)
            if "error" in checks[-1]:
                checks[-1]["error"] = "active-userns-command-failed"

    def local_failure(self, operation: str, reason: str) -> dict[str, Any]:
        """Bind a failed capture without attributing unobserved root operations."""
        value = protocol.failure_receipt(
            {"actor": "client", "operation": operation, "phase": "client-response", "binding": self.binding},
            ValueError(),
        )
        value["reason"] = reason
        phase = getattr(self, "_close_response_phase", None)
        if operation == "close" and type(phase) is str and phase in protocol.CLOSE_RESPONSE_PHASES:
            value["phase"] = phase
            value["comparisons"] = {phase: False}
        return value

    def refuse_response(self, operation: str, code: str) -> NoReturn:
        """Discard unsafe response bytes and retain their closed protocol category."""
        self.capture_failure(self.local_failure(operation, code))
        reason = "active qualification response unavailable; runtime retained"
        raise ValueError(reason) from None

    def capture_failure(self, value: dict[str, Any]) -> None:
        """Export before endpoint teardown; a reporting locator never changes the active lease name."""
        self.failures = [*self.failures[:1], *self.failures[1:3], value]
        self.evidence = {
            "schemaVersion": 1,
            "consumer": protocol.CONSUMER,
            "qualification": "none",
            "status": "failed",
            "bindingSha256": self.binding.digest(),
            "context": protocol.failure_context(asdict(self.binding), self.binding.phase),
            "failures": self.failures,
            "retained": True,
            "cleanupAuthority": False,
        }
        output = getattr(self.ctx, "scoped_failure_output", None)
        if output is not None:
            raw = (json.dumps(self.evidence, sort_keys=True) + "\n").encode("ascii")
            if len(raw) <= protocol.MAX_OUTPUT:
                try:
                    Path(output).write_bytes(raw)
                except OSError:
                    self.evidence["artifactCapture"] = "unavailable"

    def create_options(self) -> tuple[str, ...]:
        """Persist one create intent before adding the exact scoped label and profile."""
        self.evidence = self.rpc("create-intent", {"bindingSha256": self.binding.digest(), "container": None})
        return (
            "--security-opt",
            "apparmor=" + self.evidence["profileName"],
            "--label",
            "io.strukturpiloten.userns-profile=" + self.name,
        )

    def bind(self, container: str) -> None:
        """Require held-task profile proof after the one owned systemd guest starts."""
        self.evidence = self.rpc("bind", {"bindingSha256": self.binding.digest(), "container": container})

    def witness(self, checkpoint: str) -> None:
        """Request only a fixed ordered read-only checkpoint on the already-bound lease."""
        if checkpoint not in ("ready", "pre-close"):
            self.refuse_response("witness", "receipt-mismatch")
        value = self.rpc("witness", {"bindingSha256": self.binding.digest(), "checkpoint": checkpoint})
        detail = value["postExecWitness"]
        if (
            value["state"] != "attached"
            or detail is None
            or detail["samples"][-1]["checkpoint"] != checkpoint
            or not postexec_witness_valid(detail, value, complete=checkpoint == "pre-close", current=True)
        ):
            self.refuse_response("witness", "receipt-mismatch")
        self.evidence = value

    def close(self) -> None:
        """Prove guest/profile absence before native private daemon teardown."""
        if self.name == "new":
            reason = "unacknowledged active qualification retains private runtime"
            raise ValueError(reason)
        self._close_receipt = None
        value = self.rpc("close", {"bindingSha256": self.binding.digest(), "container": None})
        self._close_receipt = value
        if not self.failures:
            self.evidence = value

    def dispose_stage(self) -> dict[str, Any]:
        """Finish the existing root stage before maintained pair publication."""
        if not (
            (self.binding.purpose == "maintained-prerequisite" and self.binding.phase == "enforcement")
            or (type(self.binding) is MaintainedDirectBinding and self.binding.phase == "ordinary-direct")
            or (type(self.binding) is direct.DirectDiagnosticBinding and self.binding.phase == "direct-profiled")
        ):
            reason = "maintained final phase is required for stage disposal"
            raise ValueError(reason)
        remaining = (self.binding.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            reason = "stage disposal exceeded the original phase deadline"
            raise ValueError(reason)
        allowance = min(20.0, remaining)
        command = [
            "/usr/bin/python3.14",
            "-I",
            "-B",
            "-S",
            str(self.stage / "scripts/docker_userns_active.py"),
            "dispose-stage",
            str(self.stage),
        ]
        try:
            result = self.ctx.command(
                "scoped userns stage disposal",
                self.ctx.backend.privileged(command, allowance),
                timeout=allowance,
                check=False,
            )
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - same closed transport boundary as lease RPCs.
            self.redact_command()
            self.capture_failure(self.local_failure("dispose-stage", protocol.failure_reason(error)))
            reason = "maintained stage disposal command unavailable; runtime retained"
            raise ValueError(reason) from None
        self.redact_command()
        if (
            time.monotonic_ns() >= self.binding.deadline_ns
            or not self.ctx.checks
            or self.ctx.checks[-1].get("exitCode") != 0
        ):
            self.refuse_response("dispose-stage", "receipt-mismatch")
        if type(result) is not str:
            self.refuse_response("dispose-stage", "malformed-receipt")
        try:
            size = len(result.encode("utf-8"))
        except UnicodeError:
            self.refuse_response("dispose-stage", "malformed-receipt")
        if size > protocol.MAX_STATE:
            self.refuse_response("dispose-stage", "oversized-receipt")
        try:
            value = json.loads(result, object_pairs_hook=protocol.unique)
        except ValueError, TypeError, protocol.RefusedError:
            self.refuse_response("dispose-stage", "malformed-receipt")
        try:
            validate_stage_disposal(value, self.evidence)
        except QualificationError, ValueError, TypeError, KeyError, AttributeError:
            self.refuse_response("dispose-stage", "receipt-mismatch")
        return value
