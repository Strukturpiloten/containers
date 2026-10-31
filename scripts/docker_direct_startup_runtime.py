"""Serialize one nonqualifying gated A/B startup pair under an inherited clock."""

from __future__ import annotations

import copy
import json
import os
import signal
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate_source
from scripts import docker_runner_security as host
from scripts.docker_direct_startup_client import GateClient, project_failure
from scripts.docker_direct_startup_observations import STARTUP_SECONDS
from scripts.docker_direct_startup_plan import expected_versions
from scripts.docker_userns_active_bootstrap_bundle import context
from scripts.docker_userns_qualification import context_digest
from scripts.runtime_resource_budgets import STORE_LIMIT_BYTES, outer_container_limits, verify_outer_container_limits

if TYPE_CHECKING:
    import argparse


@dataclass
class ArmOutcome:
    """Keep cleanup acknowledgement separate from an expected negative native result."""

    summary: dict
    identity: dict | None = None
    stage_disposal: dict | None = None
    failure: dict | None = None
    secondary_failures: list[dict] = field(default_factory=list)


def _sha(value: object) -> str:
    import hashlib  # noqa: PLC0415 - pure fixed summaries only.

    return hashlib.sha256(contract.canonical(value)).hexdigest()


def _host_observation() -> tuple[dict, dict]:
    observed = host.collect()
    stable = {
        "kernel": observed["kernel"],
        "enabled": observed["apparmor"]["enabled"],
        "restriction": observed["apparmor"]["restrictUnprivilegedUserns"],
        "maximum": observed["userNamespaces"]["maximum"],
    }
    contract.require(stable["kernel"]["release"] is not None)
    contract.require(stable["enabled"] == {"state": "observed", "value": True})
    contract.require(stable["restriction"] == {"state": "observed", "value": 1})
    contract.require(
        stable["maximum"]["state"] == "observed"
        and type(stable["maximum"]["value"]) is int
        and stable["maximum"]["value"] > 0
    )
    value = {
        "schemaVersion": 1,
        "consumer": contract.CONSUMER,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "scope": "current-job-host-only-not-guest",
        "facts": {key: observed[key] for key in ("kernel", "apparmor", "userNamespaces", "collectorProcess")},
    }
    contract.require(len(contract.canonical(value)) <= contract.HOST_BYTES)
    return value, stable


def _ownership(ctx: object, container: str) -> dict:
    raw = ctx.podman(
        "read direct diagnostic owned volumes", "inspect", "--format", "{{json .Mounts}}", container, timeout=5
    )
    mounts = json.loads(raw)
    contract.require(type(mounts) is list)
    volumes = [item for item in mounts if item.get("Type") == "volume"]
    contract.require(
        len(volumes) == 1
        and volumes[0]["Destination"] == "/home/docker/.local/share/docker"
        and volumes[0]["RW"] is True
    )
    name = volumes[0]["Name"]
    import re  # noqa: PLC0415 - closed anonymous volume names only.

    contract.require(type(name) is str and re.fullmatch(r"[0-9a-f]{64}", name) is not None)
    backend = ctx.backend
    return {
        "ownerSha256": _sha(backend.owner),
        "storeSha256": _sha(str(backend.directory)),
        "sliceSha256": _sha([backend.slice, backend.slice_identity]),
        "networkSha256": _sha(backend.network_id),
        "guestSha256": _sha(container),
        "volumesSha256": _sha([name]),
    }


def _nonpolicy(guest: dict, stable_host: dict, runtime: dict) -> str:
    actor = copy.deepcopy(guest["actor"])
    actor["namespaces"] = {kind: item["relationship"] for kind, item in actor["namespaces"].items()}
    return _sha(
        {
            "actor": actor,
            "executables": guest["executables"],
            "host": stable_host,
            "outerRuntime": runtime,
            "limits": list(outer_container_limits()),
            "launcher": list(gate_source.ORIGINAL_CMD),
            "gateSha256": gate_source.GATE_SHA256,
            "recipe": "private-docker-privileged-fuse-direct-startup-only",
        }
    )


def _gated_start(plan: SimpleNamespace, ctx: object, result: ArmOutcome, identity: dict, budget: object) -> None:
    args = plan.args
    if plan.arm == "B":
        plan.operation = "profile-prepare"
        ctx.backend.prepare_scoped_profile(ctx, args.active_userns_stage, identity)
    plan.operation = "gate-prepare"
    pending = GateClient(ctx, args.active_userns_stage, identity, plan.arm)
    ctx.backend.direct_gate = pending
    pending.prepare()
    options = (*outer_container_limits(), "--device", "/dev/fuse", "--privileged", *pending.create())
    if plan.arm == "B":
        options = ctx.backend.scoped_run_options(options)
    plan.operation = "guest-create"
    container = ctx.start("start gated direct-rootless diagnostic", gate_source.GUEST_GATE, options=options)
    plan.operation = "guest-bind"
    if plan.arm == "A":
        pending.bind_control(container)
    else:
        ctx.backend.scoped_profile.bind(container)
        result.summary["profileBound"] = True
    result.summary["ownership"] = _ownership(ctx, container)
    verify_outer_container_limits(ctx, container, timeout=5)
    plan.operation = "guest-preflight"
    pending.preflight(container)
    guest = {
        "actor": pending.evidence["actor"],
        "executables": pending.evidence["executables"],
        "postExecVerified": False,
    }
    contract.validate_guest(guest)
    expected = expected_versions(ctx.name)
    contract.require(all(guest["executables"][key] == value for key, value in expected.items()))
    result.summary["nonPolicyFactsSha256"] = _nonpolicy(guest, plan.stable_host, plan.outer_runtime)
    plan.operation = "guest-release"
    pending.release(container)
    plan.operation = "startup-observation"
    startup = None
    for _sample in range(STARTUP_SECONDS):
        contract.require(not plan.cancellation.cancelled)
        startup = pending.observe(container)
        if startup["kind"] != "pending":
            break
        budget.checkpoint()
        time.sleep(min(1.0, ctx.backend.command_timeout(1.0)))
    contract.require(startup is not None and startup["kind"] != "pending")
    guest["postExecVerified"] = pending.evidence["postExecVerified"]
    result.summary.update(
        startup=startup["kind"],
        nativeExitCode=startup["nativeExitCode"],
        guest=guest,
        factsComplete="diagnosticFailure" not in startup,
    )
    if "diagnosticFailure" in startup:
        result.failure = {**_local_failure(plan, cancelled=False), "reason": startup["diagnosticFailure"]}


def _work(plan: SimpleNamespace, ctx: object, result: ArmOutcome) -> None:
    services, args = plan.services, plan.args
    plan.operation = "archive"
    with services.Budget(ctx, source_archive=plan.archive.path) as budget:
        ctx.runtime_disk_budget = budget
        plan.archive.prepare(ctx, args)
        budget.bind_source_archive(plan.archive.identity)
        budget.checkpoint()
        plan.operation = "image-import"
        identity = ctx.load_archive(plan.archive.load_path())
        budget.checkpoint()
        plan.archive.verify()
        if plan.expected_identity is not None:
            contract.require(identity == plan.expected_identity)
        result.identity = identity
        result.summary["sourceIdentitySha256"] = _sha(
            {
                "candidate": plan.provenance["candidate"],
                "image": ctx.name,
                "architecture": ctx.architecture,
                "imageIdentity": identity,
                "admissionSha256": plan.provenance["admissionSha256"],
            }
        )
        _gated_start(plan, ctx, result, identity, budget)
        budget.checkpoint()
        plan.archive.verify()
    ctx.runtime_disk_budget = None


def _local_failure(plan: SimpleNamespace, *, cancelled: bool, cleanup: bool = False) -> dict:
    return {
        "schemaVersion": 1,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "arm": plan.arm,
        "actor": "coordinator",
        "operation": "cleanup" if cleanup else getattr(plan, "operation", "allocate"),
        "reason": "cancelled" if cancelled else "operation-unverified",
        "cleanupAuthority": False,
    }


def _capture_failures(result: ArmOutcome, ctx: object | None, arm: str) -> bool:
    """Retain every validated receipt from both bounded journals at this boundary."""
    added = False
    if ctx is not None:
        clients = (getattr(ctx.backend, "direct_gate", None), ctx.backend.scoped_profile)
        for client in clients:
            if client is not None:
                for receipt in getattr(client, "failures", ()):
                    added = _retain_failure(result, project_failure(receipt, arm)) or added
    return added


def _retain_failure(result: ArmOutcome, captured: dict | None) -> bool:
    if captured is not None:
        if result.failure is None:
            result.failure = captured
            return True
        if captured != result.failure and captured not in result.secondary_failures:
            result.secondary_failures.append(captured)
            return True
    return False


def _run_arm(plan: SimpleNamespace) -> ArmOutcome:
    summary = {
        "arm": plan.arm,
        "image": plan.metadata["name"],
        "architecture": plan.architecture,
        "qualification": "none",
        "startup": "unknown",
        "nativeExitCode": None,
        "cleanupVerified": False,
        "factsComplete": False,
        "nonPolicyFactsSha256": None,
        "sourceIdentitySha256": None,
        "ownership": None,
        "kernelAttribution": "unavailable",
        "namespaceControls": contract.optional_controls(),
        "profileBound": False,
        "guest": None,
    }
    result = ArmOutcome(summary)
    ctx = None
    try:
        plan.cancellation.defer_interrupts = True
        try:
            ctx = plan.services.Context(
                image=plan.metadata["name"],
                architecture=plan.architecture,
                timeout=plan.args.timeout,
                use_sudo=plan.use_sudo,
                outer_engine="docker",
            )
        finally:
            plan.cancellation.defer_interrupts = False
        ctx.runtime_phase = "direct-control" if plan.arm == "A" else "direct-profiled"
        ctx.runtime_deadline = plan.deadline_ns / 1_000_000_000
        ctx.bind_guest_profile(plan.metadata["tests"]["docker"])
        plan.operation = "backend-prepare"
        plan.outer_runtime = ctx.prepare()
        _work(plan, ctx, result)
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - keep only closed outcomes.
        summary["factsComplete"] = False
        if not _capture_failures(result, ctx, plan.arm):
            _retain_failure(result, _local_failure(plan, cancelled=isinstance(error, KeyboardInterrupt)))
        if isinstance(error, KeyboardInterrupt):
            plan.cancellation.cancelled = True
    finally:
        plan.cancellation.defer_interrupts = True
        try:
            if ctx is not None:
                ctx.runtime_disk_budget = None
                ctx.runtime_deadline = None
                try:
                    ctx.cleanup()
                    pending = getattr(ctx.backend, "direct_gate", None)
                    if plan.arm == "A" and pending is not None:
                        contract.require(
                            pending.evidence.get("disposed") is True and pending.evidence.get("state") == "closed"
                        )
                    profile = ctx.backend.scoped_profile
                    if plan.arm == "B" and profile is not None:
                        contract.require(
                            profile.evidence.get("state") == "closed"
                            and profile.evidence.get("custodyDisposed") is True
                        )
                        result.stage_disposal = profile.dispose_stage()
                    summary["cleanupVerified"] = True
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original native status and liability.
                    summary["cleanupVerified"] = False
                    if not _capture_failures(result, ctx, plan.arm):
                        _retain_failure(
                            result, _local_failure(plan, cancelled=isinstance(error, KeyboardInterrupt), cleanup=True)
                        )
        finally:
            plan.cancellation.defer_interrupts = False
        _capture_failures(result, ctx, plan.arm)
        if time.monotonic_ns() >= plan.deadline_ns or plan.cancellation.cancelled:
            summary["factsComplete"] = False
    return result


def _execute_pair(plan: SimpleNamespace, record: dict) -> None:
    args, services, clock = plan.args, plan.services, plan.clock
    cancellation, provenance = plan.cancellation, plan.provenance
    metadata, architecture, use_sudo = plan.metadata, plan.architecture, plan.use_sudo
    before, stable = _host_observation()
    _publish_host(plan, before, "before")
    cancellation.defer_interrupts = True
    try:
        plan.source = tempfile.TemporaryDirectory(prefix="containers-direct-source-")
        source = plan.source
        plan.archive = services.Archive(Path(source.name) / "source-image.tar", Path(args.archive).resolve())
        archive = plan.archive
        archive.path.touch(mode=0o600, exist_ok=False)
    finally:
        cancellation.defer_interrupts = False
    expected_identity = None
    for arm in ("A", "B"):
        contract.require(not cancellation.cancelled)
        arm_deadline = clock.arm_deadline(time.monotonic_ns())
        if arm == "B":
            current, current_stable = _host_observation()
            _publish_host(plan, current, "between")
            contract.require(current_stable == stable)
        outcome = _run_arm(
            SimpleNamespace(
                args=args,
                metadata=metadata,
                architecture=architecture,
                use_sudo=use_sudo,
                services=services,
                arm=arm,
                archive=archive,
                expected_identity=expected_identity,
                cancellation=cancellation,
                deadline_ns=arm_deadline,
                provenance=provenance,
                stable_host=stable,
            )
        )
        record["arms"].append(outcome.summary)
        if outcome.failure is not None:
            record["failures"].append(outcome.failure)
        record["failures"].extend(outcome.secondary_failures)
        contract.require(outcome.summary["cleanupVerified"] is True)
        contract.validate_arm(outcome.summary)
        if arm == "A":
            contract.require(
                outcome.summary["factsComplete"] is True and outcome.summary["startup"] == contract.EXPECTED_A
            )
            contract.require(type(outcome.summary["nativeExitCode"]) is int and outcome.summary["nativeExitCode"] > 0)
            expected_identity = outcome.identity
            record["imageIdentity"] = outcome.identity
        else:
            contract.require(outcome.stage_disposal is not None)
            record["stageDisposed"] = True
    after, final_stable = _host_observation()
    _publish_host(plan, after, "after")
    contract.require(final_stable == stable)
    record["conclusion"] = contract.compare_pair(*record["arms"])
    contract.require(record["conclusion"] in {"profile-dependent-startup", "profile-not-demonstrated-remedy"})
    clock.validate(time.monotonic_ns())
    record["status"] = "diagnostic-complete"


def run_pair(
    args: argparse.Namespace, metadata: dict, architecture: str, *, use_sudo: bool, services: SimpleNamespace
) -> dict:
    """Run exactly one expected-negative A, verify cleanup, then one fresh B."""
    contract.finite_tuple(metadata["name"], architecture)
    contract.require(
        metadata["tests"] == {"docker": {"mode": "rootless", "outerPrivilege": "privileged", "nestedRuntime": True}}
    )
    contract.require(args.allow_privileged and not args.skip_nested and args.archive is not None)
    contract.require(args.focused_runtime == contract.PURPOSE and args.oom_accounting_mode == "qualification")
    contract.require(args.outer_engine in {"docker", "profile"} and args.active_userns_stage is not None)
    clock = contract.PairDeadline(args.direct_started_ns, args.direct_deadline_ns)
    clock.validate(time.monotonic_ns())
    contract.require(clock.deadline_ns - clock.started_ns == contract.PAIR_SECONDS * 1_000_000_000)
    provenance = context(dict(os.environ), architecture)
    contract.require(provenance["purpose"] == contract.PURPOSE and provenance["image"] == metadata["name"])
    record = {
        "schemaVersion": 1,
        "consumer": contract.CONSUMER,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "image": metadata["name"],
        "architecture": architecture,
        "profile": "docker",
        "status": "failed",
        "candidate": provenance["candidate"],
        "runId": provenance["run"],
        "runAttempt": provenance["attempt"],
        "producingJob": provenance["job"],
        "workflowContextSha256": context_digest(provenance),
        "workflowContext": provenance,
        "imageIdentity": None,
        "gateSha256": gate_source.GATE_SHA256,
        "conclusion": "inconclusive",
        "arms": [],
        "namespaceControls": contract.optional_controls(),
        "stageDisposed": False,
        "pairStartedNs": clock.started_ns,
        "pairDeadlineNs": clock.deadline_ns,
        "failures": [],
        "bounds": {
            "pairSeconds": contract.PAIR_SECONDS,
            "armWorkSeconds": contract.ARM_WORK_SECONDS,
            "cleanupReserveSeconds": contract.CLEANUP_SECONDS,
            "storeBytes": STORE_LIMIT_BYTES,
            "startupSeconds": STARTUP_SECONDS,
        },
    }
    cancellation = services.Cancellation()
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT)}
    plan = SimpleNamespace(
        args=args,
        metadata=metadata,
        architecture=architecture,
        use_sudo=use_sudo,
        services=services,
        clock=clock,
        cancellation=cancellation,
        provenance=provenance,
        source=None,
        archive=None,
    )
    try:
        for kind in previous:
            signal.signal(kind, cancellation)
        _execute_pair(plan, record)
    except Exception, KeyboardInterrupt:  # noqa: BLE001 - no generic error becomes an expected native negative.
        record["status"] = "failed"
    finally:
        cancellation.defer_interrupts = True
        try:
            if plan.archive is not None:
                plan.archive.verify()
                plan.archive.close()
            if plan.source is not None:
                plan.source.cleanup()
        except Exception, KeyboardInterrupt:  # noqa: BLE001 - uncertain source disposal invalidates completion.
            record["status"] = "failed"
        if cancellation.cancelled or time.monotonic_ns() >= clock.deadline_ns:
            record["status"] = "failed"
        try:
            contract.require(len(contract.canonical(record)) <= contract.PAIR_RECORD_BYTES)
            path = Path(args.evidence)
            path.parent.mkdir(parents=True, exist_ok=True)
            cancellation.defer_interrupts = False
            services.publish(path, record, clock.deadline_ns / 1_000_000_000)
        finally:
            for kind, handler in previous.items():
                signal.signal(kind, handler)
    return record


def _publish_host(plan: SimpleNamespace, value: dict, role: str) -> None:
    value = {
        **value,
        "image": plan.metadata["name"],
        "architecture": plan.architecture,
        "candidate": plan.provenance["candidate"],
        "runId": plan.provenance["run"],
        "runAttempt": plan.provenance["attempt"],
        "producingJob": plan.provenance["job"],
        "role": role,
    }
    contract.require(len(contract.canonical(value)) <= contract.HOST_BYTES)
    path = Path(plan.args.evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    plan.services.publish(
        path.with_name(path.stem + "-direct-host-" + role + ".json"), value, plan.clock.deadline_ns / 1_000_000_000
    )
    contract.require("publicationFailure" not in value and value.get("status") != "failed")
