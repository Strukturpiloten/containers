"""Validate exact-source manual direct-startup observations without native authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts import docker_userns_active as protocol
from scripts.docker_direct_startup_observations import STARTUP_SECONDS
from scripts.docker_direct_startup_plan import declarations, expected_versions
from scripts.docker_userns_qualification import (
    QualificationError,
    admission_document,
    context_digest,
    validate_workflow_context,
)
from scripts.runtime_resource_budgets import STORE_LIMIT_BYTES

PAIR_KEYS = (
    "schemaVersion",
    "consumer",
    "purpose",
    "qualification",
    "image",
    "architecture",
    "profile",
    "status",
    "candidate",
    "runId",
    "runAttempt",
    "producingJob",
    "workflowContextSha256",
    "imageIdentity",
    "gateSha256",
    "workflowContext",
    "conclusion",
    "arms",
    "namespaceControls",
    "stageDisposed",
    "pairStartedNs",
    "pairDeadlineNs",
    "failures",
    "bounds",
)


def _sha(value: object) -> str:
    return hashlib.sha256(contract.canonical(value)).hexdigest()


def _digest(value: object, *, prefixed: bool = False) -> None:
    contract.require(type(value) is str and re.fullmatch(("sha256:" if prefixed else "") + r"[0-9a-f]{64}", value))


def _identity(value: object, *, candidate: str, image: str, architecture: str) -> dict:
    identity = contract.exact_keys(
        value, ("manifestDigest", "configDigest", "archiveSha256", "architecture", "sourceRevision", "version")
    )
    _digest(identity["manifestDigest"], prefixed=True)
    _digest(identity["configDigest"], prefixed=True)
    _digest(identity["archiveSha256"])
    version = next(item["version"] for item in declarations() if item["name"] == image)
    contract.require(identity["architecture"] == architecture and identity["sourceRevision"] == candidate)
    contract.require(type(identity["version"]) is str and identity["version"] == version)
    return identity


def _producer_identity(candidate: str, run: str, attempt: str) -> None:
    contract.require(type(candidate) is str and re.fullmatch(r"[0-9a-f]{40}", candidate) and candidate != "0" * 40)
    contract.require(all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)))


def validate_pair_report(record: object, *, candidate: str, run: str, attempt: str) -> dict:
    """Require a complete closed pair bound to this producing source and attempt."""
    _producer_identity(candidate, run, attempt)
    pair = contract.exact_keys(record, PAIR_KEYS)
    contract.require(type(pair["schemaVersion"]) is int and pair["schemaVersion"] == contract.SCHEMA)
    contract.require(
        pair["consumer"] == contract.CONSUMER
        and pair["purpose"] == contract.PURPOSE
        and pair["qualification"] == "none"
        and pair["profile"] == "docker"
        and pair["status"] == "diagnostic-complete"
        and pair["candidate"] == candidate
        and pair["runId"] == run
        and pair["runAttempt"] == attempt
        and pair["producingJob"] == "smoke-build"
    )
    contract.finite_tuple(pair["image"], pair["architecture"])
    admission = Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json"
    admission_raw = admission.read_bytes()
    admission_sha256 = hashlib.sha256(admission_raw).hexdigest()
    context = pair["workflowContext"]
    contract.require(type(context) is dict)
    try:
        validate_workflow_context(context, admission_document(admission_raw), admission_sha256)
    except QualificationError:
        raise contract.DirectDiagnosticError from None
    contract.require(pair["workflowContextSha256"] == context_digest(context))
    contract.require(
        all(
            context[key] == value
            for key, value in {
                "candidate": candidate,
                "run": run,
                "attempt": attempt,
                "job": "smoke-build",
                "image": pair["image"],
                "architecture": pair["architecture"],
                "purpose": contract.PURPOSE,
            }.items()
        )
    )
    contract.require(pair["gateSha256"] == gate.GATE_SHA256)
    identity = _identity(
        pair["imageIdentity"], candidate=candidate, image=pair["image"], architecture=pair["architecture"]
    )
    contract.require(pair["stageDisposed"] is True and type(pair["failures"]) is list and pair["failures"] == [])
    contract.require(
        type(pair["namespaceControls"]) is dict and pair["namespaceControls"] == contract.optional_controls()
    )
    contract.require(type(pair["namespaceControls"]["attempted"]) is int)
    contract.require(type(pair["pairStartedNs"]) is int and type(pair["pairDeadlineNs"]) is int)
    contract.require(pair["pairDeadlineNs"] <= (1 << 63) - 1)
    contract.require(
        pair["pairStartedNs"] > 0
        and pair["pairDeadlineNs"] - pair["pairStartedNs"] == contract.PAIR_SECONDS * 1_000_000_000
    )
    bounds = contract.exact_keys(
        pair["bounds"], ("pairSeconds", "armWorkSeconds", "cleanupReserveSeconds", "storeBytes", "startupSeconds")
    )
    expected_bounds = {
        "pairSeconds": contract.PAIR_SECONDS,
        "armWorkSeconds": contract.ARM_WORK_SECONDS,
        "cleanupReserveSeconds": contract.CLEANUP_SECONDS,
        "storeBytes": STORE_LIMIT_BYTES,
        "startupSeconds": STARTUP_SECONDS,
    }
    contract.require(all(type(value) is int for value in bounds.values()) and bounds == expected_bounds)
    contract.require(type(pair["arms"]) is list and len(pair["arms"]) == len(("A", "B")))
    source_digest = _sha(
        {
            "candidate": candidate,
            "image": pair["image"],
            "architecture": pair["architecture"],
            "imageIdentity": identity,
            "admissionSha256": admission_sha256,
        }
    )
    versions = expected_versions(pair["image"])
    for arm in pair["arms"]:
        contract.validate_arm(arm)
        contract.require(arm["startup"] == "ready" or arm["guest"]["postExecVerified"] is False)
        contract.require((arm["image"], arm["architecture"]) == (pair["image"], pair["architecture"]))
        contract.require(arm["sourceIdentitySha256"] == source_digest)
        contract.require(all(arm["guest"]["executables"][key] == value for key, value in versions.items()))
    matched_guests = []
    for arm in pair["arms"]:
        actor = arm["guest"]["actor"]
        matched_guests.append(
            {
                "actor": actor
                | {"namespaces": {kind: value["relationship"] for kind, value in actor["namespaces"].items()}},
                "executables": arm["guest"]["executables"],
            }
        )
    contract.require(matched_guests[0] == matched_guests[1])
    conclusion = contract.compare_pair(*pair["arms"])
    contract.require(
        conclusion in {"profile-dependent-startup", "profile-not-demonstrated-remedy"}
        and pair["conclusion"] == conclusion
    )
    contract.require(len(contract.canonical(pair)) <= contract.PAIR_RECORD_BYTES)
    return pair


FAILURE_LIMIT = 8
LOCAL_OPERATIONS = frozenset(
    (
        "allocate",
        "backend-prepare",
        "archive",
        "image-import",
        "profile-prepare",
        "gate-prepare",
        "guest-create",
        "guest-bind",
        "guest-preflight",
        "guest-release",
        "startup-observation",
        "cleanup",
        "host-before",
        "host-before-publication",
        "source-prepare",
        "arm-A",
        "arm-B",
        "host-between",
        "host-between-publication",
        "host-after",
        "host-after-publication",
        "pair-compare",
        "source-cleanup",
        "pair-deadline",
        "publication",
        "diagnostics",
    )
)
LOCAL_REASONS = protocol.FAILURE_REASONS | frozenset(
    (
        "operation-unverified",
        "diagnostic-overflow",
        "unrecorded-failure",
        "logs-unavailable",
        "logs-byte-limit",
        "logs-record-limit",
        "logs-record-byte-limit",
        "logs-invalid-encoding",
    )
)
ERROR_TYPES = frozenset(
    (
        "unverified",
        "cancelled",
        "contract-refused",
        "os-error",
        "value-error",
        "type-error",
        "key-error",
        "runtime-error",
        "other",
        "overflow",
    )
)
LOCAL_KEYS = (
    "schemaVersion",
    "purpose",
    "qualification",
    "arm",
    "actor",
    "operation",
    "phase",
    "reason",
    "errorType",
    "cleanupAuthority",
)
ROOT_KEYS = (
    "schemaVersion",
    "purpose",
    "qualification",
    "arm",
    "actor",
    "operation",
    "phase",
    "reason",
    "bindingVerified",
    "bindingSha256",
    "sourceVerified",
    "retained",
    "cleanupAuthority",
    "rootReceiptSha256",
    "reportingLeaseSha256",
)
FAILED_KEYS = (
    "schemaVersion",
    "consumer",
    "purpose",
    "qualification",
    "status",
    "reason",
    "image",
    "architecture",
    "candidate",
    "runId",
    "runAttempt",
    "producingJob",
    "workflowContext",
    "workflowContextSha256",
    "gateSha256",
    "failures",
    "armOutcomes",
    "diagnosticOverflow",
    "publicationFailure",
)


def local_failure(arm: str, operation: str, error: BaseException | None = None) -> dict:
    """Classify fixed exception categories only; never expose messages or arbitrary class names."""
    categories = (
        (KeyboardInterrupt, "cancelled"),
        (contract.DirectDiagnosticError, "contract-refused"),
        (OSError, "os-error"),
        (ValueError, "value-error"),
        (TypeError, "type-error"),
        (KeyError, "key-error"),
        (RuntimeError, "runtime-error"),
    )
    category = (
        next((name for kind, name in categories if isinstance(error, kind)), "other")
        if error is not None
        else "unverified"
    )
    reason = protocol.failure_reason(error) if error is not None else "operation-unverified"
    if category == "contract-refused":
        reason = "refused"
    elif reason == "unexpected":
        reason = "operation-unverified"
    operation = operation if operation in LOCAL_OPERATIONS else "diagnostics"
    return {
        "schemaVersion": 1,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "arm": arm,
        "actor": "coordinator",
        "operation": operation,
        "phase": operation,
        "reason": reason,
        "errorType": category,
        "cleanupAuthority": False,
    }


def validate_failure(value: object) -> dict:
    """Validate a diagnostic projection without adopting any receipt or cleanup authority."""
    contract.require(type(value) is dict)
    local = value.get("actor") == "coordinator"
    failure = contract.exact_keys(value, LOCAL_KEYS if local else ROOT_KEYS)
    contract.require(type(failure["schemaVersion"]) is int and failure["schemaVersion"] == 1)
    contract.require(failure["purpose"] == contract.PURPOSE and failure["qualification"] == "none")
    contract.require(failure["arm"] in {"A", "B", "pair"} and failure["cleanupAuthority"] is False)
    if local:
        contract.require(failure["operation"] in LOCAL_OPERATIONS and failure["phase"] == failure["operation"])
        contract.require(failure["reason"] in LOCAL_REASONS and failure["errorType"] in ERROR_TYPES)
        contract.require((failure["errorType"] == "overflow") == (failure["reason"] == "diagnostic-overflow"))
        contract.require((failure["errorType"] == "cancelled") == (failure["reason"] == "cancelled"))
    else:
        contract.require(failure["arm"] in {"A", "B"})
        contract.require(failure["actor"] in {"root", "root-bootstrap", "workflow", "producer", "client"})
        contract.require(failure["operation"] in protocol.FAILURE_OPERATIONS)
        contract.require(failure["phase"] in protocol.FAILURE_PHASES and failure["reason"] in protocol.FAILURE_REASONS)
        contract.require(all(type(failure[key]) is bool for key in ("bindingVerified", "sourceVerified")))
        contract.require(failure["retained"] is None or type(failure["retained"]) is bool)
        _digest(failure["rootReceiptSha256"])
        if failure["bindingVerified"]:
            _digest(failure["bindingSha256"])
        else:
            contract.require(failure["bindingSha256"] is None and failure["reportingLeaseSha256"] is None)
        if failure["reportingLeaseSha256"] is not None:
            _digest(failure["reportingLeaseSha256"])
    contract.require(len(contract.canonical(failure)) <= contract.RECORD_BYTES)
    return failure


def _failed_identity(value: dict, *, candidate: str, run: str, attempt: str) -> None:
    _producer_identity(candidate, run, attempt)
    contract.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == contract.SCHEMA)
    contract.require(value["consumer"] == contract.CONSUMER and value["purpose"] == contract.PURPOSE)
    contract.require(value["qualification"] == "none" and value["status"] == "failed")
    contract.require(value["candidate"] == candidate and value["runId"] == run and value["runAttempt"] == attempt)
    contract.require(value["producingJob"] == "smoke-build" and value["gateSha256"] == gate.GATE_SHA256)
    contract.finite_tuple(value["image"], value["architecture"])
    raw = (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_bytes()
    context = value["workflowContext"]
    contract.require(type(context) is dict)
    try:
        validate_workflow_context(context, admission_document(raw), hashlib.sha256(raw).hexdigest())
    except QualificationError:
        raise contract.DirectDiagnosticError from None
    contract.require(value["workflowContextSha256"] == context_digest(context))
    expected = {
        "candidate": candidate,
        "run": run,
        "attempt": attempt,
        "job": "smoke-build",
        "image": value["image"],
        "architecture": value["architecture"],
        "purpose": contract.PURPOSE,
    }
    contract.require(all(context[key] == item for key, item in expected.items()))


def _arm_outcome(value: object) -> dict:
    arm = contract.exact_keys(value, ("arm", "startup", "nativeExitCode", "factsComplete", "cleanupVerified"))
    contract.require(arm["arm"] in {"A", "B"} and arm["startup"] in contract.STARTUP_KINDS)
    code = arm["nativeExitCode"]
    contract.require(code is None or (type(code) is int and 0 <= code <= contract.MAX_NATIVE_EXIT))
    contract.require(arm["startup"] != "ready" or code is None)
    contract.require(all(type(arm[key]) is bool for key in ("factsComplete", "cleanupVerified")))
    return arm


def failed_report(record: dict) -> dict:
    """Publish a separate closed failed shape; complete-pair validation stays strict."""
    failures = []
    for item in record["failures"]:
        validate_failure(item)
        if item not in failures:
            failures.append(item)
    if not failures:
        failures.append({**local_failure("pair", "diagnostics"), "reason": "unrecorded-failure"})
    overflow = len(failures) > FAILURE_LIMIT
    if overflow:
        marker = {**local_failure("pair", "diagnostics"), "reason": "diagnostic-overflow", "errorType": "overflow"}
        failures = [*failures[: FAILURE_LIMIT - 1], marker]
    value = {key: record[key] for key in FAILED_KEYS if key in record}
    value.update(
        status="failed",
        reason="diagnostic-incomplete",
        failures=failures,
        diagnosticOverflow=overflow,
        publicationFailure=None,
        armOutcomes=[
            {key: arm[key] for key in ("arm", "startup", "nativeExitCode", "factsComplete", "cleanupVerified")}
            for arm in record["arms"]
        ],
    )
    return validate_failed_report(value, candidate=value["candidate"], run=value["runId"], attempt=value["runAttempt"])


def validate_failed_report(value: object, *, candidate: str, run: str, attempt: str) -> dict:
    """Accept only bounded failed diagnostics bound to this exact source/attempt."""
    record = contract.exact_keys(value, FAILED_KEYS)
    _failed_identity(record, candidate=candidate, run=run, attempt=attempt)
    contract.require(record["reason"] == "diagnostic-incomplete")
    contract.require(record["publicationFailure"] in {None, "evidence-publication-failed"})
    failures = record["failures"]
    contract.require(type(failures) is list and 0 < len(failures) <= FAILURE_LIMIT)
    for index, failure in enumerate(failures):
        validate_failure(failure)
        contract.require(failure not in failures[:index])
    contract.require(type(record["diagnosticOverflow"]) is bool)
    markers = [index for index, item in enumerate(failures) if item["reason"] == "diagnostic-overflow"]
    contract.require(markers == ([FAILURE_LIMIT - 1] if record["diagnosticOverflow"] else []))
    if markers:
        contract.require(
            failures[-1]
            == {**local_failure("pair", "diagnostics"), "reason": "diagnostic-overflow", "errorType": "overflow"}
        )
    arms = record["armOutcomes"]
    contract.require(type(arms) is list and len(arms) <= len(contract.ROWS))
    for arm in arms:
        _arm_outcome(arm)
    contract.require([arm["arm"] for arm in arms] == ["A", "B"][: len(arms)])
    contract.require(len(contract.canonical(record)) <= contract.PAIR_RECORD_BYTES)
    return record


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        contract.require(key not in result)
        result[key] = value
    return result


def _read(path: Path) -> object:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        contract.require(stat.S_ISREG(info.st_mode) and info.st_size <= contract.PAIR_RECORD_BYTES)
        raw = os.read(descriptor, contract.PAIR_RECORD_BYTES + 1)
        contract.require(len(raw) <= contract.PAIR_RECORD_BYTES)
        return json.loads(raw, object_pairs_hook=_unique)
    finally:
        os.close(descriptor)


def _selected_pair(path: Path, *, candidate: str, run: str, attempt: str, row: tuple[str, str]) -> dict:
    image, architecture = row
    contract.finite_tuple(image, architecture)
    record = validate_pair_report(_read(path), candidate=candidate, run=run, attempt=attempt)
    contract.require((record["image"], record["architecture"]) == (image, architecture))
    return record


def _publication_failure(value: dict, *, candidate: str, run: str, attempt: str) -> dict:
    """Retain the publisher's fixed invalidation marker only over an otherwise valid pair."""
    contract.exact_keys(value, (*PAIR_KEYS, "publicationFailure"))
    contract.require(
        value["publicationFailure"] == "evidence-publication-failed" and value["conclusion"] == "inconclusive"
    )
    original = {key: value[key] for key in PAIR_KEYS}
    original.update(status="diagnostic-complete", conclusion=contract.compare_pair(*original["arms"]))
    validate_pair_report(original, candidate=candidate, run=run, attempt=attempt)
    original.update(status="failed", failures=[local_failure("pair", "publication")])
    failed = failed_report(original)
    failed["publicationFailure"] = "evidence-publication-failed"
    return failed


def _retained_record(value: object, *, candidate: str, run: str, attempt: str, row: tuple[str, str]) -> dict:
    if type(value) is dict and value.get("status") == "failed" and "arms" in value:
        retained = _publication_failure(value, candidate=candidate, run=run, attempt=attempt)
    else:
        validator = (
            validate_failed_report if type(value) is dict and value.get("status") == "failed" else validate_pair_report
        )
        retained = validator(value, candidate=candidate, run=run, attempt=attempt)
    contract.require((retained["image"], retained["architecture"]) == row)
    return retained


def retain_pair(path: Path, *, candidate: str, run: str, attempt: str, row: tuple[str, str]) -> dict:
    """Project only a closed validated pair or a fixed failure, never rejected input."""
    image, architecture = row
    contract.finite_tuple(image, architecture)
    _producer_identity(candidate, run, attempt)
    try:
        return _retained_record(_read(path), candidate=candidate, run=run, attempt=attempt, row=row)
    except OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError:
        return {
            "schemaVersion": 1,
            "consumer": contract.CONSUMER,
            "purpose": contract.PURPOSE,
            "qualification": "none",
            "status": "failed",
            "reason": "pair-evidence-refused",
            "image": image,
            "architecture": architecture,
            "candidate": candidate,
            "runId": run,
            "runAttempt": attempt,
            "producingJob": "smoke-build",
        }


def aggregate(paths: list[Path], *, candidate: str, run: str, attempt: str, complete: bool) -> dict:
    """Admit one pair for producer use, or both exact matrix reports for CI."""
    contract.require(len(paths) == (len(contract.ROWS) if complete else 1))
    records = [validate_pair_report(_read(path), candidate=candidate, run=run, attempt=attempt) for path in paths]
    if complete:
        contract.require(
            all(
                path.name == f"{record['image']}-{record['architecture']}.json"
                for path, record in zip(paths, records, strict=True)
            )
        )
    return _summary(records, candidate=candidate, run=run, attempt=attempt, complete=complete)


def _summary(records: list[dict], *, candidate: str, run: str, attempt: str, complete: bool) -> dict:
    rows = [(item["image"], item["architecture"]) for item in records]
    contract.require(len(set(rows)) == len(rows))
    if complete:
        contract.require(set(rows) == set(contract.ROWS))
    records.sort(key=lambda item: contract.ROWS.index((item["image"], item["architecture"])))
    return {
        "schemaVersion": 1,
        "consumer": contract.CONSUMER,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "status": "diagnostic-complete",
        "candidate": candidate,
        "runId": run,
        "runAttempt": attempt,
        "completeMatrix": complete,
        "pairs": [
            {"image": item["image"], "architecture": item["architecture"], "conclusion": item["conclusion"]}
            for item in records
        ],
    }


def _directory(directory: Path) -> list[Path]:
    contract.require(directory.is_dir() and not directory.is_symlink())
    paths = sorted(directory.rglob("*"))
    contract.require(all(not path.is_symlink() for path in paths))
    files = [path for path in paths if path.is_file()]
    contract.require(
        all(
            path.parent == directory or path.parent == directory / ("direct-startup-pair-" + path.stem)
            for path in files
        )
    )
    contract.require(
        all(
            path.is_file()
            or (
                path.parent == directory
                and path.name
                in {f"direct-startup-pair-{image}-{architecture}" for image, architecture in contract.ROWS}
            )
            for path in paths
        )
    )
    expected_names = {f"{image}-{architecture}.json" for image, architecture in contract.ROWS}
    contract.require(len(files) == len(expected_names) and {path.name for path in files} == expected_names)
    return files


def main() -> None:
    """Write a closed failure artifact before refusing absent or malformed evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pair", type=Path)
    source.add_argument("--retain-pair", type=Path)
    source.add_argument("--directory", type=Path)
    for name in ("candidate", "run", "attempt"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--image")
    parser.add_argument("--architecture")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.retain_pair is not None:
        retained = retain_pair(
            args.retain_pair,
            candidate=args.candidate,
            run=args.run,
            attempt=args.attempt,
            row=(args.image, args.architecture),
        )
        with args.output.open("xb") as output:
            output.write(contract.canonical(retained) + b"\n")
        return
    result = {
        "schemaVersion": 1,
        "consumer": contract.CONSUMER,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "status": "failed",
        "reason": "pair-evidence-refused",
    }
    try:
        if args.pair is not None:
            record = _selected_pair(
                args.pair,
                candidate=args.candidate,
                run=args.run,
                attempt=args.attempt,
                row=(args.image, args.architecture),
            )
            result = _summary([record], candidate=args.candidate, run=args.run, attempt=args.attempt, complete=False)
        else:
            result = aggregate(
                _directory(args.directory), candidate=args.candidate, run=args.run, attempt=args.attempt, complete=True
            )
    except OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError:
        args.output.write_bytes(contract.canonical(result) + b"\n")
        message = "Direct startup diagnostic refused; qualification:none"
        raise SystemExit(message) from None
    args.output.write_bytes(contract.canonical(result) + b"\n")


if __name__ == "__main__":
    main()
