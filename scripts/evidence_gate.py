"""Require one verified native runtime and vulnerability result per built architecture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from scripts import container_engine
from scripts.admission import image_policy
from scripts.docker_userns_qualification import MAX_NAMESPACES, NativeBinding, QualificationError, validation_profile
from scripts.oci_artifacts import archive_identity

MAX_WORKFLOW_EVENT = 262144
IMAGE_VERSION_ENV = "ImageVersion"
MAX_VERSION_CHARACTERS = 256
FIRST_PRINTABLE_CHARACTER = 32


class EvidenceError(ValueError):
    """Required architecture evidence is missing, failed, or bound to another image."""


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        msg = f"Evidence in {path} must be a JSON object."
        raise EvidenceError(msg)
    return value


def _attempt(value: object, *, run_id: str, execution_attempt: int) -> bool:
    return isinstance(value, str) and value.isdecimal() and 1 <= int(value) <= execution_attempt and run_id.isdecimal()


def _runtime_skips(record: dict[str, Any], *, nested_disabled: bool, profile: str) -> None:
    checks = record.get("checks")
    if not isinstance(checks, list) or not checks:
        msg = "Runtime evidence has no checks."
        raise EvidenceError(msg)
    for check in checks:
        if not isinstance(check, dict) or check.get("status") not in {"passed", "skipped"}:
            msg = "Runtime evidence has a failed or invalid check."
            raise EvidenceError(msg)
        if check["status"] != "skipped":
            continue
        intentional_nested = nested_disabled and check.get("reason") == "disabled in metadata"
        documented_scope = profile == "notifyPush" and check.get("name") == "integration scope"
        if not intentional_nested and not documented_scope:
            msg = f"Runtime check {check.get('name')} was skipped without a declared exemption."
            raise EvidenceError(msg)


def _observed_version(value: object, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(prefix) < len(value) <= MAX_VERSION_CHARACTERS
        and bool(value[len(prefix) :].strip())
        and not any(ord(character) < FIRST_PRINTABLE_CHARACTER for character in value)
        and (bool(prefix) or value[0].isdigit())
    )


def _outer_runtime(record: dict[str, Any], profile: str) -> None:
    """Require the CI caller policy independently of the inner engine mode."""
    engines = {"docker": "docker", "podman": "podman", "phpFpm": "podman", "notifyPush": "podman"}
    host = record.get("host")
    if not isinstance(host, dict):
        msg = "Runtime evidence lacks outer-runtime host observations."
        raise EvidenceError(msg)
    observed = host.get("outerRuntime")
    engine = engines.get(profile)
    if (
        engine is None
        or host.get("outerEngineSelection") != "profile"
        or not isinstance(observed, dict)
        or observed.get("engine") != engine
        or observed.get("rootMode") != "rootful"
        or observed.get("storage") != "invocation-owned"
    ):
        msg = "Runtime evidence does not establish the required private CI outer engine."
        raise EvidenceError(msg)
    prefix = "Docker version " if engine == "docker" else "podman version "
    version = observed.get("clientVersion")
    if not _observed_version(version, prefix):
        msg = "Runtime evidence lacks an observed outer-engine client version."
        raise EvidenceError(msg)
    if engine == "docker":
        values = (("serverVersion", ""), ("containerdVersion", "containerd "), ("systemdVersion", "systemd "))
        for name, required_prefix in values:
            value = observed.get(name)
            if not _observed_version(value, required_prefix):
                msg = "Runtime evidence lacks an observed private Docker dependency version."
                raise EvidenceError(msg)
        if observed.get("endpoint") != "private-unix" or "podmanVersion" in host:
            msg = "Docker runtime evidence has an ambient endpoint or misleading Podman identity."
            raise EvidenceError(msg)
    elif host.get("podmanVersion") != version:
        msg = "Podman runtime version fields disagree."
        raise EvidenceError(msg)


def _active_candidate(record: dict[str, Any]) -> bool:
    return (
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/TheRealBecks/issue527"
        and os.environ.get("GITHUB_JOB") == "smoke-build"
        and record.get("image") == "docker-29-conformance-rootless"
    )


def _active_validation_request() -> str:
    """Preserve the raw request while rejecting unknown or non-ASCII workflow choices."""
    try:
        event_path = Path("/home/runner/work/_temp/_github_workflow/event.json")
        if os.environ.get("GITHUB_EVENT_PATH") != str(event_path):
            reason = "Active candidate workflow context is unavailable."
            raise EvidenceError(reason)
        with event_path.open("rb") as stream:
            raw = stream.read(MAX_WORKFLOW_EVENT + 1)
        if len(raw) > MAX_WORKFLOW_EVENT:
            reason = "Active candidate workflow context exceeds its bound."
            raise EvidenceError(reason)
        requested = json.loads(raw).get("inputs", {}).get("validation_profile", "full")
        validation_profile(requested)
    except (OSError, ValueError, TypeError, AttributeError, QualificationError) as error:
        reason = "Active candidate workflow context is unverified."
        raise EvidenceError(reason) from error
    else:
        return requested


def _active_scoped_required(record: dict[str, Any]) -> bool:
    requested = _active_validation_request() if _active_candidate(record) else None
    return record.get("scopedProfileRequired") is True or (
        requested is not None and validation_profile(requested) == "docker-rootless-diagnostic"
    )


def _scoped_preflight(scoped: dict[str, Any]) -> bool:
    """Check the active helper's finite actual-host facts against reviewed admission."""
    admission = json.loads(
        (Path(__file__).resolve().parents[1] / ".github/docker-userns-active-admission.json").read_text()
    )
    cohort, facts = admission["cohort"], scoped["preflight"]
    controls, namespace = facts["controls"], scoped["namespace"]
    keys = ("parserSha256", "abiSha256", "namespaceMaskSha256", "policyVersion9Sha256", "interpreterSha256")
    return (
        all(facts[key] == cohort[key] for key in ("osID", "osVersion", "machine", "kernel", "parserVersion"))
        and all(facts["files"][key]["sha256"] == cohort[key] for key in keys)
        and facts["imageVersion"] == scoped["imageVersion"]
        and controls["enabled"] is True
        and type(controls["restricted_userns"]) is int
        and controls["restricted_userns"] == 1
        and type(controls["maximum_userns"]) is int
        and 0 < controls["maximum_userns"] <= MAX_NAMESPACES
        and (
            controls["legacy_clone"] is None
            or (type(controls["legacy_clone"]) is int and controls["legacy_clone"] == 1)
        )
        and all(
            namespace[key] == hashlib.sha256(value.encode()).hexdigest()
            for key, value in admission["policyNamespace"].items()
        )
        and all(type(namespace[key]) is int and namespace[key] > 0 for key in ("user", "mnt", "cgroup"))
    )


def _scoped_phase(record: dict[str, Any], phase: dict[str, Any]) -> None:
    """Require exact archived image, actual profile readback and completed custody."""
    scoped = phase.get("scopedProfile")
    if not isinstance(scoped, dict):
        reason = "Active systemd candidate lacks scoped qualification evidence."
        raise EvidenceError(reason)
    try:
        binding = NativeBinding(**scoped["binding"])
        binding.validate()
        identity = phase["imageIdentity"]
        observation = scoped["profileObservation"]
        valid = (
            _scoped_preflight(scoped)
            and scoped["consumer"] == "containers-ubuntu26-userns-active"
            and scoped["qualification"] == "experimental-candidate-only"
            and scoped["validationProfile"] == "docker-rootless-diagnostic"
            and validation_profile(scoped["validationProfileRequested"]) == scoped["validationProfile"]
            and scoped["bindingSha256"] == binding.digest()
            and binding.phase == phase["phase"]
            and binding.image == record["image"]
            and binding.architecture == phase["architecture"] == "amd64"
            and binding.archive_sha256 == identity["archiveSha256"]
            and binding.manifest_digest == identity["manifestDigest"]
            and binding.config_digest == identity["configDigest"]
            and binding.candidate == identity["sourceRevision"]
            and re.fullmatch(r"[0-9a-f]{32}", scoped["lease"]) is not None
            and scoped["profileName"]
            == f"dockerlens-127-upstream-rootless-{binding.run}-{binding.attempt}-{scoped['lease']}"
            and scoped["sourceManifestSha256"] == "7f6693f40311617e4854f8c6a35cbe13b3afdd3d7a8bef58978397ba1178dbd8"
            and scoped["state"] == "closed"
            and scoped["cleanOwnerVerified"] is True
            and scoped["ownerTerminationVerified"] is True
            and scoped["custodyDisposed"] is True
            and scoped["ownerReady"] is True
            and scoped["guestAbsenceVerified"] is True
            and scoped["taskAbsenceVerified"] is True
            and scoped["scopeAbsenceVerified"] is True
            and scoped["profileAbsenceVerified"] is True
            and scoped["retained"] is False
            and scoped["readerPending"] is False
            and scoped["childPending"] is False
            and scoped["imageVersionKind"] == "workflow-reported-provenance-not-vm-attestation"
            and scoped["parserExecutionNamespace"]["measuredPostExec"] is False
            and scoped["parserExecutionNamespace"]["kind"]
            == "reviewed-trusted-fixed-os-no-parser-exec-transition-assumption"
            and observation["source"] == "held-task-attr/apparmor/current"
            and observation["exactMatch"] is True
            and observation["singleLabel"] is True
            and observation["bytes"] == len((scoped["profileName"] + " (unconfined)\n").encode())
            and observation["sha256"]
            == hashlib.sha256((scoped["profileName"] + " (unconfined)\n").encode()).hexdigest()
            and observation["taskIdentityBound"] is True
            and observation["timing"] == "post-create"
        )
        # The workflow's ImageVersion is provenance and is compared only with
        # the frozen same-job report, never treated as independent VM attestation.
        if _active_candidate(record):
            valid = valid and scoped["validationProfileRequested"] == _active_validation_request()
        if os.environ.get(IMAGE_VERSION_ENV):
            valid = valid and scoped["imageVersion"] == os.environ[IMAGE_VERSION_ENV]
        if os.environ.get("GITHUB_SHA"):
            valid = valid and binding.candidate == os.environ["GITHUB_SHA"]
        if os.environ.get("GITHUB_RUN_ID"):
            valid = valid and binding.run == os.environ["GITHUB_RUN_ID"]
        if os.environ.get("GITHUB_RUN_ATTEMPT"):
            valid = valid and binding.attempt == os.environ["GITHUB_RUN_ATTEMPT"]
    except KeyError, TypeError, ValueError, QualificationError:
        valid = False
    if not valid:
        reason = "Active systemd candidate scoped identity, attachment or cleanup is unverified."
        raise EvidenceError(reason)


def _systemd_phase_backends(record: dict[str, Any], profile: str, configuration: object) -> None:
    if (
        profile != "docker"
        or not isinstance(configuration, dict)
        or configuration.get("launcher") != "systemd"
        or configuration.get("mode") != "rootless"
    ):
        return
    phases = record.get("phases")
    expected = ("clean-control", "enforcement")
    if not isinstance(phases, list) or len(phases) != len(expected):
        msg = "Systemd Docker evidence lacks both required independent runtime phases."
        raise EvidenceError(msg)
    for name, phase in zip(expected, phases, strict=True):
        if (
            not isinstance(phase, dict)
            or phase.get("phase") != name
            or phase.get("status") != "passed"
            or phase.get("cleanupVerified") is not True
            or phase.get("imageIdentity") != record.get("imageIdentity")
        ):
            msg = "Systemd Docker phase identity, admission or cleanup differs from its required contract."
            raise EvidenceError(msg)
        if _active_scoped_required(record):
            _scoped_phase(record, phase)
        _runtime_skips(phase, nested_disabled=False, profile="docker")
        _outer_runtime(
            {
                "host": {
                    "outerEngineSelection": record["host"]["outerEngineSelection"],
                    "outerRuntime": phase.get("outerRuntime"),
                }
            },
            "docker",
        )


def verify_architecture(  # noqa: PLR0913
    *,
    name: str,
    architecture: str,
    source_revision: str,
    version: str,
    run_id: str,
    execution_attempt: int,
    archive: Path,
    runtime: dict[str, Any],
    scan: dict[str, Any],
) -> None:
    """Bind runtime and scanner decisions to the same exact built OCI archive."""
    policy = image_policy(name, architecture)
    identity = archive_identity(archive, architecture)
    profile = policy["requiredRuntimeProfile"]
    metadata = next(item for item in container_engine._load_images() if item["name"] == name)  # noqa: SLF001
    test_profile = metadata.get("tests", {}).get(profile, {})
    nested_disabled = isinstance(test_profile, dict) and test_profile.get("nestedRuntime") is False
    runtime_identity = runtime.get("imageIdentity")
    if (
        runtime.get("image") != name
        or runtime.get("architecture") != architecture
        or runtime.get("profile") != profile
        or runtime.get("status") != "passed"
        or runtime.get("runId") != run_id
        or not _attempt(runtime.get("runAttempt"), run_id=run_id, execution_attempt=execution_attempt)
        or not isinstance(runtime_identity, dict)
        or runtime_identity != identity
        or identity.get("sourceRevision") != source_revision
        or identity.get("version") != version
        or not isinstance(runtime.get("host"), dict)
        or not runtime["host"]
    ):
        msg = f"Runtime evidence does not prove {name} linux/{architecture} from this archive and run."
        raise EvidenceError(msg)
    _runtime_skips(runtime, nested_disabled=nested_disabled, profile=profile)
    _outer_runtime(runtime, profile)
    _systemd_phase_backends(runtime, profile, test_profile)
    candidate = scan.get("candidateSource")
    if (
        scan.get("image") != policy["image"]
        or scan.get("architecture") != architecture
        or scan.get("admission") != policy["admission"]
        or scan.get("decision") != "passed"
        or scan.get("sourceRevision") != source_revision
        or scan.get("runId") != run_id
        or not _attempt(scan.get("runAttempt"), run_id=run_id, execution_attempt=execution_attempt)
        or not isinstance(candidate, dict)
        or candidate.get("architecture") != architecture
        or candidate.get("manifestDigest") != identity["manifestDigest"]
        or candidate.get("configDigest") != identity["configDigest"]
        or str(candidate.get("archiveSha256", "")).removeprefix("sha256:") != identity["archiveSha256"]
        or candidate.get("sourceRevision") != source_revision
        or candidate.get("version") != version
        or not isinstance(scan.get("scanner"), dict)
        or not scan["scanner"]
        or not isinstance(scan.get("database"), dict)
        or not scan["database"]
    ):
        msg = f"Vulnerability report does not prove {name} linux/{architecture} from this archive and run."
        raise EvidenceError(msg)
    baseline = scan.get("baselineSource")
    if scan.get("baselineStatus") == "absent":
        if (
            scan.get("baselineDigest") is not None
            or not isinstance(baseline, dict)
            or baseline.get("status") != "absent"
        ):
            msg = "First-publication scan lacks explicit baseline absence evidence."
            raise EvidenceError(msg)
    elif scan.get("baselineStatus") == "observed":
        if not isinstance(baseline, dict) or baseline.get("manifestDigest") != scan.get("baselineDigest"):
            msg = "Baseline scan has no verified architecture manifest."
            raise EvidenceError(msg)
    else:
        msg = "Scan report has no recognized baseline state."
        raise EvidenceError(msg)


def main() -> None:
    """Gate publication on uploaded evidence for every declared architecture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--archives-dir", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--scan-dir", required=True, type=Path)
    args = parser.parse_args()
    plan = _read(args.plan)
    source_revision = plan.get("sourceRevision")
    matches = [item for item in plan.get("images", []) if item.get("name") == args.name]
    if len(matches) != 1 or not isinstance(source_revision, str):
        msg = "Build plan does not contain the requested image and source revision."
        raise EvidenceError(msg)
    image = matches[0]
    architectures = image["build"]["architectures"]
    run_id, run_attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not run_id.isdecimal() or not run_attempt.isdecimal():
        msg = "GitHub run identity is unavailable."
        raise EvidenceError(msg)
    for architecture in architectures:
        verify_architecture(
            name=args.name,
            architecture=architecture,
            source_revision=source_revision,
            version=str(image["version"]),
            run_id=run_id,
            execution_attempt=int(run_attempt),
            archive=args.archives_dir / f"{args.name}-{architecture}.tar",
            runtime=_read(args.runtime_dir / f"{args.name}-{architecture}.json"),
            scan=_read(args.scan_dir / f"{args.name}-{architecture}-vulnerability-report.json"),
        )


if __name__ == "__main__":
    main()
