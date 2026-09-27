"""Deterministic image catalogue from metadata and separately supplied evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
MIN_SUPPORT_BOUNDARY_LENGTH = 16
RUNTIME_PROFILES = frozenset({"podman", "phpFpm", "notifyPush", "docker"})


class MaintenanceError(ValueError):
    """Metadata or evidence cannot support the claimed catalogue state."""


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        msg = f"Expected a JSON object in {path}."
        raise MaintenanceError(msg)
    return value


def _date(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        msg = f"{field} must be an ISO date string."
        raise MaintenanceError(msg)
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError as error:
        msg = f"{field} must be a valid ISO date."
        raise MaintenanceError(msg) from error


def lifecycle_for(image: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the declared lifecycle policy without inferring vendor support."""
    name = str(image["name"])
    lifecycle = image.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return {
            "state": "unknown",
            "admission": "unknown",
            "supportBoundary": "No lifecycle policy declared.",
            "reviewAfter": None,
            "requiredRuntimeProfiles": [],
        }
    state = lifecycle.get("state")
    admission = lifecycle.get("admission")
    profiles = lifecycle.get("requiredRuntimeProfiles")
    boundary = lifecycle.get("supportBoundary")
    if state not in {"maintained", "legacy", "experimental"}:
        msg = f"{name} has an invalid lifecycle state."
        raise MaintenanceError(msg)
    if admission not in {"production", "isolated-test", "disabled"}:
        msg = f"{name} has an invalid admission state."
        raise MaintenanceError(msg)
    if (
        not isinstance(profiles, list)
        or not profiles
        or len(profiles) != len(set(profiles))
        or any(profile not in RUNTIME_PROFILES for profile in profiles)
    ):
        msg = f"{name} has invalid required runtime profiles."
        raise MaintenanceError(msg)
    if not isinstance(boundary, str) or len(boundary.strip()) < MIN_SUPPORT_BOUNDARY_LENGTH:
        msg = f"{name} has no meaningful support boundary."
        raise MaintenanceError(msg)
    return {
        "state": state,
        "admission": admission,
        "supportBoundary": boundary,
        "reviewAfter": _date(lifecycle.get("reviewAfter"), field=f"{name}.reviewAfter"),
        "requiredRuntimeProfiles": profiles,
    }


def _build_evidence(image: Mapping[str, Any], evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    if evidence is None:
        return {"status": "unknown", "reason": "No successful build result supplied."}
    name = str(image["name"])
    architectures = set(image["build"]["architectures"])
    digest_map = evidence.get("architectureDigests")
    if (
        evidence.get("imageName") != name
        or evidence.get("image") != image.get("image")
        or evidence.get("version") != str(image["version"]).removeprefix("v")
        or not isinstance(evidence.get("sourceRevision"), str)
        or SHA_RE.fullmatch(evidence["sourceRevision"]) is None
        or not isinstance(evidence.get("indexDigest"), str)
        or DIGEST_RE.fullmatch(evidence["indexDigest"]) is None
        or not isinstance(digest_map, dict)
        or set(digest_map) != architectures
        or any(not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None for value in digest_map.values())
    ):
        msg = f"Build evidence for {name} does not match image, version, source, and architecture digests."
        raise MaintenanceError(msg)
    succeeded_at = evidence.get("buildSucceededAt")
    if not isinstance(succeeded_at, str):
        msg = f"Build time for {name} is missing or invalid."
        raise MaintenanceError(msg)
    try:
        parsed = dt.datetime.fromisoformat(succeeded_at)
    except ValueError as error:
        msg = f"Build time for {name} is invalid."
        raise MaintenanceError(msg) from error
    if parsed.tzinfo is None:
        msg = f"Build time for {name} must include a timezone."
        raise MaintenanceError(msg)
    component_inputs = evidence.get("componentInputs", {})
    if not isinstance(component_inputs, dict):
        msg = f"Component inputs for {name} must be an object."
        raise MaintenanceError(msg)
    for key in ("runId", "runAttempt"):
        value = evidence.get(key)
        if not isinstance(value, str) or not value.isdecimal() or int(value) < 1:
            msg = f"Build evidence for {name} has invalid {key}."
            raise MaintenanceError(msg)
    return {
        "status": "recorded",
        "sourceRevision": evidence["sourceRevision"],
        "indexDigest": evidence["indexDigest"],
        "architectureDigests": digest_map,
        "componentInputs": component_inputs,
        "buildSucceededAt": succeeded_at,
        "runId": evidence.get("runId"),
        "runAttempt": evidence.get("runAttempt"),
    }


def _runtime_coverage(
    image: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]], build: Mapping[str, Any]
) -> dict[str, Any]:
    name = str(image["name"])
    required = lifecycle_for(image)["requiredRuntimeProfiles"]
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for item in evidence:
        architecture = item.get("architecture")
        profile = item.get("profile")
        if item.get("image") != name or architecture not in image["build"]["architectures"] or profile not in required:
            msg = f"Runtime evidence does not match {name}'s declared image, architecture, or profile."
            raise MaintenanceError(msg)
        key = (str(architecture), str(profile))
        if key in by_key or item.get("status") not in {"passed", "failed", "skipped"}:
            msg = f"Runtime evidence for {name} has duplicate or invalid status at {key}."
            raise MaintenanceError(msg)
        checks = item.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or any(
                not isinstance(check, dict) or check.get("status") not in {"passed", "failed", "skipped"}
                for check in checks
            )
        ):
            msg = f"Runtime evidence for {name} has invalid checks at {key}."
            raise MaintenanceError(msg)
        if item["status"] == "passed" and any(check["status"] == "failed" for check in checks):
            msg = f"Runtime evidence for {name} has contradictory checks at {key}."
            raise MaintenanceError(msg)
        identity = item.get("imageIdentity")
        if (
            not isinstance(identity, dict)
            or identity.get("architecture") != architecture
            or any(
                not isinstance(identity.get(field), str) or DIGEST_RE.fullmatch(identity[field]) is None
                for field in ("manifestDigest", "configDigest", "archiveSha256")
            )
            or not isinstance(identity.get("sourceRevision"), str)
            or SHA_RE.fullmatch(identity["sourceRevision"]) is None
        ):
            msg = f"Runtime evidence for {name} has no verified archive identity at {key}."
            raise MaintenanceError(msg)
        if identity.get("version") not in {image["version"], str(image["version"]).removeprefix("v")}:
            msg = f"Runtime evidence for {name} has wrong version at {key}."
            raise MaintenanceError(msg)
        if build["status"] == "recorded" and identity["sourceRevision"] != build["sourceRevision"]:
            msg = f"Runtime evidence for {name} has wrong source revision at {key}."
            raise MaintenanceError(msg)
        host = item.get("host")
        if not isinstance(host, dict) or not host:
            msg = f"Runtime evidence for {name} has no host context at {key}."
            raise MaintenanceError(msg)
        by_key[key] = {
            "status": item["status"],
            "checks": checks,
            "imageIdentity": identity,
            "host": host,
            "runId": item.get("runId"),
            "runAttempt": item.get("runAttempt"),
        }
    return {
        architecture: {
            profile: by_key.get((architecture, profile), {"status": "unknown", "checks": []}) for profile in required
        }
        for architecture in image["build"]["architectures"]
    }


def catalogue(
    images: Sequence[Mapping[str, Any]],
    *,
    build_results: Mapping[str, Mapping[str, Any]] | None = None,
    runtime_results: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    registry_observations: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a catalogue; absent runtime or registry proof stays explicitly unknown."""
    build_results = build_results or {}
    runtime_results = runtime_results or {}
    registry_observations = registry_observations or {}
    known = {str(image["name"]) for image in images}
    for label, records in (("build", build_results), ("runtime", runtime_results), ("registry", registry_observations)):
        if unknown := set(records) - known:
            msg = f"Unknown images in {label} evidence: {', '.join(sorted(unknown))}."
            raise MaintenanceError(msg)
    rows: list[dict[str, Any]] = []
    for image in sorted(images, key=lambda item: str(item["name"])):
        name = str(image["name"])
        lifecycle = lifecycle_for(image)
        build = _build_evidence(image, build_results.get(name))
        observation = registry_observations.get(name)
        registry: dict[str, Any] = {"status": "unknown"}
        if observation is not None:
            if (
                observation.get("image") != image.get("image")
                or not isinstance(observation.get("digest"), str)
                or DIGEST_RE.fullmatch(observation["digest"]) is None
                or build["status"] != "recorded"
                or observation["digest"] != build["indexDigest"]
                or observation.get("reference") != f"{image['image']}@{observation['digest']}"
                or not isinstance(observation.get("observedAt"), str)
            ):
                msg = f"Registry observation for {name} does not match recorded build digest."
                raise MaintenanceError(msg)
            try:
                observed_at = dt.datetime.fromisoformat(observation["observedAt"])
            except ValueError as error:
                msg = f"Registry observation for {name} has invalid observedAt."
                raise MaintenanceError(msg) from error
            if observed_at.tzinfo is None:
                msg = f"Registry observation for {name} must include an observedAt timezone."
                raise MaintenanceError(msg)
            registry = {
                "status": "observed",
                "digest": observation["digest"],
                "reference": observation.get("reference"),
                "observedAt": observation.get("observedAt"),
            }
        rows.append(
            {
                "name": name,
                "image": image["image"],
                "version": image["version"],
                "architectures": image["build"]["architectures"],
                "lifecycle": lifecycle,
                "build": build,
                "runtimeCoverage": _runtime_coverage(image, runtime_results.get(name, []), build),
                "registry": registry,
            }
        )
    return {"schemaVersion": 1, "images": rows}


def markdown_catalogue(report: Mapping[str, Any]) -> str:
    """Render a compact human-readable index with evidence gaps visible."""
    lines = [
        "# Container maintenance catalogue",
        "",
        "Lifecycle is repository policy. Registry availability and runtime coverage require separate evidence.",
        "",
        "| Image | Lifecycle | Admission | Review after | Build digest | Registry | Runtime coverage |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for image in report["images"]:
        lifecycle = image["lifecycle"]
        coverage = image["runtimeCoverage"]
        statuses = sorted(
            {entry["status"] for profiles in coverage.values() for entry in profiles.values()}
            | {
                "skipped checks"
                for profiles in coverage.values()
                for entry in profiles.values()
                if any(check.get("status") == "skipped" for check in entry["checks"])
            }
        )
        digest = image["build"].get("indexDigest", "unknown")
        lines.append(
            f"| {image['name']} | {lifecycle['state']} | {lifecycle['admission']} | "
            f"{lifecycle['reviewAfter'] or 'unknown'} | {digest} | {image['registry']['status']} | "
            f"{', '.join(statuses) or 'unknown'} |"
        )
    lines.extend(["", "Support boundaries and component inputs are in the accompanying JSON report.", ""])
    return "\n".join(lines)


def _load_evidence(directory: Path) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    builds: dict[str, dict[str, Any]] = {}
    runtime: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(directory.rglob("*-build-result.json")):
        data = _read_json(path)
        name = data.get("imageName")
        if not isinstance(name, str) or name in builds:
            msg = f"Ambiguous build evidence in {path}."
            raise MaintenanceError(msg)
        builds[name] = data
    for path in sorted(directory.rglob("*-runtime-evidence.json")):
        data = _read_json(path)
        name = data.get("image")
        if not isinstance(name, str):
            msg = f"Runtime evidence in {path} has no image."
            raise MaintenanceError(msg)
        runtime.setdefault(name, []).append(data)
    return builds, runtime


def main() -> None:
    """Generate deterministic JSON and Markdown catalogue files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--registry-observations", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()
    from scripts import container_engine  # noqa: PLC0415

    images = container_engine._load_images()  # noqa: SLF001
    container_engine._validate_images(images)  # noqa: SLF001
    builds, runtime = _load_evidence(args.evidence_dir) if args.evidence_dir else ({}, {})
    observations = _read_json(args.registry_observations) if args.registry_observations else {}
    report = catalogue(images, build_results=builds, runtime_results=runtime, registry_observations=observations)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_output.write_text(markdown_catalogue(report), encoding="utf-8")


if __name__ == "__main__":
    main()
