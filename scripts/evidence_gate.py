"""Require one verified native runtime and vulnerability result per built architecture."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from scripts import container_engine
from scripts.admission import image_policy
from scripts.oci_artifacts import archive_identity


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
