"""Write immutable, per-build maintenance evidence assets for automatic releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from scripts.scan_sources import published_manifest

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseEvidenceError(ValueError):
    """Release and build evidence do not support an immutable asset."""


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"Expected JSON object in {path}."
        raise ReleaseEvidenceError(msg)
    return data


def _github_request(
    url: str, token: str, *, data: bytes | None = None, accept: str = "application/vnd.github+json"
) -> bytes:
    request = urllib.request.Request(  # noqa: S310
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.read()
    except (urllib.error.HTTPError, urllib.error.URLError) as error:
        msg = f"GitHub release evidence request failed: {error}."
        raise ReleaseEvidenceError(msg) from error


def _github_release(repository: str, release_tag: str, token: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(release_tag, safe="")
    value = json.loads(_github_request(f"https://api.github.com/repos/{repository}/releases/tags/{encoded}", token))
    if not isinstance(value, dict) or not isinstance(value.get("id"), int):
        msg = f"GitHub returned an invalid release for {release_tag}."
        raise ReleaseEvidenceError(msg)
    return value


def _attached_records(
    directory: Path | None, pattern: str, image_name: str, architectures: set[str]
) -> list[dict[str, Any]]:
    if directory is None:
        return []
    records = []
    for path in sorted(directory.rglob(pattern)):
        record = _read_json(path)
        if record.get("image") != image_name or record.get("architecture") not in architectures:
            msg = f"Attached maintenance evidence {path} does not match image and architecture."
            raise ReleaseEvidenceError(msg)
        records.append(record)
    return records


def record(  # noqa: C901
    build_result: dict[str, Any],
    *,
    release_origin_revision: str,
    runtime_evidence: list[dict[str, Any]] | None = None,
    scan_reports: list[dict[str, Any]] | None = None,
    published_configs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Keep immutable release origin separate from each later maintenance build source."""
    name, image, version = (build_result.get(key) for key in ("imageName", "image", "version"))
    source = build_result.get("sourceRevision")
    digest = build_result.get("indexDigest")
    architecture_digests = build_result.get("architectureDigests")
    run_id, run_attempt = build_result.get("runId"), build_result.get("runAttempt")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(image, str)
        or not image
        or not isinstance(version, str)
        or not version
        or not isinstance(source, str)
        or REVISION_RE.fullmatch(source) is None
        or REVISION_RE.fullmatch(release_origin_revision) is None
        or not isinstance(digest, str)
        or DIGEST_RE.fullmatch(digest) is None
        or not isinstance(architecture_digests, dict)
        or not architecture_digests
        or any(
            not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None for value in architecture_digests.values()
        )
        or not isinstance(run_id, str)
        or not run_id.isdecimal()
        or not isinstance(run_attempt, str)
        or not run_attempt.isdecimal()
        or not build_result.get("buildSucceededAt")
        or build_result.get("releaseTag") != f"{name}/v{version}"
    ):
        msg = "Finalized build result is incomplete or invalid."
        raise ReleaseEvidenceError(msg)
    runtime = runtime_evidence or []
    scans = scan_reports or []
    published = published_configs or {}
    if published and set(published) != set(architecture_digests):
        msg = "Published configuration evidence is incomplete."
        raise ReleaseEvidenceError(msg)
    for architecture, manifest in published.items():
        if (
            manifest.get("architecture") != architecture
            or manifest.get("manifestDigest") != architecture_digests[architecture]
        ):
            msg = "Published configuration evidence does not match build result."
            raise ReleaseEvidenceError(msg)
    for label, entries in (("runtime", runtime), ("scan", scans)):
        for entry in entries:
            if entry.get("image") != name and entry.get("image") != image:
                msg = f"{label} evidence does not match release image."
                raise ReleaseEvidenceError(msg)
            if entry.get("architecture") not in architecture_digests:
                msg = f"{label} evidence has an unsupported architecture."
                raise ReleaseEvidenceError(msg)
            candidate_source = entry.get("candidateSource")
            if isinstance(candidate_source, dict) and candidate_source.get("sourceRevision") != source:
                msg = f"{label} evidence comes from a different source revision."
                raise ReleaseEvidenceError(msg)
            if entry.get("sourceRevision") is not None and entry["sourceRevision"] != source:
                msg = f"{label} evidence comes from a different source revision."
                raise ReleaseEvidenceError(msg)
            archive_identity = entry.get("imageIdentity") if label == "runtime" else candidate_source
            if (
                isinstance(archive_identity, dict)
                and entry["architecture"] in published
                and archive_identity.get("configDigest") != published[entry["architecture"]].get("configDigest")
            ):
                msg = f"{label} archive configuration does not match published configuration."
                raise ReleaseEvidenceError(msg)
    return {
        "schemaVersion": 1,
        "imageName": name,
        "image": image,
        "version": version,
        "releaseTag": build_result["releaseTag"],
        "releaseOriginRevision": release_origin_revision,
        "buildSourceRevision": source,
        "indexDigest": digest,
        "architectureDigests": architecture_digests,
        "publicationMapping": published,
        "buildSucceededAt": build_result["buildSucceededAt"],
        "runId": run_id,
        "runAttempt": run_attempt,
        "componentInputs": build_result.get("componentInputs", {}),
        "runtimeEvidence": runtime,
        "scanReports": scans,
    }


def asset_name(evidence: dict[str, Any]) -> str:
    """Name an asset by immutable index digest and publication identity."""
    return (
        f"maintenance-evidence-{evidence['indexDigest'].replace(':', '-')}-"
        f"{evidence['runId']}-{evidence['runAttempt']}.json"
    )


def upload(evidence: dict[str, Any], payload: bytes, *, repository: str, token: str, release: dict[str, Any]) -> None:
    """Upload a new asset; an existing name must contain exactly the same bytes."""
    name = asset_name(evidence)
    assets_url = f"https://api.github.com/repos/{repository}/releases/{release['id']}/assets?per_page=100"
    assets = json.loads(_github_request(assets_url, token))
    if not isinstance(assets, list):
        msg = "GitHub returned invalid release assets."
        raise ReleaseEvidenceError(msg)
    for asset in assets:
        if isinstance(asset, dict) and asset.get("name") == name:
            expected = f"sha256:{hashlib.sha256(payload).hexdigest()}"
            if asset.get("digest") == expected:
                return
            url = asset.get("url")
            if not isinstance(url, str) or _github_request(url, token, accept="application/octet-stream") != payload:
                msg = f"Existing release asset {name} has different contents."
                raise ReleaseEvidenceError(msg)
            return
    upload_url = release.get("upload_url")
    if not isinstance(upload_url, str):
        msg = "GitHub release has no asset upload URL."
        raise ReleaseEvidenceError(msg)
    url = f"{upload_url.split('{', 1)[0]}?name={urllib.parse.quote(name)}"
    _github_request(url, token, data=payload)


def main() -> None:
    """Create a local maintenance JSON record and optionally upload it as a release asset."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-result", required=True, type=Path)
    parser.add_argument("--runtime-evidence-dir", type=Path)
    parser.add_argument("--scan-report-dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--verify-publication", action="store_true")
    args = parser.parse_args()
    build_result = _read_json(args.build_result)
    token, repository = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        parser.error("GITHUB_TOKEN and GITHUB_REPOSITORY are required to resolve release origin")
    release_tag = build_result.get("releaseTag")
    if not isinstance(release_tag, str):
        parser.error("Build result has no release tag")
    release = _github_release(repository, release_tag, token)
    origin = release.get("target_commitish")
    if not isinstance(origin, str) or REVISION_RE.fullmatch(origin) is None:
        msg = "Automatic GitHub Release has no immutable origin revision."
        raise ReleaseEvidenceError(msg)
    architectures = set(build_result.get("architectureDigests", {}))
    published = (
        {
            arch: published_manifest(build_result["image"], digest, arch)
            for arch, digest in build_result.get("architectureDigests", {}).items()
        }
        if args.verify_publication
        else {}
    )
    evidence = record(
        build_result,
        release_origin_revision=origin,
        runtime_evidence=_attached_records(
            args.runtime_evidence_dir, "*-runtime-evidence.json", build_result["imageName"], architectures
        ),
        scan_reports=_attached_records(
            args.scan_report_dir, "*vulnerability-report.json", build_result["image"], architectures
        ),
        published_configs=published,
    )
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    if args.upload:
        upload(evidence, payload, repository=repository, token=token, release=release)


if __name__ == "__main__":
    main()
