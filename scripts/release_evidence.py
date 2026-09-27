"""Write immutable, per-build maintenance evidence assets for automatic releases."""

from __future__ import annotations

import argparse
import hashlib
import http
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from scripts.admission import image_policy
from scripts.scan_sources import published_manifest

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
ASSET_PAGE_SIZE = 100


class ReleaseEvidenceError(ValueError):
    """Release and build evidence do not support an immutable asset."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        """Keep the HTTP status available for a missing-release lookup."""
        super().__init__(message)
        self.status_code = status_code


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"Expected JSON object in {path}."
        raise ReleaseEvidenceError(msg)
    return data


def _github_request(  # noqa: PLR0913
    url: str,
    token: str,
    *,
    data: bytes | None = None,
    accept: str = "application/vnd.github+json",
    method: str | None = None,
    content_type: str = "application/json",
) -> bytes:
    request = urllib.request.Request(  # noqa: S310
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": content_type} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as error:
        detail = error.read(1024).decode("utf-8", errors="replace")
        msg = f"GitHub release evidence request failed: HTTP {error.code}: {detail}."
        raise ReleaseEvidenceError(msg, status_code=error.code) from error
    except urllib.error.URLError as error:
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


def _require_complete(  # noqa: PLR0913, C901
    *,
    name: str,
    image: str,
    version: str,
    source: str,
    run_id: str,
    execution_attempt: int,
    architecture_digests: dict[str, str],
    published: dict[str, dict[str, Any]],
    runtime: list[dict[str, Any]],
    scans: list[dict[str, Any]],
) -> None:
    """Reject incomplete or cross-build evidence before recording a release asset."""
    expected = set(architecture_digests)
    if set(published) != expected:
        msg = "Every architecture needs a verified published configuration."
        raise ReleaseEvidenceError(msg)
    for label, entries in (("runtime", runtime), ("scan", scans)):
        if len(entries) != len(expected) or {entry.get("architecture") for entry in entries} != expected:
            msg = f"Exactly one {label} record is required for every architecture."
            raise ReleaseEvidenceError(msg)
    for architecture in sorted(expected):
        policy = image_policy(name, architecture)
        runtime_item = next(item for item in runtime if item["architecture"] == architecture)
        scan_item = next(item for item in scans if item["architecture"] == architecture)
        identity = runtime_item.get("imageIdentity")
        candidate = scan_item.get("candidateSource")
        baseline_source = scan_item.get("baselineSource")

        def attempt_ok(item: dict[str, Any]) -> bool:
            attempt = item.get("runAttempt")
            return (
                item.get("runId") == run_id
                and isinstance(attempt, str)
                and attempt.isdecimal()
                and 1 <= int(attempt) <= execution_attempt
            )

        if (
            runtime_item.get("image") != name
            or runtime_item.get("profile") != policy["requiredRuntimeProfile"]
            or runtime_item.get("status") != "passed"
            or not attempt_ok(runtime_item)
            or not isinstance(identity, dict)
            or identity.get("sourceRevision") != source
            or identity.get("version") != version
            or identity.get("architecture") != architecture
            or identity.get("configDigest") != published[architecture]["configDigest"]
        ):
            msg = f"Runtime evidence for {name} {architecture} does not match publication."
            raise ReleaseEvidenceError(msg)
        if (
            scan_item.get("image") != image
            or scan_item.get("admission") != policy["admission"]
            or scan_item.get("decision") != "passed"
            or scan_item.get("sourceRevision") != source
            or not attempt_ok(scan_item)
            or not isinstance(candidate, dict)
            or not isinstance(baseline_source, dict)
            or candidate.get("sourceRevision") != source
            or candidate.get("version") != version
            or candidate.get("architecture") != architecture
            or candidate.get("configDigest") != published[architecture]["configDigest"]
            or candidate.get("manifestDigest") != identity.get("manifestDigest")
            or str(candidate.get("archiveSha256", "")).removeprefix("sha256:") != identity.get("archiveSha256")
            or scan_item.get("candidateDigest") != identity.get("manifestDigest")
        ):
            msg = f"Scan evidence for {name} {architecture} does not match publication."
            raise ReleaseEvidenceError(msg)
        if scan_item.get("baselineStatus") == "absent":
            if scan_item.get("baselineDigest") is not None or baseline_source.get("status") != "absent":
                msg = f"First-publication baseline evidence for {name} {architecture} is incomplete."
                raise ReleaseEvidenceError(msg)
        elif scan_item.get("baselineStatus") != "observed" or baseline_source.get("manifestDigest") != scan_item.get(
            "baselineDigest"
        ):
            msg = f"Baseline evidence for {name} {architecture} is incomplete."
            raise ReleaseEvidenceError(msg)


def record(  # noqa: C901, PLR0912, PLR0913
    build_result: dict[str, Any],
    *,
    release_origin_revision: str,
    runtime_evidence: list[dict[str, Any]] | None = None,
    scan_reports: list[dict[str, Any]] | None = None,
    published_configs: dict[str, dict[str, Any]] | None = None,
    require_complete: bool = False,
    execution_attempt: int | None = None,
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
    if require_complete:
        if execution_attempt is None:
            msg = "Complete release evidence requires the execution attempt."
            raise ReleaseEvidenceError(msg)
        _require_complete(
            name=name,
            image=image,
            version=version,
            source=source,
            run_id=run_id,
            execution_attempt=execution_attempt,
            architecture_digests=architecture_digests,
            published=published,
            runtime=runtime,
            scans=scans,
        )
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
        "evidenceReleaseTag": f"{name}/maintenance/{run_id}-{run_attempt}",
        "evidenceReleaseRevision": source,
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


def _same_evidence_payload(existing: bytes, expected: bytes) -> bool:
    """Allow a retry to retain its original build timestamp, but no changed evidence."""
    try:
        old = json.loads(existing)
        new = json.loads(expected)
    except ValueError, TypeError:
        return False
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    timestamps = (old.pop("buildSucceededAt", None), new.pop("buildSucceededAt", None))
    if any(not isinstance(value, str) for value in timestamps):
        return False
    try:
        if any(datetime.fromisoformat(value).tzinfo is None for value in timestamps):
            return False
    except ValueError:
        return False
    return old == new


def _release_assets(repository: str, release_id: int, token: str) -> list[dict[str, Any]]:
    """Read every page so hidden extra assets cannot pass publication checks."""
    assets_url = f"https://api.github.com/repos/{repository}/releases/{release_id}/assets"
    records: list[dict[str, Any]] = []
    page = 1
    while True:
        assets = json.loads(_github_request(f"{assets_url}?per_page={ASSET_PAGE_SIZE}&page={page}", token))
        if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
            msg = "GitHub returned invalid release assets."
            raise ReleaseEvidenceError(msg)
        records.extend(assets)
        if len(assets) < ASSET_PAGE_SIZE:
            return records
        page += 1


def upload(  # noqa: C901
    evidence: dict[str, Any], payload: bytes, *, repository: str, token: str, release: dict[str, Any]
) -> bytes:
    """Upload new evidence or return an existing substantively identical asset."""
    name = asset_name(evidence)
    assets = _release_assets(repository, release["id"], token)
    if assets:
        if len(assets) != 1 or assets[0].get("name") != name:
            msg = f"Evidence release {release.get('tag_name')} has unexpected assets."
            raise ReleaseEvidenceError(msg)
        asset = assets[0]
        expected = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        if asset.get("digest") == expected and asset.get("size") == len(payload):
            return payload
        url = asset.get("url")
        if not isinstance(url, str):
            msg = f"Existing release asset {name} has no download URL."
            raise ReleaseEvidenceError(msg)
        existing = _github_request(url, token, accept="application/octet-stream")
        if existing != payload and not _same_evidence_payload(existing, payload):
            msg = f"Existing release asset {name} has different contents."
            raise ReleaseEvidenceError(msg)
        return existing
    if not release.get("draft"):
        msg = f"Published evidence release {release.get('tag_name')} has no matching asset."
        raise ReleaseEvidenceError(msg)
    upload_url = release.get("upload_url")
    if not isinstance(upload_url, str):
        msg = "GitHub release has no asset upload URL."
        raise ReleaseEvidenceError(msg)
    url = f"{upload_url.split('{', 1)[0]}?name={urllib.parse.quote(name)}"
    raw = _github_request(url, token, data=payload, content_type="application/json")
    asset = json.loads(raw)
    expected = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    if not isinstance(asset, dict) or asset.get("name") != name or asset.get("size") != len(payload):
        msg = f"GitHub returned an invalid uploaded evidence asset {name}."
        raise ReleaseEvidenceError(msg)
    if asset.get("digest") != expected:
        download_url = asset.get("url")
        if (
            not isinstance(download_url, str)
            or _github_request(download_url, token, accept="application/octet-stream") != payload
        ):
            msg = f"GitHub uploaded evidence asset {name} with different contents."
            raise ReleaseEvidenceError(msg)
    uploaded = _release_assets(repository, release["id"], token)
    if len(uploaded) != 1 or uploaded[0].get("name") != name:
        msg = f"Evidence release {release.get('tag_name')} has unexpected assets after upload."
        raise ReleaseEvidenceError(msg)
    return payload


def _evidence_release(  # noqa: C901
    repository: str, tag: str, token: str
) -> dict[str, Any] | None:
    """Resolve drafts by GraphQL tag lookup, then read their full REST metadata."""
    encoded = urllib.parse.quote(tag, safe="")
    try:
        raw = _github_request(f"https://api.github.com/repos/{repository}/releases/tags/{encoded}", token)
    except ReleaseEvidenceError as error:
        if error.status_code != http.HTTPStatus.NOT_FOUND:
            raise
    else:
        published = json.loads(raw)
        if (
            not isinstance(published, dict)
            or not isinstance(published.get("id"), int)
            or published.get("tag_name") != tag
            or published.get("draft") is not False
        ):
            msg = f"GitHub returned an invalid published evidence release for {tag}."
            raise ReleaseEvidenceError(msg)
        return published
    owner, separator, name = repository.partition("/")
    if not separator or not owner or not name or "/" in name:
        msg = f"Invalid GitHub repository identity {repository}."
        raise ReleaseEvidenceError(msg)
    query = (
        "query($owner:String!,$name:String!,$tag:String!){"
        "repository(owner:$owner,name:$name){"
        "release(tagName:$tag){databaseId isDraft tagName name}}}"
    )
    body = json.dumps({"query": query, "variables": {"owner": owner, "name": name, "tag": tag}}).encode()
    result = json.loads(_github_request("https://api.github.com/graphql", token, data=body))
    if not isinstance(result, dict) or result.get("errors") or not isinstance(result.get("data"), dict):
        msg = f"GitHub GraphQL evidence release lookup failed for {tag}."
        raise ReleaseEvidenceError(msg)
    repository_data = result["data"].get("repository")
    if not isinstance(repository_data, dict) or "release" not in repository_data:
        msg = f"GitHub GraphQL returned an invalid repository for {tag}."
        raise ReleaseEvidenceError(msg)
    found = repository_data["release"]
    if found is None:
        return None
    if (
        not isinstance(found, dict)
        or not isinstance(found.get("databaseId"), int)
        or found.get("tagName") != tag
        or found.get("isDraft") is not True
        or found.get("name") != tag
    ):
        msg = f"GitHub GraphQL returned an invalid evidence release for {tag}."
        raise ReleaseEvidenceError(msg)
    release = json.loads(
        _github_request(f"https://api.github.com/repos/{repository}/releases/{found['databaseId']}", token)
    )
    if (
        not isinstance(release, dict)
        or release.get("id") != found["databaseId"]
        or release.get("tag_name") != tag
        or release.get("draft") != found["isDraft"]
        or release.get("name") != tag
    ):
        msg = f"GitHub REST release identity does not match GraphQL for {tag}."
        raise ReleaseEvidenceError(msg)
    return release


def _validate_evidence_release(release: dict[str, Any], evidence: dict[str, Any]) -> None:
    tag = evidence["evidenceReleaseTag"]
    if (
        not isinstance(release.get("id"), int)
        or release.get("tag_name") != tag
        or release.get("name") != tag
        or release.get("target_commitish") != evidence["evidenceReleaseRevision"]
        or not isinstance(release.get("draft"), bool)
    ):
        msg = f"Evidence release {tag} does not match this publication."
        raise ReleaseEvidenceError(msg)
    if not release["draft"] and release.get("immutable") is not True:
        msg = f"Published evidence release {tag} is not immutable."
        raise ReleaseEvidenceError(msg)


def _verify_evidence_tag(evidence: dict[str, Any], *, repository: str, token: str, allow_missing: bool = False) -> None:
    """Confirm the Git tag points at the build source, or is absent for a draft."""
    tag = evidence["evidenceReleaseTag"]
    encoded = urllib.parse.quote(tag, safe="")
    try:
        raw = _github_request(f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}", token)
    except ReleaseEvidenceError as error:
        if allow_missing and error.status_code == http.HTTPStatus.NOT_FOUND:
            return
        raise
    ref = json.loads(raw)
    target = ref.get("object") if isinstance(ref, dict) else None
    if not isinstance(target, dict) or ref.get("ref") != f"refs/tags/{tag}":
        msg = f"GitHub returned an invalid evidence Git tag {tag}."
        raise ReleaseEvidenceError(msg)
    if target.get("type") == "commit":
        revision = target.get("sha")
    elif target.get("type") == "tag":
        commit = json.loads(_github_request(f"https://api.github.com/repos/{repository}/commits/{encoded}", token))
        revision = commit.get("sha") if isinstance(commit, dict) else None
    else:
        revision = None
    if revision != evidence["evidenceReleaseRevision"]:
        msg = f"Evidence release tag {tag} does not resolve to the build source revision."
        raise ReleaseEvidenceError(msg)


def _create_evidence_release(evidence: dict[str, Any], *, repository: str, token: str) -> dict[str, Any]:
    tag = evidence["evidenceReleaseTag"]
    body = json.dumps(
        {
            "tag_name": tag,
            "target_commitish": evidence["evidenceReleaseRevision"],
            "name": tag,
            "body": (
                f"Maintenance evidence for {evidence['imageName']} v{evidence['version']}\n\n"
                f"Index digest: `{evidence['indexDigest']}`\n\n"
                f"Source version release: `{evidence['releaseTag']}`\n\n"
                f"Build source: `{evidence['buildSourceRevision']}`\n\n"
                f"Actions run: https://github.com/{repository}/actions/runs/{evidence['runId']}"
            ),
            "draft": True,
            "make_latest": "false",
        }
    ).encode()
    try:
        raw = _github_request(f"https://api.github.com/repos/{repository}/releases", token, data=body)
    except ReleaseEvidenceError as error:
        if error.status_code != http.HTTPStatus.UNPROCESSABLE_ENTITY:
            raise
        release = _evidence_release(repository, tag, token)
        if release is None:
            raise
    else:
        release = json.loads(raw)
    if not isinstance(release, dict):
        msg = f"GitHub returned an invalid evidence release for {tag}."
        raise ReleaseEvidenceError(msg)
    _validate_evidence_release(release, evidence)
    if not release["draft"]:
        msg = f"GitHub did not create evidence release {tag} as a draft."
        raise ReleaseEvidenceError(msg)
    unique = _evidence_release(repository, tag, token)
    if unique is None or unique.get("id") != release["id"]:
        msg = f"Created evidence release {tag} could not be uniquely recovered."
        raise ReleaseEvidenceError(msg)
    return unique


def publish(evidence: dict[str, Any], payload: bytes, *, repository: str, token: str) -> bytes:
    """Attach verified evidence to a draft before locking its publication release."""
    tag = evidence["evidenceReleaseTag"]
    release = _evidence_release(repository, tag, token)
    if release is None:
        release = _create_evidence_release(evidence, repository=repository, token=token)
    _validate_evidence_release(release, evidence)
    if release["draft"]:
        _verify_evidence_tag(evidence, repository=repository, token=token, allow_missing=True)
    canonical = upload(evidence, payload, repository=repository, token=token, release=release)
    if release["draft"]:
        unique = _evidence_release(repository, tag, token)
        if unique is None or unique.get("id") != release["id"] or not unique.get("draft"):
            msg = f"Evidence release {tag} changed before publication."
            raise ReleaseEvidenceError(msg)
        body = json.dumps({"draft": False, "make_latest": "false"}).encode()
        _github_request(
            f"https://api.github.com/repos/{repository}/releases/{release['id']}",
            token,
            data=body,
            method="PATCH",
        )
        published = _evidence_release(repository, tag, token)
        if published is None:
            msg = f"Published evidence release {tag} disappeared."
            raise ReleaseEvidenceError(msg)
        _validate_evidence_release(published, evidence)
        if published["draft"] or published.get("id") != release["id"]:
            msg = f"Evidence release {tag} did not publish the selected draft."
            raise ReleaseEvidenceError(msg)
    _verify_evidence_tag(evidence, repository=repository, token=token)
    return canonical


def main() -> None:
    """Create a local maintenance JSON record and optionally upload it as a release asset."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-result", required=True, type=Path)
    parser.add_argument("--runtime-evidence-dir", type=Path)
    parser.add_argument("--scan-report-dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--verify-publication", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
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
            args.runtime_evidence_dir, "*.json", build_result["imageName"], architectures
        ),
        scan_reports=_attached_records(
            args.scan_report_dir, "*vulnerability-report.json", build_result["image"], architectures
        ),
        published_configs=published,
        require_complete=args.require_complete,
        execution_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
    )
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    if args.upload:
        payload = publish(evidence, payload, repository=repository, token=token)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)


if __name__ == "__main__":
    main()
