"""Collect public GHCR observations and separately verified maintenance evidence.

This is an opt-in network command. Checked-in catalogue generation never imports it.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from scripts import container_engine, release_evidence
from scripts.promotion import REVISION_ANNOTATION, PublicationIdentity

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
VERSION_TAG = re.compile(r"v\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?\Z")
MAX_ERROR = 300
MAX_WORKERS = 16
MAX_TIMEOUT = 300
MAX_CONFIG_BYTES = 4 * 1024 * 1024


class ObservationError(ValueError):
    """A registry response cannot support the proposed observation."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        msg = "Observation timestamp has no timezone."
        raise ObservationError(msg)
    return parsed


def _digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        msg = "Invalid JSON response."
        raise ObservationError(msg) from error
    if not isinstance(value, dict):
        msg = "Expected a JSON object."
        raise ObservationError(msg)
    return value


def _valid_digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        msg = "Invalid OCI digest."
        raise ObservationError(msg)
    return value


class PublicRegistry:
    """Skopeo public requests with bounded duration; no registry credentials."""

    def __init__(self, timeout: int) -> None:
        """Use a per-request timeout in seconds."""
        self.timeout = timeout
        self._tokens: dict[str, str] = {}

    def _run(self, *args: str) -> bytes:
        try:
            result = subprocess.run(  # noqa: S603
                ["skopeo", *args, "--no-creds"],  # noqa: S607
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            msg = f"Public registry request failed: {error}."
            raise ObservationError(msg) from error
        if result.returncode:
            detail = result.stderr.decode(errors="replace").strip()[:MAX_ERROR]
            msg = f"Public registry request failed: {detail}."
            raise ObservationError(msg)
        return result.stdout

    def tags(self, image: str) -> list[str]:
        """List every public tag without resolving auxiliary tag digests."""
        result = _json(self._run("list-tags", f"docker://{image}"))
        if result.get("Repository") not in {image, image.removeprefix("ghcr.io/")}:
            msg = "Registry tag listing has an unexpected repository."
            raise ObservationError(msg)
        tags = result.get("Tags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) or not tag for tag in tags):
            msg = "Registry tag listing is invalid."
            raise ObservationError(msg)
        return sorted(set(tags))

    def raw(self, image: str, selector: str, *, expected: str | None = None) -> tuple[str, dict[str, Any]]:
        """Read raw OCI JSON and independently check its content digest."""
        reference = f"docker://{image}{selector}"
        raw = self._run("inspect", "--raw", reference)
        digest = _digest(raw)
        if expected is not None and digest != expected:
            msg = f"Registry returned {digest} for expected {expected}."
            raise ObservationError(msg)
        return digest, _json(raw)

    def _config_blob(self, image: str, expected: str) -> bytes:
        """Read exact public GHCR blob bytes; skopeo --config reformats JSON."""
        repository = image.removeprefix("ghcr.io/")
        if repository == image or "/" not in repository:
            msg = "Only GHCR image configurations are supported."
            raise ObservationError(msg)
        token = self._tokens.get(repository)
        if token is None:
            scope = urllib.parse.quote(f"repository:{repository}:pull", safe=":")
            url = f"https://ghcr.io/token?scope={scope}&service=ghcr.io"
            request = urllib.request.Request(url, headers={"User-Agent": "strukturpiloten-docs"})
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                    token = _json(response.read(MAX_CONFIG_BYTES))["token"]
            except (urllib.error.URLError, TimeoutError, KeyError) as error:
                msg = f"Anonymous GHCR token request failed: {error}."
                raise ObservationError(msg) from error
            if not isinstance(token, str) or not token:
                msg = "Anonymous GHCR token response is invalid."
                raise ObservationError(msg)
            self._tokens[repository] = token
        url = f"https://ghcr.io/v2/{repository}/blobs/{expected}"
        request = urllib.request.Request(  # noqa: S310
            url, headers={"Authorization": f"Bearer {token}", "User-Agent": "strukturpiloten-docs"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                raw = response.read(MAX_CONFIG_BYTES + 1)
        except (urllib.error.URLError, TimeoutError) as error:
            msg = f"Anonymous GHCR config request failed: {error}."
            raise ObservationError(msg) from error
        if len(raw) > MAX_CONFIG_BYTES:
            msg = "Image configuration exceeds the permitted size."
            raise ObservationError(msg)
        return raw

    def config(self, image: str, digest: str, expected: str) -> dict[str, Any]:
        """Verify exact GHCR config blob bytes named by a manifest digest."""
        _valid_digest(digest)
        raw = self._config_blob(image, expected)
        if _digest(raw) != expected:
            msg = f"Registry config digest mismatch for {digest}."
            raise ObservationError(msg)
        return _json(raw)


def _platforms(registry: PublicRegistry, image: str, index: dict[str, Any]) -> list[dict[str, Any]]:
    descriptors = index.get("manifests")
    if not isinstance(descriptors, list):
        msg = "Latest reference is not a multiarch index."
        raise ObservationError(msg)
    platforms = []
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("platform"), dict):
            msg = "Index has an invalid manifest descriptor."
            raise ObservationError(msg)
        platform = descriptor["platform"]
        if platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}:
            continue  # Buildah may include non-runnable attestation descriptors.
        architecture = platform["architecture"]
        digest = _valid_digest(descriptor.get("digest"))
        _, manifest = registry.raw(image, f"@{digest}", expected=digest)
        config_descriptor = manifest.get("config")
        if not isinstance(config_descriptor, dict):
            msg = "Architecture manifest has no config descriptor."
            raise ObservationError(msg)
        config_digest = _valid_digest(config_descriptor.get("digest"))
        config = registry.config(image, digest, config_digest)
        if config.get("os") != "linux" or config.get("architecture") != architecture:
            msg = "Manifest and config architectures differ."
            raise ObservationError(msg)
        labels = config.get("config", {}).get("Labels")
        if not isinstance(labels, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()
        ):
            msg = "Image config has invalid OCI labels."
            raise ObservationError(msg)
        platforms.append(
            {
                "architecture": architecture,
                "manifestDigest": digest,
                "configDigest": config_digest,
                "labels": labels,
                "configCreatedAt": config.get("created"),
            }
        )
    if not platforms or len({row["architecture"] for row in platforms}) != len(platforms):
        msg = "No unique runnable Linux architectures in index."
        raise ObservationError(msg)
    return sorted(platforms, key=lambda row: row["architecture"])


def _github_json(url: str, *, token: str | None, timeout: int, accept: str = "application/vnd.github+json") -> bytes:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "strukturpiloten-docs"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if not url.startswith("https://api.github.com/"):
        msg = "GitHub evidence URL has an unexpected origin."
        raise ObservationError(msg)
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read()
    except (urllib.error.URLError, TimeoutError) as error:
        msg = f"GitHub evidence request failed: {error}."
        raise ObservationError(msg) from error


def _release_proof(  # noqa: C901, PLR0912, PLR0913, PLR0915
    *,
    repository: str,
    name: str,
    image: str,
    digest: str,
    index: dict[str, Any],
    platforms: list[dict[str, Any]],
    token: str | None,
    timeout: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prove a release asset is immutable and bound to this runnable image."""
    annotations = index.get("annotations")
    if not isinstance(annotations, dict):
        msg = "Index has no publication annotations."
        raise ObservationError(msg)
    identity = PublicationIdentity.from_annotations(annotations)
    source = annotations.get(REVISION_ANNOTATION)
    if not isinstance(source, str) or REVISION.fullmatch(source) is None:
        msg = "Index has no valid source revision."
        raise ObservationError(msg)
    versions = {row["labels"].get("org.opencontainers.image.version") for row in platforms}
    if len(versions) != 1 or None in versions:
        msg = "Architecture version labels differ or are missing."
        raise ObservationError(msg)
    version = versions.pop()
    if any(row["labels"].get(REVISION_ANNOTATION) != source for row in platforms):
        msg = "Architecture revision labels differ from index."
        raise ObservationError(msg)
    tag = f"{name}/maintenance/{identity.run_id}-{identity.run_attempt}"
    encoded = urllib.parse.quote(tag, safe="")
    release = _json(
        _github_json(
            f"https://api.github.com/repos/{repository}/releases/tags/{encoded}",
            token=token,
            timeout=timeout,
        )
    )
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("immutable") is not True
        or release.get("target_commitish") != source
    ):
        msg = "Evidence release is not immutable or does not match source."
        raise ObservationError(msg)
    tag_ref = _json(
        _github_json(f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}", token=token, timeout=timeout)
    )
    target = tag_ref.get("object")
    if tag_ref.get("ref") != f"refs/tags/{tag}" or not isinstance(target, dict):
        msg = "Evidence release Git tag ref is invalid."
        raise ObservationError(msg)
    if target.get("type") == "commit":
        tag_commit = target.get("sha")
    elif target.get("type") == "tag":
        commit = _json(
            _github_json(f"https://api.github.com/repos/{repository}/commits/{encoded}", token=token, timeout=timeout)
        )
        tag_commit = commit.get("sha")
    else:
        tag_commit = None
    if tag_commit != source:
        msg = "Evidence release Git tag does not resolve to build source."
        raise ObservationError(msg)
    assets = release.get("assets")
    expected_asset = release_evidence.asset_name(
        {
            "indexDigest": digest,
            "runId": str(identity.run_id),
            "runAttempt": str(identity.run_attempt),
        }
    )
    if not isinstance(assets, list) or len(assets) != 1 or assets[0].get("name") != expected_asset:
        msg = "Evidence release has no unique matching asset."
        raise ObservationError(msg)
    asset = assets[0]
    asset_url = asset.get("url")
    if not isinstance(asset_url, str) or not asset_url.startswith(
        f"https://api.github.com/repos/{repository}/releases/assets/"
    ):
        msg = "Evidence asset URL is invalid."
        raise ObservationError(msg)
    raw = _github_json(asset_url, token=token, timeout=timeout, accept="application/octet-stream")
    if asset.get("size") != len(raw) or (asset.get("digest") and asset["digest"] != _digest(raw)):
        msg = "Evidence asset size or digest mismatch."
        raise ObservationError(msg)
    evidence = _json(raw)
    build_succeeded_at = evidence.get("buildSucceededAt")
    if not isinstance(build_succeeded_at, str):
        msg = "Maintenance evidence has no build success time."
        raise ObservationError(msg)
    _timestamp(build_succeeded_at)
    expected_mapping = {
        row["architecture"]: {
            "architecture": row["architecture"],
            "manifestDigest": row["manifestDigest"],
            "configDigest": row["configDigest"],
        }
        for row in platforms
    }
    if (
        evidence.get("schemaVersion") != 1
        or evidence.get("imageName") != name
        or evidence.get("image") != image
        or evidence.get("version") != version
        or evidence.get("buildSourceRevision") != source
        or evidence.get("evidenceReleaseRevision") != source
        or evidence.get("evidenceReleaseTag") != tag
        or evidence.get("releaseTag") != f"{name}/v{version}"
        or evidence.get("indexDigest") != digest
        or evidence.get("runId") != str(identity.run_id)
        or evidence.get("runAttempt") != str(identity.run_attempt)
        or evidence.get("architectureDigests")
        != {key: value["manifestDigest"] for key, value in expected_mapping.items()}
        or evidence.get("publicationMapping") != expected_mapping
    ):
        msg = "Maintenance evidence does not match registry image identity."
        raise ObservationError(msg)
    # Reuse the publisher's full runtime/scan consistency gate. This verifies the
    # attached records but does not imply signatures, provenance, or freshness.
    release_evidence._require_complete(  # noqa: SLF001
        name=name,
        image=image,
        version=version,
        source=source,
        run_id=str(identity.run_id),
        execution_attempt=identity.run_attempt,
        architecture_digests=evidence["architectureDigests"],
        published=expected_mapping,
        runtime=evidence.get("runtimeEvidence", []),
        scans=evidence.get("scanReports", []),
    )
    proof = {
        "status": "verified",
        "releaseUrl": release.get("html_url"),
        "assetUrl": asset.get("browser_download_url"),
        "assetDigest": _digest(raw),
        "buildSucceededAt": build_succeeded_at,
        "runtime": "verified",
        "scan": "verified",
        "signature": "unknown",
        "provenance": "unknown",
    }
    return proof, evidence


def _declaration_alignment(metadata: dict[str, Any], asset: dict[str, Any]) -> dict[str, Any]:
    """Compare today's declaration with the separately verified live release."""
    differences = []

    def add(field: str, published: object, declared: object) -> None:
        if published == declared:
            return

        def display(value: object) -> str:
            return value if isinstance(value, str) else json.dumps(value, sort_keys=True)

        differences.append({"field": field, "published": display(published)[:500], "declared": display(declared)[:500]})

    add("version", f"v{asset['version']}", metadata["version"])
    add("architectures", sorted(asset["architectureDigests"]), sorted(metadata["build"]["architectures"]))
    recorded = asset.get("componentInputs")
    current = container_engine._component_inputs(metadata)  # noqa: SLF001

    def compare(field: str, published: object, declared: object) -> None:
        if isinstance(published, dict) and isinstance(declared, dict):
            for key in sorted(set(published) | set(declared)):
                compare(f"{field}.{key}", published.get(key), declared.get(key))
        else:
            add(field, published, declared)

    compare("buildInputs", recorded, current)
    return {"status": "different" if differences else "matched", "differences": differences}


def _observe_one(  # noqa: C901
    metadata: dict[str, Any], registry: PublicRegistry, repository: str, token: str | None, timeout: int
) -> dict[str, Any]:
    name, image = metadata["name"], metadata["image"]
    observed_at = _now().isoformat()
    tags = registry.tags(image)
    if "latest" not in tags:
        msg = "Registry has no latest tag."
        raise ObservationError(msg)
    digest, index = registry.raw(image, ":latest")
    platforms = _platforms(registry, image, index)
    annotations = index.get("annotations") if isinstance(index.get("annotations"), dict) else {}
    source = annotations.get(REVISION_ANNOTATION)
    if source is not None and (not isinstance(source, str) or REVISION.fullmatch(source) is None):
        msg = "Invalid source revision annotation."
        raise ObservationError(msg)
    if any(row["labels"].get(REVISION_ANNOTATION) != source for row in platforms):
        msg = "Index and architecture source revisions differ."
        raise ObservationError(msg)
    resolved: dict[str, str] = {"latest": digest}
    for tag in tags:
        if tag != "latest" and (tag == "main" or VERSION_TAG.fullmatch(tag)):
            resolved[tag] = registry.raw(image, f":{tag}")[0]
    # Mutable latest can move while tags are inspected; reject mixed snapshots.
    if registry.raw(image, ":latest")[0] != digest:
        msg = "Latest changed during registry inspection."
        raise ObservationError(msg)
    grouped: dict[str, list[str]] = {}
    for tag, tag_digest in resolved.items():
        grouped.setdefault(tag_digest, []).append(tag)
    current = sorted(grouped.pop(digest))
    history = [{"digest": key, "tags": sorted(value)} for key, value in sorted(grouped.items())]
    evidence: dict[str, Any] = {"status": "unknown", "reason": "No matching immutable release checked."}
    alignment: dict[str, Any] = {
        "status": "unknown",
        "reason": "No verified release to compare with declaration.",
        "differences": [],
    }
    try:
        evidence, asset = _release_proof(
            repository=repository,
            name=name,
            image=image,
            digest=digest,
            index=index,
            platforms=platforms,
            token=token,
            timeout=timeout,
        )
    except (ObservationError, ValueError, KeyError, TypeError) as error:
        evidence = {"status": "unavailable", "reason": str(error)[:MAX_ERROR]}
    else:
        try:
            alignment = _declaration_alignment(metadata, asset)
        except (container_engine.ContainerEngineError, KeyError, TypeError, ValueError) as error:
            alignment = {"status": "unknown", "reason": str(error)[:MAX_ERROR], "differences": []}
    latest = {
        "digest": digest,
        "reference": f"{image}@{digest}",
        "sourceRevision": source,
        "runId": annotations.get("io.github.strukturpiloten.publish.run-id"),
        "runAttempt": annotations.get("io.github.strukturpiloten.publish.run-attempt"),
        "publishedAt": None,  # Exact runnable-image publication time is not in OCI metadata.
        "platforms": platforms,
        "evidence": evidence,
        "declarationAlignment": alignment,
    }
    return {
        "name": name,
        "image": image,
        "status": "observed",
        "observedAt": observed_at,
        "stale": False,
        "refreshFailed": False,
        "refreshError": None,
        "ageSeconds": 0,
        "latest": latest,
        "tags": {
            "listed": tags,
            "currentAliases": current,
            "history": history,
            "unresolved": sorted(set(tags) - set(resolved)),
        },
    }


def _fallback(
    metadata: dict[str, Any], prior: dict[str, Any] | None, error: Exception, now: dt.datetime
) -> dict[str, Any]:
    result = (
        dict(prior)
        if prior and prior.get("image") == metadata["image"] and prior.get("status") in {"observed", "stale"}
        else {
            "name": metadata["name"],
            "image": metadata["image"],
            "observedAt": None,
            "latest": None,
            "tags": None,
        }
    )
    observed_at = result["observedAt"]
    result.update(
        {
            "status": "stale" if observed_at else "unavailable",
            "stale": bool(observed_at),
            "refreshFailed": True,
            "refreshError": str(error)[:MAX_ERROR],
            "ageSeconds": max(0, int((now - _timestamp(observed_at)).total_seconds())) if observed_at else None,
        }
    )
    return result


def collect(
    *,
    previous: dict[str, Any] | None = None,
    repository: str = "Strukturpiloten/containers",
    workers: int = 6,
    timeout: int = 30,
    registry: PublicRegistry | None = None,
) -> dict[str, Any]:
    """Observe each image independently; retain prior verified observations on failure."""
    if workers < 1 or workers > MAX_WORKERS or timeout < 1 or timeout > MAX_TIMEOUT:
        msg = "Workers or timeout are outside supported bounds."
        raise ObservationError(msg)
    images = container_engine._load_images()  # noqa: SLF001
    container_engine._validate_images(images)  # noqa: SLF001
    prior = {}
    if previous is not None:
        validate(previous)
        if previous["repository"] != repository:
            msg = "Previous snapshot belongs to another repository."
            raise ObservationError(msg)
        prior = {row["name"]: row for row in previous["images"]}
    client = registry or PublicRegistry(timeout)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    rows: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_observe_one, image, client, repository, token, timeout): image for image in images}
        for future in concurrent.futures.as_completed(futures):
            image = futures[future]
            try:
                rows.append(future.result())
            except (ObservationError, OSError, ValueError, KeyError, TypeError) as error:
                rows.append(_fallback(image, prior.get(image["name"]), error, _now()))
    generated_at = _now()
    for row in rows:
        if row["observedAt"]:
            row["ageSeconds"] = max(0, int((generated_at - _timestamp(row["observedAt"])).total_seconds()))
    result = {
        "schemaVersion": 1,
        "repository": repository,
        "generatedAt": generated_at.isoformat(),
        "images": sorted(rows, key=lambda row: row["name"]),
    }
    validate(result)
    return result


def validate(snapshot: dict[str, Any]) -> None:  # noqa: C901, PLR0912, PLR0915
    """Validate the separate publication snapshot before a website consumes it."""
    schema = json.loads((ROOT / "docs/registry-snapshot.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(snapshot), key=lambda error: list(map(str, error.path)))
    if errors:
        raise ObservationError("Invalid registry snapshot: " + "; ".join(error.message for error in errors[:5]))
    names = [row["name"] for row in snapshot["images"]]
    if len(names) != len(set(names)):
        msg = "Snapshot contains duplicate image names."
        raise ObservationError(msg)
    for row in snapshot["images"]:
        if row["observedAt"] and _timestamp(row["observedAt"]) > _timestamp(snapshot["generatedAt"]):
            msg = "Observation time is after snapshot generation."
            raise ObservationError(msg)
        if row["status"] == "observed" and (row["refreshFailed"] or row["stale"]):
            msg = "Fresh observation has contradictory failure flags."
            raise ObservationError(msg)
        if row["status"] == "stale" and (not row["refreshFailed"] or not row["observedAt"]):
            msg = "Stale observation lacks retained data or failure state."
            raise ObservationError(msg)
        if row["status"] == "unavailable" and (row["observedAt"] or row["latest"] or row["tags"]):
            msg = "Unavailable image cannot carry a current observation."
            raise ObservationError(msg)
        if row["status"] == "unavailable" and (not row["refreshFailed"] or row["stale"] or row["ageSeconds"]):
            msg = "Unavailable image has contradictory failure state."
            raise ObservationError(msg)
        latest, tags = row["latest"], row["tags"]
        if latest is None:
            continue
        if latest["reference"] != f"{row['image']}@{latest['digest']}":
            msg = "Snapshot image reference does not match digest."
            raise ObservationError(msg)
        if not row["observedAt"] or not isinstance(row["ageSeconds"], int):
            msg = "Observed image lacks a timestamp or age."
            raise ObservationError(msg)
        listed = set(tags["listed"])
        grouped_tags = [*tags["currentAliases"], *tags["unresolved"]]
        for history in tags["history"]:
            if history["digest"] == latest["digest"]:
                msg = "Historical digest equals current digest."
                raise ObservationError(msg)
            grouped_tags.extend(history["tags"])
        if (
            "latest" not in tags["currentAliases"]
            or set(grouped_tags) != listed
            or len(grouped_tags) != len(set(grouped_tags))
        ):
            msg = "Tag groups do not partition the listed tags."
            raise ObservationError(msg)
        architectures = [platform["architecture"] for platform in latest["platforms"]]
        if len(architectures) != len(set(architectures)):
            msg = "Snapshot has duplicate runnable architectures."
            raise ObservationError(msg)
        alignment = latest["declarationAlignment"]
        if (alignment["status"] == "matched" and alignment["differences"]) or (
            alignment["status"] == "different" and not alignment["differences"]
        ):
            msg = "Declaration alignment status contradicts differences."
            raise ObservationError(msg)
        if latest["sourceRevision"] is not None and any(
            platform["labels"].get(REVISION_ANNOTATION) != latest["sourceRevision"] for platform in latest["platforms"]
        ):
            msg = "Snapshot index and config revisions disagree."
            raise ObservationError(msg)


def main() -> None:
    """Write a dated publication snapshot; partial image failures remain visible."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--repository", default="Strukturpiloten/containers")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    previous = json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else None
    report = collect(previous=previous, repository=args.repository, workers=args.workers, timeout=args.timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
