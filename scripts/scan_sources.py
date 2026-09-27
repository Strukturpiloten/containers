"""Resolve and verify architecture manifest identities for vulnerability scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class SourceError(ValueError):
    """The source cannot be bound to a single verified architecture manifest."""


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        msg = "Invalid JSON in image source."
        raise SourceError(msg) from error
    if not isinstance(value, dict):
        msg = "Image source JSON must be an object."
        raise SourceError(msg)
    return value


def _descriptor(value: object) -> tuple[str, int]:
    if not isinstance(value, dict):
        msg = "Invalid OCI descriptor."
        raise SourceError(msg)
    digest, size = value.get("digest"), value.get("size")
    if not isinstance(digest, str) or SHA256_DIGEST_RE.fullmatch(digest) is None:
        msg = "Invalid OCI descriptor digest."
        raise SourceError(msg)
    if not isinstance(size, int) or size < 1:
        msg = "Invalid OCI descriptor size."
        raise SourceError(msg)
    return digest, size


def _select_manifest(index: dict[str, Any], architecture: str) -> dict[str, Any]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        msg = "Image index has no manifests."
        raise SourceError(msg)
    matches = [
        item
        for item in manifests
        if isinstance(item, dict)
        and isinstance(item.get("platform"), dict)
        and item["platform"].get("architecture") == architecture
        and item["platform"].get("os") == "linux"
    ]
    if len(matches) != 1:
        msg = f"Image index has {len(matches)} linux/{architecture} manifests."
        raise SourceError(msg)
    return matches[0]


def candidate_archive(path: Path, architecture: str, source_revision: str | None = None) -> dict[str, Any]:  # noqa: C901
    """Verify an OCI archive's single image and return its architecture manifest digest."""
    if architecture not in {"amd64", "arm64"}:
        msg = f"Unsupported architecture: {architecture}."
        raise SourceError(msg)
    archive_hash = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            archive_hash.update(chunk)
    with tarfile.open(path, "r:*") as archive:
        members = {member.name.removeprefix("./"): member for member in archive.getmembers() if member.isfile()}

        def read(name: str) -> bytes:
            member = members.get(name)
            if member is None:
                msg = f"Missing OCI archive member {name}."
                raise SourceError(msg)
            stream = archive.extractfile(member)
            if stream is None:
                msg = f"Could not read OCI archive member {name}."
                raise SourceError(msg)
            return stream.read()

        def blob(descriptor: dict[str, Any]) -> bytes:
            digest, size = _descriptor(descriptor)
            raw = read(f"blobs/sha256/{digest.removeprefix('sha256:')}")
            if len(raw) != size or _sha256(raw) != digest:
                msg = f"OCI blob {digest} failed size or digest verification."
                raise SourceError(msg)
            return raw

        index = _json(read("index.json"))
        entries = index.get("manifests")
        if not isinstance(entries, list) or len(entries) != 1:
            msg = "Candidate OCI archive must contain exactly one image."
            raise SourceError(msg)
        descriptor = entries[0]
        document = _json(blob(descriptor))
        if "manifests" in document:
            descriptor = _select_manifest(document, architecture)
            document = _json(blob(descriptor))
        manifest_digest, _ = _descriptor(descriptor)
        config = document.get("config")
        configuration = _json(blob(config))
        config_digest, _ = _descriptor(config)
        labels = configuration.get("config", {}).get("Labels", {})
        revision = labels.get("org.opencontainers.image.revision") if isinstance(labels, dict) else None
        if source_revision is not None and revision != source_revision:
            msg = "Candidate archive source revision does not match the build revision."
            raise SourceError(msg)
        if configuration.get("architecture") != architecture or configuration.get("os") != "linux":
            msg = f"Candidate archive configuration is not linux/{architecture}."
            raise SourceError(msg)
    return {
        "type": "oci-archive",
        "archive": str(path.resolve()),
        "archiveSha256": f"sha256:{archive_hash.hexdigest()}",
        "architecture": architecture,
        "manifestDigest": manifest_digest,
        "configDigest": config_digest,
        "sourceRevision": revision,
    }


def _skopeo_raw(reference: str) -> bytes:
    result = subprocess.run(  # noqa: S603
        ["skopeo", "inspect", "--raw", f"docker://{reference}"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        msg = f"Could not inspect registry reference {reference}: {result.stderr.decode(errors='replace').strip()}"
        raise SourceError(msg)
    return result.stdout


def _skopeo_inspect(reference: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603
        ["skopeo", "inspect", f"docker://{reference}"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        msg = f"Could not inspect registry configuration {reference}: {result.stderr.decode(errors='replace').strip()}"
        raise SourceError(msg)
    return _json(result.stdout)


def published_manifest(image: str, digest: str, architecture: str) -> dict[str, Any]:
    """Verify a registry architecture manifest and return its configuration digest."""
    if SHA256_DIGEST_RE.fullmatch(digest) is None or architecture not in {"amd64", "arm64"}:
        msg = "Invalid published architecture manifest identity."
        raise SourceError(msg)
    reference = f"{image}@{digest}"
    raw = _skopeo_raw(reference)
    if _sha256(raw) != digest:
        msg = "Published architecture manifest digest changed during inspection."
        raise SourceError(msg)
    manifest = _json(raw)
    config_digest, _ = _descriptor(manifest.get("config"))
    inspection = _skopeo_inspect(reference)
    if inspection.get("Architecture") != architecture or inspection.get("Os") != "linux":
        msg = f"Published manifest configuration is not linux/{architecture}."
        raise SourceError(msg)
    return {"architecture": architecture, "manifestDigest": digest, "configDigest": config_digest}


def baseline_registry(image: str, reference: str, architecture: str) -> dict[str, Any]:
    """Bind a maintained tag to its index and selected architecture manifest."""
    if architecture not in {"amd64", "arm64"} or not reference.startswith(f"{image}:"):
        msg = "Baseline must be a tag of the same image and a supported architecture."
        raise SourceError(msg)
    index_raw = _skopeo_raw(reference)
    index_digest = _sha256(index_raw)
    descriptor = _select_manifest(_json(index_raw), architecture)
    manifest_digest, _ = _descriptor(descriptor)
    published = published_manifest(image, manifest_digest, architecture)
    return {
        "type": "registry",
        "reference": reference,
        "image": image,
        "architecture": architecture,
        "indexDigest": index_digest,
        "manifestDigest": manifest_digest,
        "configDigest": published["configDigest"],
    }


def main() -> None:
    """Resolve an OCI archive or a registry baseline to a JSON identity record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("candidate", "baseline"))
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--reference")
    parser.add_argument("--source-revision")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.kind == "candidate":
        if args.archive is None:
            parser.error("candidate requires --archive")
        evidence = candidate_archive(args.archive, args.architecture, args.source_revision)
    else:
        if args.image is None or args.reference is None:
            parser.error("baseline requires --image and --reference")
        evidence = baseline_registry(args.image, args.reference, args.architecture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
