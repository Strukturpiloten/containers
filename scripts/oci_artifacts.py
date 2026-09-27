"""Inspect OCI archive identity without extracting an untrusted filesystem tree."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from pathlib import Path

MAX_METADATA_BYTES = 4 * 1024 * 1024


class ArchiveIdentityError(ValueError):
    """An OCI archive cannot prove the identity requested by a runtime check."""


def _fail(message: str) -> NoReturn:
    raise ArchiveIdentityError(message)


def _read_json(archive: tarfile.TarFile, name: str) -> tuple[dict[str, Any], bytes]:
    member = archive.getmember(name)
    if not member.isfile() or member.size > MAX_METADATA_BYTES:
        _fail(f"Invalid OCI metadata member: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        _fail(f"Unreadable OCI metadata member: {name}")
    with handle:
        data = handle.read(MAX_METADATA_BYTES + 1)
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        _fail(f"OCI metadata must be a JSON object: {name}")
    return parsed, data


def _blob(archive: tarfile.TarFile, descriptor: dict[str, Any]) -> tuple[dict[str, Any], str]:
    digest = descriptor.get("digest", "")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        _fail("OCI metadata contains an invalid blob digest.")
    parsed, data = _read_json(archive, f"blobs/sha256/{digest.removeprefix('sha256:')}")
    if hashlib.sha256(data).hexdigest() != digest.removeprefix("sha256:") or len(data) != descriptor.get("size"):
        _fail(f"OCI metadata digest or size mismatch: {digest}")
    return parsed, digest


def archive_identity(path: Path, architecture: str) -> dict[str, str]:
    """Bind a native runtime probe to the archive manifest, configuration and source."""
    with tarfile.open(path, "r:*") as archive:
        index, _ = _read_json(archive, "index.json")
        descriptors = index.get("manifests", [])
        if not isinstance(descriptors, list) or len(descriptors) != 1:
            _fail("Runtime archive must contain exactly one image descriptor.")
        manifest, manifest_digest = _blob(archive, descriptors[0])
        config_descriptor = manifest.get("config")
        if not isinstance(config_descriptor, dict):
            _fail("Runtime archive must contain an image manifest, not a multiarch index.")
        config, config_digest = _blob(archive, config_descriptor)
    if config.get("architecture") != architecture or config.get("os") != "linux":
        _fail(f"Archive does not contain the requested linux/{architecture} image.")
    labels = config.get("config", {}).get("Labels", {}) or {}
    with path.open("rb") as handle:
        archive_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {
        "manifestDigest": manifest_digest,
        "configDigest": config_digest,
        "archiveSha256": archive_digest,
        "architecture": architecture,
        "sourceRevision": str(labels.get("org.opencontainers.image.revision", "")),
        "version": str(labels.get("org.opencontainers.image.version", "")),
    }
