"""Build and consume private, same-run OCI payloads without registry fallbacks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, NoReturn

import yaml


class PayloadError(ValueError):
    """Payload metadata or evidence cannot be trusted for this build."""


def _fail(message: str) -> NoReturn:
    raise PayloadError(message)


def repository_path(root: Path, value: str) -> Path:
    """Keep manifest, recipe, context and artifact reads inside their root."""
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        _fail(f"Path escapes its root: {value}")
    return path


def sha256(path: Path) -> str:
    """Hash an artifact without loading it into memory."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _arguments(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None
        or not isinstance(item, str)
        or not item
        for key, item in value.items()
    ):
        _fail("Payload build arguments must map uppercase names to nonempty strings.")
    return value


def load_manifest(root: Path, relative_path: str) -> dict[str, Any]:
    """Load a private payload definition and reject invalid build inputs."""
    path = repository_path(root, relative_path)
    if not path.is_file():
        _fail(f"Payload manifest does not exist: {relative_path}")
    record = yaml.safe_load(path.read_text())
    if not isinstance(record, dict) or record.get("schemaVersion") != 1:
        _fail(f"Invalid payload manifest: {relative_path}")
    name = record.get("name")
    if not isinstance(name, str) or re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name) is None:
        _fail("Payload name must be a lowercase OCI-compatible name.")
    build = record.get("build")
    if not isinstance(build, dict):
        _fail("Payload build configuration is required.")
    for field in ("context", "containerfile"):
        value = build.get(field)
        if not isinstance(value, str) or not repository_path(root, value).exists():
            _fail(f"Payload build.{field} must exist inside the repository.")
    if not isinstance(record.get("provenance"), dict) or not record["provenance"]:
        _fail("Payload provenance is required.")
    _validate_architectures(build)
    _validate_consumer_contract(record)
    return record


def _validate_consumer_contract(record: dict[str, Any]) -> None:
    consumer = record.get("consumer")
    if consumer is None:
        return
    if not isinstance(consumer, dict) or set(consumer) != {"versionArg", "runtimeBaseArg"}:
        _fail("Payload consumer must define versionArg and runtimeBaseArg.")
    arguments = record["build"].get("args", {})
    for field in ("versionArg", "runtimeBaseArg"):
        if consumer[field] not in arguments:
            _fail(f"Payload consumer.{field} must reference a build argument.")


def _validate_architectures(build: dict[str, Any]) -> None:
    architectures = build.get("architectures")
    if (
        not isinstance(architectures, list)
        or not architectures
        or any(arch not in {"amd64", "arm64"} for arch in architectures)
        or len(set(architectures)) != len(architectures)
    ):
        _fail("Payload architectures must be unique supported architectures.")
    _arguments(build.get("args", {}))
    arch_args = build.get("architectureArgs", {})
    if not isinstance(arch_args, dict) or set(arch_args) - set(architectures):
        _fail("Payload architectureArgs must match supported architectures.")
    for args in arch_args.values():
        _arguments(args)


def plan_payloads(root: Path, images: list[dict[str, Any]], runners: dict[str, str]) -> dict[str, Any]:
    """Deduplicate by payload and architecture across all selected variants."""
    entries: dict[tuple[str, str], dict[str, str]] = {}
    names: dict[str, str] = {}
    for image in images:
        build = image["build"]
        manifest = build.get("payload")
        if manifest is None:
            continue
        record = load_manifest(root, manifest)
        name = record["name"]
        if name in names and names[name] != manifest:
            _fail(f"Payload name {name} is used by multiple manifests.")
        names[name] = manifest
        consumer = record.get("consumer")
        if consumer is not None:
            arguments = record["build"]["args"]
            expected_version = arguments[consumer["versionArg"]].removeprefix("v")
            image_version = image.get("version")
            if not isinstance(image_version, str) or image_version.removeprefix("v") != expected_version:
                _fail(f"Payload {name} version does not match consumer {image['name']}.")
            base_arg = consumer["runtimeBaseArg"]
            image_base = build.get("args", {}).get(base_arg, {}).get("value")
            if image_base != arguments[base_arg] or build.get("runtimeBaseArg") != base_arg:
                _fail(f"Payload {name} runtime base does not match consumer {image['name']}.")
        for architecture in build["architectures"]:
            if architecture not in record["build"]["architectures"]:
                _fail(f"Payload {name} does not support {architecture} for {image['name']}.")
            entries[name, architecture] = {
                "name": name,
                "arch": architecture,
                "runner": runners[architecture],
                "manifest": manifest,
            }
    return {"include": [entries[key] for key in sorted(entries)]}


def _run(command: list[str], root: Path) -> None:
    subprocess.run(command, cwd=root, check=True)  # noqa: S603 - argv is constructed without a shell.


def build_payload(root: Path, manifest: str, architecture: str, revision: str, output: Path) -> None:
    """Build one payload architecture and emit verifiable transfer evidence."""
    record = load_manifest(root, manifest)
    build = record["build"]
    if architecture not in build["architectures"]:
        _fail(f"Unsupported payload architecture: {architecture}")
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        _fail("Payload source revision must be a full Git SHA.")
    git = shutil.which("git") or "/usr/bin/git"
    checkout_revision = subprocess.check_output(  # noqa: S603 - fixed git command.
        [git, "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    if checkout_revision != revision:
        _fail(f"Payload source revision {revision} does not match checkout HEAD {checkout_revision}.")
    timestamp = subprocess.check_output(  # noqa: S603 - fixed git command; full SHA validated above.
        [git, "show", "-s", "--format=%ct", revision], cwd=root, text=True
    ).strip()
    arguments = {**build.get("args", {}), **build.get("architectureArgs", {}).get(architecture, {})}
    name = record["name"]
    image = f"localhost/{name}:{revision}-{architecture}"
    command = [
        "sudo",
        "buildah",
        "bud",
        "--arch",
        architecture,
        "--format",
        "oci",
        "--pull-always",
        "--no-cache",
        "--timestamp",
        timestamp,
    ]
    for key, value in sorted(arguments.items()):
        command.extend(["--build-arg", f"{key}={value}"])
    command.extend(["--tag", image, "--file", build["containerfile"], build["context"]])
    _run(command, root)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{name}-{architecture}.tar"
    _run(["sudo", "buildah", "push", "--format", "oci", image, f"oci-archive:{archive}"], root)
    evidence = {
        "schemaVersion": 1,
        "name": name,
        "architecture": architecture,
        "sourceRevision": revision,
        "manifest": manifest,
        "manifestSha256": sha256(repository_path(root, manifest)),
        "archiveSha256": sha256(archive),
        "archive": archive.name,
        "arguments": arguments,
        "provenance": record["provenance"],
    }
    (output / f"{name}-{architecture}.json").write_text(json.dumps(evidence, indent=2) + "\n")


def import_payload(root: Path, manifest: str, architecture: str, revision: str, artifacts: Path) -> str:
    """Verify exact source, metadata and archive bytes before local OCI import."""
    record = load_manifest(root, manifest)
    name = record["name"]
    evidence_path = artifacts / f"{name}-{architecture}.json"
    if not evidence_path.is_file():
        _fail(f"Missing same-run payload evidence: {evidence_path}")
    evidence = json.loads(evidence_path.read_text())
    expected = {
        "schemaVersion": 1,
        "name": name,
        "architecture": architecture,
        "sourceRevision": revision,
        "manifest": manifest,
        "manifestSha256": sha256(repository_path(root, manifest)),
        "archive": f"{name}-{architecture}.tar",
    }
    for key, value in expected.items():
        if evidence.get(key) != value:
            _fail(f"Payload {name} has mismatched {key}.")
    archive = repository_path(artifacts, evidence["archive"])
    if not archive.is_file() or sha256(archive) != evidence.get("archiveSha256"):
        _fail(f"Payload {name} archive integrity check failed.")
    image = f"localhost/{name}:{revision}-{architecture}"
    _run(["sudo", "skopeo", "copy", f"oci-archive:{archive}", f"containers-storage:{image}"], root)
    return image


def main() -> None:
    """Build a private payload for a workflow or an explicit local check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build_payload(Path(__file__).resolve().parents[1], args.manifest, args.arch, args.revision, args.output)


if __name__ == "__main__":
    main()
