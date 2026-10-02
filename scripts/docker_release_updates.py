"""Probe official Docker static archives on native runners and apply reviewed evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml
from yaml.nodes import MappingNode, ScalarNode

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[1]
ARCHES = {"amd64": "x86_64", "arm64": "aarch64"}
LINE = re.compile(r"[1-9][0-9]*\Z")
FIRST_FIXED_MAJOR = 23
COMPONENTS = ("engine", "cli", "containerd", "runc", "rootlesskit")
REVISIONS = ("dockerd", "cli", "containerd", "runc")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
REVISION = re.compile(r"[0-9a-f]{7,40}\Z")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_VERSION_OUTPUT = 8192
ARCHIVE_MEMBER_DEPTH = 2
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_UNPACKED_BYTES = 1024 * 1024 * 1024


class DockerReleaseError(ValueError):
    """Release evidence or catalogue metadata is invalid."""


def _version_tuple(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        msg = f"Invalid Docker version: {version!r}"
        raise DockerReleaseError(msg)
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _check_line(line: str, version: str) -> None:
    major, minor, _ = _version_tuple(version)
    fixed_line = LINE.fullmatch(line) is not None and int(line) >= FIRST_FIXED_MAJOR
    if (
        (line == "20.10" and (major, minor) != (20, 10))
        or (fixed_line and major != int(line))
        or (line != "20.10" and not fixed_line)
    ):
        msg = f"Version {version} does not belong to Docker line {line}"
        raise DockerReleaseError(msg)


def _archive_url(version: str, arch: str, *, rootless: bool) -> str:
    kind = "docker-rootless-extras" if rootless else "docker"
    return f"https://download.docker.com/linux/static/stable/{ARCHES[arch]}/{kind}-{version}.tgz"


def _trusted_archive_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "download.docker.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path.startswith("/linux/static/stable/")
        )
    except ValueError:
        return False


class _OfficialRedirects(HTTPRedirectHandler):
    """Reject archive redirects before contacting an untrusted host."""

    def redirect_request(  # noqa: PLR0913, PLR0917 - urllib requires this override signature.
        self, request: Request, response: object, code: int, message: str, headers: object, new_url: str
    ) -> Request | None:
        """Permit only HTTPS redirects that remain on Docker's archive host."""
        if not _trusted_archive_url(new_url):
            msg = f"Docker archive redirected outside official HTTPS host: {new_url}"
            raise DockerReleaseError(msg)
        return super().redirect_request(request, response, code, message, headers, new_url)


def _download(url: str, destination: Path) -> str:
    if not _trusted_archive_url(url):
        msg = f"Unexpected Docker archive URL: {url}"
        raise DockerReleaseError(msg)
    digest = hashlib.sha256()
    size = 0
    request = Request(url, headers={"User-Agent": "strukturpiloten-docker-release-probe/1"})  # noqa: S310
    with build_opener(_OfficialRedirects()).open(request, timeout=30) as response, destination.open("wb") as output:
        if not _trusted_archive_url(response.geturl()):
            msg = "Docker archive response came from an unexpected host"
            raise DockerReleaseError(msg)
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                msg = f"Docker archive exceeds {MAX_ARCHIVE_BYTES} bytes: {url}"
                raise DockerReleaseError(msg)
            output.write(chunk)
            digest.update(chunk)
    if not size:
        msg = f"Empty Docker archive: {url}"
        raise DockerReleaseError(msg)
    return digest.hexdigest()


def _copy_member(tar: tarfile.TarFile, member: tarfile.TarInfo, destination: Path, name: str) -> None:
    source = tar.extractfile(member)
    if source is None:
        msg = f"Unreadable Docker binary: {member.name}"
        raise DockerReleaseError(msg)
    size = 0
    with source, (destination / name).open("xb") as output:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BINARY_BYTES:
                msg = f"Docker binary exceeds {MAX_BINARY_BYTES} bytes: {member.name}"
                raise DockerReleaseError(msg)
            output.write(chunk)
    if size != member.size:
        msg = f"Truncated Docker binary: {member.name}"
        raise DockerReleaseError(msg)
    (destination / name).chmod(0o700)


def _extract_selected(archive: Path, destination: Path, names: tuple[str, ...], roots: tuple[str, ...]) -> None:
    """Copy only exact regular-file members; never extract archive paths directly."""
    found: set[str] = set()
    unpacked_size = 0
    with tarfile.open(archive, mode="r:gz") as tar:
        for count, member in enumerate(tar, start=1):
            unpacked_size += member.size
            if count > MAX_ARCHIVE_MEMBERS or unpacked_size > MAX_ARCHIVE_UNPACKED_BYTES:
                msg = "Docker archive exceeds member or unpacked-size limit"
                raise DockerReleaseError(msg)
            parts = member.name.split("/")
            while parts and parts[0] == ".":
                parts.pop(0)
            if member.name.startswith("/") or ".." in parts:
                msg = f"Unsafe Docker archive member: {member.name}"
                raise DockerReleaseError(msg)
            if not parts and member.isdir():
                continue
            if len(parts) != ARCHIVE_MEMBER_DEPTH or parts[0] not in roots or parts[1] not in names:
                continue
            name = parts[1]
            if name in found or not member.isfile() or member.size > MAX_BINARY_BYTES:
                msg = f"Unsafe or duplicate Docker binary: {member.name}"
                raise DockerReleaseError(msg)
            _copy_member(tar, member, destination, name)
            found.add(name)
    if found != set(names):
        msg = f"Docker archive lacks required regular binaries: {sorted(set(names) - found)}"
        raise DockerReleaseError(msg)


def _run_version(binary: Path) -> str:
    result = subprocess.run(  # noqa: S603
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        cwd=binary.parent,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(binary.parent)},
    )
    output = (result.stdout or result.stderr).strip()
    if len(output) > MAX_VERSION_OUTPUT:
        msg = f"Excessive version output from {binary.name}"
        raise DockerReleaseError(msg)
    return output


def _match(text: str, pattern: str, label: str) -> tuple[str, ...]:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
    if match is None:
        msg = f"Cannot parse {label} version output: {text!r}"
        raise DockerReleaseError(msg)
    return match.groups()


def _parse_versions(outputs: Mapping[str, str], requested: str) -> tuple[dict[str, str], dict[str, str]]:
    docker_version = r"^Docker version ([0-9]+\.[0-9]+\.[0-9]+), build ([0-9a-f]{7,40})\b"
    engine, dockerd_revision = _match(outputs["dockerd"], docker_version, "dockerd")
    cli, cli_revision = _match(outputs["docker"], docker_version, "docker")
    containerd_pattern = (
        r"^containerd(?: (?:containerd\.io|github\.com/containerd/containerd(?:/v2)?))? "
        r"v?([0-9]+\.[0-9]+\.[0-9]+) ([0-9a-f]{7,40})\b"
    )
    containerd, containerd_revision = _match(outputs["containerd"], containerd_pattern, "containerd")
    (runc,) = _match(outputs["runc"], r"^runc version ([0-9]+\.[0-9]+\.[0-9]+)\b", "runc")
    (runc_revision,) = _match(outputs["runc"], r"^commit: (?:v[^\s]*-g)?([0-9a-f]{7,40})\s*$", "runc commit")
    (rootlesskit,) = _match(outputs["rootlesskit"], r"^rootlesskit version ([0-9]+\.[0-9]+\.[0-9]+)\b", "rootlesskit")
    components = {"engine": engine, "cli": cli, "containerd": containerd, "runc": runc, "rootlesskit": rootlesskit}
    if engine != requested or cli != requested:
        msg = f"Docker Engine and CLI must exactly match requested version {requested}"
        raise DockerReleaseError(msg)
    for version in components.values():
        _version_tuple(version)
    revisions = {
        "dockerd": dockerd_revision.lower(),
        "cli": cli_revision.lower(),
        "containerd": containerd_revision.lower(),
        "runc": runc_revision.lower(),
    }
    return components, revisions


def probe_release(line: str, version: str, arch: str, output: Path) -> dict[str, Any]:
    """Download and inspect one architecture on its matching native Linux runner."""
    _check_line(line, version)
    if arch not in ARCHES or platform.system() != "Linux" or platform.machine() != ARCHES[arch]:
        msg = f"Probe requires a native Linux {arch} runner"
        raise DockerReleaseError(msg)
    engine_url = _archive_url(version, arch, rootless=False)
    rootless_url = _archive_url(version, arch, rootless=True)
    with tempfile.TemporaryDirectory(prefix="docker-release-probe-") as temp:
        work = Path(temp)
        engine_archive = work / "engine.tgz"
        rootless_archive = work / "rootless.tgz"
        engine_sha = _download(engine_url, engine_archive)
        rootless_sha = _download(rootless_url, rootless_archive)
        _extract_selected(engine_archive, work, ("dockerd", "docker", "containerd", "runc"), ("docker",))
        _extract_selected(rootless_archive, work, ("rootlesskit",), ("docker-rootless-extras", "docker"))
        outputs = {
            name: _run_version(work / name) for name in ("dockerd", "docker", "containerd", "runc", "rootlesskit")
        }
        components, revisions = _parse_versions(outputs, version)
    evidence = {
        "schemaVersion": 1,
        "line": line,
        "version": version,
        "arch": arch,
        "dockerArch": ARCHES[arch],
        "archives": {
            "engine": {"url": engine_url, "sha256": engine_sha},
            "rootless": {"url": rootless_url, "sha256": rootless_sha},
        },
        "components": components,
        "sourceRevision": revisions,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent, delete=False) as temp_output:
        json.dump(evidence, temp_output, indent=2)
        temp_output.write("\n")
        temp_path = Path(temp_output.name)
    temp_path.replace(output)
    return evidence


def _validate_evidence(evidence: Any, line: str, version: str, arch: str) -> dict[str, Any]:  # noqa: ANN401
    if not isinstance(evidence, dict) or any(
        evidence.get(key) != value
        for key, value in {
            "schemaVersion": 1,
            "line": line,
            "version": version,
            "arch": arch,
            "dockerArch": ARCHES[arch],
        }.items()
    ):
        msg = f"Docker evidence identity mismatch for {arch}"
        raise DockerReleaseError(msg)
    archives = evidence.get("archives")
    if not isinstance(archives, dict) or set(archives) != {"engine", "rootless"}:
        msg = f"Docker archive evidence incomplete for {arch}"
        raise DockerReleaseError(msg)
    for kind in ("engine", "rootless"):
        archive = archives[kind]
        expected_url = _archive_url(version, arch, rootless=kind == "rootless")
        if (
            not isinstance(archive, dict)
            or archive.get("url") != expected_url
            or not isinstance(archive.get("sha256"), str)
            or not SHA256.fullmatch(archive["sha256"])
        ):
            msg = f"Invalid {kind} archive URL or SHA256 for {arch}"
            raise DockerReleaseError(msg)
    components = evidence.get("components")
    revisions = evidence.get("sourceRevision")
    if (
        not isinstance(components, dict)
        or set(components) != set(COMPONENTS)
        or not isinstance(revisions, dict)
        or set(revisions) != set(REVISIONS)
    ):
        msg = f"Docker component evidence incomplete for {arch}"
        raise DockerReleaseError(msg)
    if components["engine"] != version or components["cli"] != version:
        msg = f"Docker Engine and CLI evidence must match {version}"
        raise DockerReleaseError(msg)
    for component in COMPONENTS:
        _version_tuple(components[component])
    if any(not isinstance(revisions[key], str) or not REVISION.fullmatch(revisions[key]) for key in REVISIONS):
        msg = f"Invalid Docker source revision for {arch}"
        raise DockerReleaseError(msg)
    return evidence


def _replace_scalars(source: str, replacements: Mapping[tuple[str, ...], str]) -> str:
    root = yaml.compose(source)
    if not isinstance(root, MappingNode):
        msg = "Docker metadata must be a YAML mapping"
        raise DockerReleaseError(msg)
    edits: list[tuple[int, int, str]] = []
    for path, replacement in replacements.items():
        node: Any = root
        for key in path:
            if not isinstance(node, MappingNode):
                msg = f"Missing Docker metadata key: {'.'.join(path)}"
                raise DockerReleaseError(msg)
            matches = [
                value for node_key, value in node.value if isinstance(node_key, ScalarNode) and node_key.value == key
            ]
            if len(matches) != 1:
                msg = f"Missing or duplicate Docker metadata key: {'.'.join(path)}"
                raise DockerReleaseError(msg)
            node = matches[0]
        if not isinstance(node, ScalarNode) or node.style is not None or node.start_mark.line != node.end_mark.line:
            msg = f"Docker metadata scalar has unsupported style: {'.'.join(path)}"
            raise DockerReleaseError(msg)
        edits.append((node.start_mark.index, node.end_mark.index, replacement))
    for start, end, replacement in sorted(edits, reverse=True):
        source = source[:start] + replacement + source[end:]
    return source


def _payload_replacements(evidence: dict[str, Any]) -> dict[tuple[str, ...], str]:
    version = evidence["amd64"]["version"]
    components = evidence["amd64"]["components"]
    revisions = evidence["amd64"]["sourceRevision"]
    replacements = {
        ("build", "args", "ENGINE_VERSION"): version,
        ("provenance", "engineArchive"): _archive_url(version, "amd64", rootless=False).replace(
            "x86_64", "{dockerArch}"
        ),
        ("provenance", "rootlessArchive"): _archive_url(version, "amd64", rootless=True).replace(
            "x86_64", "{dockerArch}"
        ),
    }
    for arch in ARCHES:
        archives = evidence[arch]["archives"]
        replacements[("build", "architectureArgs", arch, "ENGINE_SHA256")] = archives["engine"]["sha256"]
        replacements[("build", "architectureArgs", arch, "ROOTLESS_SHA256")] = archives["rootless"]["sha256"]
    for key, value in components.items():
        replacements[("provenance", key)] = value
    for key, value in revisions.items():
        replacements[("provenance", "sourceRevision", key)] = value
    return replacements


def _read_evidence_pair(line: str, version: str, evidence_dir: Path) -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for arch in ARCHES:
        path = evidence_dir / f"{arch}.json"
        if not path.is_file():
            msg = f"Missing native Docker evidence: {path}"
            raise DockerReleaseError(msg)
        evidence[arch] = _validate_evidence(json.loads(path.read_text(encoding="utf-8")), line, version, arch)
    for field in ("components", "sourceRevision"):
        if evidence["amd64"][field] != evidence["arm64"][field]:
            msg = f"Docker {field} differs between native architectures"
            raise DockerReleaseError(msg)
    return evidence


def _validate_existing_payload(payload: dict[str, Any], line: str, version: str) -> str:
    if payload["name"] != f"docker-{line}-payload" or set(payload["build"]["architectures"]) != set(ARCHES):
        msg = "Existing Docker payload identity or architectures are invalid"
        raise DockerReleaseError(msg)
    old_version = payload["build"]["args"]["ENGINE_VERSION"]
    _check_line(line, old_version)
    if _version_tuple(version) <= _version_tuple(old_version):
        msg = f"Docker release {version} must advance current version {old_version}"
        raise DockerReleaseError(msg)
    provenance = payload["provenance"]
    if any(provenance[key] != old_version for key in ("engine", "cli")):
        msg = "Existing Docker Engine and CLI provenance disagree with payload version"
        raise DockerReleaseError(msg)
    for component in COMPONENTS:
        _version_tuple(provenance[component])
    if any(
        not isinstance(provenance["sourceRevision"][key], str)
        or not REVISION.fullmatch(provenance["sourceRevision"][key])
        for key in REVISIONS
    ):
        msg = "Existing Docker source revisions are invalid"
        raise DockerReleaseError(msg)
    for kind, field in (("engine", "engineArchive"), ("rootless", "rootlessArchive")):
        expected = _archive_url(old_version, "amd64", rootless=kind == "rootless").replace("x86_64", "{dockerArch}")
        if provenance[field] != expected:
            msg = f"Existing Docker {field} disagrees with payload version"
            raise DockerReleaseError(msg)
    for arch, docker_arch in ARCHES.items():
        args = payload["build"]["architectureArgs"][arch]
        if args["DOCKER_ARCH"] != docker_arch or not all(
            isinstance(args[key], str) and SHA256.fullmatch(args[key]) for key in ("ENGINE_SHA256", "ROOTLESS_SHA256")
        ):
            msg = f"Existing Docker architecture pins invalid for {arch}"
            raise DockerReleaseError(msg)
    return old_version


def _prepare_payload(path: Path, line: str, version: str, evidence: dict[str, dict[str, Any]]) -> tuple[str, str]:
    payload_source = path.read_text(encoding="utf-8")
    payload = yaml.safe_load(payload_source)
    old_version = _validate_existing_payload(payload, line, version)
    replacements = _payload_replacements(evidence)
    new_payload = _replace_scalars(payload_source, replacements)
    expected_payload = yaml.safe_load(payload_source)
    for field_path, value in replacements.items():
        node = expected_payload
        for key in field_path[:-1]:
            node = node[key]
        node[field_path[-1]] = value
    if yaml.safe_load(new_payload) != expected_payload:
        msg = "Docker payload changed outside approved release fields"
        raise DockerReleaseError(msg)
    return old_version, new_payload


def _prepare_image(path: Path, line: str, mode: str, old_version: str, version: str) -> str:
    source = path.read_text(encoding="utf-8")
    metadata = yaml.safe_load(source)
    if metadata["name"] != f"docker-{line}-{mode}" or metadata["version"] != f"v{old_version}":
        msg = f"Docker {mode} image does not match current payload version"
        raise DockerReleaseError(msg)
    if metadata["build"]["payload"] != f"images/docker/upstream/{line}/payload.yaml":
        msg = f"Docker {mode} image points to the wrong payload"
        raise DockerReleaseError(msg)
    description = metadata["description"]
    if not isinstance(description, str) or description.count(f"Docker Engine {old_version}") != 1:
        msg = f"Docker {mode} description does not match current payload version"
        raise DockerReleaseError(msg)
    new_description = description.replace(f"Docker Engine {old_version}", f"Docker Engine {version}")
    new_source = _replace_scalars(source, {("version",): f"v{version}", ("description",): new_description})
    expected_metadata = dict(metadata)
    expected_metadata.update({"version": f"v{version}", "description": new_description})
    if yaml.safe_load(new_source) != expected_metadata:
        msg = f"Docker {mode} image changed outside approved release fields"
        raise DockerReleaseError(msg)
    return new_source


def verify_release(line: str, version: str, evidence_dir: Path, root: Path = ROOT) -> None:
    """Confirm an existing branch matches fresh dual-architecture probe evidence."""
    _check_line(line, version)
    evidence = _read_evidence_pair(line, version, evidence_dir)
    payload_path = root / "images/docker/upstream" / line / "payload.yaml"
    payload = yaml.safe_load(payload_path.read_text(encoding="utf-8"))
    if payload["name"] != f"docker-{line}-payload" or set(payload["build"]["architectures"]) != set(ARCHES):
        msg = "Docker payload identity or architectures are invalid"
        raise DockerReleaseError(msg)
    for arch, docker_arch in ARCHES.items():
        if payload["build"]["architectureArgs"][arch]["DOCKER_ARCH"] != docker_arch:
            msg = f"Docker payload architecture mapping invalid for {arch}"
            raise DockerReleaseError(msg)
    for field_path, expected in _payload_replacements(evidence).items():
        value = payload
        for key in field_path:
            value = value[key]
        if str(value) != expected:
            msg = f"Docker payload disagrees with fresh evidence: {'.'.join(field_path)}"
            raise DockerReleaseError(msg)
    for mode in ("rootful", "rootless"):
        path = root / f"images/docker/docker-{line}-{mode}/container.yaml"
        image = yaml.safe_load(path.read_text(encoding="utf-8"))
        if (
            image["name"] != f"docker-{line}-{mode}"
            or image["version"] != f"v{version}"
            or image["build"]["payload"] != f"images/docker/upstream/{line}/payload.yaml"
            or f"Docker Engine {version}" not in image["description"]
        ):
            msg = f"Docker {mode} image does not match fresh evidence"
            raise DockerReleaseError(msg)


def apply_release(line: str, version: str, evidence_dir: Path, root: Path = ROOT) -> list[Path]:
    """Validate both native probes and update one existing Docker compatibility line."""
    _check_line(line, version)
    evidence = _read_evidence_pair(line, version, evidence_dir)
    payload_path = root / "images/docker/upstream" / line / "payload.yaml"
    old_version, new_payload = _prepare_payload(payload_path, line, version, evidence)
    edits = {payload_path: new_payload}
    for mode in ("rootful", "rootless"):
        path = root / f"images/docker/docker-{line}-{mode}/container.yaml"
        edits[path] = _prepare_image(path, line, mode, old_version, version)
    for path, content in edits.items():
        path.write_text(content, encoding="utf-8")
    return list(edits)


def main() -> None:
    """Run the native probe or apply validated dual-architecture evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    probe = commands.add_parser("probe")
    probe.add_argument("--line", required=True)
    probe.add_argument("--version", required=True)
    probe.add_argument("--arch", choices=tuple(ARCHES), required=True)
    probe.add_argument("--output", required=True, type=Path)
    apply = commands.add_parser("apply")
    apply.add_argument("--line", required=True)
    apply.add_argument("--version", required=True)
    apply.add_argument("--evidence-dir", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--line", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "probe":
            probe_release(args.line, args.version, args.arch, args.output)
        elif args.command == "apply":
            apply_release(args.line, args.version, args.evidence_dir)
        else:
            verify_release(args.line, args.version, args.evidence_dir)
    except (DockerReleaseError, OSError, subprocess.SubprocessError, tarfile.TarError, yaml.YAMLError) as exc:
        parser.exit(1, f"Docker release update failed: {exc}\n")


if __name__ == "__main__":
    main()
