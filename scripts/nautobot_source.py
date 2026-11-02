"""Acquire the private, immutable bootstrap source before an uncredentialed build."""

# Fixed argv and generated paths; no token is passed to a command argument or image.
# ruff: noqa: EM101, EM102, S603, S607, TRY003
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "images/strukturbo/strukturbo-nautobot/source.json"
STAGED = ".build-sources/strukturbo-nautobot"


def manifest(root: Path = ROOT) -> dict[str, str]:
    """Accept only the intended repository and a full immutable commit."""
    value = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if (
        set(value) != {"repository", "sourceRef", "sourceCommit"}
        or value["repository"] != "Strukturpiloten/strukturbo-bootstrap"
        or not re.fullmatch(r"[a-f0-9]{40}", value["sourceCommit"])
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", value["sourceRef"])
    ):
        raise ValueError("Invalid Nautobot source manifest")
    return value


def extract(payload: bytes, destination: Path) -> None:
    """Extract bounded regular files only; never honor archive links or traversal."""
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("Source archive exceeds compressed size limit")
    total = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(item.name).parts[0] for item in members if item.name}
        if len(roots) != 1:
            raise ValueError("Source archive must have one repository root")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsupported source archive member")
            relative = Path(*path.parts[1:])
            if relative == Path():
                continue
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > 256 * 1024 * 1024 or member.size > 16 * 1024 * 1024:
                raise ValueError("Source archive exceeds expanded size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Missing source archive content")
            with target.open("xb") as output, stream:
                shutil.copyfileobj(stream, output)


def provenance(source: Path, declaration: dict[str, str], archive_sha256: str) -> dict[str, Any]:
    """Bind the wheel contents to the qualified package and dependency contract."""
    app = source / "apps/nautobot-strukturbo"
    package = app / "src/nautobot_strukturbo"
    paths = sorted(p for p in package.rglob("*") if p.is_file() and p.suffix in (".py", ".html"))
    if not paths or any(p.is_symlink() for p in app.rglob("*")):
        raise ValueError("Missing or linked registry source")
    files = {"/test-app/nautobot_strukturbo/" + p.relative_to(package).as_posix(): p.read_text() for p in paths}
    qualified = {"files": files, "pyproject": (app / "pyproject.toml").read_text()}
    digest = hashlib.sha256(json.dumps(qualified, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipt = json.loads((app / "qualification.json").read_text())
    if digest != receipt["source_bundle_sha256"]:
        raise ValueError("Registry source differs from its source qualification receipt")
    project = tomllib.loads((app / "pyproject.toml").read_text())["project"]
    versions = {"nautobot-strukturbo": project["version"]}
    for requirement in project["dependencies"]:
        name, version = requirement.split("==")
        versions[name] = version
    for line in (source / "images/nautobot/requirements.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split()[0].split("==")
            versions[name] = version
    return {
        "schema_version": 1,
        **declaration,
        "archive_sha256": archive_sha256,
        "qualified_source_sha256": digest,
        "versions": versions,
        "package_files": {
            "nautobot_strukturbo/" + p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths
        },
    }


def prepare(root: Path = ROOT, *, archive: Path | None = None) -> Path:
    """Stage build-only app inputs separately from the complete qualification tools."""
    declaration = manifest(root)
    staged = root / STAGED
    if staged.exists():
        raise ValueError(f"Remove the previous generated {STAGED} directory before fetching a new source")
    if archive:
        payload = archive.read_bytes()
    else:
        result = subprocess.run(
            ["gh", "api", f"repos/{declaration['repository']}/tarball/{declaration['sourceCommit']}"],
            capture_output=True,
            check=False,
            timeout=90,
        )
        if result.returncode:
            raise RuntimeError(
                "Cannot read pinned private source; GH_TOKEN needs Contents read on the bootstrap repository"
            )
        payload = result.stdout
    parent = staged.parent
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nautobot-source-", dir=parent) as temporary:
        work = Path(temporary)
        source = work / "bootstrap"
        source.mkdir()
        extract(payload, source)
        record = provenance(source, declaration, hashlib.sha256(payload).hexdigest())
        shutil.copytree(source / "apps/nautobot-strukturbo", work / "app")
        (work / "provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        work.rename(staged)
    return staged


def verify(root: Path = ROOT) -> Path:
    """Recheck staged files before testing the built image."""
    staged = root / STAGED
    old = json.loads((staged / "provenance.json").read_text())
    actual = provenance(staged / "bootstrap", manifest(root), old["archive_sha256"])
    if old != actual:
        raise ValueError("Staged qualification source differs from the image build inputs")
    return staged


def main() -> None:
    """Fetch with the host gh client; source credentials never enter the build context."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Use a previously acquired immutable source archive")
    options = parser.parse_args()
    print(prepare(archive=options.archive))  # noqa: T201


if __name__ == "__main__":
    main()
