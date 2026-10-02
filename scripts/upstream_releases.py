"""Discover upstream Podman and Docker releases and plan repository maintenance."""

# Discovery errors include the source URL, so their messages are assembled at the call site.
# ruff: noqa: TRY003, EM101, EM102

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable

PODMAN_API = "https://api.github.com/repos/podman-container-tools/podman/releases"
PODMAN_RELEASE_URL = "https://github.com/podman-container-tools/podman/releases/tag/"
DOCKER_ARCHIVE_URL = "https://download.docker.com/linux/static/stable/"
DOCKER_NOTES_URL = "https://docs.docker.com/engine/release-notes/"
VERSION_RE = re.compile(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
DOCKER_FILE_RE = re.compile(r"docker(-rootless-extras)?-((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\.tgz\Z")
PODMAN_FILE_RE = re.compile(r"podman-(\d+\.\d+)\.yaml\Z")
DOCKER_LINE_RE = re.compile(r"[1-9][0-9]*\Z")
LIFECYCLE_STATES = frozenset({"maintained", "legacy", "experimental"})
ADMISSION_STATES = frozenset({"production", "isolated-test", "disabled"})
DOCKER_ARCHITECTURES = ("x86_64", "aarch64")
DOCKER_LEGACY_MAJOR = 20
DOCKER_LEGACY_MINOR = 10
MAX_PODMAN_PAGES = 30
GITHUB_PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 20


class DiscoveryError(RuntimeError):
    """An upstream source could not be read or understood."""


@dataclass(frozen=True, order=True)
class Release:
    """A stable upstream release with a reviewable source URL."""

    version: tuple[int, int, int]
    url: str

    @property
    def version_string(self) -> str:
        """Return the canonical unprefixed version string."""
        return ".".join(map(str, self.version))


def parse_version(value: str) -> tuple[int, int, int] | None:
    """Accept only complete stable semantic version tags."""
    match = VERSION_RE.fullmatch(value)
    return tuple(map(int, match.groups())) if match else None


class _NoRedirects(HTTPRedirectHandler):
    """Keep an authenticated GitHub API request on its original host."""

    def redirect_request(self, *_args: object) -> None:
        """Reject redirects before urllib can forward Authorization."""
        return


def _read_url(url: str) -> bytes:
    if not (
        url.startswith(PODMAN_API + "?") or url in {f"{DOCKER_ARCHIVE_URL}{arch}/" for arch in DOCKER_ARCHITECTURES}
    ):
        raise DiscoveryError(f"Unexpected release source URL: {url}")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "strukturpiloten-release-monitor"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(PODMAN_API):
        headers["Authorization"] = f"Bearer {token}"
    try:
        with build_opener(_NoRedirects()).open(
            Request(url, headers=headers),  # noqa: S310
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise DiscoveryError(f"Cannot read upstream release source {url}: {exc}") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise DiscoveryError(f"Upstream release source exceeds size limit: {url}")
    return payload


def _fetch_json(url: str) -> object:
    try:
        return json.loads(_read_url(url))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError(f"Invalid JSON from {url}") from exc


def _fetch_text(url: str) -> str:
    try:
        return _read_url(url).decode("utf-8")
    except UnicodeError as exc:
        raise DiscoveryError(f"Invalid UTF-8 from {url}") from exc


def discover_podman_releases(fetch_json: Callable[[str], object] = _fetch_json) -> list[Release]:  # noqa: C901
    """Read every GitHub release page, retaining full stable Podman versions."""
    releases: dict[tuple[int, int, int], Release] = {}
    for page in range(1, MAX_PODMAN_PAGES + 1):
        url = f"{PODMAN_API}?per_page={GITHUB_PAGE_SIZE}&page={page}"
        data = fetch_json(url)
        if not isinstance(data, list):
            raise DiscoveryError(f"Unexpected GitHub release response at {url}")
        if len(data) > GITHUB_PAGE_SIZE:
            raise DiscoveryError(f"Oversized GitHub release page at {url}")
        for item in data:
            if not isinstance(item, dict):
                raise DiscoveryError(f"Malformed GitHub release at {url}")
            if not isinstance(item.get("draft"), bool) or not isinstance(item.get("prerelease"), bool):
                raise DiscoveryError(f"Missing GitHub release status at {url}")
            if item.get("draft") or item.get("prerelease"):
                continue
            tag = item.get("tag_name")
            if not isinstance(tag, str):
                raise DiscoveryError(f"Missing GitHub release tag at {url}")
            if (version := parse_version(tag)) is None:
                continue
            release_url = item.get("html_url")
            if release_url != f"{PODMAN_RELEASE_URL}{tag}":
                raise DiscoveryError(f"Unexpected Podman release URL for {tag}")
            releases[version] = Release(version, release_url)
        if len(data) < GITHUB_PAGE_SIZE:
            if not releases:
                raise DiscoveryError("Podman release source contained no stable full versions")
            return sorted(releases.values())
    raise DiscoveryError(f"Podman release pagination exceeded {MAX_PODMAN_PAGES} pages")


class _ArchiveLinks(HTMLParser):
    """Collect filenames linked from an official Docker static archive index."""

    def __init__(self) -> None:
        super().__init__()
        self.filenames: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Keep direct archive links only; ignore arbitrary URLs and subdirectories."""
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value and DOCKER_FILE_RE.fullmatch(value):
                self.filenames.add(value)


def discover_docker_releases(fetch_text: Callable[[str], str] = _fetch_text) -> list[Release]:
    """Require engine and rootless static archives on both supported architectures."""
    per_architecture: list[set[tuple[int, int, int]]] = []
    for arch in DOCKER_ARCHITECTURES:
        url = f"{DOCKER_ARCHIVE_URL}{arch}/"
        parser = _ArchiveLinks()
        parser.feed(fetch_text(url))
        engine: set[tuple[int, int, int]] = set()
        rootless: set[tuple[int, int, int]] = set()
        for filename in parser.filenames:
            match = DOCKER_FILE_RE.fullmatch(filename)
            if match is None:
                continue
            version = parse_version(match.group(2))
            if version is None:
                continue
            (rootless if match.group(1) else engine).add(version)
        if not engine or not rootless:
            raise DiscoveryError(f"Docker archive index lacks engine or rootless archives: {url}")
        per_architecture.append(engine & rootless)
    complete = set.intersection(*per_architecture)
    if not complete:
        raise DiscoveryError("Docker archive indexes have no release complete on both architectures")
    return [Release(version, f"{DOCKER_NOTES_URL}{version[0]}/") for version in sorted(complete)]


def _payload_version(path: Path, arg: str, expected_name: str) -> tuple[int, int, int]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data["name"] != expected_name:
            raise DiscoveryError(f"Payload name in {path} must be {expected_name}")
        value = data["build"]["args"][arg]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise DiscoveryError(f"Cannot read {arg} from {path}") from exc
    version = parse_version(value) if isinstance(value, str) else None
    if version is None:
        raise DiscoveryError(f"Invalid {arg} in {path}: {value!r}")
    return version


@dataclass(frozen=True)
class _ConsumerLifecycle:
    state: str
    admission: str


def _consumer_lifecycles(root: Path, project: str, line: str) -> list[_ConsumerLifecycle]:
    lifecycles = []
    for path in (root / "images" / project).glob(f"{project}-{line}-*/container.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            lifecycle = data["lifecycle"]
            state = lifecycle["state"]
            admission = lifecycle["admission"]
        except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
            raise DiscoveryError(f"Cannot read lifecycle from {path}") from exc
        if (
            not isinstance(state, str)
            or state not in LIFECYCLE_STATES
            or not isinstance(admission, str)
            or admission not in ADMISSION_STATES
        ):
            raise DiscoveryError(f"Invalid lifecycle state or admission in {path}")
        lifecycles.append(_ConsumerLifecycle(state, admission))
    if not lifecycles:
        raise DiscoveryError(f"No consumers for tracked {project} line {line}")
    return lifecycles


def _tracked_versions(root: Path, project: str) -> dict[str, tuple[int, int, int]]:
    if project == "podman":
        directory = root / "images/podman/payloads"
        paths = directory.glob("podman-*.yaml")
        arg = "OCI_VERSION"
    else:
        directory = root / "images/docker/upstream"
        paths = directory.glob("*/payload.yaml")
        arg = "ENGINE_VERSION"
    if not directory.is_dir():
        raise DiscoveryError(f"Missing payload directory: {directory}")
    tracked = {}
    for path in paths:
        if project == "podman":
            match = PODMAN_FILE_RE.fullmatch(path.name)
            line = match.group(1) if match else None
        else:
            line = path.parent.name
        if line is None:
            raise DiscoveryError(f"Invalid tracked {project} payload path: {path}")
        if project == "docker" and line != "20.10" and DOCKER_LINE_RE.fullmatch(line) is None:
            raise DiscoveryError(f"Invalid Docker compatibility line: {line}")
        version = _payload_version(path, arg, f"{project}-{line}" + ("-payload" if project == "docker" else ""))
        expected_line = f"{version[0]}.{version[1]}" if project == "podman" else _docker_line(version)
        if line != expected_line:
            raise DiscoveryError(f"Payload version {version} does not match compatibility line {line} in {path}")
        tracked[line] = version
    if not tracked:
        raise DiscoveryError(f"No tracked {project} payloads in {directory}")
    return tracked


def _line_key(line: str) -> tuple[int, ...]:
    return tuple(map(int, line.split(".")))


def _docker_line(version: tuple[int, int, int]) -> str | None:
    if version[0] == DOCKER_LEGACY_MAJOR:
        return "20.10" if version[1] == DOCKER_LEGACY_MINOR else None
    return str(version[0])


def plan_releases(  # noqa: C901
    root: Path,
    podman_releases: list[Release],
    docker_releases: list[Release],
) -> dict[str, list[dict[str, str]]]:
    """Compare complete upstream releases against tracked compatibility lines."""
    new_lines: list[dict[str, str]] = []
    docker_updates: list[dict[str, str]] = []
    for project, releases in (("podman", podman_releases), ("docker", docker_releases)):
        tracked = _tracked_versions(root, project)
        consumers = {line: _consumer_lifecycles(root, project, line) for line in tracked}
        floor = min(_line_key(line) for line in tracked)
        latest_by_line: dict[str, Release] = {}
        for release in releases:
            line = (
                f"{release.version[0]}.{release.version[1]}" if project == "podman" else _docker_line(release.version)
            )
            if line is not None and _line_key(line) >= floor:
                previous = latest_by_line.get(line)
                if previous is None or previous.version < release.version:
                    latest_by_line[line] = release
        for line in sorted(latest_by_line, key=_line_key):
            if line in tracked:
                continue
            release = latest_by_line[line]
            new_lines.append({"project": project, "line": line, "version": release.version_string, "url": release.url})
        if project == "docker":
            for line in sorted(tracked, key=_line_key):
                if all(consumer.admission == "disabled" for consumer in consumers[line]):
                    continue
                current = tracked[line]
                eligible = [
                    release
                    for release in releases
                    if release.version[0] == current[0]
                    and (line != "20.10" or release.version[1] == _line_key(line)[1])
                    and release.version > current
                ]
                if eligible:
                    candidate = max(eligible)
                    docker_updates.append(
                        {
                            "line": line,
                            "currentVersion": ".".join(map(str, current)),
                            "version": candidate.version_string,
                            "updateType": "patch" if candidate.version[1] == current[1] else "minor",
                        }
                    )
    return {"newLines": new_lines, "dockerUpdates": docker_updates}


def main(argv: list[str] | None = None) -> int:
    """Write a machine readable plan only after all discovery sources succeed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Path for the JSON release plan")
    args = parser.parse_args(argv)
    try:
        plan = plan_releases(
            Path(__file__).resolve().parents[1],
            discover_podman_releases(),
            discover_docker_releases(),
        )
    except DiscoveryError as exc:
        sys.stderr.write(f"Release discovery failed: {exc}\n")
        return 1
    args.output.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
