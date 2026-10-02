"""Create durable GitHub issues for newly discovered upstream compatibility lines."""

# Error messages identify invalid input without reflecting subprocess stderr or credentials.
# ruff: noqa: TRY003, EM101, EM102

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.upstream_releases import DOCKER_NOTES_URL, PODMAN_RELEASE_URL, parse_version

if TYPE_CHECKING:
    from collections.abc import Mapping

REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
USERNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
PODMAN_LINE_RE = re.compile(r"[1-9]\d*\.(?:0|[1-9]\d*)\Z")
DOCKER_LINE_RE = re.compile(r"[1-9]\d*\Z")
VERSION_MARKER_RE = re.compile(r"<!-- upstream-release-version:(podman|docker):([0-9.]+):([0-9.]+) -->")
LABEL = "upstream-release"
LABEL_COLOR = "0e8a16"
GH_TIMEOUT_SECONDS = 120


class NotificationError(RuntimeError):
    """A release issue cannot be safely planned or published."""


class GitHubError(NotificationError):
    """A GitHub request failed or returned unexpected data."""


def _require_repository(repository: str) -> str:
    if not REPOSITORY_RE.fullmatch(repository) or any(
        part in {".", ".."} or part.startswith("-") or part.endswith("-") for part in repository.split("/")
    ):
        raise NotificationError("Invalid GITHUB_REPOSITORY")
    return repository


class GitHub:
    """Small JSON-only wrapper for repository-relative GitHub REST requests."""

    def __init__(self, repository: str) -> None:
        """Bind all requests to one validated repository."""
        self.repository = _require_repository(repository)

    def _endpoint(self, relative_repo_path: str) -> str:
        if (
            not relative_repo_path
            or relative_repo_path.startswith(("/", "-"))
            or "//" in relative_repo_path
            or any(segment in {".", ".."} for segment in relative_repo_path.split("?", 1)[0].split("/"))
            or any(character.isspace() for character in relative_repo_path)
        ):
            raise NotificationError("Invalid repository-relative API path")
        return f"repos/{self.repository}/{relative_repo_path}"

    def _run(self, method: str, relative_repo_path: str, data: Mapping[str, object] | None, *, pages: bool) -> object:
        if method not in {"GET", "POST", "PATCH"}:
            raise NotificationError("Unsupported GitHub method")
        if (method == "GET") != (data is None):
            raise NotificationError("Invalid GitHub request body")
        command = ["gh", "api", "--method", method, self._endpoint(relative_repo_path)]
        if pages:
            command.extend(["--paginate", "--slurp"])
        if data is not None:
            command.extend(["--input", "-"])
        try:
            result = subprocess.run(  # noqa: S603
                command,
                input=json.dumps(data) if data is not None else None,
                text=True,
                capture_output=True,
                check=False,
                timeout=GH_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitHubError(f"GitHub {method} request could not run") from exc
        if result.returncode != 0:
            raise GitHubError(f"GitHub {method} request failed for {relative_repo_path} (exit {result.returncode})")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise GitHubError(f"GitHub {method} request returned invalid JSON for {relative_repo_path}") from exc

    def request(self, method: str, relative_repo_path: str, data: Mapping[str, object] | None = None) -> dict:
        """Run a single GitHub REST request and require an object response."""
        response = self._run(method, relative_repo_path, data, pages=False)
        if not isinstance(response, dict):
            raise GitHubError(f"GitHub {method} request returned an unexpected response")
        return response

    def pages(self, relative_repo_path: str) -> list[dict]:
        """Fetch and flatten every page of a GitHub REST collection."""
        response = self._run("GET", relative_repo_path, None, pages=True)
        if not isinstance(response, list) or any(not isinstance(page, list) for page in response):
            raise GitHubError("GitHub paginated request returned an unexpected response")
        items = [item for page in response for item in page]
        if any(not isinstance(item, dict) for item in items):
            raise GitHubError("GitHub paginated request contained an invalid item")
        return items


def load_policy(root: Path) -> dict[str, list[str]]:
    """Read and validate configured assignees for release issues."""
    path = root / ".github/upstream-releases.json"
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NotificationError(f"Cannot read release issue policy: {path}") from exc
    if not isinstance(policy, dict):
        raise NotificationError("Release issue policy must be an object")
    assignees = policy.get("assignees")
    if (
        not isinstance(assignees, list)
        or not assignees
        or any(not isinstance(name, str) or not USERNAME_RE.fullmatch(name) for name in assignees)
        or len(set(assignees)) != len(assignees)
    ):
        raise NotificationError("Release issue policy needs distinct, valid assignees")
    return {"assignees": assignees}


def _validate_new_line(item: object) -> dict[str, str]:
    if not isinstance(item, dict) or set(item) != {"project", "line", "version", "url"}:
        raise NotificationError("Invalid new-line plan entry")
    if any(not isinstance(value, str) for value in item.values()):
        raise NotificationError("New-line plan fields must be strings")
    project, line, version, url = (item[key] for key in ("project", "line", "version", "url"))
    parsed = parse_version(version)
    if parsed is None or version != ".".join(map(str, parsed)):
        raise NotificationError("New-line plan version must be stable full semver")
    if project == "podman":
        if not PODMAN_LINE_RE.fullmatch(line) or line != f"{parsed[0]}.{parsed[1]}":
            raise NotificationError("Podman plan line does not match its version")
        if url not in {f"{PODMAN_RELEASE_URL}v{version}", f"{PODMAN_RELEASE_URL}{version}"}:
            raise NotificationError("Invalid Podman release URL")
    elif project == "docker":
        if not DOCKER_LINE_RE.fullmatch(line) or line != str(parsed[0]):
            raise NotificationError("Docker plan line does not match its version")
        if url != f"{DOCKER_NOTES_URL}{line}/":
            raise NotificationError("Invalid Docker release notes URL")
    else:
        raise NotificationError("Unknown new-line project")
    return {"project": project, "line": line, "version": version, "url": url}


def validate_plan(plan: object) -> list[dict[str, str]]:
    """Validate the complete discovery payload before any GitHub call."""
    if not isinstance(plan, dict) or set(plan) != {"newLines", "dockerUpdates"}:
        raise NotificationError("Release plan must contain newLines and dockerUpdates")
    if not isinstance(plan["newLines"], list) or not isinstance(plan["dockerUpdates"], list):
        raise NotificationError("Release plan collections must be lists")
    lines = [_validate_new_line(item) for item in plan["newLines"]]
    if len({(item["project"], item["line"]) for item in lines}) != len(lines):
        raise NotificationError("Release plan repeats a compatibility line")
    for update in plan["dockerUpdates"]:
        if not isinstance(update, dict) or set(update) != {"line", "currentVersion", "version", "updateType"}:
            raise NotificationError("Invalid Docker update plan entry")
        line, current, version, update_type = (
            update[key] for key in ("line", "currentVersion", "version", "updateType")
        )
        if (
            not isinstance(line, str)
            or not (DOCKER_LINE_RE.fullmatch(line) or line == "20.10")
            or not isinstance(current, str)
            or not isinstance(version, str)
            or parse_version(current) is None
            or parse_version(version) is None
            or update_type not in {"patch", "minor"}
        ):
            raise NotificationError("Invalid Docker update plan entry")
    return lines


def _line_marker(project: str, line: str) -> str:
    return f"<!-- upstream-release:{project}:{line} -->"


def _version_marker(project: str, line: str, version: str) -> str:
    return f"<!-- upstream-release-version:{project}:{line}:{version} -->"


def _issue_title(project: str, line: str) -> str:
    prefix = "Podman" if project == "podman" else "Docker Engine"
    return f"Add {prefix} {line} rootful/rootless images"


def _issue_body(item: dict[str, str]) -> str:
    project, line, version, url = (item[key] for key in ("project", "line", "version", "url"))
    return (
        f"{_line_marker(project, line)}\n"
        f"{_version_marker(project, line, version)}\n\n"
        f"Upstream release: {url}\n\n"
        f"Latest stable release for the new {project} {line} compatibility line: {version}.\n\n"
        "- [ ] Add the shared payload and verify its source commit or archive checksums for amd64 and arm64.\n"
        "- [ ] Add rootful and rootless image metadata for this compatibility line.\n"
        "- [ ] Build and run the required tests on both architectures.\n"
        "- [ ] Update the image catalogue and documentation.\n"
        "- [ ] Review Renovate policies for the new compatibility line.\n"
    )


def _seen_versions(texts: list[str], project: str, line: str) -> set[tuple[int, int, int]]:
    versions = set()
    for text in texts:
        for match in VERSION_MARKER_RE.finditer(text):
            if match.group(1) == project and match.group(2) == line:
                version = parse_version(match.group(3))
                if version is not None:
                    versions.add(version)
    return versions


def _ensure_label(github: GitHub) -> str:
    labels = github.pages("labels?per_page=100")
    for label in labels:
        name = label.get("name")
        if isinstance(name, str) and name.casefold() == LABEL:
            return name
    github.request(
        "POST", "labels", {"name": LABEL, "color": LABEL_COLOR, "description": "New upstream compatibility line"}
    )
    return LABEL


def notify_new_lines(plan: object, github: GitHub, policy: Mapping[str, list[str]]) -> list[str]:  # noqa: C901
    """Create missing issues, or comment once when a later release is discovered."""
    lines = validate_plan(plan)
    assignees = policy.get("assignees")
    if not isinstance(assignees, list) or not assignees:
        raise NotificationError("Release issue assignees are missing")
    if not lines:
        return []
    issues = github.pages("issues?state=all&per_page=100")
    actions: list[str] = []
    label_name: str | None = None
    for item in lines:
        project, line, version = (item[key] for key in ("project", "line", "version"))
        marker = _line_marker(project, line)
        matching = [issue for issue in issues if "pull_request" not in issue and marker in (issue.get("body") or "")]
        if len(matching) > 1:
            raise NotificationError(f"Multiple GitHub issues contain marker {marker}")
        if not matching:
            if label_name is None:
                label_name = _ensure_label(github)
            created = github.request(
                "POST",
                "issues",
                {
                    "title": _issue_title(project, line),
                    "body": _issue_body(item),
                    "labels": [label_name],
                    "assignees": assignees,
                },
            )
            number = created.get("number")
            if not isinstance(number, int) or number < 1:
                raise GitHubError("GitHub did not return a created issue number")
            issues.append(created)
            actions.append(f"created {project} {line} issue #{number}")
            continue
        issue = matching[0]
        if issue.get("state") == "closed":
            continue
        if issue.get("state") != "open":
            raise GitHubError("GitHub issue has an unexpected state")
        number = issue.get("number")
        if not isinstance(number, int) or number < 1:
            raise GitHubError("GitHub issue lacks a valid number")
        comments = github.pages(f"issues/{number}/comments?per_page=100")
        texts = [issue.get("body") or "", *[comment.get("body") or "" for comment in comments]]
        seen = _seen_versions(texts, project, line)
        parsed = parse_version(version)
        if parsed is not None and (not seen or parsed > max(seen)):
            body = (
                f"{_version_marker(project, line, version)}\nNew stable release for this line: {version}\n{item['url']}"
            )
            github.request(
                "POST",
                f"issues/{number}/comments",
                {"body": body},
            )
            actions.append(f"commented on {project} {line} issue #{number} for {version}")
    return actions


def main(argv: list[str] | None = None) -> int:
    """Publish validated new-line notices from a discovery plan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True, help="JSON plan from scripts.upstream_releases")
    args = parser.parse_args(argv)
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        root = Path(__file__).resolve().parents[1]
        policy = load_policy(root)
        github = GitHub(os.environ.get("GITHUB_REPOSITORY", ""))
        for action in notify_new_lines(plan, github, policy):
            sys.stdout.write(f"{action}\n")
    except (OSError, UnicodeError, json.JSONDecodeError, NotificationError) as exc:
        sys.stderr.write(f"Release issue notification failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
