"""Propose verified Docker Engine updates without replacing compatibility lines."""

# Errors describe the failed GitHub/Git operation and are intentionally assembled locally.
# ruff: noqa: TRY003, EM101, EM102

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.docker_release_updates import apply_release
from scripts.release_notifications import GitHub, load_policy, validate_plan
from scripts.upstream_releases import parse_version

BRANCH_PREFIX = "automation/docker-engine-"
PR_MARKER = re.compile(r"<!-- docker-engine-update:(20\.10|[1-9]\d*):(\d+\.\d+\.\d+) -->")
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
CATALOGUE_PATHS = ("docs/image-catalogue.json", "docs/image-catalogue.md")
COMMAND_TIMEOUT_SECONDS = 180


class UpdateError(RuntimeError):
    """An update cannot be proposed safely."""


@dataclass(frozen=True)
class PublishContext:
    """Trusted workflow inputs shared by each line update."""

    root: Path
    github: GitHub
    base: str
    evidence_root: Path
    assignees: list[str]
    actor: str


def _run(arguments: list[str], root: Path) -> str:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise UpdateError(f"Required command is unavailable: {arguments[0]}")
    result = subprocess.run(  # noqa: S603 - fixed commands and separate, validated arguments.
        [executable, *arguments[1:]],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode:
        raise UpdateError(f"{arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def allowed_paths(line: str) -> set[str]:
    """Limit a bot branch to one payload, its consumers, and the generated catalogue."""
    if re.fullmatch(r"20\.10|[1-9]\d*", line) is None:
        raise UpdateError("Invalid Docker compatibility line")
    return {
        f"images/docker/upstream/{line}/payload.yaml",
        f"images/docker/docker-{line}-rootful/container.yaml",
        f"images/docker/docker-{line}-rootless/container.yaml",
        *CATALOGUE_PATHS,
    }


def classify_update(line: str, current: str, candidate: str) -> str:
    """Reject downgrades and compatibility-line changes before creating a PR."""
    allowed_paths(line)
    before, after = parse_version(current), parse_version(candidate)
    if before is None or after is None or after <= before:
        raise UpdateError("Docker update must advance a full stable version")
    for version in (before, after):
        actual_line = ".".join(map(str, version[:2])) if line == "20.10" else str(version[0])
        if actual_line != line:
            raise UpdateError("Docker update crosses its compatibility line")
    return "patch" if before[1] == after[1] else "minor"


def _current_version(root: Path, line: str) -> str:
    manifest = root / f"images/docker/upstream/{line}/payload.yaml"
    return str(yaml.safe_load(manifest.read_text(encoding="utf-8"))["build"]["args"]["ENGINE_VERSION"])


def _assert_paths(root: Path, line: str, comparison: list[str]) -> None:
    changed = set(_run(["git", "diff", "--no-renames", "--name-only", *comparison], root).splitlines())
    if unexpected := changed - allowed_paths(line):
        raise UpdateError(f"Refusing to overwrite unrelated branch changes: {', '.join(sorted(unexpected))}")


def _queue_entry(root: Path, repository: str, number: int) -> bool:
    owner, name = repository.split("/", 1)
    query = (
        "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name)"
        "{pullRequest(number:$number){mergeQueueEntry{id}}}}"
    )
    response = json.loads(
        _run(
            [
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={owner}",
                "-f",
                f"name={name}",
                "-F",
                f"number={number}",
            ],
            root,
        )
    )
    return response["data"]["repository"]["pullRequest"]["mergeQueueEntry"] is not None


def _branch_version(branch: str, line: str) -> str | None:
    match = re.fullmatch(rf"{re.escape(BRANCH_PREFIX + line)}-(\d+\.\d+\.\d+)", branch)
    if match is None:
        return None
    try:
        classify_update(line, "20.10.0" if line == "20.10" else f"{line}.0.0", match.group(1))
    except UpdateError:
        return None
    return match.group(1)


def _pull_marker(pull: dict[str, Any]) -> tuple[str, str] | None:
    matches = PR_MARKER.findall(pull.get("body") or "")
    return matches[0] if len(matches) == 1 else None


def _owned_pulls(github: GitHub, line: str, base: str, actor: str) -> list[dict[str, Any]]:
    """Select only PRs with our marker, branch shape, base, repository, and file scope."""
    owned = []
    for pull in github.pages("pulls?state=all&per_page=100"):
        marker = _pull_marker(pull)
        head = pull.get("head") or {}
        branch = head.get("ref", "")
        if marker is None or marker[0] != line or _branch_version(branch, line) is None:
            continue
        if (pull.get("base") or {}).get("ref") != base:
            continue
        head_repo = head.get("repo") or {}
        if head_repo and head_repo.get("full_name") != github.repository:
            continue
        if not head_repo and pull.get("state") == "open":
            continue
        if pull.get("state") == "open" and (pull.get("user") or {}).get("login") != actor:
            continue
        files = github.pages(f"pulls/{pull['number']}/files?per_page=100")
        changed = {name for item in files for name in (item.get("filename"), item.get("previous_filename")) if name}
        unexpected = changed - allowed_paths(line)
        if not changed or unexpected:
            details = ", ".join(sorted(unexpected)) if unexpected else "no changed files"
            raise UpdateError(f"Owned Docker PR #{pull['number']} has unexpected files: {details}")
        owned.append(pull)
    return owned


def _body(line: str, version: str, update_type: str) -> str:
    major = version.split(".", maxsplit=1)[0]
    policy = (
        "This patch is eligible for platform auto-merge after all required checks and merge-queue validation."
        if update_type == "patch"
        else "This minor update requires maintainer review; automation does not enable auto-merge."
    )
    return (
        f"<!-- docker-engine-update:{line}:{version} -->\n\n"
        f"Update the existing Docker Engine {line} rootful/rootless images to {version}.\n\n"
        "The official Engine and rootless archives were downloaded and inspected on native AMD64 and ARM64 "
        "runners. This PR updates all four archive hashes, component versions/source revisions, both image "
        "versions, and the generated catalogue together. Runtime, architecture and vulnerability checks "
        "remain required. Archive hashes record the downloaded HTTPS content; they are not upstream signatures.\n\n"
        f"[Upstream release notes](https://docs.docker.com/engine/release-notes/{major}/).\n\n"
        f"{policy}\n\n"
        "The compatibility line, image names and lifecycle policy are retained.\n"
    )


def _metadata_paths(line: str) -> tuple[str, str, str]:
    return (
        f"images/docker/upstream/{line}/payload.yaml",
        f"images/docker/docker-{line}-rootful/container.yaml",
        f"images/docker/docker-{line}-rootless/container.yaml",
    )


def _read_metadata(context: PublishContext, relative: str, ref: str | None = None) -> dict[str, Any]:
    source = (
        _run(["git", "show", f"{ref}:{relative}"], context.root)
        if ref is not None
        else (context.root / relative).read_text(encoding="utf-8")
    )
    data = yaml.safe_load(source)
    if not isinstance(data, dict):
        raise UpdateError(f"Invalid Docker metadata: {relative}")
    return data


def _assert_expected_metadata(
    context: PublishContext, line: str, version: str, ref: str | None = None, base_ref: str | None = None
) -> None:
    """Reproduce the candidate from trusted base YAML and fresh native evidence."""
    with tempfile.TemporaryDirectory(prefix="docker-pr-expected-") as temp:
        expected_root = Path(temp)
        trusted_base = base_ref or f"origin/{context.base}"
        for relative in _metadata_paths(line):
            target = expected_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_run(["git", "show", f"{trusted_base}:{relative}"], context.root), encoding="utf-8")
        apply_release(line, version, context.evidence_root / line, expected_root)
        for relative in _metadata_paths(line):
            expected = yaml.safe_load((expected_root / relative).read_text(encoding="utf-8"))
            if _read_metadata(context, relative, ref) != expected:
                raise UpdateError(f"Docker branch metadata differs from verified release: {relative}")


def _assert_generated_catalogue(context: PublishContext, branch_ref: str) -> None:
    """Require both committed catalogue files to equal deterministic generator output."""
    committed = {path: _run(["git", "show", f"{branch_ref}:{path}"], context.root) for path in CATALOGUE_PATHS}
    _run(
        [
            sys.executable,
            "-m",
            "scripts.maintenance",
            "--json-output",
            CATALOGUE_PATHS[0],
            "--markdown-output",
            CATALOGUE_PATHS[1],
        ],
        context.root,
    )
    for path, expected in committed.items():
        if (context.root / path).read_text(encoding="utf-8").strip() != expected:
            raise UpdateError(f"Docker PR catalogue differs from generated output: {path}")


def _assert_unmanaged_metadata(context: PublishContext, line: str) -> None:
    """Reject contributor changes outside the release scalars before updating an open PR."""
    payload, *images = _metadata_paths(line)
    managed = {
        payload: [
            ("build", "args", "ENGINE_VERSION"),
            *(
                ("build", "architectureArgs", arch, key)
                for arch in ("amd64", "arm64")
                for key in ("ENGINE_SHA256", "ROOTLESS_SHA256")
            ),
            *(
                ("provenance", key)
                for key in ("engineArchive", "rootlessArchive", "engine", "cli", "containerd", "runc", "rootlesskit")
            ),
            *(("provenance", "sourceRevision", key) for key in ("dockerd", "cli", "containerd", "runc")),
        ],
        **{image: [("version",), ("description",)] for image in images},
    }
    for relative, fields in managed.items():
        base = copy.deepcopy(_read_metadata(context, relative, f"origin/{context.base}"))
        candidate = copy.deepcopy(_read_metadata(context, relative))
        for field in fields:
            for data in (base, candidate):
                node = data
                for key in field[:-1]:
                    node = node[key]
                node.pop(field[-1], None)
        if base != candidate:
            raise UpdateError(f"Docker PR has changes outside release fields: {relative}")


def _prepare_branch(context: PublishContext, branch: str, line: str, pull: dict[str, Any] | None) -> bool:
    root, base = context.root, context.base
    if pull is not None:
        _run(["git", "fetch", "origin", f"{branch}:refs/remotes/origin/{branch}"], root)
        _assert_paths(root, line, [f"origin/{base}...origin/{branch}"])
        _run(["git", "switch", "-C", branch, f"origin/{branch}"], root)
        _assert_generated_catalogue(context, f"origin/{branch}")
        # Preserve contributor edits; a conflict fails instead of force-overwriting them.
        _run(["git", "merge", "--no-edit", f"origin/{base}"], root)
        _assert_unmanaged_metadata(context, line)
        return False
    remote = _run(["git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"], root)
    if remote:
        all_pulls = context.github.pages("pulls?state=all&per_page=100")
        if any((item.get("head") or {}).get("ref") == branch for item in all_pulls):
            raise UpdateError(f"Update branch already belongs to another PR: {branch}")
        _run(["git", "fetch", "origin", f"{branch}:refs/remotes/origin/{branch}"], root)
        _assert_paths(root, line, [f"origin/{base}...origin/{branch}"])
        _run(["git", "switch", "-C", branch, f"origin/{branch}"], root)
        _assert_generated_catalogue(context, f"origin/{branch}")
        _run(["git", "merge", "--no-edit", f"origin/{base}"], root)
        return True
    _run(["git", "switch", "-C", branch, f"origin/{base}"], root)
    return False


def _finish_pull(context: PublishContext, pull: dict[str, Any], update_type: str, head_sha: str) -> None:
    assigned = {item.get("login") for item in pull.get("assignees") or []}
    if set(context.assignees) - assigned:
        context.github.request("POST", f"issues/{pull['number']}/assignees", {"assignees": context.assignees})
    if update_type == "minor" and pull.get("auto_merge"):
        _run(
            ["gh", "pr", "merge", str(pull["number"]), "--repo", context.github.repository, "--disable-auto"],
            context.root,
        )
    elif update_type == "patch" and not pull.get("auto_merge"):
        _run(
            [
                "gh",
                "pr",
                "merge",
                str(pull["number"]),
                "--repo",
                context.github.repository,
                "--auto",
                "--squash",
                "--match-head-commit",
                head_sha,
            ],
            context.root,
        )


def _publish_one(context: PublishContext, update: dict[str, str]) -> None:  # noqa: PLR0915
    line, version = update["line"], update["version"]
    allowed_paths(line)
    root, github, base = context.root, context.github, context.base
    owned = _owned_pulls(github, line, base, context.actor)
    if any(pull["state"] == "closed" and _pull_marker(pull)[1] == version for pull in owned):
        sys.stdout.write(f"Docker {line}: closed decision already covers {version}.\n")
        return
    open_pulls = [pull for pull in owned if pull["state"] == "open"]
    if len(open_pulls) > 1:
        raise UpdateError(f"Docker {line} has multiple open automation PRs")
    pull = open_pulls[0] if open_pulls else None
    if pull is not None and _queue_entry(root, github.repository, int(pull["number"])):
        sys.stdout.write(f"Docker {line}: leave the queued candidate unchanged.\n")
        return
    _run(["git", "fetch", "origin", base], root)
    _run(["git", "switch", "--detach", f"origin/{base}"], root)
    current = _current_version(root, line)
    current_parsed, version_parsed = parse_version(current), parse_version(version)
    if current_parsed is not None and version_parsed is not None and current_parsed >= version_parsed:
        sys.stdout.write(f"Docker {line}: main already contains {version} or newer.\n")
        return
    update_type = classify_update(line, current, version)
    if pull is not None and _pull_marker(pull)[1] == version:
        branch = pull["head"]["ref"]
        _run(["git", "fetch", "origin", f"{branch}:refs/remotes/origin/{branch}"], root)
        _assert_paths(root, line, [f"origin/{base}...origin/{branch}"])
        merge_base = _run(["git", "merge-base", f"origin/{base}", f"origin/{branch}"], root)
        _assert_expected_metadata(context, line, version, f"origin/{branch}", merge_base)
        _run(["git", "switch", "-C", branch, f"origin/{branch}"], root)
        _assert_generated_catalogue(context, f"origin/{branch}")
        _finish_pull(context, pull, update_type, pull["head"]["sha"])
        sys.stdout.write(f"Docker {line}: existing PR already covers {version}.\n")
        return
    if pull is not None and update_type == "minor" and pull.get("auto_merge"):
        _run(["gh", "pr", "merge", str(pull["number"]), "--repo", github.repository, "--disable-auto"], root)
        pull["auto_merge"] = None
    branch = pull["head"]["ref"] if pull is not None else f"{BRANCH_PREFIX}{line}-{version}"
    orphan = _prepare_branch(context, branch, line, pull)
    if not orphan:
        _run(
            [
                sys.executable,
                "-m",
                "scripts.docker_release_updates",
                "apply",
                "--line",
                line,
                "--version",
                version,
                "--evidence-dir",
                str(context.evidence_root / line),
            ],
            root,
        )
    _assert_expected_metadata(context, line, version)
    _run(
        [
            sys.executable,
            "-m",
            "scripts.maintenance",
            "--json-output",
            CATALOGUE_PATHS[0],
            "--markdown-output",
            CATALOGUE_PATHS[1],
        ],
        root,
    )
    _run([sys.executable, "-m", "scripts.container_engine", "validate"], root)
    base_sha = _run(["git", "rev-parse", f"origin/{base}"], root)
    _run([sys.executable, "-m", "scripts.container_engine", "validate-versions", "--before", base_sha], root)
    _assert_paths(root, line, [])
    paths = sorted(allowed_paths(line))
    _run(["git", "add", "--", *paths], root)
    commit = ["git", "commit", "-m", f"Update Docker Engine {line} to {version}"]
    if orphan:
        commit.insert(2, "--allow-empty")
    _run(commit, root)
    _run(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "credential.helper=!gh auth git-credential",
            "push",
            "origin",
            f"HEAD:refs/heads/{branch}",
        ],
        root,
    )
    data = {"title": f"Update Docker Engine {line} to {version}", "body": _body(line, version, update_type)}
    if pull is None:
        pull = github.request("POST", "pulls", {**data, "head": branch, "base": base})
    else:
        pull = github.request("PATCH", f"pulls/{pull['number']}", data)
    head = _run(["git", "rev-parse", "HEAD"], root)
    _finish_pull(context, pull, update_type, head)
    sys.stdout.write(f"Proposed {pull['html_url']} ({update_type}; required CI remains enforced).\n")


def publish_updates(root: Path, plan: dict[str, Any], evidence: Path) -> None:
    """Publish only from a trusted default-branch workflow with dedicated credentials."""
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    base = os.environ.get("RELEASE_BASE_BRANCH", "main")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != f"refs/heads/{base}":
        raise UpdateError("PR publication must run in a trusted default-branch GitHub Actions workflow")
    if not os.environ.get("GH_TOKEN"):
        raise UpdateError("RELEASE_AUTOMATION_TOKEN is required to create PRs and enter the merge queue")
    github = GitHub(repository)
    policy = load_policy(root)
    validate_plan(plan)
    _run(["git", "check-ref-format", "--branch", base], root)
    if _run(["git", "status", "--porcelain"], root):
        raise UpdateError("Refusing to change branches in a dirty checkout")
    _run(["git", "config", "user.name", BOT_NAME], root)
    _run(["git", "config", "user.email", BOT_EMAIL], root)
    viewer = json.loads(_run(["gh", "api", "graphql", "-f", "query={viewer{login}}"], root))
    actor = viewer["data"]["viewer"]["login"]
    if not isinstance(actor, str) or not actor:
        raise UpdateError("Cannot identify GitHub credential actor")
    context = PublishContext(root, github, base, evidence, policy["assignees"], actor)
    for update in plan["dockerUpdates"]:
        _publish_one(context, update)


def main() -> int:
    """Consume the current workflow's verified discovery and binary evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        publish_updates(Path(__file__).resolve().parents[1], json.loads(args.plan.read_text()), args.evidence_dir)
    except (UpdateError, KeyError, ValueError, OSError) as exc:
        sys.stderr.write(f"Release PR publication failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
