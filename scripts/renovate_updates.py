"""Complete generated files using trusted code and Renovate PR data only."""

# Errors intentionally omit subprocess stderr and credentials.
# ruff: noqa: TRY003, EM101, EM102, SLF001
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import yaml

from scripts import container_engine as engine
from scripts.maintenance import catalogue, markdown_catalogue
from scripts.metadata_schema import validate_metadata_schema
from scripts.release_notifications import GitHub
from scripts.workflow_config import load_config

SHA = re.compile(r"[a-f0-9]{40}\Z")
BRANCH = re.compile(r"renovate/[A-Za-z0-9_./-]+\Z")
TEMPLATE = re.compile(r"\.github/workflow-templates/[A-Za-z0-9_-]+\.yml\.j2\Z")
METADATA = re.compile(r"images/(?:[A-Za-z0-9_.-]+/)+container\.yaml\Z")
ACTION = re.compile(
    r"uses:[ \t]*(?P<name>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[a-f0-9]{40})"
    r"[ \t]+#[ \t]*(?P<tag>v?\d+(?:\.\d+){0,2})(?=[ \t]*(?:\n|$))"
)
CONFIG = ".github/automation.yml"
CATALOGUE = ("docs/image-catalogue.json", "docs/image-catalogue.md")
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
MAX_BLOB_SIZE = 1_000_000


class RepairError(RuntimeError):
    """A PR cannot be completed within the trusted regeneration boundary."""


def _run(root: Path, arguments: list[str], *, data: str | None = None, env: dict | None = None) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            arguments,
            cwd=root,
            input=data,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepairError(f"Could not run {arguments[0]}") from exc
    if result.returncode:
        raise RepairError(f"{arguments[0]} {arguments[1]} failed (exit {result.returncode})")
    return result.stdout


def _git(root: Path, *arguments: str, data: str | None = None, env: dict | None = None) -> str:
    return _run(
        root,
        ["git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential", *arguments],
        data=data,
        env=env,
    )


def _tree(root: Path, revision: str) -> dict[str, tuple[str, str]]:
    if not SHA.fullmatch(revision):
        raise RepairError("Expected an immutable Git revision")
    entries = {}
    for entry in _git(root, "ls-tree", "-rz", "--full-tree", revision).split("\0"):
        if entry:
            attributes, path = entry.split("\t", 1)
            mode, kind, oid = attributes.split()
            entries[path] = (mode if kind == "blob" else kind, oid)
    return entries


def _read(root: Path, tree: dict[str, tuple[str, str]], path: str) -> str:
    if path not in tree or tree[path][0] != "100644":
        raise RepairError(f"Expected a regular tracked file: {path}")
    text = _git(root, "cat-file", "blob", tree[path][1])
    if len(text) > MAX_BLOB_SIZE:
        raise RepairError(f"Regeneration input is too large: {path}")
    return text


def _normal_actions(text: str) -> str:
    return ACTION.sub(lambda match: f"uses: {match['name']}@PIN # VERSION", text)


def _action_updates(before: str, after: str, updates: dict) -> None:
    old, new = list(ACTION.finditer(before)), list(ACTION.finditer(after))
    if [match["name"] for match in old] != [match["name"] for match in new]:
        return
    for previous, candidate in zip(old, new, strict=True):
        key = (previous["name"], previous["sha"], previous["tag"])
        value = (candidate["sha"], candidate["tag"])
        if key[1:] != value:
            if key in updates and updates[key] != value:
                existing = updates[key]
                old_parts = existing[1].removeprefix("v").split(".")
                new_parts = value[1].removeprefix("v").split(".")
                shared = min(len(old_parts), len(new_parts))
                if existing[0] != value[0] or old_parts[:shared] != new_parts[:shared]:
                    raise RepairError(f"Conflicting action updates for {key[0]}")
                value = existing if len(old_parts) >= len(new_parts) else value
            updates[key] = value


def _update_actions(text: str, updates: dict) -> str:
    def replace(match: re.Match) -> str:
        update = updates.get((match["name"], match["sha"], match["tag"]))
        if update is None:
            return match[0]
        return match[0].replace(match["sha"], update[0]).removesuffix(match["tag"]) + update[1]

    return ACTION.sub(replace, text)


def _python_configuration(root: Path, before: dict, head: dict) -> tuple[str, dict[str, str]]:
    text = _read(root, head, CONFIG)
    old_requirement = tomllib.loads(_read(root, before, "pyproject.toml"))["project"]["requires-python"]
    requirement = tomllib.loads(_read(root, head, "pyproject.toml"))["project"]["requires-python"]
    if requirement != old_requirement:
        match = re.fullmatch(r">=(\d+)\.(\d+),<(\d+)\.(\d+)", requirement)
        if not match or (int(match[3]), int(match[4])) != (int(match[1]), int(match[2]) + 1):
            raise RepairError("Python migration requires one explicit supported minor line")
        version = f"{match[1]}.{match[2]}"
        if tomllib.loads(_read(root, head, "uv.lock")).get("requires-python") != f"=={version}.*":
            raise RepairError("Python migration requires a matching lockfile")
        text, count = re.subn(r"(?m)^PYTHON_VERSION:[^\n]*$", f'PYTHON_VERSION: "{version}"', text)
        if count != 1:
            raise RepairError("Python migration requires one canonical interpreter pin")
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        path = temporary / CONFIG
        path.parent.mkdir()
        path.write_text(text, encoding="utf-8")
        config = load_config(temporary)
    if not requirement.startswith(f">={config['PYTHON_VERSION']},"):
        raise RepairError("Canonical Python runtime does not match project requirement")
    return text, config


def generated_changes(root: Path, base: str, head_sha: str) -> dict[str, str]:
    """Render data from an immutable PR, never importing or checking out its code.

    ``base`` must be its merge base with the trusted default branch. PR templates
    must equal that trusted ancestor except for literal action commit/tag pins.
    """
    before, head = _tree(root, base), _tree(root, head_sha)
    templates = sorted(path for path in head if TEMPLATE.fullmatch(path))
    if not templates or set(templates) != {path for path in before if TEMPLATE.fullmatch(path)}:
        raise RepairError("Renovate must not add or remove workflow templates")
    updates: dict = {}
    sources = {}
    for path in templates:
        old, new = _read(root, before, path), _read(root, head, path)
        if _normal_actions(old) != _normal_actions(new):
            raise RepairError(f"Workflow template has changes beyond action pins: {path}")
        sources[path] = new
        _action_updates(old, new, updates)
        output = path.replace("/workflow-templates/", "/workflows/").removesuffix(".j2")
        if output in before and output in head:
            _action_updates(_read(root, before, output), _read(root, head, output), updates)
    images = []
    for path in sorted(head):
        if METADATA.fullmatch(path) and "_example" not in Path(path).parts:
            image = yaml.safe_load(_read(root, head, path))
            if not isinstance(image, dict):
                raise RepairError(f"Expected image metadata mapping: {path}")
            validate_metadata_schema(image, schema_path=root / "container.schema.json", display_path=path)
            images.append({**image, "metadataFile": path})
    if not images:
        raise RepairError("No image metadata found")
    config_text, config = _python_configuration(root, before, head)
    changes = {CONFIG: config_text}
    stage_count = engine._stage_count(images)
    environment = engine._workflow_environment()
    for path, original_source in sources.items():
        source = _update_actions(original_source, updates)
        changes[path] = source
        output = path.replace("/workflow-templates/", "/workflows/").removesuffix(".j2")
        changes[output] = environment.from_string(source).render(
            stages=list(range(stage_count)),
            single_stage=stage_count == 1,
            config=config,
        )
    report = catalogue(images)
    changes[CATALOGUE[0]] = json.dumps(report, indent=2, sort_keys=True) + "\n"
    changes[CATALOGUE[1]] = markdown_catalogue(report)
    return {path: value for path, value in changes.items() if path not in head or value != _read(root, head, path)}


def eligible(pull: dict, repository: str, default_branch: str) -> bool:
    """Require an open, same-repository Renovate bot PR into the default branch."""
    head = pull.get("head", {})
    return (
        pull.get("state") == "open"
        and not pull.get("draft")
        and pull.get("user", {}).get("login") == "renovate[bot]"
        and pull.get("user", {}).get("type") == "Bot"
        and pull.get("base", {}).get("ref") == default_branch
        and head.get("repo", {}).get("full_name", "").lower() == repository.lower()
        and bool(BRANCH.fullmatch(head.get("ref", "")))
        and bool(SHA.fullmatch(head.get("sha", "")))
    )


def _queued(root: Path, repository: str, number: int) -> bool:
    owner, name = repository.split("/")
    query = (
        "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name)"
        "{pullRequest(number:$number){mergeQueueEntry{id}}}}"
    )
    response = json.loads(
        _run(
            root,
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
        )
    )
    if response.get("errors"):
        raise RepairError("Could not verify merge queue membership")
    return response["data"]["repository"]["pullRequest"]["mergeQueueEntry"] is not None


def _commit(
    root: Path,
    head: str,
    changes: dict[str, str],
    *,
    merged: str | None = None,
    default_head: str | None = None,
) -> str:
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(directory) / "index")}
        _git(root, "read-tree", merged or head, env=env)
        for path, text in sorted(changes.items()):
            oid = _git(root, "hash-object", "-w", "--stdin", data=text).strip()
            _git(root, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}", env=env)
        tree = _git(root, "write-tree", env=env).strip()
        env.update(
            {
                "GIT_AUTHOR_NAME": BOT_NAME,
                "GIT_AUTHOR_EMAIL": BOT_EMAIL,
                "GIT_COMMITTER_NAME": BOT_NAME,
                "GIT_COMMITTER_EMAIL": BOT_EMAIL,
            }
        )
        parents = ["-p", head]
        if default_head and default_head != head:
            parents.extend(["-p", default_head])
        return _git(
            root, "commit-tree", tree, *parents, data="fix: synchronize generated Renovate files\n", env=env
        ).strip()


def _report(message: str) -> None:
    sys.stdout.write(message + "\n")


def _merge_snapshot(root: Path, head: str, default_head: str) -> str | None:
    """Merge data without a checkout, hooks, filters, or PR code execution."""
    git = shutil.which("git")
    if git is None:
        raise RepairError("Git is required to compute the PR merge tree")
    result = subprocess.run(  # noqa: S603 - fixed host Git command, no PR programs
        [git, "merge-tree", "--write-tree", "--name-only", head, default_head],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode == 1:
        return None
    if result.returncode:
        raise RepairError("Could not compute the PR merge tree")
    tree = result.stdout.splitlines()[0]
    if not SHA.fullmatch(tree):
        raise RepairError("Invalid PR merge tree")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": BOT_NAME,
        "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME,
        "GIT_COMMITTER_EMAIL": BOT_EMAIL,
    }
    return _git(
        root,
        "commit-tree",
        tree,
        "-p",
        head,
        "-p",
        default_head,
        data="Preview Renovate merge for trusted generators\n",
        env=env,
    ).strip()


def _request_rebase(github: GitHub, default_branch: str, pull: dict) -> None:
    """Use Renovate's own retry checkbox only when a real merge conflicts."""
    number = pull["number"]
    current = github.request("GET", f"pulls/{number}")
    if not eligible(current, github.repository, default_branch) or current["head"]["sha"] != pull["head"]["sha"]:
        _report(f"PR #{number}: state changed; defer the rebase request.")
        return
    body = current.get("body") or ""
    updated, count = re.subn(r"(?m)^(\s*- )\[ \]( <!-- rebase-check -->)", r"\1[x]\2", body)
    if count:
        github.request("PATCH", f"pulls/{number}", {"body": updated})
    elif "[x] <!-- rebase-check -->" not in body:
        raise RepairError("Renovate rebase checkbox is missing")
    _report(f"PR #{number}: merge conflict; requested Renovate's own rebase/retry.")


def _push_completion(root: Path, github: GitHub, pull: dict, commit: str, paths: list[str]) -> None:
    number, head, branch = pull["number"], pull["head"]["sha"], pull["head"]["ref"]
    try:
        _git(root, "push", f"--force-with-lease=refs/heads/{branch}:{head}", "origin", f"{commit}:refs/heads/{branch}")
    except RepairError:
        if github.request("GET", f"pulls/{number}")["head"]["sha"] == head:
            raise RepairError("Completion push failed; verify the bot's Contents and Workflows write access") from None
        _report(f"PR #{number}: concurrent update won the push; defer to the next event.")
    else:
        _report(f"PR #{number}: completed {', '.join(paths)}; normal CI will run on {commit}.")


def _ready_pull(root: Path, github: GitHub, default_branch: str, pull: dict) -> bool:
    if not eligible(pull, github.repository, default_branch):
        return False
    number, head, branch = pull["number"], pull["head"]["sha"], pull["head"]["ref"]
    if _queued(root, github.repository, number):
        _report(f"PR #{number}: already queued; left unchanged.")
        return False
    _git(root, "check-ref-format", f"refs/heads/{branch}")
    _git(root, "fetch", "--no-tags", "origin", f"refs/heads/{branch}")
    if _git(root, "rev-parse", "FETCH_HEAD").strip() != head:
        _report(f"PR #{number}: branch changed; defer to the next event.")
        return False
    login = pull["user"]["login"]
    bot_authors = {
        BOT_EMAIL,
        f"{login}@users.noreply.github.com",
        f"{pull['user']['id']}+{login}@users.noreply.github.com",
    }
    authors = set(_git(root, "log", "--format=%ae", f"origin/{default_branch}..{head}").splitlines())
    if not authors <= bot_authors:
        _report(f"PR #{number}: custom commits present; left unchanged.")
        return False
    return True


def repair_pull(root: Path, github: GitHub, default_branch: str, pull: dict) -> None:
    """Append an idempotent, lease-guarded completion commit to one eligible PR."""
    if not _ready_pull(root, github, default_branch, pull):
        return
    number, head = pull["number"], pull["head"]["sha"]
    default_head = _git(root, "rev-parse", f"origin/{default_branch}").strip()
    merged = _merge_snapshot(root, head, default_head)
    if merged is None:
        if not _queued(root, github.repository, number):
            _request_rebase(github, default_branch, pull)
        return
    changes = generated_changes(root, default_head, merged)
    if not changes:
        _report(f"PR #{number}: generated files already match.")
        return
    current = github.request("GET", f"pulls/{number}")
    if (
        not eligible(current, github.repository, default_branch)
        or current["head"]["sha"] != head
        or _queued(root, github.repository, number)
    ):
        _report(f"PR #{number}: state changed; defer to the next event.")
        return
    commit = _commit(root, head, changes, merged=merged, default_head=default_head)
    _push_completion(root, github, pull, commit, sorted(changes))


def main() -> int:
    """Run only from a trusted default-branch Actions workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull-request", type=int)
    arguments = parser.parse_args()
    github = GitHub(os.environ.get("GITHUB_REPOSITORY", ""))
    default_branch = os.environ.get("DEFAULT_BRANCH", "")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or not default_branch
        or os.environ.get("GITHUB_REF") != f"refs/heads/{default_branch}"
        or os.environ.get("GITHUB_EVENT_NAME") not in {"pull_request_target", "schedule", "workflow_dispatch"}
    ):
        raise RepairError("Regeneration requires a trusted default-branch workflow")
    root = Path(__file__).resolve().parents[1]
    _git(root, "fetch", "--no-tags", "origin", f"refs/heads/{default_branch}:refs/remotes/origin/{default_branch}")
    _git(root, "merge-base", "--is-ancestor", "HEAD", f"origin/{default_branch}")
    pulls = (
        [github.request("GET", f"pulls/{arguments.pull_request}")]
        if arguments.pull_request
        else github.pages(f"pulls?state=open&base={default_branch}&per_page=100")
    )
    failed = False
    for pull in pulls:
        try:
            repair_pull(root, github, default_branch, pull)
        except (RepairError, ValueError) as exc:
            sys.stderr.write(f"::error::PR #{pull['number']}: {exc}\n")
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
