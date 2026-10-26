"""Unprivileged bounded Git-object proof and pinned SDK handoff; never a root entry point."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from scripts import docker_userns_policy_source as source

ROOT = Path(__file__).resolve().parents[1]
CLOSURE = ".github/docker-userns-helper-closure.json"
ADMISSION = ".github/docker-userns-unused-admission.json"
MANIFEST = ".github/docker-userns-policy-source.json"
FILES = (
    "scripts/__init__.py",
    "scripts/docker_userns_custody.py",
    "scripts/docker_userns_custody_child.py",
    "scripts/docker_userns_hosted.py",
    "scripts/docker_userns_policy_source.py",
    CLOSURE,
    ADMISSION,
    MANIFEST,
)
MAX_OBJECT = 262144
MAX_EVENT = 262144
MAX_BUDGET = 64
PULL_REQUEST = 492
MAX_BUNDLE = 2 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")


def need(value: object) -> None:
    """Refuse a malformed unprivileged handoff without exposing raw inputs."""
    if not value:
        reason = "unused-bundle-refused"
        raise ValueError(reason)


def git_object(kind: str, identifier: str) -> bytes:
    """Read one finite raw object through the existing checkout's unprivileged Git."""
    need(kind in {"commit", "tree", "blob"} and COMMIT.fullmatch(identifier))
    env = {
        **source.ENVIRONMENT,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    command = ["/usr/bin/git", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "cat-file"]
    size = subprocess.run(  # noqa: S603 - fixed unprivileged Git object reader.
        [*command, "-s", identifier], cwd=ROOT, env=env, capture_output=True, timeout=3, check=True
    ).stdout
    need(size.strip().isdigit() and 0 < int(size) <= MAX_OBJECT)
    raw = subprocess.run(  # noqa: S603 - fixed unprivileged Git object reader.
        [*command, kind, identifier], cwd=ROOT, env=env, capture_output=True, timeout=3, check=True
    ).stdout
    need(
        len(raw) == int(size)
        and hashlib.sha1(
            kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw,
            usedforsecurity=False,
        ).hexdigest()
        == identifier
    )
    return raw


def tree_entries(raw: bytes) -> dict[str, tuple[str, str]]:
    """Decode only Git's finite binary tree framing, retaining modes for the verifier."""
    result = {}
    offset = 0
    while offset < len(raw):
        end = raw.index(b"\0", offset)
        mode, name = raw[offset:end].split(b" ", 1)
        need(end + 21 <= len(raw))
        decoded = name.decode("utf-8", "strict")
        need(decoded not in result and decoded not in {"", ".", ".."} and "/" not in decoded)
        result[decoded] = (mode.decode("ascii"), raw[end + 1 : end + 21].hex())
        offset = end + 21
    need(offset == len(raw))
    return result


def proof(candidate: str) -> list[dict[str, str]]:
    """Collect exactly the connected commit/tree/blob closure needed by bootstrap."""
    objects: dict[str, tuple[str, bytes]] = {}

    def get(kind: str, identifier: str) -> bytes:
        if identifier not in objects:
            objects[identifier] = (kind, git_object(kind, identifier))
        need(objects[identifier][0] == kind)
        return objects[identifier][1]

    commit = get("commit", candidate)
    tree = commit.split(b"\n", 1)[0]
    need(re.fullmatch(rb"tree [0-9a-f]{40}", tree))
    root = tree[5:].decode("ascii")
    for path in FILES:
        current = root
        components = path.split("/")
        for index, name in enumerate(components):
            mode, identifier = tree_entries(get("tree", current))[name]
            if index + 1 == len(components):
                need(mode == "100644")
                get("blob", identifier)
            else:
                need(mode == "40000")
                current = identifier
    return [
        {"oid": identifier, "kind": kind, "data": base64.b64encode(raw).decode("ascii")}
        for identifier, (kind, raw) in objects.items()
    ]


def context(environment: dict[str, str]) -> dict[str, Any]:
    """Bind the fixed same-repository PR merge job and bounded checked event data."""
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "ImageOS": "ubuntu26",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "Strukturpiloten/containers",
        "GITHUB_REF": "refs/pull/492/merge",
        "GITHUB_JOB": "userns-custody-unused",
        "GITHUB_WORKFLOW_REF": "Strukturpiloten/containers/.github/workflows/ci.yml@refs/pull/492/merge",
    }
    need(all(environment.get(key) == value for key, value in expected.items()))
    candidate = environment.get("GITHUB_SHA", "")
    need(COMMIT.fullmatch(candidate) and environment.get("GITHUB_WORKFLOW_SHA") == candidate)
    event_path = Path("/home/runner/work/_temp/_github_workflow/event.json")
    need(environment.get("GITHUB_EVENT_PATH") == str(event_path))
    with event_path.open("rb") as stream:
        raw = stream.read(MAX_EVENT + 1)
    need(len(raw) <= MAX_EVENT)
    event = json.loads(raw, object_pairs_hook=source.unique_object)
    pr = event["pull_request"]
    need(
        event["number"] == PULL_REQUEST
        and pr["number"] == PULL_REQUEST
        and pr["head"]["ref"] == "TheRealBecks/issue442-main-reconciled"
    )
    need(all(pr[side]["repo"]["full_name"] == "Strukturpiloten/containers" for side in ("head", "base")))
    head, base = pr["head"]["sha"], pr["base"]["sha"]
    need(COMMIT.fullmatch(head) and COMMIT.fullmatch(base))
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        need(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")))
    with Path("/home/runner/work/_temp/docker-userns-custody-deadline").open("rb") as stream:
        budget = stream.read(MAX_BUDGET + 1)
    need(len(budget) <= MAX_BUDGET and re.fullmatch(rb"[1-9][0-9]{0,19}\n", budget))
    need(time.monotonic_ns() < int(budget))
    return {
        "candidate": candidate,
        "deadlineNs": int(budget),
        "workflow": environment["GITHUB_WORKFLOW_SHA"],
        "checkout": candidate,
        "repository": "Strukturpiloten/containers",
        "job": "userns-custody-unused",
        "checkoutIdentity": "github-pr-merge",
        "head": head,
        "base": base,
        "run": environment["GITHUB_RUN_ID"],
        "attempt": environment["GITHUB_RUN_ATTEMPT"],
        "imageOS": "ubuntu26",
        "imageVersion": environment["ImageVersion"],
    }


def main() -> int:
    """Create one finite handoff and fetch only the existing manifest's SDK closure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    need(os.geteuid() != 0)
    observed = context(dict(os.environ))
    checkout = subprocess.run(
        ["/usr/bin/git", "--no-pager", "--no-replace-objects", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        env={
            **source.ENVIRONMENT,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
        },
        capture_output=True,
        timeout=3,
        check=True,
    ).stdout
    need(checkout == (observed["candidate"] + "\n").encode("ascii"))
    observed["checkout"] = checkout.strip().decode("ascii")
    manifest = source.manifest()
    deadline = time.monotonic() + 12
    sources = []
    for item in manifest["source"]["files"]:
        raw = source.fetch(manifest["source"]["commit"], item["path"], item["size"], deadline)
        need(len(raw) == item["size"] and hashlib.sha256(raw).hexdigest() == item["sha256"])
        sources.append({"path": item["path"], "data": base64.b64encode(raw).decode("ascii")})
    value = {"schemaVersion": 1, "context": observed, "objects": proof(observed["candidate"]), "sources": sources}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    need(len(raw) <= MAX_BUNDLE)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
