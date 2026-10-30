"""Produce a bounded unprivileged proof for the separate active root bootstrap.

The producer has no policy authority. The fixed workflow program independently
verifies every Git object and immutable source pin before staging root code.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from scripts import docker_userns_active as diagnostic
from scripts import docker_userns_bootstrap_bundle as git
from scripts import docker_userns_policy_source as source
from scripts.docker_userns_qualification import (
    QualificationError,
    admission_document,
    event_scope,
    selected_manual_ref,
    validate_workflow_context,
    validation_profile,
)

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = "containers-ubuntu26-userns-active"
ADMISSION = ".github/docker-userns-active-admission.json"
CLOSURE = ".github/docker-userns-active-helper-closure.json"
MANIFEST = ".github/docker-userns-policy-source.json"
FILES = (
    "scripts/__init__.py",
    "scripts/docker_userns_active.py",
    "scripts/docker_userns_qualification.py",
    "scripts/docker_runner_security.py",
    "scripts/docker_userns_custody_child.py",
    "scripts/docker_userns_policy_source.py",
    "scripts/docker_userns_custody.py",
    "scripts/docker_userns_hosted.py",
    "scripts/docker_userns_dryparse.py",
    "scripts/runtime_docker_diagnostics.py",
    "scripts/runtime_docker_systemd_guard.py",
    ADMISSION,
    CLOSURE,
    MANIFEST,
)
MAX_BUNDLE = 2 * 1024 * 1024
MAX_EVENT = 262144


def require(value: object) -> None:
    """Refuse the producer without emitting caller-supplied content."""
    if not value:
        reason = "active-bootstrap-bundle-refused"
        raise ValueError(reason)


def _selected_environment_ref(environment: dict[str, str], progress: dict[str, Any] | None) -> None:
    if progress is not None:
        progress["phase"] = "producer-workflow"
    try:
        selected = selected_manual_ref(environment.get("GITHUB_REF"))
    except QualificationError as error:
        reason = "active-bootstrap-producer-refused"
        raise ValueError(reason) from error
    if progress is not None:
        progress["phase"] = "producer-workflow-ref"
    require(environment.get("GITHUB_WORKFLOW_REF") == "Strukturpiloten/containers/.github/workflows/ci.yml@" + selected)


def context(
    environment: dict[str, str], architecture: str, *, progress: dict[str, Any] | None = None
) -> dict[str, str]:
    """Bind only the finite reviewed manual contexts, never a publication caller."""
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "GITHUB_REPOSITORY": "Strukturpiloten/containers",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_JOB": "smoke-build",
        "ImageOS": diagnostic.REPORTED_IMAGE_OS.get(architecture, "ubuntu26"),
    }

    def phase(name: str) -> None:
        if progress is not None:
            progress["phase"] = name

    groups = (
        ("producer-runner-identity", ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS")),
        ("producer-repository", ("GITHUB_REPOSITORY",)),
        ("producer-workflow", ("GITHUB_EVENT_NAME", "GITHUB_JOB")),
        ("producer-image-os", ("ImageOS",)),
    )
    for name, keys in groups:
        phase(name)
        if name == "producer-image-os":
            image_os = environment.get("ImageOS")
            phase(
                {
                    None: "producer-image-os-missing",
                    "": "producer-image-os-empty",
                    "ubuntu20": "producer-image-os-ubuntu20",
                    "ubuntu22": "producer-image-os-ubuntu22",
                    "ubuntu24": "producer-image-os-ubuntu24",
                    "ubuntu26": "producer-image-os-ubuntu26",
                    "ubuntu20-arm": "producer-image-os-ubuntu20-arm",
                    "ubuntu22-arm": "producer-image-os-ubuntu22-arm",
                    "ubuntu24-arm": "producer-image-os-ubuntu24-arm",
                    "ubuntu26-arm": "producer-image-os-ubuntu26-arm",
                    "ubuntu20-arm64": "producer-image-os-ubuntu20-arm64",
                    "ubuntu22-arm64": "producer-image-os-ubuntu22-arm64",
                    "ubuntu24-arm64": "producer-image-os-ubuntu24-arm64",
                    "ubuntu26-arm64": "producer-image-os-ubuntu26-arm64",
                }.get(image_os, "producer-image-os-other")
            )
            require(image_os == expected["ImageOS"])
        else:
            require(all(environment.get(key) == expected[key] for key in keys))
    _selected_environment_ref(environment, progress)
    phase("producer-architecture")
    require(architecture in {"amd64", "arm64"})
    require(environment.get("RUNNER_ARCH") == {"amd64": "X64", "arm64": "ARM64"}[architecture])
    phase("producer-candidate")
    selected = environment.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", selected) and environment.get("GITHUB_WORKFLOW_SHA") == selected)
    phase("producer-run-attempt")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")))
    phase("producer-image-version")
    version = environment.get("ImageVersion", "")
    require(re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", version))
    if progress is not None:
        progress["context"] = {
            "candidate": selected,
            "run": environment["GITHUB_RUN_ID"],
            "attempt": environment["GITHUB_RUN_ATTEMPT"],
            "job": expected["GITHUB_JOB"],
            "image": "docker-29-conformance-rootless",
            "architecture": architecture,
        }
    phase("producer-event-path")
    event_path = Path("/home/runner/work/_temp/_github_workflow/event.json")
    require(environment.get("GITHUB_EVENT_PATH") == str(event_path))
    phase("producer-event-read")
    with event_path.open("rb") as stream:
        raw = stream.read(MAX_EVENT + 1)
    require(len(raw) <= MAX_EVENT)
    event = json.loads(raw, object_pairs_hook=source.unique_object)
    require(type(event) is dict and type(event.get("inputs", {})) is dict)
    phase("producer-choice")
    requested = event.get("inputs", {}).get("validation_profile", "full")
    canonical = validation_profile(requested)
    purpose, selected_ref = event_scope(event)
    phase("producer-workflow")
    require(environment.get("GITHUB_REF") == selected_ref)
    phase("producer-workflow-ref")
    workflow_ref = "Strukturpiloten/containers/.github/workflows/ci.yml@" + selected_ref
    require(environment.get("GITHUB_WORKFLOW_REF") == workflow_ref)
    phase("producer-choice")
    admission_raw = (ROOT / ADMISSION).read_bytes()
    admission = admission_document(admission_raw)
    result = {
        "candidate": selected,
        "workflow": selected,
        "checkout": selected,
        "repository": expected["GITHUB_REPOSITORY"],
        "event": "workflow_dispatch",
        "ref": selected_ref,
        "workflowRef": workflow_ref,
        "job": expected["GITHUB_JOB"],
        "run": environment["GITHUB_RUN_ID"],
        "attempt": environment["GITHUB_RUN_ATTEMPT"],
        "architecture": architecture,
        "image": "docker-29-conformance-rootless",
        "imageOS": expected["ImageOS"],
        "imageVersion": version,
        "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
        "validationProfile": canonical,
        "validationProfileRequested": requested,
        "purpose": purpose,
        "admissionRevision": admission["revision"],
        "admissionSha256": hashlib.sha256(admission_raw).hexdigest(),
    }
    validate_workflow_context(result, admission, result["admissionSha256"])
    return result


def proof(candidate: str) -> list[dict[str, str]]:
    """Reuse only finite raw Git readers; connect the new exact closure independently."""
    objects: dict[str, tuple[str, bytes]] = {}

    def get(kind: str, identifier: str) -> bytes:
        if identifier not in objects:
            objects[identifier] = (kind, git.git_object(kind, identifier))
        require(objects[identifier][0] == kind)
        return objects[identifier][1]

    commit = get("commit", candidate)
    header = commit.split(b"\n", 1)[0]
    require(re.fullmatch(rb"tree [0-9a-f]{40}", header))
    for path in FILES:
        current = header[5:].decode("ascii")
        parts = path.split("/")
        for index, name in enumerate(parts):
            mode, identifier = git.tree_entries(get("tree", current))[name]
            if index == len(parts) - 1:
                require(mode == "100644")
                get("blob", identifier)
            else:
                require(mode == "40000")
                current = identifier
    return [{"oid": oid, "kind": kind, "data": base64.b64encode(raw).decode()} for oid, (kind, raw) in objects.items()]


def bundle(architecture: str, *, progress: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect source bytes without root execution or policy compilation/loading."""
    progress = {} if progress is None else progress
    require(os.geteuid() != 0)
    binding = context(dict(os.environ), architecture, progress=progress)
    progress.update(context=binding, phase="producer-source")
    manifest = source.manifest(ROOT / MANIFEST)
    sdk = {}
    deadline = time.monotonic() + 30
    for item in manifest["source"]["files"]:
        raw = source.fetch(manifest["source"]["commit"], item["path"], item["size"], deadline)
        require(len(raw) == item["size"] and hashlib.sha256(raw).hexdigest() == item["sha256"])
        sdk[item["path"]] = base64.b64encode(raw).decode()
    diagnostic.comparison(progress, "producer-source", matched=True)
    progress["phase"] = "producer-proof"
    objects = proof(binding["candidate"])
    diagnostic.comparison(progress, "producer-proof", matched=True)
    return {
        "schemaVersion": 2,
        "consumer": CONSUMER,
        "context": binding,
        "objects": objects,
        "sdk": sdk,
    }


def main() -> int:
    """Write one exclusive bounded handoff; no bootstrap or mutation occurs here."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-output", type=Path)
    arguments = parser.parse_args()
    progress: dict[str, Any] = {"actor": "producer", "operation": "producer", "phase": "producer-context"}
    try:
        encoded = (json.dumps(bundle(arguments.architecture, progress=progress), sort_keys=True) + "\n").encode("ascii")
        progress["phase"] = "producer-output"
        require(len(encoded) <= MAX_BUNDLE)
        descriptor = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
    except (OSError, ValueError, KeyError, TypeError, QualificationError, diagnostic.RefusedError) as error:
        raw = diagnostic.encoded(diagnostic.failure_receipt(progress, error))
        if arguments.failure_output is not None:
            with suppress(OSError):
                arguments.failure_output.write_bytes(raw)
        sys.stdout.buffer.write(raw)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
