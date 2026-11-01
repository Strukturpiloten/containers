"""Construct and independently check the exact nonqualifying manual pair plan."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import TYPE_CHECKING

from scripts import build_payloads, container_engine
from scripts import docker_direct_startup_contract as contract

if TYPE_CHECKING:
    from scripts.ci_validation_scope import Context


def declarations() -> list[dict]:
    """Require actual direct declarations and canonical payload ownership."""
    loaded = {image["name"]: image for image in container_engine._load_images()}  # noqa: SLF001 - reuse canonical declarations and normalization.
    result = []
    for name, architecture in contract.ROWS:
        image = loaded[name]
        series = name.removeprefix("docker-").removesuffix("-rootless")
        path = "images/docker/upstream/" + series + "/payload.yaml"
        contract.require(
            image["tests"] == {"docker": {"mode": "rootless", "outerPrivilege": "privileged", "nestedRuntime": True}}
        )
        contract.require(image["dependencies"]["internal"] == [])
        contract.require(image["build"]["architectures"] == ["amd64", "arm64"])
        contract.require(image["build"]["payload"] == path)
        manifest = build_payloads.load_manifest(container_engine._repo_root(), path)  # noqa: SLF001 - reuse canonical declarations and normalization.
        contract.require(manifest["name"] == "docker-" + series + "-payload")
        contract.require(
            manifest["build"]["architectures"] == ["amd64", "arm64"]
            and architecture in manifest["build"]["architectures"]
        )
        result.append(container_engine._normalize_image(image, 0))  # noqa: SLF001 - reuse canonical declarations and normalization.
    return result


def expected_versions(image: str) -> dict[str, str]:
    """Read canonical payload versions; never maintain duplicate software pins."""
    contract.require(type(image) is str and image in {name for name, _architecture in contract.ROWS})
    series = image.removeprefix("docker-").removesuffix("-rootless")
    manifest = build_payloads.load_manifest(
        container_engine._repo_root(),  # noqa: SLF001 - canonical repository root.
        "images/docker/upstream/" + series + "/payload.yaml",
    )
    return {
        "rootlesskitVersion": manifest["provenance"]["rootlesskit"],
        "engineVersion": manifest["provenance"]["engine"],
    }


def build_plan(context: Context) -> dict:
    """Select no reverse dependencies or architectures beyond the two reviewed rows."""
    contract.require(context.event_name == "workflow_dispatch" and context.ref_name == contract.BRANCH)
    contract.require(context.selected_profile == contract.PROFILE and context.default_branch == "main")
    contract.require(
        type(context.source_revision) is str and re.fullmatch(r"[0-9a-f]{40}", context.source_revision) is not None
    )
    contract.require(context.source_revision != "0" * 40)
    images = declarations()
    smoke = []
    payloads = []
    for (name, architecture), image in zip(contract.ROWS, images, strict=True):
        series = name.removeprefix("docker-").removesuffix("-rootless")
        payload = "docker-" + series + "-payload"
        smoke.append(
            {
                "name": name,
                "arch": architecture,
                "runner": container_engine.RUNNERS[architecture],
                "stage": 0,
                "payloadName": payload,
            }
        )
        payloads.append(
            {
                "name": payload,
                "arch": architecture,
                "runner": container_engine.RUNNERS[architecture],
                "manifest": image["build"]["payload"],
            }
        )
    stages = [
        {
            "buildMatrix": {"include": smoke},
            "publishMatrix": {
                "include": [{"name": row["name"], "stage": 0, "buildMatrix": {"include": [row]}} for row in smoke]
            },
        }
    ]
    count = container_engine._stage_count(container_engine._load_images())  # noqa: SLF001 - canonical stage count.
    stages.extend({"buildMatrix": {"include": []}, "publishMatrix": {"include": []}} for _stage in range(1, count))
    return {
        "schemaVersion": 1,
        "eventName": context.event_name,
        "refName": context.ref_name,
        "defaultBranch": context.default_branch,
        "sourceRevision": context.source_revision,
        "hasImages": True,
        "levels": [[name for name, _architecture in contract.ROWS]],
        "images": images,
        "smokeBuildMatrix": {"include": smoke},
        "stageMatrices": stages,
        "payloadMatrix": {"include": payloads},
        "selection": {
            "scope": contract.PURPOSE,
            "target": "",
            "reason": "manual nonqualifying direct startup pair",
            "changedFiles": [],
            "directImages": [name for name, _architecture in contract.ROWS],
            "reverseDependencies": [],
            "noCache": True,
        },
        "validationProfile": contract.PROFILE,
        "purpose": contract.PURPOSE,
        "qualification": "none",
    }


def validate_plan(plan: dict, context: Context) -> None:
    """Refuse every missing, widened, reordered, relabelled or unknown plan field."""
    # Canonical bytes also distinguish Boolean-as-integer fields.
    contract.require(contract.canonical(plan) == contract.canonical(build_plan(context)))


def main() -> None:
    """Write one exact manual plan before matrix outputs can be published."""
    from scripts.ci_validation_scope import Context  # noqa: PLC0415 - avoid a module-cycle at import time.

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    for field in ("event-name", "ref-name", "source-revision", "default-branch"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    context = Context(
        args.event_name, contract.PROFILE, contract.PROFILE, args.ref_name, args.source_revision, args.default_branch
    )
    plan = build_plan(context)
    args.output.write_bytes(contract.canonical(plan) + b"\n")


if __name__ == "__main__":
    main()
