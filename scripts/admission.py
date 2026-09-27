"""Resolve declared lifecycle policy for architecture build and scan jobs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from scripts import container_engine
from scripts.maintenance import lifecycle_for


class AdmissionError(ValueError):
    """Image metadata cannot support a publication admission decision."""


def image_policy(name: str, architecture: str) -> dict[str, Any]:
    """Return registry and lifecycle admission values from validated repository metadata."""
    images = container_engine._load_images()  # noqa: SLF001
    container_engine._validate_images(images)  # noqa: SLF001
    matches = [image for image in images if image["name"] == name]
    if len(matches) != 1:
        msg = f"Expected exactly one metadata record for {name}."
        raise AdmissionError(msg)
    image = matches[0]
    if architecture not in image["build"]["architectures"]:
        msg = f"Architecture {architecture} is not declared for {name}."
        raise AdmissionError(msg)
    lifecycle = lifecycle_for(image)
    if lifecycle["admission"] == "unknown" or len(lifecycle["requiredRuntimeProfiles"]) != 1:
        msg = f"{name} needs explicit admission and one required runtime profile."
        raise AdmissionError(msg)
    image_ref = str(image["image"])
    return {
        "name": name,
        "image": image_ref,
        "architecture": architecture,
        "version": str(image["version"]).removeprefix("v"),
        "admission": lifecycle["admission"],
        "requiredRuntimeProfile": lifecycle["requiredRuntimeProfiles"][0],
        "baselineRef": f"{image_ref}:latest",
    }


def main() -> None:
    """Write trusted scan configuration and optional GitHub step outputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    policy = image_policy(args.name, args.architecture)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    source_revision = plan.get("sourceRevision") if isinstance(plan, dict) else None
    if not isinstance(source_revision, str) or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        msg = "Build plan has no source revision."
        raise AdmissionError(msg)
    policy["sourceRevision"] = source_revision
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            for key in ("image", "admission", "baselineRef", "requiredRuntimeProfile", "sourceRevision"):
                output.write(f"{key}={policy[key]}\n")


if __name__ == "__main__":
    main()
