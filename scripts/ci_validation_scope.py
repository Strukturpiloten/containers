"""Assert the closed manual CI scope before publishing workload matrix outputs."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts import build_payloads, container_engine
from scripts.docker_userns_qualification import QualificationError, validation_profile

TARGET = "docker-29-conformance-rootless"
PAYLOAD = "docker-29-payload"
MANIFEST = "images/docker/upstream/29/payload.yaml"
BOUNDED = "docker-rootless-qualification"
PROFILES = {"full", "docker-rootless-diagnostic", BOUNDED}
ARCHITECTURES = ("amd64", "arm64")


class ScopeError(ValueError):
    """Refuse missing, contradictory or widened selection without scheduling work."""


@dataclass(frozen=True)
class Context:
    """Trusted event and selector fields, separate from the mutable planner output."""

    event_name: str
    requested_profile: str
    selected_profile: str
    ref_name: str
    source_revision: str
    default_branch: str


def _need(condition: object, reason: str) -> None:
    if not condition:
        raise ScopeError(reason)


def _selection(selection: dict, context: Context) -> None:
    requested = validation_profile(context.requested_profile) if context.event_name == "workflow_dispatch" else "full"
    _need(
        context.selected_profile in PROFILES and context.selected_profile == requested,
        "Selected profile differs from request.",
    )
    focused = selection.get("focusedRuntimeRequested")
    diagnostic = requested == "docker-rootless-diagnostic"
    _need(type(focused) is str and focused in {"witness-diagnostic", "mandatory-accounting"}, "Unknown focused input.")
    _need(diagnostic or focused == "witness-diagnostic", "Focused accounting requires diagnostic scope.")
    _need(
        selection
        == {
            "validationProfile": requested,
            "focusedRuntimeRequested": focused,
            "focusedRuntime": focused if diagnostic else "none",
            "oomAccountingMode": "diagnostic" if diagnostic and focused == "witness-diagnostic" else "qualification",
            "qualification": "none" if diagnostic else "pending",
        },
        "Selection artifact is incomplete or contradictory.",
    )


def _declaration() -> dict[str, Any]:
    images = container_engine._load_images()  # noqa: SLF001 - share the trusted declaration loader, never a second planner.
    declared = next(image for image in images if image["name"] == TARGET)
    _need(
        declared["tests"]
        == {
            "docker": {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged", "nestedRuntime": True}
        }
        and declared["tests"]["docker"]["nestedRuntime"] is True
        and declared["dependencies"]["internal"] == [],
        "Fixture runtime or dependency declaration drifted.",
    )
    _need(declared["build"]["architectures"] == list(ARCHITECTURES), "Fixture architecture declaration drifted.")
    _need(declared["build"]["payload"] == MANIFEST, "Fixture payload declaration drifted.")
    manifest = build_payloads.load_manifest(container_engine._repo_root(), MANIFEST)  # noqa: SLF001
    _need(
        manifest["name"] == PAYLOAD and manifest["build"]["architectures"] == list(ARCHITECTURES),
        "Payload declaration drifted.",
    )
    return container_engine._normalize_image(declared, 0)  # noqa: SLF001 - compare the actual declared normalized image.


def _matrices(plan: dict) -> None:
    runners = container_engine.RUNNERS
    smoke = [
        {"name": TARGET, "arch": architecture, "runner": runners[architecture], "stage": 0, "payloadName": PAYLOAD}
        for architecture in ARCHITECTURES
    ]
    payloads = [
        {"name": PAYLOAD, "arch": architecture, "runner": runners[architecture], "manifest": MANIFEST}
        for architecture in ARCHITECTURES
    ]
    _need(plan["smokeBuildMatrix"] == {"include": smoke}, "Bounded smoke matrix differs from the exact declared pair.")
    _need(all(type(entry["stage"]) is int for entry in plan["smokeBuildMatrix"]["include"]), "Invalid stage type.")
    _need(
        plan["payloadMatrix"] == {"include": payloads}, "Bounded payload matrix differs from the exact declared pair."
    )
    stages = plan["stageMatrices"]
    first = {
        "buildMatrix": {"include": smoke},
        "publishMatrix": {"include": [{"name": TARGET, "stage": 0, "buildMatrix": {"include": smoke}}]},
    }
    _need(
        isinstance(stages, list)
        and bool(stages)
        and json.dumps(stages[0], sort_keys=True) == json.dumps(first, sort_keys=True),
        "Bounded stage matrix differs.",
    )
    _need(
        all(stage == {"buildMatrix": {"include": []}, "publishMatrix": {"include": []}} for stage in stages[1:]),
        "Bounded stage matrix widened.",
    )


def _bounded(plan: dict, context: Context) -> None:
    _need(
        set(plan) - {"validationProfile"}
        == {
            "schemaVersion",
            "eventName",
            "refName",
            "defaultBranch",
            "sourceRevision",
            "hasImages",
            "levels",
            "images",
            "smokeBuildMatrix",
            "stageMatrices",
            "payloadMatrix",
            "selection",
        },
        "Bounded plan fields are missing or unknown.",
    )
    _need(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,179}", context.ref_name) is not None
        and bool(context.default_branch),
        "Build-plan ref is missing or malformed.",
    )
    _need(context.event_name == "workflow_dispatch", "Bounded qualification requires manual CI.")
    _need(type(plan["schemaVersion"]) is int and plan["schemaVersion"] == 1, "Unknown build-plan schema.")
    _need(
        plan["eventName"] == context.event_name
        and plan["refName"] == context.ref_name
        and plan["defaultBranch"] == context.default_branch,
        "Build-plan event/ref differs.",
    )
    _need(
        re.fullmatch(r"[0-9a-f]{40}", context.source_revision) is not None
        and plan["sourceRevision"] == context.source_revision,
        "Build-plan source differs.",
    )
    _need(
        plan["hasImages"] is True
        and plan["levels"] == [[TARGET]]
        and json.dumps(plan["images"], sort_keys=True) == json.dumps([_declaration()], sort_keys=True),
        "Bounded image selection differs from its declaration.",
    )
    _need(
        plan["selection"]
        == {
            "scope": "image",
            "target": TARGET,
            "reason": "manual image rebuild: " + TARGET,
            "changedFiles": [],
            "directImages": [TARGET],
            "reverseDependencies": [],
            "noCache": True,
        },
        "Bounded selection is missing, widened or cacheable.",
    )
    _need(plan["selection"]["noCache"] is True, "Bounded selection must disable cache.")
    _matrices(plan)


def validate_plan(plan: object, selection: object, context: Context) -> dict:
    """Require an exact bounded plan and preserve its actual canonical profile."""
    _need(type(plan) is dict and type(selection) is dict, "Plan and selection must be objects.")
    _selection(selection, context)
    _need(
        "validationProfile" not in plan or plan["validationProfile"] == context.selected_profile,
        "Build-plan profile was relabelled.",
    )
    if context.selected_profile == BOUNDED:
        _bounded(plan, context)
    return {**plan, "validationProfile": context.selected_profile}


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        _need(key not in result, "Duplicate JSON field.")
        result[key] = value
    return result


def main() -> None:
    """Validate before CI outputs, annotating only a successfully checked plan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    for name in (
        "event-name",
        "requested-profile",
        "selected-profile",
        "ref-name",
        "source-revision",
        "default-branch",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(), object_pairs_hook=_unique)
        selection = json.loads(args.selection.read_text(), object_pairs_hook=_unique)
        context = Context(
            args.event_name,
            args.requested_profile,
            args.selected_profile,
            args.ref_name,
            args.source_revision,
            args.default_branch,
        )
        result = validate_plan(plan, selection, context)
    except OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration, QualificationError:
        parser.exit(1, "CI profile or selected build plan failed its closed scope contract.\n")
    args.plan.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
