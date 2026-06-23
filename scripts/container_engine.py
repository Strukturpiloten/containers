"""Validate metadata and plan dependency-aware container monorepo builds."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import yaml

if TYPE_CHECKING:
    from collections.abc import Sequence

RUNNERS = {
    "amd64": "ubuntu-24.04",
    "arm64": "ubuntu-24.04-arm",
}

MAX_DEFAULT_STAGES = 4

type JsonMap = dict[str, Any]


@dataclass(frozen=True)
class PlanOptions:
    """Inputs that influence image selection and workflow matrix generation."""

    event_name: str
    ref_name: str
    default_branch: str
    before: str | None
    sha: str
    max_stages: int


@dataclass(frozen=True)
class _BuildResult:
    image_name: str
    image_ref: str
    source_revision: str
    index_digest: str
    architecture_digests: dict[str, str]
    tags: Sequence[str]


@dataclass(frozen=True)
class _GitHubContext:
    actor: str
    event_name: str
    ref_name: str
    repository: str
    run_attempt: str
    run_id: str
    server_url: str
    sha: str
    token: str | None


class ContainerEngineError(Exception):
    """Raised when container metadata cannot produce a safe build plan."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _repo_relative_path(path: Path) -> str:
    return path.relative_to(_repo_root()).as_posix()


def _fail(message: str) -> NoReturn:
    raise ContainerEngineError(message)


def _write_stdout(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _write_stderr(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _write_github_outputs(outputs: dict[str, str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    lines = [f"{name}={value}" for name, value in outputs.items()]
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        return

    _write_stdout("\n".join(lines))


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value

    _fail(f"Environment variable {name} is required.")


def _github_context(*, require_token: bool) -> _GitHubContext:
    token = _required_env("GITHUB_TOKEN") if require_token else os.environ.get("GITHUB_TOKEN")
    return _GitHubContext(
        actor=_required_env("GITHUB_ACTOR"),
        event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
        ref_name=os.environ.get("GITHUB_REF_NAME", ""),
        repository=_required_env("GITHUB_REPOSITORY"),
        run_attempt=_required_env("GITHUB_RUN_ATTEMPT"),
        run_id=_required_env("GITHUB_RUN_ID"),
        server_url=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        sha=_required_env("GITHUB_SHA"),
        token=token,
    )


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        _fail(f"Required executable not found on PATH: {name}.")
    return path


def _run(command: Sequence[str], *, input_text: str | None = None, capture_stdout: bool = False) -> str:
    result = subprocess.run(  # noqa: S603
        command,
        capture_output=capture_stdout,
        check=False,
        input=input_text,
        text=True,
    )
    if result.returncode != 0:
        _fail(f"Command failed with exit code {result.returncode}: {' '.join(command)}")
    return result.stdout if capture_stdout else ""


def _load_json(path: Path) -> JsonMap:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        _fail(f"{path} must contain a JSON object.")
    return value


def _entry(entry_json: str, *, require_arch: bool) -> tuple[str, str | None]:
    try:
        value = json.loads(entry_json)
    except json.JSONDecodeError as error:
        _fail(f"Matrix entry is not valid JSON: {error}")

    if not isinstance(value, dict):
        _fail("Matrix entry must be a JSON object.")

    image_name = value.get("name")
    if not isinstance(image_name, str) or not image_name:
        _fail("Matrix entry must define a non-empty image name.")

    architecture = value.get("arch")
    if require_arch and (not isinstance(architecture, str) or not architecture):
        _fail("Matrix entry must define a non-empty architecture.")

    return image_name, architecture if isinstance(architecture, str) and architecture else None


def _plan_image(plan: JsonMap, image_name: str) -> JsonMap:
    images = plan.get("images")
    if not isinstance(images, list):
        _fail("Build plan must define images as a list.")

    for image in images:
        if isinstance(image, dict) and image.get("name") == image_name:
            return image

    _fail(f"Image {image_name} is not part of the build plan.")


def _optional_plan_image(plan: JsonMap, image_name: str) -> JsonMap | None:
    images = plan.get("images", [])
    if not isinstance(images, list):
        return None
    for image in images:
        if isinstance(image, dict) and image.get("name") == image_name:
            return image
    return None


def _image_build(image: JsonMap) -> JsonMap:
    build = image.get("build")
    if not isinstance(build, dict):
        _fail(f"Image {image.get('name', '<unknown>')} is missing build metadata.")
    return build


def _image_architectures(image: JsonMap) -> list[str]:
    architectures = _image_build(image).get("architectures")
    if not isinstance(architectures, list) or not all(isinstance(architecture, str) for architecture in architectures):
        _fail(f"Image {image.get('name', '<unknown>')} has invalid build architectures.")
    return architectures


def _image_build_args(image: JsonMap) -> JsonMap:
    build_args = _image_build(image).get("args", {})
    if not isinstance(build_args, dict):
        _fail(f"Image {image.get('name', '<unknown>')} has invalid build args.")
    return build_args


def _internal_dependencies(image: JsonMap) -> list[JsonMap]:
    dependencies = image.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return []
    internal_dependencies = dependencies.get("internal", [])
    if not isinstance(internal_dependencies, list):
        return []
    return [dependency for dependency in internal_dependencies if isinstance(dependency, dict)]


def _split_image_digest(reference: str) -> tuple[str, str]:
    if "@" not in reference:
        return reference, ""
    image_name, digest = reference.split("@", 1)
    return image_name, digest


def _build_arg(name: str, value: str) -> list[str]:
    return ["--build-arg", f"{name}={value}"]


def _safe_ref_tag(ref_name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", ref_name.lower()).strip("-")


def _image_metadata_paths() -> list[Path]:
    return sorted(_repo_root().glob("images/**/container.yaml"))


def _load_images() -> list[JsonMap]:
    images: list[JsonMap] = []

    for path in _image_metadata_paths():
        with path.open("r", encoding="utf-8") as handle:
            metadata = yaml.safe_load(handle)

        if not isinstance(metadata, dict):
            _fail(f"{_repo_relative_path(path)} must contain a YAML mapping.")

        metadata["metadataFile"] = _repo_relative_path(path)
        images.append(metadata)

    names = [str(image.get("name", "")) for image in images]
    duplicate_names = sorted(name for name in set(names) if names.count(name) > 1)
    if duplicate_names:
        _fail(f"Duplicate image names: {', '.join(duplicate_names)}.")

    return images


def _require_string(metadata: JsonMap, key: str) -> str:
    value = metadata.get(key)
    if isinstance(value, str) and value:
        return value

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define a non-empty {key}.")


def _require_mapping(metadata: JsonMap, key: str) -> JsonMap:
    value = metadata.get(key)
    if isinstance(value, dict):
        return value

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define {key} as a mapping.")


def _require_array(metadata: JsonMap, key: str) -> list[Any]:
    value = metadata.get(key)
    if isinstance(value, list):
        return value

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define {key} as a list.")


def _validate_build_paths(metadata_file: str, build: JsonMap) -> None:
    context = build.get("context")
    containerfile = build.get("containerfile")

    if not isinstance(context, str) or not context:
        _fail(f"{metadata_file} must define build.context.")

    if not isinstance(containerfile, str) or not containerfile:
        _fail(f"{metadata_file} must define build.containerfile.")

    if not (_repo_root() / context).is_dir():
        _fail(f"{metadata_file} build.context does not exist: {context}.")

    if not (_repo_root() / containerfile).is_file():
        _fail(f"{metadata_file} build.containerfile does not exist: {containerfile}.")


def _validate_architectures(metadata_file: str, build: JsonMap) -> None:
    architectures = build.get("architectures")
    if not isinstance(architectures, list) or not architectures:
        _fail(f"{metadata_file} must define at least one build.architectures entry.")

    unsupported_architectures = [architecture for architecture in architectures if architecture not in RUNNERS]
    if unsupported_architectures:
        _fail(f"{metadata_file} uses unsupported architectures: {', '.join(unsupported_architectures)}.")


def _validate_build_args(metadata_file: str, build: JsonMap) -> None:
    build_args = build.get("args", {})
    if not isinstance(build_args, dict):
        _fail(f"{metadata_file} build.args must be a mapping.")

    for arg_name, arg_definition in build_args.items():
        if not isinstance(arg_definition, dict):
            _fail(f"{metadata_file} build arg {arg_name} must be a mapping.")

        arg_type = arg_definition.get("type")
        if not isinstance(arg_type, str) or not arg_type:
            _fail(f"{metadata_file} build arg {arg_name} must define type.")

        arg_value = arg_definition.get("value")
        if not isinstance(arg_value, str) or not arg_value:
            _fail(f"{metadata_file} build arg {arg_name} must define value.")


def _validate_dependencies(metadata_file: str, image: JsonMap, image_names: set[str]) -> None:
    dependencies = image.get("dependencies", {})
    if not isinstance(dependencies, dict):
        _fail(f"{metadata_file} dependencies must be a mapping.")

    internal_dependencies = dependencies.get("internal", [])
    external_dependencies = dependencies.get("external", [])

    if not isinstance(internal_dependencies, list):
        _fail(f"{metadata_file} dependencies.internal must be a list.")

    if not isinstance(external_dependencies, list):
        _fail(f"{metadata_file} dependencies.external must be a list.")

    for dependency in internal_dependencies:
        if (
            not isinstance(dependency, dict)
            or not isinstance(dependency.get("image"), str)
            or not isinstance(
                dependency.get("arg"),
                str,
            )
        ):
            _fail(f"{metadata_file} internal dependencies must define image and arg.")

        if dependency["image"] not in image_names:
            _fail(f"{metadata_file} references unknown internal image {dependency['image']}.")


def _validate_inputs(metadata_file: str, image: JsonMap) -> None:
    image_inputs = _require_array(image, "inputs")
    if not all(isinstance(image_input, str) and image_input for image_input in image_inputs):
        _fail(f"{metadata_file} inputs must be non-empty strings.")


def _validate_release(metadata_file: str, image: JsonMap) -> None:
    release = image.get("release", {})
    if not isinstance(release, dict):
        _fail(f"{metadata_file} release must be a mapping.")


def _validate_image(image: JsonMap, image_names: set[str]) -> None:
    metadata_file = image["metadataFile"]
    for key in ("name", "image", "title", "description", "license", "vendor"):
        _require_string(image, key)

    build = _require_mapping(image, "build")
    _validate_build_paths(metadata_file, build)
    _validate_architectures(metadata_file, build)
    _validate_build_args(metadata_file, build)
    _validate_dependencies(metadata_file, image, image_names)
    _validate_inputs(metadata_file, image)
    _validate_release(metadata_file, image)


def _validate_images(images: list[JsonMap]) -> None:
    if not images:
        _fail("No image metadata files found in images/**/container.yaml.")

    image_names = {_require_string(image, "name") for image in images}
    for image in images:
        _validate_image(image, image_names)

    _topological_levels(images)


def _dependency_names(image: JsonMap) -> list[str]:
    dependencies = image.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return []

    internal_dependencies = dependencies.get("internal", [])
    if not isinstance(internal_dependencies, list):
        return []

    return [dependency["image"] for dependency in internal_dependencies]


def _topological_levels(images: list[JsonMap], selected_names: set[str] | None = None) -> list[list[str]]:
    selected = selected_names or {image["name"] for image in images}
    image_by_name = {image["name"]: image for image in images}
    dependencies_by_name: dict[str, set[str]] = {}
    dependents_by_name: dict[str, set[str]] = defaultdict(set)

    for name in selected:
        dependencies = {
            _dependency for _dependency in _dependency_names(image_by_name[name]) if _dependency in selected
        }
        dependencies_by_name[name] = dependencies
        for dependency in dependencies:
            dependents_by_name[dependency].add(name)

    ready = sorted(name for name, dependencies in dependencies_by_name.items() if not dependencies)
    levels: list[list[str]] = []
    processed: set[str] = set()

    while ready:
        levels.append(ready)
        next_ready: list[str] = []

        for name in ready:
            processed.add(name)
            for dependent in dependents_by_name[name]:
                dependencies_by_name[dependent].discard(name)
                if not dependencies_by_name[dependent]:
                    next_ready.append(dependent)

        ready = sorted({name for name in next_ready if name not in processed})

    unprocessed = selected - processed
    if unprocessed:
        _fail(f"Internal image dependency cycle detected: {', '.join(sorted(unprocessed))}.")

    return levels


def _changed_files(before: str | None, sha: str, event_name: str) -> list[str]:
    if event_name != "push" or not before or not sha or set(before) == {"0"}:
        return []

    git = shutil.which("git")
    if git is None:
        return []

    result = subprocess.run(  # noqa: S603
        [git, "-C", str(_repo_root()), "diff", "--name-only", before, sha],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        return []

    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _input_matches(pattern: str, file_path: str) -> bool:
    if pattern.endswith("/**"):
        base = pattern.removesuffix("/**")
        return file_path == base or file_path.startswith(f"{base}/")

    return fnmatch.fnmatchcase(file_path, pattern)


def _selected_image_names(images: list[JsonMap], options: PlanOptions) -> set[str]:
    if options.event_name in {"schedule", "workflow_dispatch"}:
        return {image["name"] for image in images if image.get("build", {}).get("scheduled", True) is not False}

    files = _changed_files(before=options.before, sha=options.sha, event_name=options.event_name)
    if not files:
        return {image["name"] for image in images}

    return {
        image["name"]
        for image in images
        if any(_input_matches(pattern, changed_file) for pattern in image["inputs"] for changed_file in files)
    }


def _expand_reverse_dependencies(images: list[JsonMap], selected_names: set[str]) -> set[str]:
    dependents: dict[str, set[str]] = defaultdict(set)
    for image in images:
        for dependency_name in _dependency_names(image):
            dependents[dependency_name].add(image["name"])

    expanded = set(selected_names)
    queue = deque(selected_names)

    while queue:
        name = queue.popleft()
        for dependent in dependents[name]:
            if dependent in expanded:
                continue
            expanded.add(dependent)
            queue.append(dependent)

    return expanded


def _normalize_image(image: JsonMap, level: int) -> JsonMap:
    build = image["build"]
    return {
        "name": image["name"],
        "image": image["image"],
        "title": image["title"],
        "description": image["description"],
        "license": image["license"],
        "vendor": image["vendor"],
        "metadataFile": image["metadataFile"],
        "level": level,
        "build": {
            "context": build["context"],
            "containerfile": build["containerfile"],
            "architectures": build["architectures"],
            "args": build.get("args", {}),
        },
        "dependencies": image.get("dependencies", {"internal": [], "external": []}),
        "release": image.get("release", {}),
    }


def _stage_build_matrix(selected_images: list[JsonMap], stage: int) -> JsonMap:
    entries = [
        {
            "name": image["name"],
            "arch": architecture,
            "runner": RUNNERS[architecture],
            "stage": stage,
        }
        for image in selected_images
        if image["level"] == stage
        for architecture in image["build"]["architectures"]
    ]
    return {"include": entries}


def _stage_publish_matrix(selected_images: list[JsonMap], stage: int) -> JsonMap:
    entries = [{"name": image["name"], "stage": stage} for image in selected_images if image["level"] == stage]
    return {"include": entries}


def _build_plan(images: list[JsonMap], options: PlanOptions) -> JsonMap:
    selected_names = _selected_image_names(images, options)
    selected_names = _expand_reverse_dependencies(images, selected_names)
    levels = _topological_levels(images, selected_names) if selected_names else []

    if len(levels) > options.max_stages:
        _fail(f"Build plan needs {len(levels)} dependency stages, but workflow supports {options.max_stages}.")

    level_by_name = {name: level_index for level_index, level in enumerate(levels) for name in level}
    selected_images = [
        _normalize_image(image, level_by_name[image["name"]])
        for image in sorted(
            (image for image in images if image["name"] in selected_names),
            key=lambda image: (level_by_name[image["name"]], image["name"]),
        )
    ]

    stage_matrices = [
        {
            "buildMatrix": _stage_build_matrix(selected_images, stage),
            "publishMatrix": _stage_publish_matrix(selected_images, stage),
        }
        for stage in range(options.max_stages)
    ]

    return {
        "schemaVersion": 1,
        "eventName": options.event_name,
        "refName": options.ref_name,
        "defaultBranch": options.default_branch,
        "sourceRevision": options.sha,
        "hasImages": bool(selected_images),
        "levels": levels,
        "images": selected_images,
        "stageMatrices": stage_matrices,
    }


def _github_outputs(plan: JsonMap) -> str:
    outputs = [f"has_builds={'true' if plan['hasImages'] else 'false'}"]
    for index, stage in enumerate(plan["stageMatrices"]):
        build_matrix = stage["buildMatrix"]
        publish_matrix = stage["publishMatrix"]
        has_builds = bool(build_matrix["include"])
        outputs.append(f"stage_{index}_has_builds={'true' if has_builds else 'false'}")
        outputs.append(f"stage_{index}_build_matrix={json.dumps(build_matrix, separators=(',', ':'))}")
        outputs.append(f"stage_{index}_publish_matrix={json.dumps(publish_matrix, separators=(',', ':'))}")

    return "\n".join(outputs)


def _write_json(path: Path, value: JsonMap) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _build_base_args(plan: JsonMap, image: JsonMap, context: _GitHubContext) -> tuple[list[str], str, str]:
    build_args: list[str] = []
    base_name = ""
    base_digest = ""

    for arg_name, arg_definition in _image_build_args(image).items():
        if not isinstance(arg_definition, dict):
            continue
        arg_value = arg_definition.get("value", "")
        arg_type = arg_definition.get("type", "")
        if not isinstance(arg_value, str) or not arg_value:
            continue

        build_args.extend(_build_arg(arg_name, arg_value))
        if not base_name and arg_type == "external-image":
            base_name, base_digest = _split_image_digest(arg_value)

    for dependency in _internal_dependencies(image):
        dependency_name = dependency.get("image")
        dependency_arg = dependency.get("arg")
        if not isinstance(dependency_name, str) or not isinstance(dependency_arg, str):
            continue

        dependency_image = _optional_plan_image(plan, dependency_name)
        if dependency_image is not None:
            dependency_ref = f"{dependency_image['image']}:sha-{context.sha}"
        else:
            fallback = _image_build_args(image).get(dependency_arg, {})
            dependency_ref = fallback.get("value", "") if isinstance(fallback, dict) else ""

        if not isinstance(dependency_ref, str) or not dependency_ref:
            _fail(f"Missing pinned fallback value for internal dependency {dependency_name} ({dependency_arg}).")

        build_args.extend(_build_arg(dependency_arg, dependency_ref))
        if not base_name:
            base_name, base_digest = _split_image_digest(dependency_ref)

    return build_args, base_name, base_digest


def _command_build_arch_image(args: argparse.Namespace) -> None:
    image_name, architecture = _entry(args.entry_json, require_arch=True)
    if architecture is None:
        _fail("Architecture is required for architecture builds.")

    context = _github_context(require_token=False)
    plan = _load_json(Path(args.plan))
    image = _plan_image(plan, image_name)
    architectures = _image_architectures(image)
    if architecture not in architectures:
        _fail(f"Image {image_name} does not support architecture {architecture}.")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{image_name}-{architecture}.tar"
    local_image = f"localhost/{image_name}:{context.run_id}-{context.run_attempt}-{architecture}"
    created = dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    build_args, base_name, base_digest = _build_base_args(plan, image, context)

    command = [
        _tool("sudo"),
        _tool("buildah"),
        "bud",
        "--arch",
        architecture,
        "--format",
        "oci",
        "--pull-always",
    ]
    if context.event_name in {"schedule", "workflow_dispatch"}:
        command.append("--no-cache")

    build = _image_build(image)
    command.extend(build_args)
    command.extend(_build_arg("OCI_BASE_DIGEST", base_digest))
    command.extend(_build_arg("OCI_BASE_NAME", base_name))
    command.extend(_build_arg("OCI_CREATED", created))
    command.extend(_build_arg("OCI_DESCRIPTION", str(image["description"])))
    command.extend(
        _build_arg(
            "OCI_DOCUMENTATION", f"{context.server_url}/{context.repository}/tree/{context.sha}/images/{image_name}"
        )
    )
    command.extend(_build_arg("OCI_LICENSES", str(image["license"])))
    command.extend(_build_arg("OCI_REVISION", context.sha))
    command.extend(_build_arg("OCI_SOURCE", f"{context.server_url}/{context.repository}"))
    command.extend(_build_arg("OCI_TITLE", str(image["title"])))
    command.extend(_build_arg("OCI_URL", f"{context.server_url}/{context.repository}/pkgs/container/{image_name}"))
    command.extend(_build_arg("OCI_VENDOR", str(image["vendor"])))
    command.extend(_build_arg("OCI_VERSION", f"sha-{context.sha}"))
    command.extend(["--tag", local_image, "--file", str(build["containerfile"]), str(build["context"])])

    _write_stdout(f"Building {image_name} for {architecture}.")
    _run(command)
    _run([_tool("sudo"), _tool("buildah"), "push", "--format", "oci", local_image, f"oci-archive:{archive_path}"])
    _write_github_outputs({"image_name": image_name, "arch": architecture, "archive_path": str(archive_path)})


def _unique_tags(tags: Sequence[str]) -> list[str]:
    unique: list[str] = []
    for tag in tags:
        if tag and tag not in unique:
            unique.append(tag)
    return unique


def _architecture_digests(raw_manifest: str, architectures: Sequence[str]) -> dict[str, str]:
    manifest = json.loads(raw_manifest)
    manifests = manifest.get("manifests") if isinstance(manifest, dict) else None
    if not isinstance(manifests, list):
        _fail("Published image manifest does not contain an OCI manifest list.")

    digests: dict[str, str] = {}
    for architecture in architectures:
        for entry in manifests:
            if not isinstance(entry, dict):
                continue
            platform = entry.get("platform", {})
            digest = entry.get("digest")
            if (
                isinstance(platform, dict)
                and platform.get("os") == "linux"
                and platform.get("architecture") == architecture
                and isinstance(digest, str)
                and digest
            ):
                digests[architecture] = digest
                break
        if architecture not in digests:
            _fail(f"Published manifest does not contain a linux/{architecture} digest.")
    return digests


def _write_build_result(output_dir: Path, result: _BuildResult) -> Path:
    build_result = output_dir / f"{result.image_name}-build-result.json"
    _write_json(
        build_result,
        {
            "imageName": result.image_name,
            "image": result.image_ref,
            "sourceRevision": result.source_revision,
            "indexDigest": result.index_digest,
            "architectureDigests": result.architecture_digests,
            "tags": list(result.tags),
            "rebuilt": True,
            "releaseEligible": True,
        },
    )
    return build_result


def _command_publish_image(args: argparse.Namespace) -> None:
    image_name, _architecture = _entry(args.entry_json, require_arch=False)
    context = _github_context(require_token=True)
    if context.token is None:
        _fail("GITHUB_TOKEN is required to publish images.")

    plan = _load_json(Path(args.plan))
    image = _plan_image(plan, image_name)
    architectures = _image_architectures(image)
    archives_dir = Path(args.archives_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    image_ref = str(image["image"])
    sha_tag = f"sha-{context.sha}"
    tags = _unique_tags([sha_tag, _safe_ref_tag(context.ref_name)])
    manifest_name = f"{image_name}-{context.run_id}-{context.run_attempt}"
    sudo = _tool("sudo")
    podman = _tool("podman")
    skopeo = _tool("skopeo")

    _run([sudo, podman, "manifest", "create", manifest_name])
    try:
        for architecture in architectures:
            archive_path = archives_dir / f"{image_name}-{architecture}.tar"
            local_image = f"localhost/{image_name}:{context.run_id}-{context.run_attempt}-{architecture}"
            if not archive_path.is_file():
                _fail(f"Missing OCI archive for {image_name} {architecture}: {archive_path}")
            _run([sudo, skopeo, "copy", f"oci-archive:{archive_path}", f"containers-storage:{local_image}"])
            _run(
                [
                    sudo,
                    podman,
                    "manifest",
                    "add",
                    "--arch",
                    architecture,
                    manifest_name,
                    f"containers-storage:{local_image}",
                ]
            )

        for tag in tags:
            _run(
                [
                    sudo,
                    podman,
                    "manifest",
                    "push",
                    "--all",
                    "--format",
                    "oci",
                    manifest_name,
                    f"docker://{image_ref}:{tag}",
                ]
            )

        credentials = f"{context.actor}:{context.token}"
        raw_manifest = _run(
            [sudo, skopeo, "inspect", "--raw", "--creds", credentials, f"docker://{image_ref}:{sha_tag}"],
            capture_stdout=True,
        )
        (output_dir / f"{image_name}-index.json").write_text(raw_manifest, encoding="utf-8")
        index_digest = _run(
            [
                sudo,
                skopeo,
                "inspect",
                "--creds",
                credentials,
                "--format",
                "{{.Digest}}",
                f"docker://{image_ref}:{sha_tag}",
            ],
            capture_stdout=True,
        ).strip()
        architecture_digests = _architecture_digests(raw_manifest, architectures)

        syft = _tool("syft")
        _run([syft, "login", "ghcr.io", "--username", context.actor, "--password-stdin"], input_text=context.token)
        for architecture, digest in architecture_digests.items():
            _run(
                [
                    syft,
                    "scan",
                    "--from",
                    "registry",
                    f"{image_ref}@{digest}",
                    "-o",
                    f"spdx-json={output_dir}/sbom-{image_name}-{architecture}.spdx.json",
                ],
            )

        _run([_tool("cosign"), "sign", "--yes", "--recursive", f"{image_ref}@{index_digest}"])
        build_result = _write_build_result(
            output_dir,
            _BuildResult(
                image_name=image_name,
                image_ref=image_ref,
                source_revision=context.sha,
                index_digest=index_digest,
                architecture_digests=architecture_digests,
                tags=tags,
            ),
        )
        _write_github_outputs(
            {
                "image_name": image_name,
                "image": image_ref,
                "index_digest": index_digest,
                "amd64_digest": architecture_digests.get("amd64", ""),
                "arm64_digest": architecture_digests.get("arm64", ""),
                "build_result": str(build_result),
                "sbom_amd64": str(output_dir / f"sbom-{image_name}-amd64.spdx.json"),
                "sbom_arm64": str(output_dir / f"sbom-{image_name}-arm64.spdx.json"),
            },
        )
    finally:
        subprocess.run([sudo, podman, "manifest", "rm", manifest_name], check=False)  # noqa: S603


def _command_validate(_args: argparse.Namespace) -> None:
    images = _load_images()
    _validate_images(images)
    _write_stdout(f"Validated {len(images)} image metadata file(s).")


def _command_plan(args: argparse.Namespace) -> None:
    images = _load_images()
    _validate_images(images)
    options = PlanOptions(
        event_name=args.event_name,
        ref_name=args.ref_name,
        default_branch=args.default_branch,
        before=args.before,
        sha=args.sha,
        max_stages=args.max_stages,
    )
    plan = _build_plan(images, options)
    _write_json(Path(args.output), plan)
    _write_stdout(f"Planned {len(plan['images'])} image(s).")


def _command_github_outputs(args: argparse.Namespace) -> None:
    with Path(args.build_plan).open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    _write_stdout(_github_outputs(plan))


def _parser() -> argparse.ArgumentParser:
    root_parser = argparse.ArgumentParser(description="Plan and validate container monorepo builds.")
    subparsers = root_parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.set_defaults(func=_command_validate)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch"))
    plan_parser.add_argument("--ref-name", default=os.environ.get("GITHUB_REF_NAME", ""))
    plan_parser.add_argument("--default-branch", default=os.environ.get("GITHUB_DEFAULT_BRANCH", "main"))
    plan_parser.add_argument("--before", default=os.environ.get("GITHUB_EVENT_BEFORE"))
    plan_parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    plan_parser.add_argument("--max-stages", type=int, default=MAX_DEFAULT_STAGES)
    plan_parser.add_argument("--output", default="build-plan.json")
    plan_parser.set_defaults(func=_command_plan)

    outputs_parser = subparsers.add_parser("github-outputs")
    outputs_parser.add_argument("build_plan")
    outputs_parser.set_defaults(func=_command_github_outputs)

    build_arch_parser = subparsers.add_parser("build-arch-image")
    build_arch_parser.add_argument("--plan", required=True)
    build_arch_parser.add_argument("--entry-json", required=True)
    build_arch_parser.add_argument("--output-dir", required=True)
    build_arch_parser.set_defaults(func=_command_build_arch_image)

    publish_parser = subparsers.add_parser("publish-image")
    publish_parser.add_argument("--plan", required=True)
    publish_parser.add_argument("--entry-json", required=True)
    publish_parser.add_argument("--archives-dir", required=True)
    publish_parser.add_argument("--output-dir", required=True)
    publish_parser.set_defaults(func=_command_publish_image)

    return root_parser


def _main() -> int:
    args = _parser().parse_args()
    try:
        args.func(args)
    except ContainerEngineError as error:
        _write_stderr(f"container-engine: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
