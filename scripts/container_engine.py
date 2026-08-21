"""Validate metadata and plan dependency-aware container monorepo builds."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import http
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, cast

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from scripts.metadata_schema import MetadataSchemaError, validate_metadata_schema
from scripts.policy import (
    canonical_build_tag,
    maintained_semver_tags,
    normalize_version,
    promotion_tags,
    semver_tags,
    unique_tags,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

RUNNERS = {
    "amd64": "ubuntu-24.04",
    "arm64": "ubuntu-24.04-arm",
}

PUBLISH_WORKFLOW_PATH = Path(".github/workflows/publish-images.yml")
PUBLISH_WORKFLOW_TEMPLATE_PATH = Path(".github/workflow-templates/publish-images.yml.j2")
RELEASE_WORKFLOW_PATH = Path(".github/workflows/release-image.yml")
RELEASE_WORKFLOW_TEMPLATE_PATH = Path(".github/workflow-templates/release-image.yml.j2")
OCI_LABELS_ENV_PATH = Path("shared/oci-labels.env")
CONTAINER_SCHEMA_PATH = Path("container.schema.json")
IMAGES_GLOB = "images/**/container.yaml"
EXCLUDED_IMAGE_DIR = "_example"
GLOBAL_IMAGE_INPUTS = (
    ".containerignore",
    ".github/actions/build-arch-image/**",
    ".github/actions/publish-image/**",
    "scripts/container_engine.py",
    "scripts/policy.py",
)
SHA256_DIGEST_LENGTH = 71
GIT_SHA_LENGTH = 40
LOWERCASE_HEX_DIGITS = frozenset("0123456789abcdef")
IMAGE_METADATA_PART_COUNT = 4

type JsonMap = dict[str, Any]
type JsonList = list[Any]


@dataclass(frozen=True)
class PlanOptions:
    """Inputs that influence image selection and workflow matrix generation."""

    event_name: str
    ref_name: str
    default_branch: str
    before: str | None
    sha: str
    max_stages: int | None
    scope: str = "all"
    target: str | None = None


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


def _oci_labels() -> dict[str, str]:
    """Load static OCI label values from shared/oci-labels.env."""
    env_path = _repo_root() / OCI_LABELS_ENV_PATH
    if not env_path.is_file():
        _fail(f"OCI labels env file not found: {OCI_LABELS_ENV_PATH}")

    labels: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            _fail(f"Invalid line in {OCI_LABELS_ENV_PATH}: {line}")
        key, value = stripped.split("=", 1)
        labels[key.strip()] = value.strip()

    for required in ("OCI_LICENSES", "OCI_SOURCE", "OCI_VENDOR"):
        if required not in labels:
            _fail(f"{OCI_LABELS_ENV_PATH} must define {required}.")
    return labels


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
    return cast("JsonMap", value)


def _json_map(value: object) -> JsonMap | None:
    return cast("JsonMap", value) if isinstance(value, dict) else None


def _json_list(value: object) -> JsonList | None:
    return cast("JsonList", value) if isinstance(value, list) else None


def _string_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None

    values = cast("list[object]", value)
    if not all(isinstance(item, str) for item in values):
        return None
    return cast("list[str]", values)


def _json_map_items(mapping: JsonMap) -> list[tuple[str, object]]:
    return [(key, value) for key, value in mapping.items()]


def _entry(entry_json: str, *, require_arch: bool) -> tuple[str, str | None]:
    try:
        value = json.loads(entry_json)
    except json.JSONDecodeError as error:
        _fail(f"Matrix entry is not valid JSON: {error}")

    entry = _json_map(value)
    if entry is None:
        _fail("Matrix entry must be a JSON object.")

    image_name = entry.get("name")
    if not isinstance(image_name, str) or not image_name:
        _fail("Matrix entry must define a non-empty image name.")

    architecture = entry.get("arch")
    if require_arch and (not isinstance(architecture, str) or not architecture):
        _fail("Matrix entry must define a non-empty architecture.")

    return image_name, architecture if isinstance(architecture, str) and architecture else None


def _plan_image(plan: JsonMap, image_name: str) -> JsonMap:
    images = _json_list(plan.get("images"))
    if images is None:
        _fail("Build plan must define images as a list.")

    for image in images:
        image_metadata = _json_map(image)
        if image_metadata is not None and image_metadata.get("name") == image_name:
            return image_metadata

    _fail(f"Image {image_name} is not part of the build plan.")


def _optional_plan_image(plan: JsonMap, image_name: str) -> JsonMap | None:
    images = _json_list(plan.get("images", []))
    if images is None:
        return None
    for image in images:
        image_metadata = _json_map(image)
        if image_metadata is not None and image_metadata.get("name") == image_name:
            return image_metadata
    return None


def _image_build(image: JsonMap) -> JsonMap:
    build = image.get("build")
    build_metadata = _json_map(build)
    if build_metadata is None:
        _fail(f"Image {image.get('name', '<unknown>')} is missing build metadata.")
    return build_metadata


def _image_architectures(image: JsonMap) -> list[str]:
    architectures = _image_build(image).get("architectures")
    architecture_list = _string_list(architectures)
    if architecture_list is None:
        _fail(f"Image {image.get('name', '<unknown>')} has invalid build architectures.")
    return architecture_list


def _image_build_args(image: JsonMap) -> JsonMap:
    build_args = _image_build(image).get("args", {})
    build_args_map = _json_map(build_args)
    if build_args_map is None:
        _fail(f"Image {image.get('name', '<unknown>')} has invalid build args.")
    return build_args_map


def _internal_dependencies(image: JsonMap) -> list[JsonMap]:
    dependencies = image.get("dependencies", {})
    dependencies_map = _json_map(dependencies)
    if dependencies_map is None:
        return []
    internal_dependencies = _json_list(dependencies_map.get("internal", []))
    if internal_dependencies is None:
        return []
    return [dependency for dependency in (_json_map(item) for item in internal_dependencies) if dependency is not None]


def _split_image_digest(reference: str) -> tuple[str, str]:
    if "@" not in reference:
        return reference, ""
    image_name, digest = reference.split("@", 1)
    return image_name, digest


def _build_arg(name: str, value: str) -> list[str]:
    return ["--build-arg", f"{name}={value}"]


def _image_metadata_paths() -> list[Path]:
    return sorted(path for path in _repo_root().glob(IMAGES_GLOB) if EXCLUDED_IMAGE_DIR not in path.parts)


def _load_images() -> list[JsonMap]:
    images: list[JsonMap] = []

    for path in _image_metadata_paths():
        with path.open("r", encoding="utf-8") as handle:
            metadata = yaml.safe_load(handle)

        metadata_map = _json_map(metadata)
        if metadata_map is None:
            _fail(f"{_repo_relative_path(path)} must contain a YAML mapping.")

        metadata_file = _repo_relative_path(path)
        try:
            validate_metadata_schema(
                metadata_map,
                schema_path=_repo_root() / CONTAINER_SCHEMA_PATH,
                display_path=metadata_file,
            )
        except MetadataSchemaError as error:
            _fail(str(error))

        metadata_map["metadataFile"] = metadata_file
        images.append(metadata_map)

    names = [str(image.get("name", "")) for image in images]
    duplicate_names = sorted(name for name in set(names) if names.count(name) > 1)
    if duplicate_names:
        _fail(f"Duplicate image names: {', '.join(duplicate_names)}.")

    image_refs = [str(image.get("image", "")) for image in images]
    duplicate_image_refs = sorted(image_ref for image_ref in set(image_refs) if image_refs.count(image_ref) > 1)
    if duplicate_image_refs:
        _fail(f"Duplicate registry image references: {', '.join(duplicate_image_refs)}.")

    return images


def _require_string(metadata: JsonMap, key: str) -> str:
    value = metadata.get(key)
    if isinstance(value, str) and value:
        return value

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define a non-empty {key}.")


def _require_mapping(metadata: JsonMap, key: str) -> JsonMap:
    value = metadata.get(key)
    mapping = _json_map(value)
    if mapping is not None:
        return mapping

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define {key} as a mapping.")


def _require_array(metadata: JsonMap, key: str) -> list[Any]:
    value = metadata.get(key)
    array = _json_list(value)
    if array is not None:
        return array

    metadata_file = metadata.get("metadataFile", "container metadata")
    _fail(f"{metadata_file} must define {key} as a list.")


def _validate_build_paths(metadata_file: str, build: JsonMap) -> None:
    context = build.get("context")
    containerfile = build.get("containerfile")

    if not isinstance(context, str) or not context:
        _fail(f"{metadata_file} must define build.context.")

    if not isinstance(containerfile, str) or not containerfile:
        _fail(f"{metadata_file} must define build.containerfile.")

    repository_root = _repo_root().resolve()
    context_path = (_repo_root() / context).resolve()
    containerfile_path = (_repo_root() / containerfile).resolve()
    if not context_path.is_relative_to(repository_root) or not containerfile_path.is_relative_to(repository_root):
        _fail(f"{metadata_file} build paths must remain inside the repository.")

    if not context_path.is_dir():
        _fail(f"{metadata_file} build.context does not exist: {context}.")

    if not containerfile_path.is_file():
        _fail(f"{metadata_file} build.containerfile does not exist: {containerfile}.")


def _validate_architectures(metadata_file: str, build: JsonMap) -> None:
    architectures = build.get("architectures")
    architecture_list = _string_list(architectures)
    if not architecture_list:
        _fail(f"{metadata_file} must define at least one build.architectures entry.")

    unsupported_architectures = [architecture for architecture in architecture_list if architecture not in RUNNERS]
    if unsupported_architectures:
        _fail(f"{metadata_file} uses unsupported architectures: {', '.join(unsupported_architectures)}.")


def _validate_build_args(metadata_file: str, build: JsonMap) -> None:
    build_args = _json_map(build.get("args", {}))
    if build_args is None:
        _fail(f"{metadata_file} build.args must be a mapping.")

    for arg_name, arg_definition in _json_map_items(build_args):
        arg_definition_map = _json_map(arg_definition)
        if arg_definition_map is None:
            _fail(f"{metadata_file} build arg {arg_name} must be a mapping.")

        arg_type = arg_definition_map.get("type")
        if arg_type not in {"external-image", "internal-image", "static"}:
            _fail(f"{metadata_file} build arg {arg_name} uses unsupported type {arg_type}.")

        arg_value = arg_definition_map.get("value")
        if not isinstance(arg_value, str) or not arg_value:
            _fail(f"{metadata_file} build arg {arg_name} must define value.")

    runtime_base_arg = build.get("runtimeBaseArg")
    runtime_definition = _json_map(build_args.get(runtime_base_arg)) if isinstance(runtime_base_arg, str) else None
    if runtime_definition is None or runtime_definition.get("type") not in {"external-image", "internal-image"}:
        _fail(f"{metadata_file} build.runtimeBaseArg must reference an external-image or internal-image build arg.")


def _reference_matches_image(reference: str, image: str) -> bool:
    return reference.startswith((f"{image}:", f"{image}@"))


def _declared_image_args(build_args: JsonMap, arg_type: str) -> set[str]:
    declared: set[str] = set()
    for name, definition_candidate in _json_map_items(build_args):
        definition = _json_map(definition_candidate)
        if definition is not None and definition.get("type") == arg_type:
            declared.add(name)
    return declared


def _validate_internal_dependency_entries(
    metadata_file: str,
    entries: JsonList,
    build_args: JsonMap,
    image_names: set[str],
) -> set[str]:
    dependency_args: set[str] = set()
    for dependency_candidate in entries:
        dependency = _json_map(dependency_candidate)
        if dependency is None:
            _fail(f"{metadata_file} internal dependencies must be mappings.")

        dependency_name = dependency.get("image")
        dependency_arg = dependency.get("arg")
        if not isinstance(dependency_name, str) or not isinstance(dependency_arg, str):
            _fail(f"{metadata_file} internal dependencies must define image and arg.")
        if dependency_name not in image_names:
            _fail(f"{metadata_file} references unknown internal image {dependency_name}.")

        arg_definition = _json_map(build_args.get(dependency_arg))
        if arg_definition is None or arg_definition.get("type") != "internal-image":
            _fail(f"{metadata_file} internal dependency arg {dependency_arg} must use type internal-image.")

        arg_value = arg_definition.get("value")
        expected_image = f"ghcr.io/strukturpiloten/{dependency_name}"
        if not isinstance(arg_value, str) or not _reference_matches_image(arg_value, expected_image):
            _fail(f"{metadata_file} internal dependency {dependency_name} does not match build arg {dependency_arg}.")
        dependency_args.add(dependency_arg)
    return dependency_args


def _validate_external_dependency_entries(
    metadata_file: str,
    entries: JsonList,
    build_args: JsonMap,
) -> set[str]:
    dependency_args: set[str] = set()
    for dependency_candidate in entries:
        dependency = _json_map(dependency_candidate)
        if dependency is None:
            _fail(f"{metadata_file} external dependencies must be mappings.")

        dependency_arg = dependency.get("arg")
        dependency_image = dependency.get("image")
        if not isinstance(dependency_arg, str) or not isinstance(dependency_image, str):
            _fail(f"{metadata_file} external dependencies must define image and arg.")

        arg_definition = _json_map(build_args.get(dependency_arg))
        if arg_definition is None or arg_definition.get("type") != "external-image":
            _fail(f"{metadata_file} external dependency arg {dependency_arg} must use type external-image.")

        arg_value = arg_definition.get("value")
        if not isinstance(arg_value, str) or not _reference_matches_image(arg_value, dependency_image):
            _fail(f"{metadata_file} external dependency {dependency_image} does not match build arg {dependency_arg}.")
        dependency_args.add(dependency_arg)
    return dependency_args


def _validate_dependencies(metadata_file: str, image: JsonMap, image_names: set[str]) -> None:
    dependencies = _json_map(image.get("dependencies", {}))
    if dependencies is None:
        _fail(f"{metadata_file} dependencies must be a mapping.")

    internal_dependencies = _json_list(dependencies.get("internal", []))
    external_dependencies = _json_list(dependencies.get("external", []))

    if internal_dependencies is None:
        _fail(f"{metadata_file} dependencies.internal must be a list.")

    if external_dependencies is None:
        _fail(f"{metadata_file} dependencies.external must be a list.")

    build_args = _image_build_args(image)
    internal_args = _validate_internal_dependency_entries(metadata_file, internal_dependencies, build_args, image_names)
    external_args = _validate_external_dependency_entries(metadata_file, external_dependencies, build_args)
    declared_internal_args = _declared_image_args(build_args, "internal-image")
    declared_external_args = _declared_image_args(build_args, "external-image")
    if internal_args != declared_internal_args:
        _fail(f"{metadata_file} must declare exactly one internal dependency for every internal-image build arg.")
    if external_args != declared_external_args:
        _fail(f"{metadata_file} must declare exactly one external dependency for every external-image build arg.")


def _validate_inputs(metadata_file: str, image: JsonMap) -> None:
    image_inputs = _require_array(image, "inputs")
    if not all(isinstance(image_input, str) and image_input for image_input in image_inputs):
        _fail(f"{metadata_file} inputs must be non-empty strings.")

    build = _image_build(image)
    required_paths = (metadata_file, str(build["containerfile"]))
    for required_path in required_paths:
        if not any(_input_matches(str(pattern), required_path) for pattern in image_inputs):
            _fail(f"{metadata_file} inputs do not include required build path {required_path}.")


def _validate_version(metadata_file: str, image: JsonMap) -> None:
    version = _require_string(image, "version")
    try:
        semver_tags(version)
    except ValueError:
        _fail(f"{metadata_file} version must match SemVer major.minor.patch with an optional prerelease: {version}.")


def _validate_image(image: JsonMap, image_names: set[str]) -> None:
    metadata_file = image["metadataFile"]
    for key in ("name", "image", "title", "description", "version"):
        _require_string(image, key)

    expected_image = f"ghcr.io/strukturpiloten/{image['name']}"
    if image["image"] != expected_image:
        _fail(f"{metadata_file} image must be {expected_image}.")

    _validate_version(metadata_file, image)
    build = _require_mapping(image, "build")
    _validate_build_paths(metadata_file, build)
    _validate_architectures(metadata_file, build)
    _validate_build_args(metadata_file, build)
    _validate_dependencies(metadata_file, image, image_names)
    _validate_inputs(metadata_file, image)


def _validate_images(images: list[JsonMap]) -> None:
    if not images:
        _fail(f"No image metadata files found in {IMAGES_GLOB}.")

    image_names = {_require_string(image, "name") for image in images}
    for image in images:
        _validate_image(image, image_names)

    _topological_levels(images)


def _dependency_names(image: JsonMap) -> list[str]:
    dependencies = _json_map(image.get("dependencies", {}))
    if dependencies is None:
        return []

    internal_dependencies = _json_list(dependencies.get("internal", []))
    if internal_dependencies is None:
        return []

    names: list[str] = []
    for dependency_candidate in internal_dependencies:
        dependency = _json_map(dependency_candidate)
        if dependency is not None and isinstance(dependency.get("image"), str):
            names.append(dependency["image"])
    return names


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


def _changed_files(before: str | None, sha: str, event_name: str) -> list[str] | None:
    if event_name not in {"pull_request", "push"} or not before or not sha or set(before) == {"0"}:
        return None

    git = shutil.which("git")
    if git is None:
        _write_stderr("warning: git is unavailable; falling back to a full image rebuild.")
        return None

    result = subprocess.run(  # noqa: S603
        [git, "-C", str(_repo_root()), "diff", "--name-only", before, sha],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        _write_stderr(
            f"warning: could not inspect changed files for {before}..{sha}; falling back to a full image rebuild."
        )
        return None

    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _input_matches(pattern: str, file_path: str) -> bool:
    if pattern.endswith("/**"):
        base = pattern.removesuffix("/**")
        return file_path == base or file_path.startswith(f"{base}/")

    return fnmatch.fnmatchcase(file_path, pattern)


def _image_family(image: JsonMap) -> str:
    metadata_file = image.get("metadataFile")
    if not isinstance(metadata_file, str):
        return ""
    parts = Path(metadata_file).parts
    return parts[1] if len(parts) >= IMAGE_METADATA_PART_COUNT and parts[0] == "images" else ""


def _manual_image_names(images: list[JsonMap], options: PlanOptions) -> tuple[set[str], str]:
    scope = options.scope or "all"
    target = (options.target or "").strip()
    if scope == "all":
        return (
            {image["name"] for image in images},
            "manual all-image rebuild",
        )

    if scope == "image":
        selected = {image["name"] for image in images if image.get("name") == target}
        if not selected:
            _fail(f"Manual image target does not exist: {target or '<empty>'}.")
        return selected, f"manual image rebuild: {target}"

    if scope == "family":
        selected = {image["name"] for image in images if _image_family(image) == target}
        if not selected:
            _fail(f"Manual image family does not exist: {target or '<empty>'}.")
        return selected, f"manual family rebuild: {target}"

    _fail(f"Unsupported manual build scope: {scope}.")


def _selected_images(images: list[JsonMap], options: PlanOptions) -> tuple[set[str], list[str] | None, str]:
    if options.event_name == "schedule":
        return (
            {image["name"] for image in images if image.get("build", {}).get("scheduled", True) is not False},
            None,
            "daily scheduled security rebuild",
        )

    if options.event_name == "workflow_dispatch":
        selected, reason = _manual_image_names(images, options)
        return selected, None, reason

    files = _changed_files(before=options.before, sha=options.sha, event_name=options.event_name)
    if files is None:
        return {image["name"] for image in images}, None, "changed-file diff unavailable; safe full rebuild"

    if any(_input_matches(pattern, changed_file) for pattern in GLOBAL_IMAGE_INPUTS for changed_file in files):
        return {image["name"] for image in images}, files, "global image-build input changed"

    selected = {
        image["name"]
        for image in images
        if any(_input_matches(pattern, changed_file) for pattern in image["inputs"] for changed_file in files)
    }
    reason = "image-specific or shared runtime input changed" if selected else "validation-only changes"
    return selected, files, reason


def _selected_image_names(images: list[JsonMap], options: PlanOptions) -> set[str]:
    selected, _files, _reason = _selected_images(images, options)
    return selected


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
        "version": normalize_version(image["version"]),
        "image": image["image"],
        "title": image["title"],
        "description": image["description"],
        "metadataFile": image["metadataFile"],
        "family": _image_family(image),
        "level": level,
        "build": {
            "context": build["context"],
            "containerfile": build["containerfile"],
            "architectures": build["architectures"],
            "runtimeBaseArg": build["runtimeBaseArg"],
            "args": build.get("args", {}),
        },
        "dependencies": image.get("dependencies", {"internal": [], "external": []}),
    }


def _stage_build_matrix(selected_images: list[JsonMap], stage: int) -> JsonMap:
    entries: list[JsonMap] = []
    for image in selected_images:
        if image["level"] != stage:
            continue
        entries.extend(
            {
                "name": image["name"],
                "arch": architecture,
                "runner": RUNNERS[architecture],
                "stage": stage,
            }
            for architecture in _image_architectures(image)
        )
    return {"include": entries}


def _stage_publish_matrix(selected_images: list[JsonMap], stage: int) -> JsonMap:
    entries: list[JsonMap] = [
        {"name": image["name"], "stage": stage} for image in selected_images if image["level"] == stage
    ]
    return {"include": entries}


def _smoke_build_matrix(selected_images: list[JsonMap]) -> JsonMap:
    entries: list[JsonMap] = []
    for image in selected_images:
        entries.extend(
            {
                "name": image["name"],
                "arch": architecture,
                "runner": RUNNERS[architecture],
                "stage": image["level"],
            }
            for architecture in _image_architectures(image)
        )
    return {"include": entries}


def _build_plan(images: list[JsonMap], options: PlanOptions) -> JsonMap:
    direct_names, changed_files, selection_reason = _selected_images(images, options)
    selected_names = set(direct_names)
    selected_names = _expand_reverse_dependencies(images, selected_names)
    reverse_dependency_names = selected_names - direct_names
    levels = _topological_levels(images, selected_names) if selected_names else []
    max_stages = options.max_stages or _stage_count(images)

    if len(levels) > max_stages:
        _fail(f"Build plan needs {len(levels)} dependency stages, but workflow supports {max_stages}.")

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
        for stage in range(max_stages)
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
        "smokeBuildMatrix": _smoke_build_matrix(selected_images),
        "stageMatrices": stage_matrices,
        "selection": {
            "scope": options.scope,
            "target": options.target or "",
            "reason": selection_reason,
            "changedFiles": changed_files or [],
            "directImages": sorted(direct_names),
            "reverseDependencies": sorted(reverse_dependency_names),
            "noCache": options.event_name in {"schedule", "workflow_dispatch"},
        },
    }


def _github_outputs(plan: JsonMap) -> str:
    outputs = [
        f"has_builds={'true' if plan['hasImages'] else 'false'}",
        f"smoke_build_matrix={json.dumps(plan['smokeBuildMatrix'], separators=(',', ':'))}",
    ]
    for index, stage in enumerate(plan["stageMatrices"]):
        build_matrix = stage["buildMatrix"]
        publish_matrix = stage["publishMatrix"]
        has_builds = bool(build_matrix["include"])
        outputs.append(f"stage_{index}_has_builds={'true' if has_builds else 'false'}")
        outputs.append(f"stage_{index}_build_matrix={json.dumps(build_matrix, separators=(',', ':'))}")
        outputs.append(f"stage_{index}_publish_matrix={json.dumps(publish_matrix, separators=(',', ':'))}")

    return "\n".join(outputs)


def _plan_summary(plan: JsonMap) -> str:
    selection = _json_map(plan.get("selection", {})) or {}
    lines = [
        "## Container build plan",
        "",
        f"- Event: `{plan.get('eventName', '')}`",
        f"- Selection: {selection.get('reason', 'unknown')}",
        f"- Cache disabled: `{'yes' if selection.get('noCache') else 'no'}`",
    ]
    changed_files = _string_list(selection.get("changedFiles", [])) or []
    if changed_files:
        lines.append(f"- Changed files: {len(changed_files)}")
    reverse_dependencies = _string_list(selection.get("reverseDependencies", [])) or []
    if reverse_dependencies:
        lines.append(f"- Added reverse dependencies: `{', '.join(reverse_dependencies)}`")

    images = _json_list(plan.get("images", [])) or []
    if not images:
        lines.extend(["", "No container images need to be built."])
        return "\n".join(lines)

    maintenance_event = plan.get("eventName") == "schedule" or (
        plan.get("eventName") == "workflow_dispatch" and plan.get("refName") == plan.get("defaultBranch")
    )
    publishing_event = plan.get("eventName") in {"push", "schedule", "workflow_dispatch"}
    lines.extend(
        [
            "",
            "| Image | Family | Architectures | Dependency stage | Planned promotion tags |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for image_candidate in images:
        image = _json_map(image_candidate) or {}
        architectures = _image_architectures(image)
        version = str(image.get("version", ""))
        planned_tags = []
        if publishing_event:
            planned_tags = promotion_tags(
                event_name=str(plan.get("eventName", "")),
                ref_name=str(plan.get("refName", "")),
                default_branch=str(plan.get("defaultBranch", "")),
                sha=str(plan.get("sourceRevision", "")),
            )
        if maintenance_event:
            planned_tags.extend(maintained_semver_tags(version))
        displayed_tags = ", ".join(unique_tags(planned_tags)) or "none (non-publishing)"
        lines.append(
            f"| `{image.get('name', '')}` | `{image.get('family', '')}` | "
            f"`{', '.join(architectures)}` | {image.get('level', 0)} | `{displayed_tags}` |"
        )

    if maintenance_event:
        lines.extend(["", "SemVer tags are promoted only when the matching stable GitHub Release already exists."])
    return "\n".join(lines)


def _write_json(path: Path, value: JsonMap) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _stage_count(images: list[JsonMap]) -> int:
    return max(1, len(_topological_levels(images)))


def _workflow_environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_repo_root() / PUBLISH_WORKFLOW_TEMPLATE_PATH.parent),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
        variable_start_string="[[",
        variable_end_string="]]",
        block_start_string="[%",
        block_end_string="%]",
        autoescape=True,
        undefined=StrictUndefined,
    )


def _publish_workflow(stage_count: int) -> str:
    environment = _workflow_environment()
    template = environment.get_template(PUBLISH_WORKFLOW_TEMPLATE_PATH.name)
    return template.render(stages=list(range(stage_count)), single_stage=stage_count == 1)


def _release_workflow(images: list[JsonMap]) -> str:
    environment = _workflow_environment()
    template = environment.get_template(RELEASE_WORKFLOW_TEMPLATE_PATH.name)
    return template.render(image_names=sorted(str(image["name"]) for image in images))


def _command_generate_workflow(args: argparse.Namespace) -> None:
    images = _load_images()
    _validate_images(images)
    stage_count = _stage_count(images)
    workflows = (
        (PUBLISH_WORKFLOW_PATH, _publish_workflow(stage_count)),
        (RELEASE_WORKFLOW_PATH, _release_workflow(images)),
    )

    if args.check:
        stale_paths = [
            path
            for path, workflow in workflows
            if not (_repo_root() / path).exists() or (_repo_root() / path).read_text(encoding="utf-8") != workflow
        ]
        if stale_paths:
            _fail(f"{', '.join(str(path) for path in stale_paths)} is stale. Run generate-workflow without --check.")
        _write_stdout(
            f"Generated workflows are up to date with {stage_count} dependency stage(s) "
            f"and {len(images)} image choice(s)."
        )
        return

    for path, workflow in workflows:
        workflow_path = _repo_root() / path
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(workflow, encoding="utf-8")
    _write_stdout(
        f"Wrote generated workflows with {stage_count} dependency stage(s) and {len(images)} image choice(s)."
    )


def _dependency_result_reference(
    *,
    dependency_name: str,
    dependency_image: JsonMap,
    dependency_results_dir: Path | None,
    source_revision: str,
) -> str:
    if dependency_results_dir is None:
        _fail(f"Build results are required for selected internal dependency {dependency_name}.")

    result_path = dependency_results_dir / f"{dependency_name}-build-result.json"
    if not result_path.is_file():
        _fail(f"Missing build result for selected internal dependency {dependency_name}: {result_path}.")

    result = _load_json(result_path)
    expected_image = str(dependency_image["image"])
    if result.get("imageName") != dependency_name or result.get("image") != expected_image:
        _fail(f"Build result for internal dependency {dependency_name} does not match the build plan.")
    if result.get("sourceRevision") != source_revision:
        _fail(f"Build result for internal dependency {dependency_name} comes from a different source revision.")

    digest = result.get("indexDigest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != SHA256_DIGEST_LENGTH:
        _fail(f"Build result for internal dependency {dependency_name} has an invalid index digest.")
    return f"{expected_image}@{digest}"


def _build_base_args(
    plan: JsonMap,
    image: JsonMap,
    context: _GitHubContext,
    dependency_results_dir: Path | None,
    *,
    use_published_dependency_fallback: bool = False,
) -> tuple[list[str], str, str]:
    build_args: list[str] = []
    effective_values: dict[str, str] = {}

    for arg_name, arg_definition in _json_map_items(_image_build_args(image)):
        arg_definition_map = _json_map(arg_definition)
        if arg_definition_map is None:
            continue
        arg_value = arg_definition_map.get("value", "")
        if not isinstance(arg_value, str) or not arg_value:
            continue

        effective_values[arg_name] = arg_value
        build_args.extend(_build_arg(arg_name, arg_value))

    for dependency in _internal_dependencies(image):
        dependency_name = dependency.get("image")
        dependency_arg = dependency.get("arg")
        if not isinstance(dependency_name, str) or not isinstance(dependency_arg, str):
            continue

        dependency_image = _optional_plan_image(plan, dependency_name)
        if dependency_image is not None and not use_published_dependency_fallback:
            dependency_ref = _dependency_result_reference(
                dependency_name=dependency_name,
                dependency_image=dependency_image,
                dependency_results_dir=dependency_results_dir,
                source_revision=str(plan.get("sourceRevision", context.sha)),
            )
        else:
            fallback = _json_map(_image_build_args(image).get(dependency_arg, {}))
            dependency_ref = fallback.get("value", "") if fallback is not None else ""

        if not isinstance(dependency_ref, str) or not dependency_ref:
            _fail(f"Missing pinned fallback value for internal dependency {dependency_name} ({dependency_arg}).")

        effective_values[dependency_arg] = dependency_ref
        build_args.extend(_build_arg(dependency_arg, dependency_ref))

    runtime_base_arg = _image_build(image).get("runtimeBaseArg")
    runtime_base = effective_values.get(str(runtime_base_arg), "")
    base_name, base_digest = _split_image_digest(runtime_base)
    if not base_name or not base_digest.startswith("sha256:"):
        _fail(f"Image {image.get('name', '<unknown>')} has no digest-pinned effective runtime base image.")

    return build_args, base_name, base_digest


def _source_timestamp(source_revision: str) -> tuple[int, str]:
    if len(source_revision) != GIT_SHA_LENGTH or not set(source_revision.lower()) <= LOWERCASE_HEX_DIGITS:
        _fail(f"Build source must be a full Git commit SHA: {source_revision}.")
    raw_timestamp = _run(
        [_tool("git"), "-C", str(_repo_root()), "show", "-s", "--format=%ct", source_revision],
        capture_stdout=True,
    ).strip()
    try:
        timestamp = int(raw_timestamp)
    except ValueError:
        _fail(f"Git returned an invalid source timestamp for {source_revision}: {raw_timestamp}.")
    if timestamp <= 0:
        _fail(f"Git returned a non-positive source timestamp for {source_revision}.")
    created = dt.datetime.fromtimestamp(timestamp, tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return timestamp, created


def _command_build_arch_image(args: argparse.Namespace) -> None:
    image_name, architecture = _entry(args.entry_json, require_arch=True)
    if architecture is None:
        _fail("Architecture is required for architecture builds.")

    context = _github_context(require_token=False)
    plan = _load_json(Path(args.plan))
    image = _plan_image(plan, image_name)
    source_revision = str(plan.get("sourceRevision", ""))
    source_timestamp, created = _source_timestamp(source_revision)
    architectures = _image_architectures(image)
    if architecture not in architectures:
        _fail(f"Image {image_name} does not support architecture {architecture}.")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{image_name}-{architecture}.tar"
    local_image = f"localhost/{image_name}:{context.run_id}-{context.run_attempt}-{architecture}"
    dependency_results_dir = Path(args.dependency_results_dir) if args.dependency_results_dir else None
    build_args, base_name, base_digest = _build_base_args(
        plan,
        image,
        context,
        dependency_results_dir,
        use_published_dependency_fallback=args.use_published_dependency_fallback,
    )
    oci_labels = _oci_labels()

    command = [
        _tool("sudo"),
        _tool("buildah"),
        "bud",
        "--arch",
        architecture,
        "--format",
        "oci",
        "--pull-always",
        "--timestamp",
        str(source_timestamp),
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
            "OCI_DOCUMENTATION",
            f"{context.server_url}/{context.repository}/tree/{source_revision}/images/{image_name}",
        )
    )
    command.extend(_build_arg("OCI_LICENSES", oci_labels["OCI_LICENSES"]))
    command.extend(_build_arg("OCI_REVISION", source_revision))
    command.extend(_build_arg("OCI_SOURCE", oci_labels["OCI_SOURCE"]))
    command.extend(_build_arg("OCI_TITLE", str(image["title"])))
    command.extend(_build_arg("OCI_URL", f"{context.server_url}/{context.repository}/pkgs/container/{image_name}"))
    command.extend(_build_arg("OCI_VENDOR", oci_labels["OCI_VENDOR"]))
    command.extend(_build_arg("OCI_VERSION", str(image["version"])))
    command.extend(_build_arg("SOURCE_DATE_EPOCH", str(source_timestamp)))
    command.extend(["--tag", local_image, "--file", str(build["containerfile"]), str(build["context"])])

    _write_stdout(f"Building {image_name} for {architecture}.")
    _run(command)
    _run([_tool("sudo"), _tool("buildah"), "push", "--format", "oci", local_image, f"oci-archive:{archive_path}"])
    _write_github_outputs({"image_name": image_name, "arch": architecture, "archive_path": str(archive_path)})


def _architecture_digests(raw_manifest: str, architectures: Sequence[str]) -> dict[str, str]:
    manifest = json.loads(raw_manifest)
    manifest_map = _json_map(manifest)
    manifests = _json_list(manifest_map.get("manifests")) if manifest_map is not None else None
    if manifests is None:
        _fail("Published image manifest does not contain an OCI manifest list.")

    digests: dict[str, str] = {}
    for architecture in architectures:
        for entry_candidate in manifests:
            entry = _json_map(entry_candidate)
            if entry is None:
                continue
            platform = _json_map(entry.get("platform", {}))
            digest = entry.get("digest")
            if (
                platform is not None
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
    try:
        canonical_tag = canonical_build_tag(sha=context.sha, run_id=context.run_id, run_attempt=context.run_attempt)
    except ValueError as error:
        _fail(str(error))
    tags = unique_tags(
        [
            canonical_tag,
            *promotion_tags(
                event_name=context.event_name,
                ref_name=context.ref_name,
                default_branch=args.default_branch,
                sha=context.sha,
            ),
        ]
    )
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
                f"docker://{image_ref}:{canonical_tag}",
            ]
        )

        raw_manifest = _run(
            [sudo, skopeo, "inspect", "--raw", f"docker://{image_ref}:{canonical_tag}"],
            capture_stdout=True,
        )
        (output_dir / f"{image_name}-index.json").write_text(raw_manifest, encoding="utf-8")
        index_digest = _run(
            [
                sudo,
                skopeo,
                "inspect",
                "--format",
                "{{.Digest}}",
                f"docker://{image_ref}:{canonical_tag}",
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
                source_revision=str(plan.get("sourceRevision", context.sha)),
                index_digest=index_digest,
                architecture_digests=architecture_digests,
                tags=tags,
            ),
        )
        _write_github_outputs(
            {
                "image_name": image_name,
                "image": image_ref,
                "version": str(image["version"]),
                "index_digest": index_digest,
                "canonical_tag": canonical_tag,
                "amd64_digest": architecture_digests.get("amd64", ""),
                "arm64_digest": architecture_digests.get("arm64", ""),
                "build_result": str(build_result),
                "sbom_amd64": str(output_dir / f"sbom-{image_name}-amd64.spdx.json"),
                "sbom_arm64": str(output_dir / f"sbom-{image_name}-arm64.spdx.json"),
            },
        )
    finally:
        subprocess.run([sudo, podman, "manifest", "rm", manifest_name], check=False)  # noqa: S603


def _remote_digest(command_prefix: Sequence[str], reference: str) -> str | None:
    command = [*command_prefix, "inspect", "--format", "{{.Digest}}", f"docker://{reference}"]
    result = subprocess.run(command, capture_output=True, check=False, text=True)  # noqa: S603
    if result.returncode == 0:
        digest = result.stdout.strip()
        if digest.startswith("sha256:") and len(digest) == SHA256_DIGEST_LENGTH:
            return digest
        _fail(f"Registry returned an invalid digest for {reference}.")

    missing_markers = ("manifest unknown", "name unknown", "not found")
    if any(marker in result.stderr.lower() for marker in missing_markers):
        return None
    _fail(f"Could not inspect registry reference {reference}.")


def _github_release_exists(context: _GitHubContext, image_name: str, version: str) -> bool:
    if not context.token:
        _fail("GITHUB_TOKEN is required to verify maintained SemVer releases.")
    release_tag = f"{image_name}/v{normalize_version(version)}"
    api_root = (
        "https://api.github.com" if context.server_url == "https://github.com" else f"{context.server_url}/api/v3"
    )
    encoded_tag = urllib.parse.quote(release_tag, safe="")
    request = urllib.request.Request(  # noqa: S310
        f"{api_root}/repos/{context.repository}/releases/tags/{encoded_tag}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {context.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.status == http.HTTPStatus.OK
    except urllib.error.HTTPError as error:
        if error.code == http.HTTPStatus.NOT_FOUND:
            return False
        _fail(f"GitHub release lookup failed for {release_tag}: HTTP {error.code}.")
    except urllib.error.URLError as error:
        _fail(f"GitHub release lookup failed for {release_tag}: {error.reason}.")


def _command_promote_image(args: argparse.Namespace) -> None:
    context = _github_context(require_token=False)
    digest = args.digest
    if not digest.startswith("sha256:") or len(digest) != SHA256_DIGEST_LENGTH:
        _fail(f"Invalid image index digest: {digest}.")

    tags = promotion_tags(
        event_name=context.event_name,
        ref_name=context.ref_name,
        default_branch=args.default_branch,
        sha=context.sha,
    )
    maintenance_tags = maintained_semver_tags(args.version)
    maintenance_event = context.event_name == "schedule" or (
        context.event_name == "workflow_dispatch" and context.ref_name == args.default_branch
    )
    if maintenance_event and maintenance_tags:
        if _github_release_exists(context, args.image_name, args.version):
            tags = unique_tags([*tags, *maintenance_tags])
        else:
            message = (
                f"Skipping maintained SemVer tags for {args.image_name} {args.version}: "
                "matching GitHub Release not found."
            )
            _write_stdout(message)
    command_prefix = [_tool("sudo"), _tool("skopeo")]
    immutable_tag = f"sha-{context.sha}" if context.event_name == "push" else None

    for tag in tags:
        target = f"{args.image}:{tag}"
        existing_digest = _remote_digest(command_prefix, target)
        if existing_digest == digest:
            _write_stdout(f"Registry tag {target} already points to {digest}.")
            continue
        if tag == immutable_tag and existing_digest is not None:
            _fail(f"Refusing to overwrite immutable registry tag {target} ({existing_digest}).")

        _run(
            [
                *command_prefix,
                "copy",
                "--all",
                f"docker://{args.image}@{digest}",
                f"docker://{target}",
            ]
        )
        _write_stdout(f"Promoted {target} to {digest}.")

    if args.build_result:
        build_result_path = Path(args.build_result)
        build_result = _load_json(build_result_path)
        recorded_tags = _string_list(build_result.get("tags", [])) or []
        build_result["tags"] = unique_tags([*recorded_tags, *tags])
        _write_json(build_result_path, build_result)
    _write_github_outputs({"promoted_tags": ",".join(tags)})


def _command_validate(_args: argparse.Namespace) -> None:
    images = _load_images()
    _validate_images(images)
    _write_stdout(f"Validated {len(images)} image metadata file(s).")


def _release_metadata(image_name: str) -> tuple[JsonMap, str, list[str]]:
    images = _load_images()
    _validate_images(images)
    image = next((candidate for candidate in images if candidate.get("name") == image_name), None)
    if image is None:
        _fail(f"Image {image_name} not found in repository metadata.")

    version = normalize_version(str(image["version"]))
    try:
        release_tags = semver_tags(version)
    except ValueError as error:
        _fail(str(error))
    return image, version, release_tags


def _command_release_info(args: argparse.Namespace) -> None:
    image, version, release_tags = _release_metadata(args.image)
    _write_github_outputs(
        {
            "image_name": str(image["name"]),
            "version": version,
            "release_tag": release_tags[0],
        }
    )


def _command_release_image(args: argparse.Namespace) -> None:
    image_name = args.image
    image, version, release_tags = _release_metadata(image_name)

    context = _github_context(require_token=False)
    if context.ref_name != args.default_branch:
        _fail(f"Releases must run from the default branch {args.default_branch}, not {context.ref_name}.")

    image_ref = str(image["image"])
    skopeo = _tool("skopeo")
    source_revision = args.source_sha.lower()
    if len(source_revision) != GIT_SHA_LENGTH or not set(source_revision) <= LOWERCASE_HEX_DIGITS:
        _fail(f"Release source must be a full lowercase Git commit SHA: {args.source_sha}.")

    source_tag = f"sha-{source_revision}"
    source_reference = f"{image_ref}:{source_tag}"
    index_digest = _remote_digest([skopeo], source_reference)
    if index_digest is None:
        _fail(f"Immutable source {source_reference} does not exist.")

    config_raw = _run([skopeo, "inspect", "--config", f"docker://{source_reference}"], capture_stdout=True)
    image_config = _json_map(json.loads(config_raw))
    config = _json_map(image_config.get("config")) if image_config is not None else None
    labels = _json_map(config.get("Labels")) if config is not None else None
    inspection = {"Digest": index_digest, "Labels": labels}

    index_digest = _validate_release_inspection(
        inspection,
        source_reference=source_reference,
        source_revision=source_revision,
        version=version,
    )

    command_prefix = [skopeo]
    exact_reference = f"{image_ref}:{release_tags[0]}"
    existing_exact_digest = _remote_digest(command_prefix, exact_reference)
    if existing_exact_digest is not None and existing_exact_digest != index_digest:
        _fail(f"Refusing to replace existing release tag {exact_reference} ({existing_exact_digest}).")

    for tag in release_tags:
        if tag == release_tags[0] and existing_exact_digest == index_digest:
            _write_stdout(f"Release tag {exact_reference} already points to {index_digest}.")
            continue
        _write_stdout(f"Tagging {image_ref}:{tag} -> {index_digest}")
        _run(
            [
                skopeo,
                "copy",
                "--all",
                f"docker://{image_ref}@{index_digest}",
                f"docker://{image_ref}:{tag}",
            ]
        )

    _write_stdout(f"Released {image_name} version {version}: {', '.join(release_tags)} -> {image_ref}@{index_digest}")
    _write_github_outputs(
        {
            "image_name": image_name,
            "image": image_ref,
            "version": version,
            "index_digest": index_digest,
            "tags": ",".join(release_tags),
        }
    )


def _validate_release_inspection(
    inspection: JsonMap,
    *,
    source_reference: str,
    source_revision: str,
    version: str,
) -> str:
    index_digest = inspection.get("Digest")
    if not isinstance(index_digest, str) or not index_digest.startswith("sha256:"):
        _fail(f"Could not resolve digest for immutable source {source_reference}.")

    labels = _json_map(inspection.get("Labels"))
    if labels is None:
        _fail(f"Immutable source {source_reference} has no OCI labels.")
    if labels.get("org.opencontainers.image.revision") != source_revision:
        _fail(f"Immutable source {source_reference} was not built from revision {source_revision}.")
    if labels.get("org.opencontainers.image.version") != version:
        _fail(f"Immutable source {source_reference} does not carry OCI version {version}.")
    return index_digest


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
        scope=args.scope,
        target=args.target,
    )
    plan = _build_plan(images, options)
    _write_json(Path(args.output), plan)
    _write_stdout(f"Planned {len(plan['images'])} image(s).")


def _command_github_outputs(args: argparse.Namespace) -> None:
    with Path(args.build_plan).open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    _write_stdout(_github_outputs(plan))


def _command_plan_summary(args: argparse.Namespace) -> None:
    plan = _load_json(Path(args.build_plan))
    _write_stdout(_plan_summary(plan))


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915
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
    plan_parser.add_argument("--max-stages", type=int)
    plan_parser.add_argument("--scope", default=os.environ.get("BUILD_SCOPE", "all"))
    plan_parser.add_argument("--target", default=os.environ.get("BUILD_TARGET"))
    plan_parser.add_argument("--output", default="build-plan.json")
    plan_parser.set_defaults(func=_command_plan)

    outputs_parser = subparsers.add_parser("github-outputs")
    outputs_parser.add_argument("build_plan")
    outputs_parser.set_defaults(func=_command_github_outputs)

    summary_parser = subparsers.add_parser("plan-summary")
    summary_parser.add_argument("build_plan")
    summary_parser.set_defaults(func=_command_plan_summary)

    build_arch_parser = subparsers.add_parser("build-arch-image")
    build_arch_parser.add_argument("--plan", required=True)
    build_arch_parser.add_argument("--entry-json", required=True)
    build_arch_parser.add_argument("--output-dir", required=True)
    build_arch_parser.add_argument("--dependency-results-dir")
    build_arch_parser.add_argument("--use-published-dependency-fallback", action="store_true")
    build_arch_parser.set_defaults(func=_command_build_arch_image)

    publish_parser = subparsers.add_parser("publish-image")
    publish_parser.add_argument("--plan", required=True)
    publish_parser.add_argument("--entry-json", required=True)
    publish_parser.add_argument("--archives-dir", required=True)
    publish_parser.add_argument("--output-dir", required=True)
    publish_parser.add_argument("--default-branch", required=True)
    publish_parser.set_defaults(func=_command_publish_image)

    promote_parser = subparsers.add_parser("promote-image")
    promote_parser.add_argument("--image-name", required=True)
    promote_parser.add_argument("--image", required=True)
    promote_parser.add_argument("--version", required=True)
    promote_parser.add_argument("--digest", required=True)
    promote_parser.add_argument("--default-branch", required=True)
    promote_parser.add_argument("--build-result")
    promote_parser.set_defaults(func=_command_promote_image)

    generate_workflow_parser = subparsers.add_parser("generate-workflow")
    generate_workflow_parser.add_argument("--check", action="store_true")
    generate_workflow_parser.set_defaults(func=_command_generate_workflow)

    release_info_parser = subparsers.add_parser("release-info")
    release_info_parser.add_argument("--image", required=True)
    release_info_parser.set_defaults(func=_command_release_info)

    release_parser = subparsers.add_parser("release-image")
    release_parser.add_argument("--image", required=True)
    release_parser.add_argument("--source-sha", required=True)
    release_parser.add_argument("--default-branch", required=True)
    release_parser.set_defaults(func=_command_release_image)

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
