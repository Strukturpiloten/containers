"""Recognize narrowly scoped CI-tool updates without trusting changed filenames alone."""

from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from pathlib import Path

CONFIG_PATH = ".github/automation.yml"
TOOL_KEYS = frozenset({"UV_VERSION", "ACTIONLINT_VERSION"})
CANARY_IMAGES = frozenset({"docker-29-rootless", "podman-alpine-3.24-rootful", "nextcloud-phpfpm"})


def _document(root: Path, revision: str, path: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603 - Git receives separate revision/path arguments, never a shell.
        ["git", "show", f"{revision}:{path}"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    value = yaml.safe_load(result.stdout)
    if not isinstance(value, dict):
        msg = f"Expected a YAML mapping in {path}."
        raise TypeError(msg)
    return value


def _non_major_version_change(before: object, after: object) -> bool:
    pattern = r"v?(\d+)\.\d+\.\d+"
    if not isinstance(before, str) or not isinstance(after, str):
        return False
    old = re.fullmatch(pattern, before)
    new = re.fullmatch(pattern, after)
    return bool(old and new and old[1] == new[1])


def _workflow_matches(before: dict[str, Any], after: dict[str, Any], versions: dict[str, tuple[str, str]]) -> bool:
    old_env, new_env = before.get("env", {}), after.get("env", {})
    if not isinstance(old_env, dict) or not isinstance(new_env, dict):
        return False
    for key, (old, new) in versions.items():
        if key in old_env or key in new_env:
            if old_env.get(key) != old or new_env.get(key) != new:
                return False
            del old_env[key]
            del new_env[key]
    return before == after


def is_tool_only_change(root: Path, before: str, after: str, files: list[str]) -> bool:
    """Require non-major tool pins and otherwise identical generated workflow documents.

    Unsupported keys, mixed source/template changes, malformed YAML and unavailable
    Git history conservatively retain the ordinary build-selection policy.
    """
    if CONFIG_PATH not in files:
        return False
    generated = {
        f".github/workflows/{path.name.removesuffix('.j2')}"
        for path in (root / ".github/workflow-templates").glob("*.yml.j2")
    }
    if not generated or set(files) - generated - {CONFIG_PATH}:
        return False
    try:
        old, new = _document(root, before, CONFIG_PATH), _document(root, after, CONFIG_PATH)
        if old.keys() != new.keys():
            return False
        changed = {key for key in old if old[key] != new[key]}
        if (
            not changed
            or not changed <= TOOL_KEYS
            or not all(_non_major_version_change(old[key], new[key]) for key in changed)
        ):
            return False
        versions = {key: (old[key], new[key]) for key in changed}
        return all(
            _workflow_matches(_document(root, before, path), _document(root, after, path), versions)
            for path in sorted(generated)
        )
    except OSError, TypeError, ValueError, subprocess.SubprocessError, yaml.YAMLError:
        return False
