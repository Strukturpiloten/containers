"""Pure tag and version policies shared by publishing, releasing, and tests."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

VERSION_PATTERN = r"^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
SEMVER_PART_COUNT = 3


def normalize_version(version: str) -> str:
    """Strip the optional display prefix from a validated SemVer version."""
    return version.removeprefix("v")


def semver_tags(version: str) -> list[str]:
    """Return exact and moving tags without promoting prereleases to stable aliases."""
    normalized = normalize_version(version)
    if not re.fullmatch(VERSION_PATTERN, normalized):
        msg = f"Invalid SemVer version: {version}"
        raise ValueError(msg)

    if "-" in normalized:
        return [f"v{normalized}"]

    parts = normalized.split(".")
    if len(parts) != SEMVER_PART_COUNT:
        msg = f"Invalid SemVer version: {version}"
        raise ValueError(msg)
    return [f"v{normalized}", f"v{parts[0]}.{parts[1]}", f"v{parts[0]}"]


def _comparison(left: object, right: object) -> int:
    return (left > right) - (left < right)  # type: ignore[operator]


def _semver_parts(version: str) -> tuple[tuple[int, int, int], list[str] | None]:
    normalized = normalize_version(version)
    if not re.fullmatch(VERSION_PATTERN, normalized):
        msg = f"Invalid SemVer version: {version}"
        raise ValueError(msg)
    core, separator, prerelease = normalized.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    return (major, minor, patch), prerelease.split(".") if separator else None


def _compare_prerelease(left: list[str], right: list[str]) -> int:
    for left_identifier, right_identifier in zip(left, right, strict=False):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return _comparison(int(left_identifier), int(right_identifier))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return _comparison(left_identifier, right_identifier)
    return _comparison(len(left), len(right))


def compare_semver(left: str, right: str) -> int:
    """Compare two supported SemVer values using SemVer precedence rules."""
    left_core, left_prerelease = _semver_parts(left)
    right_core, right_prerelease = _semver_parts(right)
    core_comparison = _comparison(left_core, right_core)
    if core_comparison:
        return core_comparison
    if left_prerelease is None or right_prerelease is None:
        return _comparison(right_prerelease is not None, left_prerelease is not None)
    return _compare_prerelease(left_prerelease, right_prerelease)


def safe_ref_tag(ref_name: str) -> str:
    """Convert a Git ref name into a portable OCI tag."""
    return re.sub(r"[^a-z0-9._-]+", "-", ref_name.lower()).strip("-")


def unique_tags(tags: Sequence[str]) -> list[str]:
    """Preserve tag order while removing empty and duplicate entries."""
    return list(dict.fromkeys(tag for tag in tags if tag))


def canonical_build_tag(*, sha: str, run_id: str, run_attempt: str) -> str:
    """Return an immutable tag unique to one workflow run attempt."""
    if not sha or not run_id or not run_attempt:
        msg = "A source SHA, run ID, and run attempt are required to create a canonical build tag."
        raise ValueError(msg)
    return f"run-{run_id}-{run_attempt}-sha-{sha}"


def promotion_tags(*, event_name: str, ref_name: str, default_branch: str, sha: str) -> list[str]:
    """Return tags promoted only after signing and attestations complete."""
    tags: list[str] = []
    if event_name == "push":
        tags.append(f"sha-{sha}")
    tags.append(safe_ref_tag(ref_name))
    if ref_name == default_branch:
        tags.append("latest")
    return unique_tags(tags)
