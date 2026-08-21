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
    """Return immutable and moving aliases without promoting prereleases."""
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
