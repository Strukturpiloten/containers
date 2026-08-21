"""Validate container metadata against the checked-in JSON Schema."""

from __future__ import annotations

import json
from functools import cache
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class MetadataSchemaError(ValueError):
    """Raised when container metadata does not satisfy the repository schema."""


@cache
def _load_schema(schema_path: Path) -> dict[str, Any]:
    with schema_path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator.check_schema(schema)
    return schema


def validate_metadata_schema(metadata: Mapping[str, object], *, schema_path: Path, display_path: str) -> None:
    """Validate metadata and report all schema errors with their instance paths."""
    validator = Draft202012Validator(_load_schema(schema_path.resolve()))
    errors = sorted(validator.iter_errors(metadata), key=lambda error: tuple(str(part) for part in error.absolute_path))
    if not errors:
        return

    details: list[str] = []
    for error in errors:
        instance_path = ".".join(str(part) for part in error.absolute_path) or "$"
        details.append(f"{instance_path}: {error.message}")
    message = f"{display_path} failed schema validation: {'; '.join(details)}"
    raise MetadataSchemaError(message)
