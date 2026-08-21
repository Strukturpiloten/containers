"""Tests for the checked-in container metadata schema."""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path

import yaml

from scripts.metadata_schema import MetadataSchemaError, validate_metadata_schema

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPOSITORY_ROOT / "container.schema.json"
EXAMPLE_PATH = REPOSITORY_ROOT / "images/_example/example-servicename/container.yaml"


class MetadataSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.example = yaml.safe_load(EXAMPLE_PATH.read_text(encoding="utf-8"))

    def test_example_satisfies_schema(self) -> None:
        validate_metadata_schema(self.example, schema_path=SCHEMA_PATH, display_path="example")

    def test_unknown_fields_are_rejected(self) -> None:
        metadata = deepcopy(self.example)
        metadata["unexpected"] = True
        with self.assertRaisesRegex(MetadataSchemaError, "Additional properties are not allowed"):
            validate_metadata_schema(metadata, schema_path=SCHEMA_PATH, display_path="example")

    def test_image_arguments_require_digest_pinning(self) -> None:
        metadata = deepcopy(self.example)
        metadata["build"]["args"]["BASE_IMAGE"]["value"] = "docker.io/library/example:latest"
        with self.assertRaisesRegex(MetadataSchemaError, "does not match"):
            validate_metadata_schema(metadata, schema_path=SCHEMA_PATH, display_path="example")

    def test_schema_version_is_enforced(self) -> None:
        metadata = deepcopy(self.example)
        metadata["schemaVersion"] = 2
        with self.assertRaisesRegex(MetadataSchemaError, "1 was expected"):
            validate_metadata_schema(metadata, schema_path=SCHEMA_PATH, display_path="example")


if __name__ == "__main__":
    unittest.main()
