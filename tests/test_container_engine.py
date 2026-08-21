"""Unit tests for dependency planning and release validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import container_engine as engine

DIGEST = f"sha256:{'a' * 64}"


def _options() -> engine.PlanOptions:
    return engine.PlanOptions(
        event_name="push",
        ref_name="main",
        default_branch="main",
        before="b" * 40,
        sha="c" * 40,
        max_stages=None,
    )


class PlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.images = [
            {"name": "base", "build": {}, "dependencies": {"internal": []}, "inputs": ["images/base/**"]},
            {
                "name": "app",
                "build": {},
                "dependencies": {"internal": [{"image": "base", "arg": "BASE_IMAGE"}]},
                "inputs": ["images/app/**"],
            },
        ]

    def test_topological_levels_and_reverse_dependencies(self) -> None:
        self.assertEqual(engine._topological_levels(self.images), [["base"], ["app"]])
        self.assertEqual(engine._expand_reverse_dependencies(self.images, {"base"}), {"base", "app"})

    def test_changed_image_selection(self) -> None:
        with patch.object(engine, "_changed_files", return_value=["images/app/Containerfile"]):
            self.assertEqual(engine._selected_image_names(self.images, _options()), {"app"})

    def test_global_automation_change_selects_every_image(self) -> None:
        with patch.object(engine, "_changed_files", return_value=["scripts/container_engine.py"]):
            self.assertEqual(engine._selected_image_names(self.images, _options()), {"base", "app"})

    def test_unavailable_diff_uses_safe_full_rebuild(self) -> None:
        with patch.object(engine, "_changed_files", return_value=None):
            self.assertEqual(engine._selected_image_names(self.images, _options()), {"base", "app"})

    def test_reliable_empty_diff_selects_nothing(self) -> None:
        with patch.object(engine, "_changed_files", return_value=[]):
            self.assertEqual(engine._selected_image_names(self.images, _options()), set())


class InternalDependencyTests(unittest.TestCase):
    @staticmethod
    def _context(*, event_name: str = "push") -> engine._GitHubContext:
        return engine._GitHubContext(
            actor="actor",
            event_name=event_name,
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="1",
            run_id="100",
            server_url="https://github.com",
            sha="c" * 40,
            token=None,
        )

    def test_selected_internal_dependency_uses_published_digest(self) -> None:
        context = self._context()
        dependency = {"name": "base", "image": "ghcr.io/strukturpiloten/base"}
        image = {
            "name": "app",
            "build": {
                "runtimeBaseArg": "BASE_IMAGE",
                "args": {"BASE_IMAGE": {"type": "internal-image", "value": f"ghcr.io/strukturpiloten/base@{DIGEST}"}},
            },
            "dependencies": {"internal": [{"image": "base", "arg": "BASE_IMAGE"}]},
        }
        plan = {"images": [dependency, image]}

        with tempfile.TemporaryDirectory() as temporary_directory:
            result_path = Path(temporary_directory) / "base-build-result.json"
            result_path.write_text(
                json.dumps(
                    {
                        "imageName": "base",
                        "image": "ghcr.io/strukturpiloten/base",
                        "sourceRevision": context.sha,
                        "indexDigest": DIGEST,
                    }
                ),
                encoding="utf-8",
            )
            build_args, base_name, base_digest = engine._build_base_args(
                plan,
                image,
                context,
                Path(temporary_directory),
            )

        self.assertIn(f"BASE_IMAGE=ghcr.io/strukturpiloten/base@{DIGEST}", build_args)
        self.assertEqual(base_name, "ghcr.io/strukturpiloten/base")
        self.assertEqual(base_digest, DIGEST)

    def test_dependency_result_revision_must_match(self) -> None:
        dependency = {"name": "base", "image": "ghcr.io/strukturpiloten/base"}
        with tempfile.TemporaryDirectory() as temporary_directory:
            result_path = Path(temporary_directory) / "base-build-result.json"
            result_path.write_text(
                json.dumps(
                    {
                        "imageName": "base",
                        "image": "ghcr.io/strukturpiloten/base",
                        "sourceRevision": "wrong",
                        "indexDigest": DIGEST,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(engine.ContainerEngineError, "different source revision"):
                engine._dependency_result_reference(
                    dependency_name="base",
                    dependency_image=dependency,
                    dependency_results_dir=Path(temporary_directory),
                    source_revision="expected",
                )

    def test_runtime_base_comes_from_explicit_runtime_argument(self) -> None:
        images = engine._load_images()
        image = next(candidate for candidate in images if candidate["name"] == "nextcloud-notifypush")
        _build_args, base_name, base_digest = engine._build_base_args(
            {"images": [image]},
            image,
            self._context(),
            None,
        )
        self.assertEqual(base_name, "docker.io/alpine:3.24.1")
        self.assertEqual(base_digest, "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b")


class ReleaseValidationTests(unittest.TestCase):
    def test_release_candidate_must_match_revision_and_version(self) -> None:
        inspection = {
            "Digest": DIGEST,
            "Labels": {
                "org.opencontainers.image.revision": "c" * 40,
                "org.opencontainers.image.version": "1.2.3",
            },
        }
        self.assertEqual(
            engine._validate_release_inspection(
                inspection,
                source_reference="example:sha-source",
                source_revision="c" * 40,
                version="1.2.3",
            ),
            DIGEST,
        )

        with self.assertRaisesRegex(engine.ContainerEngineError, "does not carry OCI version"):
            engine._validate_release_inspection(
                inspection,
                source_reference="example:sha-source",
                source_revision="c" * 40,
                version="2.0.0",
            )


class PromotionTests(unittest.TestCase):
    def test_existing_sha_tag_cannot_be_overwritten(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="push",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="1",
            run_id="100",
            server_url="https://github.com",
            sha="c" * 40,
            token=None,
        )
        args = SimpleNamespace(image="ghcr.io/strukturpiloten/example", digest=DIGEST, default_branch="main")
        with (
            patch.object(engine, "_github_context", return_value=context),
            patch.object(engine, "_tool", side_effect=lambda name: name),
            patch.object(engine, "_remote_digest", return_value=f"sha256:{'b' * 64}"),
            patch.object(engine, "_run") as run,
            self.assertRaisesRegex(engine.ContainerEngineError, "Refusing to overwrite immutable registry tag"),
        ):
            engine._command_promote_image(args)
        run.assert_not_called()


class RepositoryValidationTests(unittest.TestCase):
    def test_repository_metadata_validates(self) -> None:
        images = engine._load_images()
        engine._validate_images(images)
        self.assertGreaterEqual(len(images), 3)


if __name__ == "__main__":
    unittest.main()
