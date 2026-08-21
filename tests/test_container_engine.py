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
            {
                "name": "base",
                "metadataFile": "images/runtime/base/container.yaml",
                "build": {},
                "dependencies": {"internal": []},
                "inputs": ["images/base/**"],
            },
            {
                "name": "app",
                "metadataFile": "images/apps/app/container.yaml",
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

    def test_validation_only_change_selects_no_images(self) -> None:
        for changed_file in (".github/renovate.json", "container.schema.json", "pyproject.toml", "uv.lock"):
            with (
                self.subTest(changed_file=changed_file),
                patch.object(engine, "_changed_files", return_value=[changed_file]),
            ):
                self.assertEqual(engine._selected_image_names(self.images, _options()), set())

    def test_unavailable_diff_uses_safe_full_rebuild(self) -> None:
        with patch.object(engine, "_changed_files", return_value=None):
            self.assertEqual(engine._selected_image_names(self.images, _options()), {"base", "app"})

    def test_reliable_empty_diff_selects_nothing(self) -> None:
        with patch.object(engine, "_changed_files", return_value=[]):
            self.assertEqual(engine._selected_image_names(self.images, _options()), set())

    def test_manual_image_and_family_selection(self) -> None:
        image_options = engine.PlanOptions(
            event_name="workflow_dispatch",
            ref_name="main",
            default_branch="main",
            before=None,
            sha="c" * 40,
            max_stages=None,
            scope="image",
            target="app",
        )
        family_options = engine.PlanOptions(
            event_name="workflow_dispatch",
            ref_name="main",
            default_branch="main",
            before=None,
            sha="c" * 40,
            max_stages=None,
            scope="family",
            target="runtime",
        )
        self.assertEqual(engine._selected_image_names(self.images, image_options), {"app"})
        self.assertEqual(engine._selected_image_names(self.images, family_options), {"base"})

    def test_manual_all_includes_images_excluded_from_schedule(self) -> None:
        images = [*self.images, {"name": "manual-only", "build": {"scheduled": False}}]
        options = engine.PlanOptions(
            event_name="workflow_dispatch",
            ref_name="main",
            default_branch="main",
            before=None,
            sha="c" * 40,
            max_stages=None,
        )
        self.assertEqual(engine._selected_image_names(images, options), {"base", "app", "manual-only"})

    def test_invalid_manual_target_fails(self) -> None:
        options = engine.PlanOptions(
            event_name="workflow_dispatch",
            ref_name="main",
            default_branch="main",
            before=None,
            sha="c" * 40,
            max_stages=None,
            scope="family",
            target="missing",
        )
        with self.assertRaisesRegex(engine.ContainerEngineError, "does not exist"):
            engine._selected_image_names(self.images, options)

    def test_pull_request_diff_uses_base_and_head(self) -> None:
        with patch.object(engine, "_changed_files", return_value=["images/app/Containerfile"]) as changed_files:
            options = engine.PlanOptions(
                event_name="pull_request",
                ref_name="feature",
                default_branch="main",
                before="b" * 40,
                sha="c" * 40,
                max_stages=None,
            )
            self.assertEqual(engine._selected_image_names(self.images, options), {"app"})
        changed_files.assert_called_once_with(before="b" * 40, sha="c" * 40, event_name="pull_request")

    def test_build_plan_exposes_smoke_matrix_and_selection_reason(self) -> None:
        images = engine._load_images()
        with patch.object(
            engine,
            "_changed_files",
            return_value=["images/nextcloud/nextcloud-notifypush/Containerfile"],
        ):
            plan = engine._build_plan(images, _options())
        self.assertEqual([image["name"] for image in plan["images"]], ["nextcloud-notifypush"])
        self.assertEqual(
            {entry["arch"] for entry in plan["smokeBuildMatrix"]["include"]},
            {"amd64", "arm64"},
        )
        self.assertEqual(plan["selection"]["reason"], "image-specific or shared runtime input changed")
        plan["eventName"] = "pull_request"
        self.assertIn("none (non-publishing)", engine._plan_summary(plan))


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

    def test_pr_smoke_build_uses_pinned_internal_fallback(self) -> None:
        context = self._context(event_name="pull_request")
        dependency = {"name": "base", "image": "ghcr.io/strukturpiloten/base"}
        image = {
            "name": "app",
            "build": {
                "runtimeBaseArg": "BASE_IMAGE",
                "args": {"BASE_IMAGE": {"type": "internal-image", "value": f"ghcr.io/strukturpiloten/base@{DIGEST}"}},
            },
            "dependencies": {"internal": [{"image": "base", "arg": "BASE_IMAGE"}]},
        }
        build_args, base_name, base_digest = engine._build_base_args(
            {"sourceRevision": context.sha, "images": [dependency, image]},
            image,
            context,
            None,
            use_published_dependency_fallback=True,
        )
        self.assertIn(f"BASE_IMAGE=ghcr.io/strukturpiloten/base@{DIGEST}", build_args)
        self.assertEqual(base_name, "ghcr.io/strukturpiloten/base")
        self.assertEqual(base_digest, DIGEST)

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
    def test_release_metadata_is_derived_from_selected_image(self) -> None:
        image, version, release_tags = engine._release_metadata("nextcloud-phpfpm")
        self.assertEqual(image["name"], "nextcloud-phpfpm")
        self.assertEqual(version, "1.0.0")
        self.assertEqual(release_tags, ["v1.0.0", "v1.0", "v1"])
        with self.assertRaisesRegex(engine.ContainerEngineError, "not found in repository metadata"):
            engine._release_metadata("missing")

    def test_release_info_writes_derived_version(self) -> None:
        with patch.object(engine, "_write_github_outputs") as outputs:
            engine._command_release_info(SimpleNamespace(image="nextcloud-notifypush"))
        outputs.assert_called_once_with(
            {
                "image_name": "nextcloud-notifypush",
                "version": "1.0.0",
                "release_tag": "v1.0.0",
            }
        )

    def test_release_workflow_choices_are_generated_from_metadata(self) -> None:
        workflow = engine._release_workflow(engine._load_images())
        self.assertIn("type: choice", workflow)
        self.assertIn("          - nextcloud-notifypush", workflow)
        self.assertIn("          - nextcloud-phpfpm", workflow)
        self.assertIn("          - typo3-phpfpm", workflow)
        self.assertEqual(workflow.count("          - nextcloud-notifypush\n"), 1)
        self.assertEqual(workflow.count("          - nextcloud-phpfpm\n"), 1)
        self.assertEqual(workflow.count("          - typo3-phpfpm\n"), 1)
        self.assertNotIn("example-servicename", workflow)
        self.assertNotIn("inputs.version", workflow)

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

    def test_source_timestamp_is_derived_from_git_commit(self) -> None:
        with (
            patch.object(engine, "_tool", return_value="git"),
            patch.object(engine, "_run", return_value="1700000000\n"),
        ):
            timestamp, created = engine._source_timestamp("c" * 40)
        self.assertEqual(timestamp, 1700000000)
        self.assertEqual(created, "2023-11-14T22:13:20Z")


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
        args = SimpleNamespace(
            image_name="example",
            image="ghcr.io/strukturpiloten/example",
            version="1.2.3",
            digest=DIGEST,
            default_branch="main",
            build_result=None,
        )
        with (
            patch.object(engine, "_github_context", return_value=context),
            patch.object(engine, "_tool", side_effect=lambda name: name),
            patch.object(engine, "_remote_digest", return_value=f"sha256:{'b' * 64}"),
            patch.object(engine, "_run") as run,
            self.assertRaisesRegex(engine.ContainerEngineError, "Refusing to overwrite immutable registry tag"),
        ):
            engine._command_promote_image(args)
        run.assert_not_called()

    def test_scheduled_rebuild_moves_released_semver_tags(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="schedule",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="1",
            run_id="100",
            server_url="https://github.com",
            sha="c" * 40,
            token="token",  # noqa: S106
        )
        args = SimpleNamespace(
            image_name="example",
            image="ghcr.io/strukturpiloten/example",
            version="1.2.3",
            digest=DIGEST,
            default_branch="main",
            build_result=None,
        )
        with (
            patch.object(engine, "_github_context", return_value=context),
            patch.object(engine, "_github_release_exists", return_value=True),
            patch.object(engine, "_tool", side_effect=lambda name: name),
            patch.object(engine, "_remote_digest", return_value=None),
            patch.object(engine, "_write_github_outputs") as outputs,
            patch.object(engine, "_run") as run,
        ):
            engine._command_promote_image(args)

        promoted_targets = [call.args[0][-1] for call in run.call_args_list]
        self.assertEqual(
            promoted_targets,
            [
                "docker://ghcr.io/strukturpiloten/example:main",
                "docker://ghcr.io/strukturpiloten/example:latest",
                "docker://ghcr.io/strukturpiloten/example:v1.2.3",
                "docker://ghcr.io/strukturpiloten/example:v1.2",
                "docker://ghcr.io/strukturpiloten/example:v1",
            ],
        )
        outputs.assert_called_once_with({"promoted_tags": "main,latest,v1.2.3,v1.2,v1"})

    def test_scheduled_rebuild_skips_semver_without_release(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="schedule",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="1",
            run_id="100",
            server_url="https://github.com",
            sha="c" * 40,
            token="token",  # noqa: S106
        )
        args = SimpleNamespace(
            image_name="example",
            image="ghcr.io/strukturpiloten/example",
            version="1.2.3",
            digest=DIGEST,
            default_branch="main",
            build_result=None,
        )
        with (
            patch.object(engine, "_github_context", return_value=context),
            patch.object(engine, "_github_release_exists", return_value=False),
            patch.object(engine, "_tool", side_effect=lambda name: name),
            patch.object(engine, "_remote_digest", return_value=None),
            patch.object(engine, "_write_github_outputs") as outputs,
            patch.object(engine, "_run") as run,
        ):
            engine._command_promote_image(args)
        self.assertEqual(len(run.call_args_list), 2)
        outputs.assert_called_once_with({"promoted_tags": "main,latest"})

    def test_scheduled_rebuild_records_promoted_tags_in_build_result(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="schedule",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="1",
            run_id="100",
            server_url="https://github.com",
            sha="c" * 40,
            token="token",  # noqa: S106
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            build_result_path = Path(temporary_directory) / "example-build-result.json"
            build_result_path.write_text(json.dumps({"tags": ["run-100-1"]}), encoding="utf-8")
            args = SimpleNamespace(
                image_name="example",
                image="ghcr.io/strukturpiloten/example",
                version="1.2.3",
                digest=DIGEST,
                default_branch="main",
                build_result=str(build_result_path),
            )
            with (
                patch.object(engine, "_github_context", return_value=context),
                patch.object(engine, "_github_release_exists", return_value=True),
                patch.object(engine, "_tool", side_effect=lambda name: name),
                patch.object(engine, "_remote_digest", return_value=None),
                patch.object(engine, "_write_github_outputs"),
                patch.object(engine, "_run"),
            ):
                engine._command_promote_image(args)

            result = json.loads(build_result_path.read_text(encoding="utf-8"))

        self.assertEqual(result["tags"], ["run-100-1", "main", "latest", "v1.2.3", "v1.2", "v1"])


class RepositoryValidationTests(unittest.TestCase):
    def test_repository_metadata_validates(self) -> None:
        images = engine._load_images()
        engine._validate_images(images)
        self.assertGreaterEqual(len(images), 3)


if __name__ == "__main__":
    unittest.main()
