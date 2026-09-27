"""Registry promotion scenarios that can arise from reruns and partial publication."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import container_engine as engine
from scripts.promotion import RUN_ATTEMPT_ANNOTATION, RUN_ID_ANNOTATION, PublicationIdentity

IMAGE = "ghcr.io/strukturpiloten/example"
OLD = f"sha256:{'a' * 64}"
NEW = f"sha256:{'b' * 64}"
REVISION = "c" * 40


def _annotations(run_id: int, attempt: int = 1, revision: str = REVISION) -> dict[str, str]:
    return {
        RUN_ID_ANNOTATION: str(run_id),
        RUN_ATTEMPT_ANNOTATION: str(attempt),
        "org.opencontainers.image.revision": revision,
    }


class PublicationScenarios(unittest.TestCase):
    def test_local_oci_index_records_publication_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = Path(directory)
            blobs = layout / "blobs" / "sha256"
            blobs.mkdir(parents=True)
            original = json.dumps({"schemaVersion": 2, "manifests": [{"digest": OLD}]}).encode()
            original_digest = hashlib.sha256(original).hexdigest()
            (blobs / original_digest).write_bytes(original)
            (layout / "index.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.index.v1+json",
                                "digest": f"sha256:{original_digest}",
                                "size": len(original),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            engine._annotate_oci_layout(layout, _annotations(100, 2))
            descriptor = json.loads((layout / "index.json").read_text(encoding="utf-8"))["manifests"][0]
            content = (blobs / descriptor["digest"].removeprefix("sha256:")).read_bytes()
            self.assertEqual(descriptor["size"], len(content))
            self.assertEqual(descriptor["digest"], f"sha256:{hashlib.sha256(content).hexdigest()}")
            self.assertEqual(json.loads(content)["annotations"], _annotations(100, 2))

    def test_index_annotations_identify_rerun_independent_of_archives(self) -> None:
        raw_index = json.dumps({"schemaVersion": 2, "manifests": [], "annotations": _annotations(100, 2)})
        context = engine._GitHubContext(
            actor="actor",
            event_name="schedule",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=None,
        )
        with (
            patch.object(engine, "_run_external", return_value=raw_index) as run,
            patch.object(engine, "_remote_digest", return_value=OLD),
        ):
            identity = engine._validate_publication_source(["skopeo"], IMAGE, OLD, context)
        self.assertEqual(identity, PublicationIdentity(100, 2))
        self.assertIn("--raw", run.call_args.args[0])

    def test_finalize_rerun_accepts_prior_successful_publish_attempt(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="schedule",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "build-result.json"
            result_path.write_text(
                json.dumps(
                    {
                        "imageName": "example",
                        "image": IMAGE,
                        "version": "1.0.0",
                        "sourceRevision": REVISION,
                        "indexDigest": OLD,
                        "runId": "100",
                        "runAttempt": "1",
                    }
                ),
                encoding="utf-8",
            )
            engine._validated_release_build_result(
                result_path, context=context, image_name="example", image_ref=IMAGE, version="1.0.0"
            )
        with (
            patch.object(engine, "_registry_annotations", return_value=_annotations(100, 1)),
            patch.object(engine, "_remote_digest", return_value=OLD) as digest,
        ):
            identity = engine._validate_publication_source(
                ["skopeo"], IMAGE, OLD, context, expected_identity=PublicationIdentity(100, 1)
            )
        self.assertEqual(identity, PublicationIdentity(100, 1))
        self.assertIn("run-100-1-sha-", digest.call_args.args[1])

    def test_retry_reuses_prior_immutable_publication_before_any_registry_copy(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="push",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=REVISION,
        )
        raw_index = json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": NEW}]})
        canonical = engine.canonical_build_tag(sha=REVISION, run_id="100", run_attempt="1")
        image = {"image": IMAGE, "version": "v1.0.0", "build": {"args": {}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archives = root / "archives"
            archives.mkdir()
            (archives / "example-amd64.tar").write_bytes(b"archive")
            args = SimpleNamespace(
                entry_json="{}",
                plan=str(root / "plan.json"),
                archives_dir=str(archives),
                output_dir=str(root / "results"),
                default_branch="main",
            )

            def digest(_prefix: list[str], reference: str) -> str | None:
                if reference in {f"{IMAGE}:sha-{REVISION}", f"{IMAGE}:{canonical}"}:
                    return OLD
                return None

            with (
                patch.object(engine, "_entry", return_value=("example", None)),
                patch.object(engine, "_github_context", return_value=context),
                patch.object(engine, "_load_json", return_value={"sourceRevision": REVISION}),
                patch.object(engine, "_plan_image", return_value=image),
                patch.object(engine, "_image_architectures", return_value=["amd64"]),
                patch.object(engine, "_tool", side_effect=lambda name: name),
                patch.object(engine, "_run"),
                patch.object(engine, "_annotate_oci_layout"),
                patch.object(engine, "_oci_layout_index_raw", return_value=raw_index),
                patch.object(engine, "_remote_digest", side_effect=digest),
                patch.object(engine, "_registry_annotations", return_value=_annotations(100, 1)),
                patch.object(
                    engine,
                    "_run_external",
                    side_effect=lambda command, **_kwargs: raw_index if "--raw" in command else "",
                ) as external,
                patch.object(engine, "_write_github_outputs") as outputs,
                patch.object(engine.subprocess, "run"),
            ):
                engine._command_publish_image(args)
            result = json.loads((root / "results" / "example-build-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["indexDigest"], OLD)
            self.assertEqual(result["runAttempt"], "1")
            self.assertEqual(result["architectureDigests"], {"amd64": NEW})
            self.assertEqual(outputs.call_args.args[0]["canonical_tag"], canonical)
            self.assertFalse(any("copy" in call.args[0] for call in external.call_args_list))
            promote_args = SimpleNamespace(
                image=IMAGE,
                digest=OLD,
                build_result=str(root / "results" / "example-build-result.json"),
                default_branch="main",
            )
            with (
                patch.object(engine, "_github_context", return_value=context),
                patch.object(engine, "_tool", side_effect=lambda name: name),
                patch.object(engine, "_registry_annotations", return_value=_annotations(100, 1)),
                patch.object(engine, "_remote_digest", return_value=OLD),
                patch.object(engine, "_write_github_outputs"),
            ):
                engine._command_promote_image(promote_args)
            promoted = json.loads((root / "results" / "example-build-result.json").read_text(encoding="utf-8"))
            self.assertEqual(promoted["runAttempt"], "1")
            self.assertIn(f"sha-{REVISION}", promoted["tags"])

    def test_immutable_retry_rejects_changed_architecture_contents(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="push",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=None,
        )
        remote = json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": NEW}]})
        with (
            patch.object(engine, "_remote_digest", return_value=OLD),
            patch.object(engine, "_registry_annotations", return_value=_annotations(100, 1)),
            patch.object(engine, "_run_external", return_value=remote),
            self.assertRaisesRegex(engine.ContainerEngineError, "different architecture contents"),
        ):
            engine._reusable_immutable_publication(["skopeo"], IMAGE, REVISION, {"amd64": OLD}, context)

    def test_immutable_retry_rejects_other_run_even_with_same_contents(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="push",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=None,
        )
        for foreign_run in (99, 101):
            with (
                self.subTest(foreign_run=foreign_run),
                patch.object(engine, "_remote_digest", return_value=OLD),
                patch.object(engine, "_registry_annotations", return_value=_annotations(foreign_run, 1)),
                self.assertRaisesRegex(engine.ContainerEngineError, "another publication"),
            ):
                engine._reusable_immutable_publication(["skopeo"], IMAGE, REVISION, {"amd64": NEW}, context)

    def test_promotion_accepts_prior_attempt_result_from_same_run(self) -> None:
        context = engine._GitHubContext(
            actor="actor",
            event_name="push",
            ref_name="main",
            repository="Strukturpiloten/containers",
            run_attempt="2",
            run_id="100",
            server_url="https://github.com",
            sha=REVISION,
            token=None,
        )
        result = {
            "image": IMAGE,
            "indexDigest": OLD,
            "sourceRevision": REVISION,
            "runId": "100",
            "runAttempt": "1",
            "tags": [],
        }
        args = SimpleNamespace(image=IMAGE, digest=OLD, build_result="result.json", default_branch="main")
        with (
            patch.object(engine, "_github_context", return_value=context),
            patch.object(engine, "_load_json", return_value=result),
            patch.object(engine, "_tool", side_effect=lambda name: name),
            patch.object(engine, "_registry_annotations", return_value=_annotations(100, 1)),
            patch.object(engine, "_remote_digest", return_value=OLD),
            patch.object(engine, "_write_json") as write,
            patch.object(engine, "_write_github_outputs"),
        ):
            engine._command_promote_image(args)
        write.assert_called_once()
        self.assertEqual(result["runAttempt"], "1")

    def _preflight(
        self,
        *,
        candidate: PublicationIdentity,
        current: dict[str, str | None],
        annotations: dict[str, dict[str, str]],
        legacy_labels: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, str | None]:
        with (
            patch.object(engine, "_remote_digest", side_effect=lambda _prefix, reference: current[reference]),
            patch.object(
                engine, "_registry_annotations", side_effect=lambda _prefix, reference: annotations[reference]
            ),
            patch.object(
                engine, "_registry_labels", side_effect=lambda _prefix, reference: (legacy_labels or {})[reference]
            ),
        ):
            return engine._preflight_promotion(
                ["skopeo"], IMAGE, OLD, tags=["main", "latest"], identity=candidate, source_revision=REVISION
            )

    def test_older_run_cannot_replace_newer_successful_aliases(self) -> None:
        current = {f"{IMAGE}:main": NEW, f"{IMAGE}:latest": NEW}
        annotations = {reference: _annotations(200) for reference in current}
        with self.assertRaisesRegex(engine.ContainerEngineError, "Stale publication"):
            self._preflight(candidate=PublicationIdentity(100, 2), current=current, annotations=annotations)

    def test_partial_publication_rejects_before_copying_any_alias(self) -> None:
        current = {f"{IMAGE}:main": OLD, f"{IMAGE}:latest": NEW}
        annotations = {f"{IMAGE}:latest": _annotations(200)}
        with self.assertRaisesRegex(engine.ContainerEngineError, "Stale publication"):
            self._preflight(candidate=PublicationIdentity(100, 2), current=current, annotations=annotations)

    def test_same_source_newer_rebuild_may_promote_and_old_rebuild_may_not(self) -> None:
        current = {f"{IMAGE}:main": NEW, f"{IMAGE}:latest": NEW}
        annotations = {reference: _annotations(100, 1) for reference in current}
        self.assertEqual(
            self._preflight(candidate=PublicationIdentity(100, 2), current=current, annotations=annotations),
            {"main": NEW, "latest": NEW},
        )
        newer_annotations = {reference: _annotations(100, 2) for reference in current}
        with self.assertRaisesRegex(engine.ContainerEngineError, "Stale publication"):
            self._preflight(candidate=PublicationIdentity(100, 1), current=current, annotations=newer_annotations)

    def test_identical_retry_is_idempotent_even_with_legacy_alias(self) -> None:
        current = {f"{IMAGE}:main": OLD, f"{IMAGE}:latest": OLD}
        self.assertEqual(
            self._preflight(candidate=PublicationIdentity(100, 2), current=current, annotations={}),
            {"main": OLD, "latest": OLD},
        )

    def test_legacy_alias_requires_strict_source_ancestry(self) -> None:
        current = {f"{IMAGE}:main": NEW, f"{IMAGE}:latest": None}
        annotations = {f"{IMAGE}:main": {}}
        labels = {f"{IMAGE}:main": {"org.opencontainers.image.revision": "d" * 40}}
        with patch.object(engine, "_git_is_strict_ancestor", return_value=True) as ancestor:
            self.assertEqual(
                self._preflight(
                    candidate=PublicationIdentity(100, 1),
                    current=current,
                    annotations=annotations,
                    legacy_labels=labels,
                ),
                {"main": NEW, "latest": None},
            )
        ancestor.assert_called_once_with("d" * 40, REVISION)

        labels[f"{IMAGE}:main"]["org.opencontainers.image.revision"] = REVISION
        with self.assertRaisesRegex(engine.ContainerEngineError, "strict ancestor"):
            self._preflight(
                candidate=PublicationIdentity(100, 1),
                current=current,
                annotations=annotations,
                legacy_labels=labels,
            )

    def test_explicit_rollback_requires_expected_current_digest(self) -> None:
        args = SimpleNamespace(
            image=IMAGE,
            tag="latest",
            digest=OLD,
            expected_current_digest=NEW,
            reason="incident-123",
        )
        with (
            patch.object(engine, "_tool", return_value="skopeo"),
            patch.object(engine, "_remote_digest", side_effect=[OLD, NEW]),
            patch.object(engine, "_run_external") as copy,
        ):
            engine._command_rollback_image(args)
        self.assertIn("--preserve-digests", copy.call_args.args[0])

        with (
            patch.object(engine, "_tool", return_value="skopeo"),
            patch.object(engine, "_remote_digest", side_effect=[OLD, OLD]),
            patch.object(engine, "_run_external") as copy,
            self.assertRaisesRegex(engine.ContainerEngineError, "changed"),
        ):
            engine._command_rollback_image(args)
        copy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
