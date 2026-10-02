"""Release PR publication preserves line boundaries and maintainer decisions."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.docker_release_updates import apply_release
from scripts.release_pull_requests import (
    PublishContext,
    UpdateError,
    _assert_expected_metadata,
    _assert_generated_catalogue,
    _assert_paths,
    _owned_pulls,
    _publish_one,
    allowed_paths,
    classify_update,
    publish_updates,
)
from tests.test_docker_release_updates import NEW_VERSION, ROOT, _evidence


def _pull(version: str, *, state: str = "open", branch_version: str | None = None, auto_merge: bool = False) -> dict:
    return {
        "number": 42,
        "state": state,
        "body": f"<!-- docker-engine-update:29:{version} -->",
        "head": {
            "ref": f"automation/docker-engine-29-{branch_version or version}",
            "sha": "abc123",
            "repo": {"full_name": "strukturpiloten/containers"},
        },
        "base": {"ref": "main"},
        "user": {"login": "release-actor"},
        "auto_merge": {"enabled_at": "today"} if auto_merge else None,
        "assignees": [{"login": "TheRealBecks"}],
        "html_url": "https://github.com/strukturpiloten/containers/pull/42",
    }


class FakeGitHub:
    """In-memory REST fixture for publisher decisions."""

    repository = "strukturpiloten/containers"

    def __init__(self, pulls: list[dict] | None = None, files: list[dict] | None = None) -> None:
        """Keep PR metadata and changed-file responses."""
        self.pulls = pulls or []
        self.files = files if files is not None else [{"filename": "images/docker/upstream/29/payload.yaml"}]
        self.requests: list[tuple[str, str, dict]] = []

    def pages(self, path: str) -> list[dict]:
        return self.pulls if path.startswith("pulls?state=") else self.files

    def request(self, method: str, path: str, data: dict) -> dict:
        self.requests.append((method, path, data))
        if path == "pulls":
            return {
                "number": 200,
                "html_url": "https://github.com/strukturpiloten/containers/pull/200",
                "auto_merge": None,
            }
        if path.startswith("pulls/"):
            return {**self.pulls[0], **data}
        return {}


class ReleasePullRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _context(self, github: FakeGitHub) -> PublishContext:
        return PublishContext(self.root, github, "main", self.root / "evidence", ["TheRealBecks"], "release-actor")

    def test_paths_are_confined_to_one_existing_line_and_catalogue(self) -> None:
        paths = allowed_paths("29")
        self.assertEqual(len(paths), 5)
        self.assertIn("images/docker/upstream/29/payload.yaml", paths)
        self.assertIn("images/docker/docker-29-rootless/container.yaml", paths)
        self.assertNotIn("images/docker/upstream/28/payload.yaml", paths)
        with self.assertRaisesRegex(UpdateError, "Invalid Docker compatibility line"):
            allowed_paths("29/../../other")

    def test_renamed_source_outside_allowlist_is_detected(self) -> None:
        with (
            patch("scripts.release_pull_requests._run", return_value="README.md\n") as run,
            self.assertRaisesRegex(UpdateError, "README.md"),
        ):
            _assert_paths(self.root, "29", ["origin/main...origin/automation/docker-engine-29-29.8.2"])
        self.assertIn("--no-renames", run.call_args.args[0])

    def test_candidate_yaml_must_equal_fresh_evidence_applied_to_base(self) -> None:
        paths = (
            "images/docker/upstream/29/payload.yaml",
            "images/docker/docker-29-rootful/container.yaml",
            "images/docker/docker-29-rootless/container.yaml",
        )
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        evidence_dir = self.root / "evidence/29"
        evidence_dir.mkdir(parents=True)
        for arch in ("amd64", "arm64"):
            (evidence_dir / f"{arch}.json").write_text(json.dumps(_evidence(arch)), encoding="utf-8")
        apply_release("29", NEW_VERSION, evidence_dir, self.root)

        def base_show(arguments: list[str], _root: Path) -> str:
            return (ROOT / arguments[2].split(":", maxsplit=1)[1]).read_text(encoding="utf-8")

        with patch("scripts.release_pull_requests._run", side_effect=base_show):
            _assert_expected_metadata(self._context(FakeGitHub()), "29", NEW_VERSION)
            path = self.root / paths[1]
            metadata = yaml.safe_load(path.read_text(encoding="utf-8"))
            metadata["lifecycle"]["admission"] = "production"
            path.write_text(yaml.safe_dump(metadata), encoding="utf-8")
            with self.assertRaisesRegex(UpdateError, "differs from verified release"):
                _assert_expected_metadata(self._context(FakeGitHub()), "29", NEW_VERSION)

    def test_same_version_catalogue_must_match_generator_output(self) -> None:
        docs = self.root / "docs"
        docs.mkdir()
        committed = {"docs/image-catalogue.json": "canonical json", "docs/image-catalogue.md": "canonical markdown"}

        def regenerate(arguments: list[str], _root: Path) -> str:
            if arguments[:2] == ["git", "show"]:
                return committed[arguments[2].split(":", maxsplit=1)[1]]
            for relative, content in {
                "docs/image-catalogue.json": "canonical json",
                "docs/image-catalogue.md": "canonical markdown",
            }.items():
                (self.root / relative).write_text(content, encoding="utf-8")
            return ""

        with patch("scripts.release_pull_requests._run", side_effect=regenerate):
            _assert_generated_catalogue(self._context(FakeGitHub()), "origin/automation/docker-engine-29-29.8.2")
            committed["docs/image-catalogue.md"] = "tampered markdown"
            with self.assertRaisesRegex(UpdateError, "differs from generated output"):
                _assert_generated_catalogue(self._context(FakeGitHub()), "origin/automation/docker-engine-29-29.8.2")

    def test_local_invocation_stops_before_git_or_github_mutation(self) -> None:
        with (
            patch.dict("os.environ", {"GITHUB_ACTIONS": "false", "GITHUB_REF": "refs/heads/main"}),
            patch("scripts.release_pull_requests._run") as run,
            self.assertRaisesRegex(UpdateError, "trusted default-branch"),
        ):
            publish_updates(self.root, {"newLines": [], "dockerUpdates": []}, self.root / "evidence")
        run.assert_not_called()

    def test_classification_rejects_downgrade_and_line_crossing(self) -> None:
        self.assertEqual(classify_update("29", "29.8.1", "29.8.2"), "patch")
        self.assertEqual(classify_update("29", "29.8.1", "29.9.0"), "minor")
        self.assertEqual(classify_update("20.10", "20.10.24", "20.10.25"), "patch")
        with self.assertRaisesRegex(UpdateError, "advance"):
            classify_update("29", "29.8.1", "29.8.0")
        with self.assertRaisesRegex(UpdateError, "compatibility line"):
            classify_update("29", "29.8.1", "30.0.0")
        with self.assertRaisesRegex(UpdateError, "compatibility line"):
            classify_update("20.10", "20.10.24", "20.11.0")

    def test_ownership_requires_marker_branch_base_repo_and_allowed_files(self) -> None:
        owned = _pull("29.8.2")
        unrelated = [
            {**owned, "number": 43, "body": "No release marker"},
            {**owned, "number": 44, "head": {**owned["head"], "ref": "feature/unrelated"}},
            {**owned, "number": 45, "base": {"ref": "other"}},
            {**owned, "number": 46, "head": {**owned["head"], "repo": {"full_name": "someone/fork"}}},
        ]
        self.assertEqual(_owned_pulls(FakeGitHub([*unrelated, owned]), "29", "main", "release-actor"), [owned])
        bad_files = [{"filename": "images/docker/upstream/29/payload.yaml", "previous_filename": "README.md"}]
        with self.assertRaisesRegex(UpdateError, "unexpected files"):
            _owned_pulls(FakeGitHub([owned], bad_files), "29", "main", "release-actor")

    def test_same_version_open_pr_is_idempotent(self) -> None:
        github = FakeGitHub([_pull("29.8.2", auto_merge=True)])
        with (
            patch("scripts.release_pull_requests._run") as run,
            patch("scripts.release_pull_requests._queue_entry", return_value=False),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
            patch("scripts.release_pull_requests._assert_generated_catalogue"),
        ):
            _publish_one(self._context(github), {"line": "29", "version": "29.8.2"})
        self.assertFalse(
            any(
                command[:2] in (["git", "commit"], ["git", "push"])
                for command in (call.args[0] for call in run.call_args_list)
            )
        )
        self.assertEqual(github.requests, [])

    def test_same_version_retry_completes_missing_auto_merge(self) -> None:
        pull = _pull("29.8.2")
        pull["assignees"] = []
        github = FakeGitHub([pull])
        commands: list[list[str]] = []

        def record(arguments: list[str], _root: Path) -> str:
            commands.append(arguments)
            return ""

        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._queue_entry", return_value=False),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
            patch("scripts.release_pull_requests._assert_generated_catalogue"),
        ):
            _publish_one(self._context(github), {"line": "29", "version": "29.8.2"})
        self.assertTrue(any("--auto" in command and "abc123" in command for command in commands))
        self.assertTrue(any(path == "issues/42/assignees" for _, path, _ in github.requests))
        self.assertFalse(any("push" in command or "commit" in command for command in commands))

    def test_orphan_branch_is_adopted_only_when_no_pr_claims_it(self) -> None:
        github = FakeGitHub()
        commands: list[list[str]] = []

        def record(arguments: list[str], _root: Path) -> str:
            commands.append(arguments)
            if arguments[:3] == ["git", "ls-remote", "--heads"]:
                return "abc123 refs/heads/automation/docker-engine-29-29.8.2"
            return "abc123" if arguments[:3] == ["git", "rev-parse", "HEAD"] else ""

        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
            patch("scripts.release_pull_requests._assert_generated_catalogue"),
        ):
            _publish_one(self._context(github), {"line": "29", "version": "29.8.2"})
        self.assertTrue(any(command[:2] == ["git", "commit"] and "--allow-empty" in command for command in commands))
        self.assertTrue(any(method == "POST" and path == "pulls" for method, path, _ in github.requests))
        self.assertFalse(any("--force" in command for command in commands))

        impostor = _pull("29.8.2")
        impostor["user"]["login"] = "someone-else"
        github = FakeGitHub([impostor])
        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            self.assertRaisesRegex(UpdateError, "another PR"),
        ):
            _publish_one(self._context(github), {"line": "29", "version": "29.8.2"})
        self.assertEqual(github.requests, [])

    def test_queued_pr_remains_untouched_when_newer_release_arrives(self) -> None:
        github = FakeGitHub([_pull("29.8.2")])
        with (
            patch("scripts.release_pull_requests._queue_entry", return_value=True),
            patch("scripts.release_pull_requests._run") as run,
        ):
            _publish_one(self._context(github), {"line": "29", "version": "29.8.3"})
        run.assert_not_called()
        self.assertEqual(github.requests, [])

    def test_closed_decision_is_respected_but_newer_version_gets_new_branch(self) -> None:
        github = FakeGitHub([_pull("29.8.2", state="closed")])
        context = self._context(github)
        with patch("scripts.release_pull_requests._run") as run:
            _publish_one(context, {"line": "29", "version": "29.8.2"})
        run.assert_not_called()
        commands: list[list[str]] = []

        def record(arguments: list[str], _root: Path) -> str:
            commands.append(arguments)
            return "abc123" if arguments[:3] == ["git", "rev-parse", "HEAD"] else ""

        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
        ):
            _publish_one(context, {"line": "29", "version": "29.8.3"})
        self.assertIn(["git", "switch", "-C", "automation/docker-engine-29-29.8.3", "origin/main"], commands)
        self.assertTrue(any(method == "POST" and path == "pulls" for method, path, _ in github.requests))
        self.assertFalse(any("--force" in command or "-f" in command for command in commands))

    def test_patch_auto_merge_and_minor_disables_existing_auto_merge(self) -> None:
        commands: list[list[str]] = []

        def record(arguments: list[str], _root: Path) -> str:
            commands.append(arguments)
            return "abc123" if arguments[:3] == ["git", "rev-parse", "HEAD"] else ""

        patch_github = FakeGitHub()
        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
        ):
            _publish_one(self._context(patch_github), {"line": "29", "version": "29.8.2"})
        self.assertTrue(any("--auto" in command and "--match-head-commit" in command for command in commands))

        commands.clear()
        minor_github = FakeGitHub([_pull("29.8.2", auto_merge=True)])
        with (
            patch("scripts.release_pull_requests._run", side_effect=record),
            patch("scripts.release_pull_requests._current_version", return_value="29.8.1"),
            patch("scripts.release_pull_requests._assert_paths"),
            patch("scripts.release_pull_requests._assert_expected_metadata"),
            patch("scripts.release_pull_requests._assert_unmanaged_metadata"),
            patch("scripts.release_pull_requests._assert_generated_catalogue"),
            patch("scripts.release_pull_requests._queue_entry", return_value=False),
        ):
            _publish_one(self._context(minor_github), {"line": "29", "version": "29.9.0"})
        self.assertTrue(any("--disable-auto" in command for command in commands))
        self.assertFalse(any("--auto" in command for command in commands))
        self.assertFalse(any("--force" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
