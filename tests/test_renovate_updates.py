"""Regenerate real Git snapshots without executing PR code or overwriting new heads."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import container_engine as engine
from scripts import renovate_updates as repair
from tests.test_maintenance import IMAGE as CATALOGUE_FIXTURE
from tests.test_workflow_config import FIXTURE

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ".github/workflow-templates/documentation.yml.j2"
OUTPUT = ".github/workflows/documentation.yml"
IMAGE = "images/fixtures/example/container.yaml"
# Authored fixture only; these versions and image digests are not registry evidence.
METADATA_FIXTURE = {
    **CATALOGUE_FIXTURE,
    "schemaVersion": 1,
    "version": "v98.76.54",
    "title": "Synthetic fixture",
    "description": "Independent test data for generated dependency files",
    "build": {
        "context": ".",
        "containerfile": "Containerfile",
        "architectures": ["amd64"],
        "runtimeBaseArg": "BASE_IMAGE",
        "args": {"BASE_IMAGE": {"value": f"docker.io/library/alpine:3.24@sha256:{'a' * 64}", "type": "external-image"}},
    },
    "dependencies": {
        "internal": [],
        "external": [{"name": "alpine", "image": "docker.io/library/alpine", "arg": "BASE_IMAGE"}],
    },
    "inputs": ["Containerfile"],
}
TEMPLATE = """name: Fixture
on: workflow_dispatch
env:
  PYTHON_VERSION: "<<( config.PYTHON_VERSION )>>"
jobs:
  pages:
    runs-on: <<( config.AMD64_RUNNER )>>
    steps:
      - uses: actions/deploy-pages@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4
      - uses: actions/upload-pages-artifact@cccccccccccccccccccccccccccccccccccccccc # v4
"""


def _pull() -> dict:
    return {
        "number": 42,
        "state": "open",
        "draft": False,
        "user": {"login": "renovate[bot]", "type": "Bot", "id": 29139614},
        "base": {"ref": "main"},
        "head": {"sha": "a" * 40, "ref": "renovate/package", "repo": {"full_name": "example/repo"}},
    }


class GeneratedSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        repair._git(self.root, "init", "--initial-branch=main")
        repair._git(self.root, "config", "user.name", "Fixture")
        repair._git(self.root, "config", "user.email", "fixture@example.invalid")
        shutil.copyfile(ROOT / "container.schema.json", self.root / "container.schema.json")
        first = self.commit(
            {
                SOURCE: TEMPLATE,
                repair.CONFIG: yaml.safe_dump(FIXTURE),
                IMAGE: yaml.safe_dump(METADATA_FIXTURE),
                "pyproject.toml": '[project]\nrequires-python = ">=3.14,<3.15"\n',
                "uv.lock": 'requires-python = "==3.14.*"\n',
            }
        )
        self.base = self.commit(repair.generated_changes(self.root, first, first))

    def commit(self, files: dict[str, str]) -> str:
        for relative, text in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        repair._git(self.root, "add", "--all")
        repair._git(self.root, "commit", "--no-verify", "-m", "Fixture")
        return repair._git(self.root, "rev-parse", "HEAD").strip()

    def assert_idempotent(self, head: str, changes: dict[str, str]) -> None:
        completed = repair._commit(self.root, head, changes)
        self.assertEqual(repair._git(self.root, "rev-parse", f"{completed}^1").strip(), head)
        self.assertEqual(repair.generated_changes(self.root, self.base, completed), {})
        self.assertEqual(repair._git(self.root, "status", "--porcelain"), "")

    def test_podman_update_regenerates_catalogue_without_modifying_checkout(self) -> None:
        image = yaml.safe_load((self.root / IMAGE).read_text())
        image["version"] = "v98.76.55"
        head = self.commit({IMAGE: yaml.safe_dump(image)})
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertEqual(set(changes), {repair.CATALOGUE[0]})
        self.assertEqual(json.loads(changes[repair.CATALOGUE[0]])["images"][0]["version"], "v98.76.55")
        self.assert_idempotent(head, changes)

    def test_generated_only_pages_updates_reach_template(self) -> None:
        output = (self.root / OUTPUT).read_text().replace("a" * 40 + " # v4", "b" * 40 + " # v5")
        output = output.replace("c" * 40 + " # v4", "d" * 40 + " # v5.0.0")
        head = self.commit({OUTPUT: output})
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertEqual(set(changes), {SOURCE})
        self.assertIn("b" * 40 + " # v5", changes[SOURCE])
        self.assertIn("d" * 40 + " # v5.0.0", changes[SOURCE])
        self.assert_idempotent(head, changes)

    def test_template_only_action_update_regenerates_output(self) -> None:
        head = self.commit({SOURCE: TEMPLATE.replace("a" * 40 + " # v4", "b" * 40 + " # v5")})
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertEqual(set(changes), {OUTPUT})
        self.assertIn("b" * 40 + " # v5", changes[OUTPUT])
        self.assert_idempotent(head, changes)

    def test_major_and_full_action_tag_updates_agree_when_commit_is_identical(self) -> None:
        head = self.commit(
            {
                SOURCE: TEMPLATE.replace("a" * 40 + " # v4", "b" * 40 + " # v5.0.0"),
                OUTPUT: (self.root / OUTPUT).read_text().replace("a" * 40 + " # v4", "b" * 40 + " # v5"),
            }
        )
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertIn("b" * 40 + " # v5.0.0", changes[OUTPUT])
        self.assert_idempotent(head, changes)

    def test_python_migration_without_explicit_interpreter_pin_is_rejected(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15,<3.16"\n',
                "uv.lock": 'requires-python = "==3.15.*"\n',
            }
        )
        with self.assertRaisesRegex(repair.RepairError, "runtime does not match"):
            repair.generated_changes(self.root, self.base, head)

    def test_python_migration_without_matching_lock_is_rejected(self) -> None:
        head = self.commit({"pyproject.toml": '[project]\nrequires-python = ">=3.15,<3.16"\n'})
        with self.assertRaisesRegex(repair.RepairError, "matching lockfile"):
            repair.generated_changes(self.root, self.base, head)

    def test_coordinated_python_migration_preserves_explicit_patch_pin(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15,<3.16"\n',
                "uv.lock": 'requires-python = "==3.15.*"\n',
                repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.15.4"}),
            }
        )
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertNotIn(repair.CONFIG, changes)
        self.assertEqual(yaml.safe_load(changes[OUTPUT])["env"]["PYTHON_VERSION"], "3.15.4")
        self.assert_idempotent(head, changes)

    def test_immature_or_floating_python_migration_is_rejected(self) -> None:
        for version in ("3.15", "3.15.0", "3.15.1", "3.15.2", "3.15.3"):
            with self.subTest(version=version):
                head = self.commit(
                    {
                        "pyproject.toml": '[project]\nrequires-python = ">=3.15,<3.16"\n',
                        "uv.lock": 'requires-python = "==3.15.*"\n',
                        repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": version}),
                    }
                )
                with self.assertRaisesRegex(repair.RepairError, "patch level 4 or later"):
                    repair.generated_changes(self.root, self.base, head)

    def test_patch_specific_python_requirement_and_lock_migrate_automatically(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15.4, <3.16"\n',
                "uv.lock": 'requires-python = ">=3.15.4, <3.16"\n',
                repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.15.4"}),
            }
        )
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertEqual(yaml.safe_load(changes[OUTPUT])["env"]["PYTHON_VERSION"], "3.15.4")
        self.assert_idempotent(head, changes)

    def test_python_pin_below_project_patch_requirement_is_rejected(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15.5,<3.16"\n',
                "uv.lock": 'requires-python = ">=3.15.5, <3.16"\n',
                repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.15.4"}),
            }
        )
        with self.assertRaisesRegex(repair.RepairError, "runtime does not match"):
            repair.generated_changes(self.root, self.base, head)

    def test_python_patch_requirement_rejects_a_broad_stale_lock(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15.4,<3.16"\n',
                "uv.lock": 'requires-python = "==3.15.*"\n',
                repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.15.4"}),
            }
        )
        with self.assertRaisesRegex(repair.RepairError, "matching lockfile"):
            repair.generated_changes(self.root, self.base, head)

    def test_python_patch_update_within_supported_line_is_preserved(self) -> None:
        head = self.commit({repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.14.8"})})
        changes = repair.generated_changes(self.root, self.base, head)
        self.assertNotIn(repair.CONFIG, changes)
        self.assertEqual(yaml.safe_load(changes[OUTPUT])["env"]["PYTHON_VERSION"], "3.14.8")
        self.assert_idempotent(head, changes)

    def test_new_main_templates_are_included_in_a_python_repair(self) -> None:
        head = self.commit(
            {
                "pyproject.toml": '[project]\nrequires-python = ">=3.15,<3.16"\n',
                "uv.lock": 'requires-python = "==3.15.*"\n',
                repair.CONFIG: yaml.safe_dump({**FIXTURE, "PYTHON_VERSION": "3.15.4"}),
            }
        )
        repair._git(self.root, "switch", "-c", "advanced-main", self.base)
        new_source = ".github/workflow-templates/new-workflow.yml.j2"
        new_output = ".github/workflows/new-workflow.yml"
        main = self.commit({new_source: TEMPLATE, new_output: (self.root / OUTPUT).read_text()})
        merged = repair._merge_snapshot(self.root, head, main)
        self.assertIsNotNone(merged)
        changes = repair.generated_changes(self.root, main, merged)
        self.assertEqual(yaml.safe_load(changes[new_output])["env"]["PYTHON_VERSION"], "3.15.4")
        completed = repair._commit(self.root, head, changes, merged=merged, default_head=main)
        self.assertEqual(repair._git(self.root, "rev-parse", f"{completed}^1").strip(), head)
        self.assertEqual(repair._git(self.root, "rev-parse", f"{completed}^2").strip(), main)
        self.assertEqual(repair.generated_changes(self.root, main, completed), {})

    def test_real_merge_conflict_is_deferred_to_renovate(self) -> None:
        head = self.commit({"fixture.txt": "pr change\n"})
        repair._git(self.root, "switch", "-c", "advanced-main", self.base)
        main = self.commit({"fixture.txt": "main change\n"})
        self.assertIsNone(repair._merge_snapshot(self.root, head, main))

    def test_plain_main_merge_is_distinct_from_a_custom_human_commit(self) -> None:
        repair._git(self.root, "config", "user.email", "29139614+renovate[bot]@users.noreply.github.com")
        head = self.commit({"dependency.txt": "bot update\n"})
        repair._git(self.root, "switch", "-c", "advanced-main", self.base)
        repair._git(self.root, "config", "user.email", "person@example.invalid")
        main = self.commit({"main.txt": "trusted change\n"})
        repair._git(self.root, "update-ref", "refs/remotes/origin/main", main)
        repair._git(self.root, "switch", "--detach", head)
        repair._git(self.root, "merge", "--no-edit", main)
        merged = repair._git(self.root, "rev-parse", "HEAD").strip()
        pull = _pull()
        pull["head"]["sha"] = merged
        self.assertFalse(repair._custom_commits(self.root, "main", pull))
        pull["head"]["sha"] = self.commit({"custom.txt": "human edit\n"})
        self.assertTrue(repair._custom_commits(self.root, "main", pull))

    def test_conflicting_action_candidates_are_rejected(self) -> None:
        head = self.commit(
            {
                SOURCE: TEMPLATE.replace("a" * 40, "b" * 40),
                OUTPUT: (self.root / OUTPUT).read_text().replace("a" * 40, "e" * 40),
            }
        )
        with self.assertRaisesRegex(repair.RepairError, "Conflicting action"):
            repair.generated_changes(self.root, self.base, head)

    def test_template_code_changes_are_rejected_before_rendering(self) -> None:
        marker = self.root / "executed"
        malicious = TEMPLATE + f"<<( cycler.__init__.__globals__.os.system('touch {marker}') )>>\n"
        head = self.commit({SOURCE: malicious})
        with self.assertRaisesRegex(repair.RepairError, "beyond action pins"):
            repair.generated_changes(self.root, self.base, head)
        self.assertFalse(marker.exists())

    def test_template_rename_to_another_action_is_not_a_pin_update(self) -> None:
        head = self.commit({SOURCE: TEMPLATE.replace("actions/deploy-pages", "someone/other-action")})
        with self.assertRaisesRegex(repair.RepairError, "beyond action pins"):
            repair.generated_changes(self.root, self.base, head)

    def test_symlink_metadata_is_not_read(self) -> None:
        path = self.root / IMAGE
        path.unlink()
        path.symlink_to(ROOT / "LICENSE")
        head = self.commit({"unrelated.txt": "fixture"})
        with self.assertRaisesRegex(repair.RepairError, "regular tracked file"):
            repair.generated_changes(self.root, self.base, head)


class RepairOwnershipTests(unittest.TestCase):
    def test_conflict_requests_renovate_retry_idempotently(self) -> None:
        github = repair.GitHub("example/repo")
        body = "Description\n - [ ] <!-- rebase-check -->If you want to rebase/retry this PR, check this box\n"
        with patch.object(github, "request", side_effect=[{**_pull(), "body": body}, {}]) as request:
            repair._request_rebase(github, "main", _pull())
        updated = request.call_args.args[2]["body"]
        self.assertIn("[x] <!-- rebase-check -->", updated)
        with patch.object(github, "request", return_value={**_pull(), "body": updated}) as request:
            repair._request_rebase(github, "main", _pull())
        request.assert_called_once_with("GET", "pulls/42")

    def test_only_open_same_repository_bot_prs_into_default_branch_are_eligible(self) -> None:
        pull = _pull()
        self.assertTrue(repair.eligible(pull, "Example/Repo", "main"))
        for changes in (
            {"state": "closed"},
            {"draft": True},
            {"user": {"login": "renovate[bot]", "type": "User"}},
            {"user": {"login": "other[bot]", "type": "Bot"}},
            {"base": {"ref": "other"}},
            {"head": {**pull["head"], "repo": {"full_name": "someone/fork"}}},
            {"head": {**pull["head"], "ref": "feature/renovate"}},
            {"head": {**pull["head"], "sha": "main"}},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(repair.eligible({**pull, **changes}, "example/repo", "main"))

    def test_queued_pull_is_never_modified(self) -> None:
        github = repair.GitHub("example/repo")
        with patch.object(repair, "_queued", return_value=True), patch.object(repair, "_git") as git:
            repair.repair_pull(Path(), github, "main", _pull())
        git.assert_not_called()

    def test_custom_commits_are_preserved_without_requesting_rebase(self) -> None:
        github = repair.GitHub("example/repo")

        def git_command(_root: Path, *arguments: str, **_kwargs: object) -> str:
            return f"{'f' * 40} person@example.invalid\n" if arguments[0] == "log" else "a" * 40

        with (
            patch.object(repair, "_queued", return_value=False),
            patch.object(repair, "_git", side_effect=git_command),
            patch.object(repair, "_merge_snapshot") as merge,
            patch.object(github, "request") as request,
        ):
            repair.repair_pull(Path(), github, "main", _pull())
        merge.assert_not_called()
        request.assert_not_called()

    def _attempt(self, *, changed_head: bool = False, queued_race: bool = False) -> tuple:
        github = repair.GitHub("example/repo")
        current = _pull()
        if changed_head:
            current["head"]["sha"] = "b" * 40

        def git_command(_root: Path, *arguments: str, **_kwargs: object) -> str:
            if arguments[0] == "log":
                return f"{'f' * 40} 29139614+renovate[bot]@users.noreply.github.com\n"
            return "a" * 40 if arguments[0] == "rev-parse" else "c" * 40

        with (
            patch.object(github, "request", return_value=current),
            patch.object(repair, "_queued", side_effect=[False, queued_race]),
            patch.object(repair, "_git", side_effect=git_command) as git,
            patch.object(repair, "_merge_snapshot", return_value="e" * 40),
            patch.object(repair, "generated_changes", return_value={repair.CATALOGUE[0]: "generated"}),
            patch.object(repair, "_commit", return_value="d" * 40) as commit,
        ):
            repair.repair_pull(Path(), github, "main", _pull())
        return git, commit

    def test_concurrent_head_update_prevents_commit_or_push(self) -> None:
        git, commit = self._attempt(changed_head=True)
        commit.assert_not_called()
        self.assertFalse(any(call.args[1] == "push" for call in git.call_args_list))

    def test_entering_queue_during_generation_prevents_push(self) -> None:
        git, commit = self._attempt(queued_race=True)
        commit.assert_not_called()
        self.assertFalse(any(call.args[1] == "push" for call in git.call_args_list))

    def test_push_is_guarded_by_original_remote_sha(self) -> None:
        git, commit = self._attempt()
        commit.assert_called_once()
        push = next(call for call in git.call_args_list if call.args[1] == "push")
        self.assertIn(f"--force-with-lease=refs/heads/renovate/package:{'a' * 40}", push.args)
        self.assertIn(f"{'d' * 40}:refs/heads/renovate/package", push.args)

    def test_lost_push_race_is_deferred_without_overwriting_the_winner(self) -> None:
        github = repair.GitHub("example/repo")
        newer = _pull()
        newer["head"]["sha"] = "b" * 40
        with (
            patch.object(repair, "_git", side_effect=repair.RepairError("lease rejected")) as git,
            patch.object(github, "request", return_value=newer),
        ):
            repair._push_completion(Path(), github, _pull(), "c" * 40, [repair.CATALOGUE[0]])
        git.assert_called_once()

    def test_permission_failure_is_reported_instead_of_silently_skipped(self) -> None:
        github = repair.GitHub("example/repo")
        with (
            patch.object(repair, "_git", side_effect=[repair.RepairError("push rejected"), "a" * 40]),
            patch.object(github, "request", return_value=_pull()),
            self.assertRaisesRegex(repair.RepairError, "Contents and Workflows write"),
        ):
            repair._push_completion(Path(), github, _pull(), "c" * 40, [repair.CATALOGUE[0]])

    def test_workflow_permission_diagnostic_does_not_reflect_credentials(self) -> None:
        result = subprocess.CompletedProcess(
            ["git", "push"],
            1,
            stdout="",
            stderr="refusing to allow update workflow without workflows permission credential-secret",
        )
        with (
            patch.object(repair.subprocess, "run", return_value=result),
            self.assertRaises(repair.WorkflowPermissionError) as error,
        ):
            repair._run(Path(), ["git", "push"])
        self.assertIn("Workflows write", str(error.exception))
        self.assertNotIn("credential-secret", str(error.exception))

    def test_local_execution_cannot_publish(self) -> None:
        with (
            patch("sys.argv", ["renovate_updates"]),
            patch.dict("os.environ", {"GITHUB_ACTIONS": "false", "GITHUB_REPOSITORY": "example/repo"}),
            self.assertRaisesRegex(repair.RepairError, "trusted default-branch"),
        ):
            repair.main()

    def test_workflow_uses_default_branch_code_and_a_separate_automation_credential(self) -> None:
        workflow = yaml.safe_load(
            engine._workflow_environment()
            .from_string(
                (ROOT / ".github/workflow-templates/renovate-generated-files.yml.j2").read_text(),
            )
            .render(config=FIXTURE)
        )
        self.assertIn("pull_request_target", workflow[True])
        self.assertIn("schedule", workflow[True])
        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        steps = workflow["jobs"]["complete"]["steps"]
        self.assertEqual(steps[0]["with"]["ref"], "${{ github.event.repository.default_branch }}")
        self.assertFalse(steps[0]["with"]["persist-credentials"])
        self.assertEqual(steps[-1]["env"]["GH_TOKEN"], "${{ secrets.RELEASE_AUTOMATION_TOKEN }}")
        config = json.loads((ROOT / ".github/renovate.json").read_text())
        self.assertTrue(any(re.fullmatch(pattern[1:-1], repair.BOT_EMAIL) for pattern in config["gitIgnoredAuthors"]))


if __name__ == "__main__":
    unittest.main()
