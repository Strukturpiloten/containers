"""Regression tests for durable upstream release issue notifications."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_notifications import GitHub, GitHubError, NotificationError, load_policy, notify_new_lines


def _new_line(project: str = "podman", line: str = "6.2", version: str = "6.2.1") -> dict[str, str]:
    url = (
        f"https://github.com/podman-container-tools/podman/releases/tag/v{version}"
        if project == "podman"
        else f"https://docs.docker.com/engine/release-notes/{line}/"
    )
    return {"project": project, "line": line, "version": version, "url": url}


def _plan(*lines: dict[str, str]) -> dict:
    return {"newLines": list(lines), "dockerUpdates": []}


class FakeGitHub:
    def __init__(self) -> None:
        """Initialize an in-memory GitHub issue collection."""
        self.issues: list[dict] = []
        self.labels: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.calls: list[tuple[str, str, object]] = []

    def pages(self, path: str) -> list[dict]:
        self.calls.append(("GET", path, None))
        if path.startswith("issues?state=all"):
            return list(self.issues)
        if path.startswith("labels?"):
            return list(self.labels)
        if path.startswith("issues/") and "/comments?" in path:
            number = int(path.split("/")[1])
            return list(self.comments.get(number, []))
        raise AssertionError(path)

    def request(self, method: str, path: str, data: dict | None = None) -> dict:
        self.calls.append((method, path, data))
        if (method, path) == ("POST", "labels"):
            self.labels.append(dict(data or {}))
            return self.labels[-1]
        if (method, path) == ("POST", "issues"):
            issue = {**(data or {}), "number": len(self.issues) + 1, "state": "open"}
            self.issues.append(issue)
            return issue
        if method == "POST" and path.endswith("/comments"):
            number = int(path.split("/")[1])
            comment = dict(data or {})
            self.comments.setdefault(number, []).append(comment)
            return comment
        raise AssertionError((method, path))


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.github = FakeGitHub()
        self.policy = {"assignees": ["TheRealBecks"]}

    def test_two_reruns_create_one_assigned_issue_and_preserve_progress(self) -> None:
        plan = _plan(_new_line())
        actions = notify_new_lines(plan, self.github, self.policy)
        self.assertEqual(actions, ["created podman 6.2 issue #1"])
        issue = self.github.issues[0]
        self.assertEqual(issue["title"], "Add Podman 6.2 rootful/rootless images")
        self.assertEqual(issue["labels"], ["upstream-release"])
        self.assertEqual(issue["assignees"], ["TheRealBecks"])
        self.assertIn("amd64 and arm64", issue["body"])
        self.assertIn("Renovate policies", issue["body"])
        issue["title"] = "Maintainer's new title"
        issue["body"] = issue["body"].replace("- [ ] Add rootful", "- [x] Add rootful")
        saved_body = issue["body"]
        self.assertEqual(notify_new_lines(plan, self.github, self.policy), [])
        self.assertEqual(notify_new_lines(plan, self.github, self.policy), [])
        self.assertEqual(issue["title"], "Maintainer's new title")
        self.assertEqual(issue["body"], saved_body)
        self.assertEqual(self.github.comments, {})
        self.assertEqual(len([call for call in self.github.calls if call[:2] == ("POST", "issues")]), 1)

    def test_later_patch_adds_only_one_comment_without_editing_issue(self) -> None:
        notify_new_lines(_plan(_new_line()), self.github, self.policy)
        original_body = self.github.issues[0]["body"]
        newer = _plan(_new_line(version="6.2.3"))
        self.assertEqual(
            notify_new_lines(newer, self.github, self.policy),
            [
                "commented on podman 6.2 issue #1 for 6.2.3",
            ],
        )
        self.assertIn("<!-- upstream-release-version:podman:6.2:6.2.3 -->", self.github.comments[1][0]["body"])
        self.assertEqual(notify_new_lines(newer, self.github, self.policy), [])
        self.assertEqual(notify_new_lines(_plan(_new_line(version="6.2.2")), self.github, self.policy), [])
        self.assertEqual(len(self.github.comments[1]), 1)
        self.assertEqual(self.github.issues[0]["body"], original_body)

    def test_closed_matching_issue_is_respected(self) -> None:
        notify_new_lines(_plan(_new_line()), self.github, self.policy)
        self.github.issues[0]["state"] = "closed"
        self.assertEqual(notify_new_lines(_plan(_new_line(version="6.2.4")), self.github, self.policy), [])
        self.assertEqual(self.github.issues[0]["state"], "closed")
        self.assertEqual(len(self.github.issues), 1)
        self.assertEqual(self.github.comments, {})

    def test_docker_issue_and_unmarked_issue(self) -> None:
        self.github.issues.append({"number": 1, "state": "open", "body": "Manual Docker 30 investigation"})
        result = notify_new_lines(_plan(_new_line("docker", "30", "30.0.0")), self.github, self.policy)
        self.assertEqual(result, ["created docker 30 issue #2"])
        self.assertEqual(self.github.issues[0]["body"], "Manual Docker 30 investigation")
        self.assertEqual(self.github.issues[1]["title"], "Add Docker Engine 30 rootful/rootless images")

    def test_existing_label_keeps_its_color_and_description(self) -> None:
        self.github.labels = [{"name": "Upstream-Release", "color": "ffffff", "description": "Maintainer label"}]
        notify_new_lines(_plan(_new_line()), self.github, self.policy)
        self.assertEqual(self.github.labels[0]["color"], "ffffff")
        self.assertEqual(self.github.issues[0]["labels"], ["Upstream-Release"])
        self.assertFalse(any(call[:2] == ("POST", "labels") for call in self.github.calls))

    def test_invalid_plan_is_rejected_before_github_calls(self) -> None:
        for invalid in (
            _plan({**_new_line(), "line": "6.3"}),
            _plan({**_new_line(), "version": "6.2.1-rc1"}),
            _plan({**_new_line(), "version": "v6.2.1"}),
            _plan({**_new_line(), "url": "https://example.test/evil"}),
            _plan({**_new_line(), "project": "docker"}),
            _plan(_new_line(), _new_line()),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(NotificationError):
                notify_new_lines(invalid, self.github, self.policy)
        self.assertEqual(self.github.calls, [])

    def test_multiple_marked_issues_fail_instead_of_modifying_either(self) -> None:
        marker = "<!-- upstream-release:podman:6.2 -->"
        self.github.issues = [
            {"number": 1, "state": "open", "body": marker},
            {"number": 2, "state": "open", "body": marker},
        ]
        with self.assertRaises(NotificationError):
            notify_new_lines(_plan(_new_line()), self.github, self.policy)
        self.assertFalse(any(call[0] == "POST" for call in self.github.calls))


class GitHubTests(unittest.TestCase):
    def test_rejects_repository_injection(self) -> None:
        for repository in ("", "owner/repo/other", "../../repo", "-flag/repo", "owner/repo\n--help"):
            with self.subTest(repository=repository), self.assertRaises(NotificationError):
                GitHub(repository)

    @patch("scripts.release_notifications.subprocess.run")
    def test_uses_argv_and_json_stdin_without_shell(self, run: object) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = '{"number": 123}'
        github = GitHub("Strukturpiloten/containers")
        response = github.request("POST", "issues", {"title": "test; $(whoami)"})
        self.assertEqual(response["number"], 123)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:4], ["gh", "api", "--method", "POST"])
        self.assertEqual(args[0][-2:], ["--input", "-"])
        self.assertEqual(json.loads(kwargs["input"]), {"title": "test; $(whoami)"})
        self.assertNotIn("shell", kwargs)

    @patch("scripts.release_notifications.subprocess.run")
    def test_paginated_failure_is_fatal(self, run: object) -> None:
        run.return_value.returncode = 1
        run.return_value.stderr = "secret token"
        with self.assertRaises(GitHubError) as caught:
            GitHub("owner/repo").pages("issues?state=all&per_page=100")
        self.assertNotIn("secret token", str(caught.exception))

    @patch("scripts.release_notifications.subprocess.run")
    def test_pages_flattens_all_gh_pages(self, run: object) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = '[[{"number":1}],[{"number":2}]]'
        self.assertEqual(
            GitHub("owner/repo").pages("issues?state=all&per_page=100"),
            [
                {"number": 1},
                {"number": 2},
            ],
        )
        self.assertEqual(run.call_args.args[0][-2:], ["--paginate", "--slurp"])

    def test_policy_validates_assignees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".github/upstream-releases.json"
            path.parent.mkdir()
            path.write_text('{"assignees":["TheRealBecks"]}', encoding="utf-8")
            self.assertEqual(load_policy(root), {"assignees": ["TheRealBecks"]})
            path.write_text('{"assignees":["-bad"]}', encoding="utf-8")
            with self.assertRaises(NotificationError):
                load_policy(root)


if __name__ == "__main__":
    unittest.main()
