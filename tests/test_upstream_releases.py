"""Tests for read-only upstream release discovery and planning."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import upstream_releases
from scripts.upstream_releases import (
    DiscoveryError,
    Release,
    discover_docker_releases,
    discover_podman_releases,
    plan_releases,
)


def _release(version: str) -> dict[str, object]:
    return {
        "tag_name": f"v{version}",
        "html_url": f"https://github.com/podman-container-tools/podman/releases/tag/v{version}",
        "draft": False,
        "prerelease": False,
    }


def _index(*filenames: str) -> str:
    return "<html>" + "".join(f'<a href="{filename}">archive</a>' for filename in filenames) + "</html>"


def _docker_archives(version: str) -> tuple[str, str]:
    return f"docker-{version}.tgz", f"docker-rootless-extras-{version}.tgz"


class DiscoveryTests(unittest.TestCase):
    def test_podman_paginates_and_filters_non_stable_tags(self) -> None:
        first = [_release("6.2.3") for _ in range(100)]
        second = [
            _release("6.1.7"),
            {**_release("6.3.0"), "draft": True},
            {**_release("6.4.0"), "prerelease": True},
            {**_release("6.5.0"), "tag_name": "v6.5.0-rc1"},
        ]
        seen: list[str] = []

        def fetch(url: str) -> object:
            seen.append(url)
            return first if "&page=1" in url else second

        releases = discover_podman_releases(fetch)
        self.assertEqual([release.version_string for release in releases], ["6.1.7", "6.2.3"])
        self.assertEqual(len(seen), 2)

    def test_podman_rejects_api_errors_and_untrusted_urls(self) -> None:
        with self.assertRaises(DiscoveryError):
            discover_podman_releases(lambda _url: {"message": "rate limit"})
        with self.assertRaises(DiscoveryError):
            discover_podman_releases(lambda _url: [{**_release("6.2.0"), "html_url": "https://elsewhere.invalid"}])

    def test_docker_requires_both_archives_on_both_architectures(self) -> None:
        amd64 = _index(*_docker_archives("29.8.2"), *_docker_archives("30.0.0"), *_docker_archives("31.0.0"))
        arm64 = _index(*_docker_archives("29.8.2"), *_docker_archives("30.0.0"), "docker-31.0.0.tgz")
        releases = discover_docker_releases(lambda url: amd64 if "/x86_64/" in url else arm64)
        self.assertEqual([release.version_string for release in releases], ["29.8.2", "30.0.0"])
        self.assertEqual(releases[-1].url, "https://docs.docker.com/engine/release-notes/30/")

    def test_docker_rejects_empty_or_incomplete_indexes(self) -> None:
        with self.assertRaises(DiscoveryError):
            discover_docker_releases(lambda _url: "<html>unrecognized listing</html>")
        with self.assertRaises(DiscoveryError):
            discover_docker_releases(
                lambda url: (
                    _index(*_docker_archives("30.0.0")) if "/x86_64/" in url else _index(*_docker_archives("29.9.0"))
                ),
            )


class PlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self._podman("5.8", "5.8.9", "legacy")
        self._podman("6.0", "6.0.5", "maintained")
        self._podman("6.1", "6.1.2", "maintained")
        self._docker("20.10", "20.10.24", "legacy", "disabled")
        self._docker("28", "28.5.1", "legacy")
        self._docker("29", "29.8.1", "maintained")

    def _podman(self, line: str, version: str, state: str, admission: str = "isolated-test") -> None:
        path = self.root / f"images/podman/payloads/podman-{line}.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"name: podman-{line}\nbuild:\n  args:\n    OCI_VERSION: {version}\n", encoding="utf-8")
        consumer = self.root / f"images/podman/podman-{line}-rootful/container.yaml"
        consumer.parent.mkdir(parents=True, exist_ok=True)
        consumer.write_text(f"lifecycle:\n  state: {state}\n  admission: {admission}\n", encoding="utf-8")

    def _docker(self, line: str, version: str, state: str, admission: str = "isolated-test") -> None:
        path = self.root / f"images/docker/upstream/{line}/payload.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"name: docker-{line}-payload\nbuild:\n  args:\n    ENGINE_VERSION: {version}\n", encoding="utf-8"
        )
        consumer = self.root / f"images/docker/docker-{line}-rootful/container.yaml"
        consumer.parent.mkdir(parents=True, exist_ok=True)
        consumer.write_text(f"lifecycle:\n  state: {state}\n  admission: {admission}\n", encoding="utf-8")

    def test_plans_latest_new_lines_and_only_eligible_docker_updates(self) -> None:
        podman = [
            Release((5, 9, 2), "https://example.test/5.9.2"),
            Release((6, 1, 9), "https://example.test/6.1.9"),
            Release((6, 2, 0), "https://example.test/6.2.0"),
            Release((6, 2, 3), "https://example.test/6.2.3"),
        ]
        docker = [
            Release((20, 10, 25), "https://example.test/20.10.25"),
            Release((20, 11, 0), "https://example.test/20.11.0"),
            Release((28, 6, 0), "https://example.test/28.6.0"),
            Release((29, 8, 0), "https://example.test/29.8.0"),
            Release((29, 8, 2), "https://example.test/29.8.2"),
            Release((29, 9, 0), "https://example.test/29.9.0"),
            Release((30, 0, 0), "https://example.test/30.0.0"),
        ]
        plan = plan_releases(self.root, podman, docker)
        self.assertEqual(
            plan["newLines"],
            [
                {"project": "podman", "line": "5.9", "version": "5.9.2", "url": "https://example.test/5.9.2"},
                {"project": "podman", "line": "6.2", "version": "6.2.3", "url": "https://example.test/6.2.3"},
                {"project": "docker", "line": "30", "version": "30.0.0", "url": "https://example.test/30.0.0"},
            ],
        )
        self.assertEqual(
            plan["dockerUpdates"],
            [
                {"line": "28", "currentVersion": "28.5.1", "version": "28.6.0", "updateType": "minor"},
                {"line": "29", "currentVersion": "29.8.1", "version": "29.9.0", "updateType": "minor"},
            ],
        )

    def test_disabled_line_is_covered_and_does_not_update(self) -> None:
        self._podman("6.2", "6.2.0", "legacy", "disabled")
        plan = plan_releases(
            self.root,
            [Release((6, 2, 3), "https://example.test/6.2.3")],
            [Release((20, 10, 25), "https://example.test/20.10.25")],
        )
        self.assertEqual(plan, {"newLines": [], "dockerUpdates": []})

    def test_legacy_20_10_stays_on_its_minor_and_patch_updates(self) -> None:
        self._docker("20.10", "20.10.24", "legacy")
        plan = plan_releases(
            self.root,
            [],
            [
                Release((20, 10, 25), "https://example.test/20.10.25"),
                Release((20, 11, 0), "https://example.test/20.11.0"),
                Release((29, 8, 2), "https://example.test/29.8.2"),
            ],
        )
        self.assertEqual(
            plan["dockerUpdates"],
            [
                {"line": "20.10", "currentVersion": "20.10.24", "version": "20.10.25", "updateType": "patch"},
                {"line": "29", "currentVersion": "29.8.1", "version": "29.8.2", "updateType": "patch"},
            ],
        )

    def test_real_lifecycle_states_and_admission_gate(self) -> None:
        self._podman("6.1", "6.1.2", "experimental", "isolated-test")
        self._podman("6.0", "6.0.5", "maintained", "production")
        self._docker("28", "28.5.1", "legacy", "disabled")
        plan = plan_releases(
            self.root,
            [Release((5, 9, 0), "https://example.test/5.9.0")],
            [Release((28, 6, 0), "https://example.test/28.6.0")],
        )
        self.assertEqual(
            plan["newLines"],
            [{"project": "podman", "line": "5.9", "version": "5.9.0", "url": "https://example.test/5.9.0"}],
        )
        self.assertEqual(plan["dockerUpdates"], [])

    def test_malformed_lifecycle_fails_closed(self) -> None:
        consumer = self.root / "images/docker/docker-29-rootful/container.yaml"
        consumer.write_text("lifecycle:\n  state: maintained\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "Cannot read lifecycle"):
            plan_releases(self.root, [], [])
        consumer.write_text("lifecycle:\n  state: archived\n  admission: isolated-test\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "Invalid lifecycle"):
            plan_releases(self.root, [], [])
        consumer.write_text("lifecycle:\n  state: [maintained]\n  admission: isolated-test\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "Invalid lifecycle"):
            plan_releases(self.root, [], [])

    def test_payload_name_and_version_must_match_line(self) -> None:
        payload = self.root / "images/podman/payloads/podman-6.1.yaml"
        payload.write_text("name: podman-6.0\nbuild:\n  args:\n    OCI_VERSION: 6.1.2\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "Payload name"):
            plan_releases(self.root, [], [])
        payload.write_text("name: podman-6.1\nbuild:\n  args:\n    OCI_VERSION: 6.0.2\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "does not match compatibility line"):
            plan_releases(self.root, [], [])
        self._podman("6.1", "6.1.2", "maintained")
        payload = self.root / "images/docker/upstream/29/payload.yaml"
        payload.write_text("name: docker-28-payload\nbuild:\n  args:\n    ENGINE_VERSION: 29.8.1\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "Payload name"):
            plan_releases(self.root, [], [])
        payload.write_text("name: docker-29-payload\nbuild:\n  args:\n    ENGINE_VERSION: 28.5.1\n", encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "does not match compatibility line"):
            plan_releases(self.root, [], [])
        self._docker("29", "29.8.1", "maintained")
        payload = self.root / "images/docker/upstream/20.10/payload.yaml"
        payload.write_text(
            "name: docker-20.10-payload\nbuild:\n  args:\n    ENGINE_VERSION: 20.11.0\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(DiscoveryError, "does not match compatibility line"):
            plan_releases(self.root, [], [])


class RedirectTests(unittest.TestCase):
    def test_authenticated_api_redirects_are_rejected(self) -> None:
        handler = upstream_releases._NoRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid"))


if __name__ == "__main__":
    unittest.main()
