"""Tests for immutable snapshots and maintained SemVer tag policy."""

from __future__ import annotations

import unittest

from scripts.policy import canonical_build_tag, maintained_semver_tags, promotion_tags, semver_tags


class PolicyTests(unittest.TestCase):
    def test_stable_semver_includes_moving_aliases(self) -> None:
        self.assertEqual(semver_tags("v1.2.3"), ["v1.2.3", "v1.2", "v1"])

    def test_prerelease_does_not_move_stable_aliases(self) -> None:
        self.assertEqual(semver_tags("1.2.3-rc.1"), ["v1.2.3-rc.1"])
        self.assertEqual(maintained_semver_tags("1.2.3-rc.1"), [])

    def test_stable_release_has_maintained_semver_tags(self) -> None:
        self.assertEqual(maintained_semver_tags("1.2.3"), ["v1.2.3", "v1.2", "v1"])

    def test_canonical_build_tag_is_unique_per_attempt(self) -> None:
        first = canonical_build_tag(sha="a" * 40, run_id="100", run_attempt="1")
        second = canonical_build_tag(sha="a" * 40, run_id="100", run_attempt="2")
        self.assertNotEqual(first, second)

    def test_push_promotes_sha_branch_and_latest(self) -> None:
        self.assertEqual(
            promotion_tags(event_name="push", ref_name="main", default_branch="main", sha="a" * 40),
            [f"sha-{'a' * 40}", "main", "latest"],
        )

    def test_scheduled_rebuild_does_not_move_sha_tag(self) -> None:
        self.assertEqual(
            promotion_tags(event_name="schedule", ref_name="main", default_branch="main", sha="a" * 40),
            ["main", "latest"],
        )


if __name__ == "__main__":
    unittest.main()
