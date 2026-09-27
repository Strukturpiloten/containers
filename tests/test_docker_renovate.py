"""Regression checks for Docker image base extraction and Renovate grouping."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DISTROS = (
    "alpine-3.24",
    "arch",
    "debian-11",
    "debian-12",
    "debian-13",
    "fedora-43",
    "fedora-44",
    "opensuse-leap-16.0",
    "opensuse-tumbleweed",
    "ubuntu-22.04",
    "ubuntu-24.04",
    "ubuntu-26.04",
)
MODES = ("rootful", "rootless")


def _matches_path(patterns: list[str], path: str) -> bool:
    return any(re.search(pattern[1:-1], path) is not None for pattern in patterns)


def _matching_group_rules(rules: list[dict], path: str, package: str) -> list[dict]:
    return [
        rule
        for rule in rules
        if rule.get("groupName", "").startswith("Docker ")
        and _matches_path(rule["matchFileNames"], path)
        and package in rule.get("matchPackageNames", [package])
        and "digest" in rule.get("matchUpdateTypes", [])
    ]


class DockerRenovateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads((ROOT / ".github/renovate.json").read_text(encoding="utf-8"))
        cls.rules = cls.config["packageRules"]
        cls.managers = cls.config["customManagers"]

    def test_generic_metadata_manager_extracts_each_distro_base_once(self) -> None:
        manager = next(
            item
            for item in self.managers
            if item["description"] == "Track external pinned container image tags and digests in container metadata"
        )
        extraction = re.compile(manager["matchStrings"][0].replace("(?<", "(?P<"))
        for distro in DISTROS:
            for mode in MODES:
                with self.subTest(distro=distro, mode=mode):
                    path = f"images/docker/docker-{distro}-{mode}/container.yaml"
                    source = (ROOT / path).read_text(encoding="utf-8")
                    metadata = yaml.safe_load(source)
                    base = metadata["build"]["args"]["DISTRO_IMAGE"]["value"]
                    matches = list(extraction.finditer(source))
                    self.assertEqual(len(matches), 1)
                    match = matches[0]
                    self.assertEqual(
                        f"{match.group('depName')}:{match.group('currentValue')}@{match.group('currentDigest')}",
                        base,
                    )
                    matching_managers = [
                        item["description"]
                        for item in self.managers
                        if _matches_path(item["managerFilePatterns"], path)
                    ]
                    self.assertEqual(matching_managers, [manager["description"]])

    def test_declared_distro_releases_are_frozen_but_digest_updates_are_grouped_by_line(self) -> None:
        freeze = next(
            rule
            for rule in self.rules
            if rule["description"]
            == "Keep distro compatibility images on their declared OS release while allowing digest refreshes"
        )
        self.assertFalse(freeze["enabled"])
        self.assertEqual(set(freeze["matchUpdateTypes"]), {"major", "minor", "patch"})
        groups = set()
        for distro in DISTROS:
            pair_groups = set()
            pair_bases = set()
            for mode in MODES:
                with self.subTest(distro=distro, mode=mode):
                    path = f"images/docker/docker-{distro}-{mode}/container.yaml"
                    metadata = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
                    base = metadata["build"]["args"]["DISTRO_IMAGE"]["value"]
                    package = base.split(":", 1)[0]
                    pair_bases.add(base)
                    self.assertTrue(_matches_path(freeze["matchFileNames"], path))
                    matches = _matching_group_rules(self.rules, path, package)
                    self.assertEqual(len(matches), 1)
                    self.assertEqual(matches[0].get("matchManagers"), ["custom.regex"])
                    self.assertEqual(matches[0].get("matchDatasources"), ["docker"])
                    pair_groups.add(matches[0]["groupName"])
            self.assertEqual(len(pair_bases), 1)
            self.assertEqual(len(pair_groups), 1)
            groups.update(pair_groups)
        self.assertEqual(len(groups), len(DISTROS))

    def test_upstream_alpine_pin_and_group_exclude_distro_images(self) -> None:
        pin = next(
            rule
            for rule in self.rules
            if rule.get("allowedVersions") == r"/^3\.24$/" and "Docker" in rule["description"]
        )
        group = next(rule for rule in self.rules if rule.get("groupName") == "Docker Alpine 3.24 base")
        payload = "images/docker/upstream/29/payload.yaml"
        upstream = "images/docker/docker-29-rootless/container.yaml"
        distro = "images/docker/docker-alpine-3.24-rootless/container.yaml"
        for path in (payload, upstream):
            with self.subTest(path=path):
                self.assertTrue(_matches_path(pin["matchFileNames"], path))
                self.assertTrue(_matches_path(group["matchFileNames"], path))
        self.assertFalse(_matches_path(pin["matchFileNames"], distro))
        self.assertFalse(_matches_path(group["matchFileNames"], distro))
        self.assertEqual(len(_matching_group_rules(self.rules, distro, "docker.io/library/alpine")), 1)


if __name__ == "__main__":
    unittest.main()
