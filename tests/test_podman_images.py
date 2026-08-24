"""Contract tests for the Podman compatibility-image families."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from scripts import container_engine as engine

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCE_VERSIONS = {
    "5.4": "5.4.2",
    "5.5": "5.5.2",
    "5.6": "5.6.2",
    "5.7": "5.7.1",
    "5.8": "5.8.6",
    "6.0": "6.0.2",
    "6.1": "6.1.0",
}
EXPECTED_DISTRO_ARCHITECTURES = {
    "debian-11": ["amd64", "arm64"],
    "debian-12": ["amd64", "arm64"],
    "debian-13": ["amd64", "arm64"],
    "ubuntu-22.04": ["amd64", "arm64"],
    "ubuntu-24.04": ["amd64", "arm64"],
    "ubuntu-26.04": ["amd64", "arm64"],
    "fedora-43": ["amd64", "arm64"],
    "fedora-44": ["amd64", "arm64"],
    "opensuse-leap-16.0": ["amd64", "arm64"],
    "opensuse-tumbleweed": ["amd64", "arm64"],
    "ubi-8": ["amd64", "arm64"],
    "ubi-9": ["amd64", "arm64"],
    "ubi-10": ["amd64", "arm64"],
    "centos-stream-9": ["amd64", "arm64"],
    "centos-stream-10": ["amd64", "arm64"],
    "alpine-3.24": ["amd64", "arm64"],
    "arch": ["amd64"],
}
ROOT_MODES = ("rootful", "rootless")


class PodmanImageTests(unittest.TestCase):
    def setUp(self) -> None:
        podman_images = {
            image["name"]: image for image in engine._load_images() if str(image["name"]).startswith("podman-")
        }
        source_pattern = re.compile(r"^podman-\d+\.\d+-(?:rootful|rootless)$")
        self.source_images = {name: image for name, image in podman_images.items() if source_pattern.fullmatch(name)}
        self.distro_images = {name: image for name, image in podman_images.items() if name not in self.source_images}

    def test_every_upstream_source_line_has_both_root_modes(self) -> None:
        expected_names = {f"podman-{line}-{mode}" for line in EXPECTED_SOURCE_VERSIONS for mode in ROOT_MODES}
        self.assertEqual(set(self.source_images), expected_names)

    def test_source_versions_architectures_and_commits_match_per_line(self) -> None:
        for line, version in EXPECTED_SOURCE_VERSIONS.items():
            with self.subTest(line=line):
                rootful = self.source_images[f"podman-{line}-rootful"]
                rootless = self.source_images[f"podman-{line}-rootless"]
                self.assertEqual(rootful["version"], f"v{version}")
                self.assertEqual(rootless["version"], f"v{version}")
                self.assertEqual(rootful["build"]["architectures"], ["amd64", "arm64"])
                self.assertEqual(rootless["build"]["architectures"], ["amd64", "arm64"])
                rootful_commit = rootful["build"]["args"]["PODMAN_COMMIT"]["value"]
                rootless_commit = rootless["build"]["args"]["PODMAN_COMMIT"]["value"]
                self.assertRegex(rootful_commit, r"^[a-f0-9]{40}$")
                self.assertEqual(rootless_commit, rootful_commit)

    def test_every_distro_target_has_both_root_modes(self) -> None:
        expected_names = {
            f"podman-{distribution}-{mode}" for distribution in EXPECTED_DISTRO_ARCHITECTURES for mode in ROOT_MODES
        }
        self.assertEqual(set(self.distro_images), expected_names)

    def test_distro_images_use_pinned_native_bases_and_expected_architectures(self) -> None:
        for distribution, architectures in EXPECTED_DISTRO_ARCHITECTURES.items():
            for mode in ROOT_MODES:
                with self.subTest(distribution=distribution, mode=mode):
                    image = self.distro_images[f"podman-{distribution}-{mode}"]
                    build = image["build"]
                    self.assertEqual(image["version"], "v1.0.0")
                    self.assertEqual(build["containerfile"], "images/podman/distro-shared/Containerfile")
                    self.assertEqual(build["architectures"], architectures)
                    self.assertRegex(
                        build["args"]["DISTRO_IMAGE"]["value"],
                        r"^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$",
                    )

    def test_modes_have_separate_users_and_storage(self) -> None:
        all_targets = [*EXPECTED_SOURCE_VERSIONS, *EXPECTED_DISTRO_ARCHITECTURES]
        for target in all_targets:
            with self.subTest(target=target):
                images = self.source_images if target in EXPECTED_SOURCE_VERSIONS else self.distro_images
                rootful_args = images[f"podman-{target}-rootful"]["build"]["args"]
                rootless_args = images[f"podman-{target}-rootless"]["build"]["args"]
                self.assertEqual(rootful_args["RUN_AS_USER"]["value"], "root")
                self.assertEqual(rootful_args["STORAGE_PATH"]["value"], "/var/lib/containers")
                self.assertEqual(rootless_args["RUN_AS_USER"]["value"], "podman")
                self.assertEqual(
                    rootless_args["STORAGE_PATH"]["value"],
                    "/home/podman/.local/share/containers",
                )

    def test_podman_6_source_images_use_matching_version_2_network_helpers(self) -> None:
        for line in ("6.0", "6.1"):
            for mode in ROOT_MODES:
                with self.subTest(line=line, mode=mode):
                    args = self.source_images[f"podman-{line}-{mode}"]["build"]["args"]
                    self.assertRegex(args["NETAVARK_VERSION"]["value"], r"^2\.")
                    self.assertRegex(args["AARDVARK_VERSION"]["value"], r"^2\.")
                    self.assertRegex(args["NETAVARK_COMMIT"]["value"], r"^[a-f0-9]{40}$")
                    self.assertRegex(args["AARDVARK_COMMIT"]["value"], r"^[a-f0-9]{40}$")

    def test_distro_recipe_records_the_native_package_revision(self) -> None:
        recipe = (REPOSITORY_ROOT / "images/podman/distro-shared/Containerfile").read_text(encoding="utf-8")
        for package_tool in ("dpkg-query", "rpm --query", "apk info", "pacman --query"):
            with self.subTest(package_tool=package_tool):
                self.assertIn(package_tool, recipe)
        self.assertIn("rhel:10|centos:10", recipe)
        self.assertIn("firewall_package=nftables", recipe)
        self.assertIn("rootless_network_package=passt", recipe)
        self.assertIn("account_name_for_id()", recipe)
        self.assertNotIn("awk -F:", recipe)
        self.assertIn("groupmod --new-name podman", recipe)
        self.assertIn("usermod --login podman", recipe)
        self.assertIn("chmod 0755 /run/user", recipe)
        self.assertIn("chmod 0700 /run/user/1000", recipe)
        self.assertIn("/usr/share/strukturpiloten/podman-package-version", recipe)
        self.assertEqual(recipe.count("FROM "), 1)

    def test_host_smoke_tests_use_isolated_podman_state(self) -> None:
        action_directory = REPOSITORY_ROOT / ".github/actions/build-arch-image"
        action = (action_directory / "action.yml").read_text(encoding="utf-8")
        containers_conf = (action_directory / "podman-smoke-containers.conf").read_text(encoding="utf-8")

        for option, variable in (
            ("root", "HOST_PODMAN_ROOT"),
            ("runroot", "HOST_PODMAN_RUNROOT"),
            ("tmpdir", "HOST_PODMAN_TMPDIR"),
        ):
            with self.subTest(option=option):
                self.assertEqual(action.count(f'--{option} "${{{variable}}}"'), 2)

        self.assertNotIn("sudo podman load", action)
        self.assertNotIn("sudo podman run", action)
        self.assertEqual(action.count("CONTAINERS_CONF_OVERRIDE:"), 2)
        self.assertEqual(action.count('sudo env "CONTAINERS_CONF_OVERRIDE=${CONTAINERS_CONF_OVERRIDE}"'), 2)
        self.assertEqual(action.count('"${host_podman[@]}" tag'), 1)
        self.assertIn('"podman-debian-11-rootless"', action)
        self.assertIn('"podman-ubuntu-22.04-rootless"', action)
        self.assertEqual(action.count("github.event_name != 'pull_request'"), 1)
        self.assertEqual(action.count("run_args+=(--privileged)"), 2)
        self.assertNotIn("--cap-add SYS_ADMIN", action)
        self.assertNotIn("--cap-add MKNOD", action)
        self.assertIn('lock_type = "file"', containers_conf)


if __name__ == "__main__":
    unittest.main()
