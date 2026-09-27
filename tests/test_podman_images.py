"""Contract tests for the Podman compatibility-image families."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from scripts import container_engine as engine
from scripts import runtime_tests

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCE_LINES = ("5.4", "5.5", "5.6", "5.7", "5.8", "6.0", "6.1")
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
PACKAGE_QUERY_BY_PLATFORM = {
    **{
        platform: "dpkg-query"
        for platform in EXPECTED_DISTRO_ARCHITECTURES
        if platform.startswith(("debian-", "ubuntu-"))
    },
    **{
        platform: "rpm --query"
        for platform in EXPECTED_DISTRO_ARCHITECTURES
        if platform.startswith(("fedora-", "centos-", "ubi-", "opensuse-"))
    },
    "alpine-3.24": "apk info",
    "arch": "pacman --query",
}


class PodmanImageTests(unittest.TestCase):
    def setUp(self) -> None:
        podman_images = {
            image["name"]: image for image in engine._load_images() if str(image["name"]).startswith("podman-")
        }
        source_pattern = re.compile(r"^podman-\d+\.\d+-(?:rootful|rootless)$")
        self.source_images = {name: image for name, image in podman_images.items() if source_pattern.fullmatch(name)}
        self.distro_images = {name: image for name, image in podman_images.items() if name not in self.source_images}

    def test_every_upstream_source_line_has_both_root_modes(self) -> None:
        expected_names = {f"podman-{line}-{mode}" for line in EXPECTED_SOURCE_LINES for mode in ROOT_MODES}
        self.assertEqual(set(self.source_images), expected_names)

    def test_source_versions_architectures_and_commits_match_per_line(self) -> None:
        for line in EXPECTED_SOURCE_LINES:
            with self.subTest(line=line):
                rootful = self.source_images[f"podman-{line}-rootful"]
                rootless = self.source_images[f"podman-{line}-rootless"]
                self.assertRegex(rootful["version"], rf"^v{re.escape(line)}\.(0|[1-9]\d*)$")
                self.assertEqual(rootless["version"], rootful["version"])
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
                    platform_directory = f"images/podman/platforms/{distribution}"
                    self.assertEqual(build["containerfile"], f"{platform_directory}/Containerfile")
                    self.assertEqual(build["architectures"], architectures)
                    self.assertIn(f"{platform_directory}/**", image["inputs"])
                    self.assertNotIn("images/podman/distro-shared/**", image["inputs"])
                    self.assertNotIn("images/podman/shared/**", image["inputs"])
                    self.assertRegex(
                        build["args"]["DISTRO_IMAGE"]["value"],
                        r"^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$",
                    )

    def test_modes_have_separate_users_and_storage(self) -> None:
        all_targets = [*EXPECTED_SOURCE_LINES, *EXPECTED_DISTRO_ARCHITECTURES]
        for target in all_targets:
            with self.subTest(target=target):
                images = self.source_images if target in EXPECTED_SOURCE_LINES else self.distro_images
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

    def test_distro_platforms_own_their_recipe_and_runtime_configuration(self) -> None:
        platform_root = REPOSITORY_ROOT / "images/podman/platforms"
        self.assertEqual(
            {path.name for path in platform_root.iterdir() if path.is_dir()},
            set(EXPECTED_DISTRO_ARCHITECTURES),
        )

        for platform, package_query in PACKAGE_QUERY_BY_PLATFORM.items():
            with self.subTest(platform=platform):
                directory = platform_root / platform
                recipe = (directory / "Containerfile").read_text(encoding="utf-8")
                rootful_config = (directory / "containers.conf").read_text(encoding="utf-8")
                rootless_config = (directory / "rootless-containers.conf").read_text(encoding="utf-8")
                self.assertIn(package_query, recipe)
                self.assertIn("account_name_for_id()", recipe)
                self.assertIn("groupmod --new-name podman", recipe)
                self.assertIn("usermod --login podman", recipe)
                self.assertIn("/usr/share/strukturpiloten/podman-package-version", recipe)
                self.assertNotIn('case "${ID}"', recipe)
                self.assertEqual(recipe.count("FROM "), 1)
                self.assertIn(f"platforms/{platform}/containers.conf", recipe)
                self.assertIn(f"platforms/{platform}/rootless-containers.conf", recipe)
                self.assertIn("volumes = [", rootless_config)
                if platform == "opensuse-leap-16.0":
                    self.assertIn('runtime = "runc"', rootful_config)
                    self.assertIn('cgroups = "enabled"', rootful_config)
                elif platform == "opensuse-tumbleweed":
                    self.assertIn('runtime = "crun"', rootful_config)
                    self.assertIn('cgroups = "enabled"', rootful_config)
                    self.assertIn('cgroups = "enabled"', rootless_config)
                else:
                    self.assertIn('runtime = "crun"', rootful_config)
                    self.assertIn('cgroups = "disabled"', rootful_config)

    def test_podman_test_profiles_match_image_family_and_mode(self) -> None:
        for name, image in {**self.source_images, **self.distro_images}.items():
            with self.subTest(image=name):
                profile = image["tests"]["podman"]
                mode = "rootless" if name.endswith("-rootless") else "rootful"
                self.assertEqual(profile["mode"], mode)
                expected_privilege = (
                    "unprivileged" if name in self.source_images and mode == "rootless" else "privileged"
                )
                self.assertEqual(profile["outerPrivilege"], expected_privilege)
                expected_nested_runtime = not (
                    mode == "rootless" and name.startswith(("podman-ubi-", "podman-opensuse-"))
                )
                self.assertEqual(profile.get("nestedRuntime", True), expected_nested_runtime)

    def test_host_smoke_tests_use_isolated_podman_state(self) -> None:
        action_directory = REPOSITORY_ROOT / ".github/actions/build-arch-image"
        action = (action_directory / "action.yml").read_text(encoding="utf-8")
        containers_conf = (action_directory / "podman-smoke-containers.conf").read_text(encoding="utf-8")
        runtime = (REPOSITORY_ROOT / "scripts/runtime_tests.py").read_text(encoding="utf-8")

        self.assertEqual(action.count("python -m scripts.runtime_tests"), 1)
        self.assertIn("--archive", action)
        self.assertIn("--evidence", action)
        self.assertIn("Upload runtime evidence", action)
        self.assertIn("--root", runtime)
        self.assertIn("--runroot", runtime)
        self.assertIn("--tmpdir", runtime)
        self.assertIn("CONTAINERS_CONF_OVERRIDE", runtime)
        self.assertEqual(action.count("github.event_name != 'pull_request'"), 1)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", action)
        self.assertIn("--allow-privileged", action)
        self.assertIn("privileged test requires trusted context", runtime)
        self.assertIn("nestedRuntime", runtime)
        self.assertIn('lock_type = "file"', containers_conf)

    def test_nested_runtime_respects_trusted_privilege_boundary(self) -> None:
        privileged = self.distro_images["podman-debian-12-rootless"]["tests"]["podman"]
        unprivileged = self.source_images["podman-6.1-rootless"]["tests"]["podman"]
        context = MagicMock()
        context.run.return_value = "podman version"

        runtime_tests._podman(context, privileged, archive=Path("test.tar"), allow_privileged=False, skip_nested=False)
        self.assertEqual(context.run.call_count, 1)
        context.skip.assert_called_once_with("nested Podman runtime", "privileged test requires trusted context")

        context.reset_mock()
        runtime_tests._podman(context, privileged, archive=Path("test.tar"), allow_privileged=True, skip_nested=False)
        self.assertIn("--privileged", context.run.call_args.kwargs["options"])

        context.reset_mock()
        runtime_tests._podman(
            context, unprivileged, archive=Path("test.tar"), allow_privileged=False, skip_nested=False
        )
        self.assertIn("apparmor=unconfined", context.run.call_args.kwargs["options"])
        self.assertNotIn("--privileged", context.run.call_args.kwargs["options"])

    def test_local_source_build_normalizes_the_metadata_version(self) -> None:
        command = engine._local_podman_build_command(
            self.source_images["podman-5.4-rootful"],
            architecture="amd64",
            local_image="localhost/test:source",
            source_revision="a" * 40,
            source_timestamp=1_700_000_000,
        )

        self.assertIn("OCI_VERSION=5.4.2", command)
        self.assertNotIn("OCI_VERSION=v5.4.2", command)


if __name__ == "__main__":
    unittest.main()
