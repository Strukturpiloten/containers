"""Contract tests for the source-built Podman image family."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts import container_engine as engine

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PODMAN_VERSIONS = {
    "5.4": "5.4.2",
    "5.5": "5.5.2",
    "5.6": "5.6.2",
    "5.7": "5.7.1",
    "5.8": "5.8.6",
    "6.0": "6.0.2",
    "6.1": "6.1.0",
}


class PodmanImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.images = {
            image["name"]: image for image in engine._load_images() if str(image["name"]).startswith("podman-")
        }

    def test_every_requested_line_has_both_root_modes(self) -> None:
        expected_names = {
            f"podman-{line}-{mode}" for line in EXPECTED_PODMAN_VERSIONS for mode in ("rootful", "rootless")
        }
        self.assertEqual(set(self.images), expected_names)

    def test_versions_architectures_and_pinned_sources_match_per_line(self) -> None:
        for line, version in EXPECTED_PODMAN_VERSIONS.items():
            with self.subTest(line=line):
                rootful = self.images[f"podman-{line}-rootful"]
                rootless = self.images[f"podman-{line}-rootless"]
                self.assertEqual(rootful["version"], f"v{version}")
                self.assertEqual(rootless["version"], f"v{version}")
                self.assertEqual(rootful["build"]["architectures"], ["amd64", "arm64"])
                self.assertEqual(rootless["build"]["architectures"], ["amd64", "arm64"])
                rootful_commit = rootful["build"]["args"]["PODMAN_COMMIT"]["value"]
                rootless_commit = rootless["build"]["args"]["PODMAN_COMMIT"]["value"]
                self.assertRegex(rootful_commit, r"^[a-f0-9]{40}$")
                self.assertEqual(rootless_commit, rootful_commit)

    def test_modes_have_separate_users_and_storage(self) -> None:
        for line in EXPECTED_PODMAN_VERSIONS:
            with self.subTest(line=line):
                rootful_args = self.images[f"podman-{line}-rootful"]["build"]["args"]
                rootless_args = self.images[f"podman-{line}-rootless"]["build"]["args"]
                self.assertEqual(rootful_args["RUN_AS_USER"]["value"], "root")
                self.assertEqual(rootful_args["STORAGE_PATH"]["value"], "/var/lib/containers")
                self.assertEqual(rootless_args["RUN_AS_USER"]["value"], "podman")
                self.assertEqual(
                    rootless_args["STORAGE_PATH"]["value"],
                    "/home/podman/.local/share/containers",
                )

    def test_podman_6_uses_matching_version_2_network_helpers(self) -> None:
        for line in ("6.0", "6.1"):
            for mode in ("rootful", "rootless"):
                with self.subTest(line=line, mode=mode):
                    args = self.images[f"podman-{line}-{mode}"]["build"]["args"]
                    self.assertRegex(args["NETAVARK_VERSION"]["value"], r"^2\.")
                    self.assertRegex(args["AARDVARK_VERSION"]["value"], r"^2\.")
                    self.assertRegex(args["NETAVARK_COMMIT"]["value"], r"^[a-f0-9]{40}$")
                    self.assertRegex(args["AARDVARK_COMMIT"]["value"], r"^[a-f0-9]{40}$")

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
        self.assertIn('lock_type = "file"', containers_conf)


if __name__ == "__main__":
    unittest.main()
