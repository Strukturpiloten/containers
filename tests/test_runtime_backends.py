"""Pure selection and isolated Podman adapter regression controls."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import container_engine
from scripts.runtime_backends import PodmanBackend, select_outer_engine


class OuterEngineSelectionTests(unittest.TestCase):
    def test_shared_backend_and_expiry_inputs_preserve_global_rebuild_selection(self) -> None:
        required = {
            "scripts/runtime_backends.py",
            "scripts/runtime_docker_backend.py",
            "scripts/runtime_docker_expiry.py",
        }
        self.assertTrue(required.issubset(container_engine.GLOBAL_IMAGE_INPUTS))

    def test_ci_policy_is_explicit_and_buildah_remains_independent(self) -> None:
        root = Path(__file__).resolve().parents[1]
        action = yaml.safe_load((root / ".github/actions/build-arch-image/action.yml").read_text())
        steps = {step["name"]: step for step in action["runs"]["steps"]}
        self.assertIn("--outer-engine profile", steps["Verify image runtime"]["run"])
        self.assertIn("scripts.container_engine build-arch-image", steps["Build image archive"]["run"])
        self.assertIn("buildah podman skopeo", steps["Install OCI tooling"]["run"])

    def test_explicit_engine_does_not_depend_on_inner_profile(self) -> None:
        for profile in ("docker", "podman", "phpFpm", "notifyPush"):
            for engine in ("docker", "podman"):
                with self.subTest(profile=profile, engine=engine):
                    self.assertEqual(select_outer_engine(engine, profile), engine)

    def test_profile_policy_is_closed_and_does_not_use_image_names(self) -> None:
        expected = {"docker": "docker", "podman": "podman", "phpFpm": "podman", "notifyPush": "podman"}
        for profile, engine in expected.items():
            with self.subTest(profile=profile):
                self.assertEqual(select_outer_engine("profile", profile), engine)

    def test_unknown_policy_or_profile_fails_without_a_runtime_call(self) -> None:
        with patch("subprocess.run") as run:
            for selection, profile in (("auto", "docker"), ("", "podman"), ("profile", "other"), ("podman", "other")):
                with self.subTest(selection=selection, profile=profile), self.assertRaises(ValueError):
                    select_outer_engine(selection, profile)
            run.assert_not_called()


class PodmanAdapterTests(unittest.TestCase):
    def test_adapter_retains_exact_existing_prefix_and_only_owned_directories(self) -> None:
        for sudo in ((), ("sudo", "-n")):
            with self.subTest(sudo=sudo), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configuration = root / "configuration.conf"
                backend = PodmanBackend(root, sudo, configuration)
                with patch("subprocess.run") as run:
                    backend.initialize()
                    self.assertEqual(
                        backend.command_prefix(),
                        [
                            *sudo,
                            "env",
                            f"CONTAINERS_CONF_OVERRIDE={configuration}",
                            "podman",
                            "--root",
                            str(root / "root"),
                            "--runroot",
                            str(root / "runroot"),
                            "--tmpdir",
                            str(root / "tmp"),
                        ],
                    )
                    run.assert_not_called()
                self.assertEqual({path.name for path in root.iterdir()}, {"root", "runroot", "tmp"})


if __name__ == "__main__":
    unittest.main()
