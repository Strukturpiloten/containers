"""Podman identity formats must reach qualification as full immutable SHA-256 IDs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import runtime_nautobot
from scripts.runtime_tests import ProbeError, RuntimeContext

ROOT = Path(__file__).resolve().parents[1]


class RuntimeNautobotTests(unittest.TestCase):
    def test_both_podman_inspect_id_formats_use_the_qualified_cli_contract(self) -> None:
        for identifier in ("a" * 64, "sha256:" + "a" * 64):
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as directory:
                staged = Path(directory)
                (staged / "provenance.json").write_text(json.dumps({"qualified_source_sha256": "expected"}))
                context = Mock(spec=RuntimeContext)
                context._sudo = []
                context._podman = ["podman", "--root", "/owned/store"]
                context.image_ref = "localhost/test:runtime"
                context.podman.return_value = json.dumps(
                    [
                        {
                            "Id": identifier,
                            "Config": {
                                "Entrypoint": [],
                                "Cmd": ["nautobot-server", "start", "--ini", "/opt/nautobot/uwsgi.ini"],
                            },
                        }
                    ]
                )
                context.command.side_effect = ["", "Qualified installed registry source SHA-256: expected"]
                with patch.object(runtime_nautobot, "verify", return_value=staged):
                    runtime_nautobot.run(context)
                command = context.command.call_args.args[1]
                self.assertEqual(command[command.index("--image") + 1], "sha256:" + "a" * 64)
                self.assertIn("--installed", command)
                removed = [call for call in context.podman.call_args_list if call.args[1:3] == ("image", "rm")]
                self.assertEqual(len(removed), 2)

    def test_fixture_images_are_released_when_qualification_tool_setup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = Mock(spec=RuntimeContext)
            context.command.side_effect = ProbeError("synthetic setup failure")
            with (
                patch.object(runtime_nautobot, "verify", return_value=Path(directory)),
                self.assertRaisesRegex(ProbeError, "setup failure"),
            ):
                runtime_nautobot.run(context)
            removed = [call for call in context.podman.call_args_list if call.args[1:3] == ("image", "rm")]
            self.assertEqual(len(removed), 2)

    def test_apparmor_workaround_requires_rootful_ci_and_observed_crun_stacking(self) -> None:
        cases = [
            ("true", True, True, "containers-default-0.66.0//&crun (enforce)", True),
            ("true", True, True, "containers-default-0.66.0 (enforce)", False),
            ("true", True, True, "containers-default-0.67.0//&crun (enforce)", False),
            ("true", True, False, "unconfined", False),
            ("false", True, True, "containers-default-0.66.0//&crun (enforce)", False),
            ("true", False, True, "containers-default-0.66.0//&crun (enforce)", False),
        ]
        for ci, rootful, enabled, profile, expected in cases:
            with self.subTest(ci=ci, rootful=rootful, enabled=enabled, profile=profile):
                context = Mock(spec=RuntimeContext)
                context._sudo = ["sudo", "-n"] if rootful else []
                context.image_ref = "localhost/strukturbo-nautobot:synthetic-test"
                context.podman.side_effect = [json.dumps({"apparmorEnabled": enabled}), profile]
                with patch.dict("os.environ", {"GITHUB_ACTIONS": ci}):
                    arguments = runtime_nautobot._fixture_compatibility(context)
                self.assertEqual(arguments, ["--fixture-apparmor-unconfined"] if expected else [])
                if expected:
                    context.skip.assert_called_once()
                else:
                    context.skip.assert_not_called()


if __name__ == "__main__":
    unittest.main()
