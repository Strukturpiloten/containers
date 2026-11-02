"""Podman identity formats must reach qualification as full immutable SHA-256 IDs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import runtime_nautobot

ROOT = Path(__file__).resolve().parents[1]


class RuntimeNautobotTests(unittest.TestCase):
    def test_both_podman_inspect_id_formats_use_the_qualified_cli_contract(self) -> None:
        for identifier in ("a" * 64, "sha256:" + "a" * 64):
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as directory:
                staged = Path(directory)
                (staged / "provenance.json").write_text(json.dumps({"qualified_source_sha256": "expected"}))
                context = Mock()
                context._sudo = []
                context._podman = ["podman", "--root", "/owned/store"]
                context.image_ref = "localhost/test:runtime"
                context.podman.side_effect = [
                    "",
                    "",
                    json.dumps([{
                        "Id": identifier,
                        "Config": {"Entrypoint": [], "Cmd": ["nautobot-server", "start", "--ini", "/opt/nautobot/uwsgi.ini"]},
                    }]),
                ]
                context.command.side_effect = ["", "Qualified installed registry source SHA-256: expected"]
                with patch.object(runtime_nautobot, "verify", return_value=staged):
                    runtime_nautobot.run(context)
                command = context.command.call_args.args[1]
                self.assertEqual(command[command.index("--image") + 1], "sha256:" + "a" * 64)
                self.assertIn("--installed", command)


if __name__ == "__main__":
    unittest.main()
