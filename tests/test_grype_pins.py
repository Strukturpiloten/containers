"""The scanner's two release archives must move as one reviewed update."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts.grype_pins import GrypePinError, validate_action, validate_script

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/scan-vulnerabilities/action.yml"
CONFIG = ROOT / ".github/renovate.json"


class GrypePinTests(unittest.TestCase):
    def test_action_has_matching_release_versions_and_verified_archives(self) -> None:
        pins = validate_action(ACTION)
        self.assertEqual(set(pins), {"amd64", "arm64"})
        script = ACTION.read_text(encoding="utf-8")
        self.assertIn('archive="grype_${release#v}_linux_${machine}.tar.gz"', script)
        self.assertIn("releases/download/${release}/${archive}", script)
        self.assertIn("sha256sum -c -", script)

    def test_partial_architecture_update_is_rejected(self) -> None:
        script = ACTION.read_text(encoding="utf-8")
        release, digest = validate_action(ACTION)["arm64"]
        arm64_pin = f"machine=arm64\n            release={release}\n            expected={digest}"
        self.assertIn(arm64_pin, script)
        other_release = "v999.0.0" if release != "v999.0.0" else "v0.0.0"
        mismatched = script.replace(arm64_pin, arm64_pin.replace(release, other_release))
        with self.assertRaisesRegex(GrypePinError, "must match"):
            validate_script(mismatched)
        missing = script.replace(arm64_pin, arm64_pin.replace(f"release={release}\n            ", ""))
        with self.assertRaisesRegex(GrypePinError, "one release"):
            validate_script(missing)

    def test_renovate_extracts_both_version_checksum_pairs(self) -> None:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        managers = [
            manager
            for manager in config["customManagers"]
            if manager.get("datasourceTemplate") == "github-release-attachments"
            and manager.get("packageNameTemplate") == "anchore/grype"
        ]
        self.assertEqual(len(managers), 1)
        manager = managers[0]
        self.assertTrue(
            any(
                re.fullmatch(pattern[1:-1], ".github/actions/scan-vulnerabilities/action.yml")
                for pattern in manager["managerFilePatterns"]
            )
        )
        self.assertEqual(len(manager["matchStrings"]), 1)
        # Renovate's named-group syntax differs only in spelling from Python's.
        pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
        matches = list(re.finditer(pattern, ACTION.read_text(encoding="utf-8")))
        self.assertEqual(len(matches), 2)
        self.assertEqual(
            {(match["currentValue"], match["currentDigest"]) for match in matches},
            set(validate_action(ACTION).values()),
        )
        rules = [
            rule
            for rule in config["packageRules"]
            if "anchore/grype" in rule.get("matchPackageNames", [])
            and "github-release-attachments" in rule.get("matchDatasources", [])
        ]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["groupName"], "Grype scanner archives")
        self.assertFalse(rules[0]["automerge"])


if __name__ == "__main__":
    unittest.main()
