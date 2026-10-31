"""Inert exact-byte controls for the inactive fixed source gate."""

from __future__ import annotations

import hashlib
import unittest

from scripts import docker_direct_startup_gate as gate


class DirectGateTests(unittest.TestCase):
    def test_gate_reads_one_inert_token_and_execs_only_the_original_launcher(self) -> None:
        self.assertEqual(
            gate.GATE_SOURCE,
            b"#!/bin/sh\n"
            b"set -eu\n"
            b'[ "$#" -eq 0 ] || exit 125\n'
            b"IFS= read -r containers_direct_release < /run/containers-direct-startup/release\n"
            b'[ "$containers_direct_release" = containers-direct-startup-release-v1 ] || exit 125\n'
            b"unset containers_direct_release\n"
            b"exec /usr/local/bin/start-dockerd\n",
        )
        self.assertEqual(gate.RELEASE_TOKEN, b"containers-direct-startup-release-v1\n")
        self.assertEqual(gate.ORIGINAL_CMD, ("/usr/local/bin/start-dockerd",))
        self.assertEqual(gate.GATE_SHA256, hashlib.sha256(gate.GATE_SOURCE).hexdigest())

    def test_source_has_no_environment_capture_replay_or_dynamic_shell_evaluation(self) -> None:
        for prohibited in (b"eval", b"environ", b"export ", b"env -i", b". /", b"source ", b"$@"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, gate.GATE_SOURCE)
        self.assertEqual(gate.GATE_SOURCE.count(b"read -r"), 1)
        self.assertEqual(gate.GATE_SOURCE.count(b"exec "), 1)


if __name__ == "__main__":
    unittest.main()
