"""Offline tests for the single-slice nonrenewing expiry mechanism."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts.runtime_docker_expiry import expire


class SliceExpiryTests(unittest.TestCase):
    def test_exact_inode_is_stopped_at_the_original_deadline(self) -> None:
        name = "strukturpiloten" + "a" * 32 + ".slice"
        with (
            patch("os.geteuid", return_value=0),
            patch("time.monotonic_ns", side_effect=[0, 0, 1_000_000_000]),
            patch("time.sleep") as sleep,
            patch("pathlib.Path.stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
            patch("subprocess.run") as run,
        ):
            expire(name, "1:2", 1_000_000_000)
        sleep.assert_called_once_with(1)
        run.assert_called_once_with(
            ["/usr/bin/systemctl", "stop", "--no-block", name], check=True, capture_output=True, timeout=5
        )

    def test_absent_cgroup_is_not_a_stop_request(self) -> None:
        with (
            patch("os.geteuid", return_value=0),
            patch("time.monotonic_ns", return_value=0),
            patch("pathlib.Path.stat", side_effect=[SimpleNamespace(st_dev=1, st_ino=2), FileNotFoundError]),
            patch("subprocess.run") as run,
        ):
            expire("strukturpiloten" + "a" * 32 + ".slice", "1:2", 0)
        run.assert_not_called()

    def test_foreign_or_replaced_slice_is_never_stopped(self) -> None:
        for name, identity, uid in (
            ("system.slice", "1:2", 0),
            ("strukturpiloten" + "a" * 32 + ".slice", "1:2", 1000),
            ("strukturpiloten" + "a" * 32 + ".slice", "1:3", 0),
        ):
            with (
                self.subTest(name=name, uid=uid, identity=identity),
                patch("os.geteuid", return_value=uid),
                patch("time.monotonic_ns", return_value=0),
                patch("pathlib.Path.stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                patch("subprocess.run") as run,
                self.assertRaises(ValueError),
            ):
                expire(name, identity, 0)
            run.assert_not_called()

    def test_expired_or_renewed_deadline_is_rejected(self) -> None:
        for deadline in (-61 * 1_000_000_000, 1801 * 1_000_000_000):
            with (
                self.subTest(deadline=deadline),
                patch("os.geteuid", return_value=0),
                patch("time.monotonic_ns", return_value=0),
                patch("subprocess.run") as run,
                self.assertRaises(ValueError),
            ):
                expire("strukturpiloten" + "a" * 32 + ".slice", "1:2", deadline)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
