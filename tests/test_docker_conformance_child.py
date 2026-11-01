"""Hermetic launcher dispatch and real child-only copy-up repair; no native runtime."""

from __future__ import annotations

import os
import shlex
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOTLESS_UID = 1000
LAUNCHER = ROOT / "images/docker/conformance/start-daemon.sh"


class ConformanceChildPath(unittest.TestCase):
    def run_child(self, directory: Path, *, fail_unlink: bool = False) -> subprocess.CompletedProcess:
        """Remap only the fixed literal in the extracted child snippet for this test."""
        source = LAUNCHER.read_text()
        child = source.split("    sh -ec '\n", 1)[1].rsplit("\n    '", 1)[0]
        target = directory / "containerd"
        child = child.replace("/run/containerd", shlex.quote(str(target)))
        commands = directory / "bin"
        commands.mkdir()
        daemon = commands / "dockerd"
        daemon.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CHILD_ARGUMENTS"\n')
        daemon.chmod(0o700)
        if fail_unlink:
            unlink = commands / "rm"
            unlink.write_text("#!/bin/sh\nexit 1\n")
            unlink.chmod(0o700)
        return subprocess.run(  # noqa: S603 - execute only repository-authored shell with temporary inert commands.
            ["/bin/sh", "-ec", child],
            env=os.environ | {"PATH": str(commands) + ":/usr/bin:/bin", "CHILD_ARGUMENTS": str(directory / "argv")},
            capture_output=True,
            check=False,
            timeout=5,
        )

    def test_symlink_detachment_preserves_parent_target_inode_owner_mode_and_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "original"
            original.mkdir(mode=0o750)
            sentinel = original / "sentinel"
            sentinel.write_bytes(b"parent-owned-data")
            sentinel.chmod(0o640)
            before = original.stat(), sentinel.stat(), sentinel.read_bytes()
            (directory / "containerd").symlink_to(original, target_is_directory=True)
            result = self.run_child(directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((directory / "containerd").is_symlink())
            self.assertFalse((directory / "containerd").exists())
            after = original.stat(), sentinel.stat(), sentinel.read_bytes()
            for old, new in zip(before[:2], after[:2], strict=True):
                self.assertEqual(
                    (old.st_dev, old.st_ino, old.st_uid, old.st_gid, old.st_mode),
                    (new.st_dev, new.st_ino, new.st_uid, new.st_gid, new.st_mode),
                )
            self.assertEqual(before[2], after[2])
            self.assertEqual(
                (directory / "argv").read_text(), "--config-file=/etc/strukturpiloten/docker/daemon.json\n"
            )

    def test_absent_dangling_and_private_directory_are_safe_without_recursive_changes(self) -> None:
        for kind in ("absent", "dangling", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                target = directory / "containerd"
                if kind == "dangling":
                    target.symlink_to(directory / "missing")
                if kind == "directory":
                    target.mkdir(mode=0o700)
                    (target / "sentinel").write_bytes(b"keep")
                    before = target.stat()
                result = self.run_child(directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                if kind == "directory":
                    self.assertEqual(target.stat().st_ino, before.st_ino)
                    self.assertEqual((target / "sentinel").read_bytes(), b"keep")
                else:
                    self.assertFalse(target.is_symlink())
                    self.assertFalse(target.exists())

    def test_conflicting_file_or_unlink_failure_refuses_before_daemon(self) -> None:
        for kind in ("file", "unlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                target = directory / "containerd"
                if kind == "file":
                    target.write_bytes(b"keep")
                else:
                    target.symlink_to(directory / "missing")
                before = target.lstat()
                result = self.run_child(directory, fail_unlink=kind == "unlink")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((directory / "argv").exists())
                self.assertEqual(target.lstat().st_ino, before.st_ino)
                if kind == "file":
                    self.assertEqual(target.read_bytes(), b"keep")

    def test_rootful_and_external_guards_preserve_dispatch_and_copyup_order(self) -> None:
        for uid, bus_present in ((0, False), (1000, True), (1000, False), (1001, True)):
            with self.subTest(uid=uid, bus=bus_present), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                commands = directory / "bin"
                commands.mkdir()
                for command, body in {
                    "id": 'printf "%s\\n" "$FIXTURE_UID"',
                    "dockerd": 'printf "%s\\n" "$@" > "$FIXTURE_DAEMON"',
                    "rootlesskit": 'printf "%s\\n" "$@" > "$FIXTURE_KIT"',
                }.items():
                    executable = commands / command
                    executable.write_text("#!/bin/sh\n" + body + "\n")
                    executable.chmod(0o700)
                bus = directory / "bus"
                with socket.socket(socket.AF_UNIX) as connection:
                    if bus_present:
                        connection.bind(str(bus))
                    source = LAUNCHER.read_text().replace("/run/user/1000/bus", str(bus))
                    result = subprocess.run(  # noqa: S603 - execute only repository-authored shell with temporary inert commands.
                        ["/bin/sh", "-ec", source],
                        env=os.environ
                        | {
                            "PATH": str(commands) + ":/usr/bin:/bin",
                            "FIXTURE_UID": str(uid),
                            "FIXTURE_DAEMON": str(directory / "daemon"),
                            "FIXTURE_KIT": str(directory / "kit"),
                        },
                        capture_output=True,
                        check=False,
                        timeout=5,
                    )
                if uid == 0:
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(
                        (directory / "daemon").read_text(), "--config-file=/etc/strukturpiloten/docker/daemon.json\n"
                    )
                    self.assertFalse((directory / "kit").exists())
                elif uid == ROOTLESS_UID and bus_present:
                    self.assertEqual(result.returncode, 0)
                    arguments = (directory / "kit").read_text().splitlines()
                    self.assertEqual(
                        arguments[:9],
                        [
                            "--net=slirp4netns",
                            "--mtu=65520",
                            "--disable-host-loopback",
                            "--port-driver=builtin",
                            "--copy-up=/etc",
                            "--copy-up=/run",
                            "--propagation=rslave",
                            "sh",
                            "-ec",
                        ],
                    )
                    self.assertIn("rm -- /run/containerd", "\n".join(arguments[9:]))
                    self.assertFalse((directory / "daemon").exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((directory / "kit").exists())
                    self.assertFalse((directory / "daemon").exists())
