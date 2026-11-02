"""Private source staging rejects unsafe archives and stale qualification evidence."""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import nautobot_source as source

ROOT = Path(__file__).resolve().parents[1]


def archive(name: str, *, link: bool = False) -> bytes:
    """Build a small malicious or regular repository archive."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        member = tarfile.TarInfo(name)
        if link:
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp/outside"  # noqa: S108
            target.addfile(member)
        else:
            member.size = 1
            target.addfile(member, io.BytesIO(b"x"))
    return output.getvalue()


class SourceTests(unittest.TestCase):
    def test_traversal_absolute_paths_and_links_are_rejected(self) -> None:
        for name, link in (("repo/../../outside", False), ("/repo/outside", False), ("repo/link", True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    source.extract(archive(name, link=link), Path(directory))
                self.assertFalse((Path(directory) / "outside").exists())

    def test_duplicate_files_are_not_overwritten(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as target:
            for _ in range(2):
                member = tarfile.TarInfo("repo/file")
                member.size = 1
                target.addfile(member, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(FileExistsError):
            source.extract(output.getvalue(), Path(directory))

    def test_source_manifest_rejects_mutable_revision_in_commit_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / source.MANIFEST
            path.parent.mkdir(parents=True)
            declaration = source.manifest(ROOT)
            declaration["sourceCommit"] = "main"
            path.write_text(json.dumps(declaration))
            with self.assertRaises(ValueError):
                source.manifest(root)

    def test_existing_generated_directory_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / source.MANIFEST
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(source.manifest(ROOT)))
            (root / source.STAGED).mkdir(parents=True)
            with patch.object(source.subprocess, "run") as run, self.assertRaises(ValueError):
                source.prepare(root)
            run.assert_not_called()

    def test_renovate_extracts_the_exact_source_branch_and_commit(self) -> None:
        import re  # noqa: PLC0415

        config = json.loads((ROOT / ".github/renovate.json").read_text())
        manager = next(item for item in config["customManagers"] if item.get("datasourceTemplate") == "git-refs")
        pattern = re.compile(manager["matchStrings"][0].replace("(?<", "(?P<"))
        found = pattern.search((ROOT / source.MANIFEST).read_text())
        self.assertIsNotNone(found)
        declaration = source.manifest(ROOT)
        self.assertEqual(found.group("currentDigest"), declaration["sourceCommit"])
        self.assertEqual(found.group("currentValue"), declaration["sourceRef"])
        self.assertEqual(found.group("depName"), declaration["repository"])
        self.assertEqual(manager["versioningTemplate"], "git")

    def test_failed_authentication_does_not_echo_credentials_or_stage_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / source.MANIFEST
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(source.manifest(ROOT)))
            failure = SimpleNamespace(returncode=1, stderr=b"TOKEN_SENTINEL", stdout=b"")
            with patch.object(source.subprocess, "run", return_value=failure), self.assertRaises(RuntimeError) as error:
                source.prepare(root)
            self.assertNotIn("TOKEN_SENTINEL", str(error.exception))
            self.assertFalse((root / source.STAGED).exists())

    def test_renovate_covers_both_hash_locked_requirements_files(self) -> None:
        import re  # noqa: PLC0415

        config = json.loads((ROOT / ".github/renovate.json").read_text())
        patterns = config["pip_requirements"]["managerFilePatterns"]
        for name in ("requirements.txt", "build-requirements.txt"):
            path = "images/nautobot/strukturbo-nautobot/" + name
            self.assertTrue(any(re.search(pattern[1:-1], path) for pattern in patterns))
            for line in (ROOT / path).read_text().splitlines():
                if line and not line.startswith("#"):
                    self.assertRegex(line, r"^[a-z_-]+==[0-9.]+ --hash=sha256:[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
