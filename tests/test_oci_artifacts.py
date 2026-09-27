"""Runtime evidence must identify the native image whose bytes were executed."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.oci_artifacts import ArchiveIdentityError, archive_identity


class ArchiveIdentityTests(unittest.TestCase):
    def fixture(
        self, path: Path, *, architecture: str = "amd64", corrupt: bool = False, duplicate: bool = False
    ) -> dict:
        config = json.dumps(
            {
                "architecture": architecture,
                "os": "linux",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.revision": "a" * 40,
                        "org.opencontainers.image.version": "1.0.0",
                    }
                },
            }
        ).encode()
        config_digest = hashlib.sha256(config).hexdigest()
        manifest = json.dumps(
            {"schemaVersion": 2, "config": {"digest": f"sha256:{config_digest}", "size": len(config)}, "layers": []}
        ).encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        descriptor = {"digest": f"sha256:{manifest_digest}", "size": len(manifest)}
        index = json.dumps(
            {"schemaVersion": 2, "manifests": [descriptor, descriptor] if duplicate else [descriptor]}
        ).encode()
        with tarfile.open(path, "w") as archive:
            for name, data in (
                ("index.json", index),
                (f"blobs/sha256/{manifest_digest}", manifest),
                (f"blobs/sha256/{config_digest}", b"{}" if corrupt else config),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return {"manifestDigest": f"sha256:{manifest_digest}", "configDigest": f"sha256:{config_digest}"}

    def test_identity_binds_manifest_configuration_source_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            expected = self.fixture(path)
            identity = archive_identity(path, "amd64")
            self.assertEqual(identity["manifestDigest"], expected["manifestDigest"])
            self.assertEqual(identity["configDigest"], expected["configDigest"])
            self.assertEqual(identity["sourceRevision"], "a" * 40)
            self.assertEqual(identity["archiveSha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_wrong_architecture_corrupt_metadata_and_ambiguous_archives_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            for options in ({"architecture": "arm64"}, {"corrupt": True}, {"duplicate": True}):
                with self.subTest(options=options):
                    self.fixture(path, **options)
                    with self.assertRaises(ArchiveIdentityError):
                        archive_identity(path, "amd64")


if __name__ == "__main__":
    unittest.main()
