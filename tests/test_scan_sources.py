"""Verify OCI archive manifest identity is derived from content and architecture."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.scan_sources import SourceError, baseline_registry, candidate_archive


def _blob(value: dict) -> tuple[bytes, dict]:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return raw, {"digest": f"sha256:{hashlib.sha256(raw).hexdigest()}", "size": len(raw)}


def _archive(path: Path, *, architecture: str = "amd64") -> tuple[str, str]:
    config_raw, config = _blob(
        {
            "architecture": architecture,
            "os": "linux",
            "config": {"Labels": {"org.opencontainers.image.revision": "b" * 40}},
        }
    )
    manifest_raw, manifest = _blob({"schemaVersion": 2, "config": config, "layers": []})
    index_raw = json.dumps({"schemaVersion": 2, "manifests": [manifest]}).encode()
    with tarfile.open(path, "w") as archive:
        for name, raw in (
            ("index.json", index_raw),
            (f"blobs/sha256/{manifest['digest'].removeprefix('sha256:')}", manifest_raw),
            (f"blobs/sha256/{config['digest'].removeprefix('sha256:')}", config_raw),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return manifest["digest"], config["digest"]


class SourceIdentityTests(unittest.TestCase):
    def test_archive_manifest_and_config_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            manifest, config = _archive(path)
            evidence = candidate_archive(path, "amd64", "b" * 40)
            self.assertEqual(evidence["manifestDigest"], manifest)
            self.assertEqual(evidence["configDigest"], config)
            self.assertNotEqual(evidence["archiveSha256"], manifest)
            with self.assertRaises(SourceError):
                candidate_archive(path, "arm64")
            with self.assertRaises(SourceError):
                candidate_archive(path, "amd64", "c" * 40)

    def test_registry_baseline_selects_matching_architecture(self) -> None:
        manifest_raw, descriptor = _blob(
            {"schemaVersion": 2, "config": {"digest": f"sha256:{'c' * 64}", "size": 1}, "layers": []}
        )
        index_raw = json.dumps(
            {"manifests": [{**descriptor, "platform": {"os": "linux", "architecture": "amd64"}}]}
        ).encode()
        with (
            patch("scripts.scan_sources._skopeo_raw", side_effect=[index_raw, manifest_raw]),
            patch("scripts.scan_sources._skopeo_inspect", return_value={"Architecture": "amd64", "Os": "linux"}),
        ):
            evidence = baseline_registry("ghcr.io/example", "ghcr.io/example:1", "amd64")
        self.assertEqual(evidence["manifestDigest"], descriptor["digest"])
        self.assertEqual(evidence["indexDigest"], f"sha256:{hashlib.sha256(index_raw).hexdigest()}")
        with patch("scripts.scan_sources._skopeo_raw", return_value=index_raw), self.assertRaises(SourceError):
            baseline_registry("ghcr.io/example", "ghcr.io/example:1", "arm64")


if __name__ == "__main__":
    unittest.main()
