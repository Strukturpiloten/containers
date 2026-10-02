"""Docker static release updates require two matching native archive probes."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

import yaml

from scripts.docker_release_updates import (
    ARCHES,
    DockerReleaseError,
    _download,
    _extract_selected,
    _OfficialRedirects,
    _parse_versions,
    _run_version,
    _validate_evidence,
    apply_release,
    probe_release,
    verify_release,
)

ROOT = Path(__file__).resolve().parents[1]
OLD_VERSION = str(
    yaml.safe_load((ROOT / "images/docker/upstream/29/payload.yaml").read_text(encoding="utf-8"))["build"]["args"][
        "ENGINE_VERSION"
    ]
)
OLD_MAJOR, OLD_MINOR, OLD_PATCH = map(int, OLD_VERSION.split("."))
NEW_VERSION = f"{OLD_MAJOR}.{OLD_MINOR}.{OLD_PATCH + 1}"


def _evidence(arch: str) -> dict:
    docker_arch = ARCHES[arch]
    base = f"https://download.docker.com/linux/static/stable/{docker_arch}"
    return {
        "schemaVersion": 1,
        "line": "29",
        "version": NEW_VERSION,
        "arch": arch,
        "dockerArch": docker_arch,
        "archives": {
            "engine": {"url": f"{base}/docker-{NEW_VERSION}.tgz", "sha256": "a" * 64},
            "rootless": {"url": f"{base}/docker-rootless-extras-{NEW_VERSION}.tgz", "sha256": "b" * 64},
        },
        "components": {
            "engine": NEW_VERSION,
            "cli": NEW_VERSION,
            "containerd": "2.3.6",
            "runc": "1.5.2",
            "rootlesskit": "3.1.1",
        },
        "sourceRevision": {
            "dockerd": "123abcd",
            "cli": "234bcde",
            "containerd": "345cdef",
            "runc": "456defa",
        },
    }


class DockerReleaseUpdatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        payload = Path("images/docker/upstream/29/payload.yaml")
        paths = [payload, *(Path(f"images/docker/docker-29-{mode}/container.yaml") for mode in ("rootful", "rootless"))]
        for path in paths:
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, self.root / path)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        for arch in ARCHES:
            self._write_evidence(arch, _evidence(arch))

    def _write_evidence(self, arch: str, evidence: dict) -> None:
        (self.evidence_dir / f"{arch}.json").write_text(json.dumps(evidence), encoding="utf-8")

    def test_apply_updates_both_images_and_all_payload_provenance(self) -> None:
        changed = apply_release("29", NEW_VERSION, self.evidence_dir, self.root)
        verify_release("29", NEW_VERSION, self.evidence_dir, self.root)
        self.assertEqual(len(changed), 3)
        payload_path = self.root / "images/docker/upstream/29/payload.yaml"
        payload = yaml.safe_load(payload_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["build"]["args"]["ENGINE_VERSION"], NEW_VERSION)
        self.assertEqual(payload["provenance"]["containerd"], "2.3.6")
        self.assertEqual(payload["provenance"]["sourceRevision"]["runc"], "456defa")
        self.assertEqual(payload["build"]["architectureArgs"]["arm64"]["ROOTLESS_SHA256"], "b" * 64)
        for mode in ("rootful", "rootless"):
            path = self.root / f"images/docker/docker-29-{mode}/container.yaml"
            metadata = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["version"], f"v{NEW_VERSION}")
            self.assertIn(f"Docker Engine {NEW_VERSION}", metadata["description"])
            self.assertEqual(metadata["lifecycle"]["admission"], "isolated-test")

    def test_verify_rejects_orphan_branch_with_stale_archive_hash(self) -> None:
        apply_release("29", NEW_VERSION, self.evidence_dir, self.root)
        evidence = _evidence("arm64")
        evidence["archives"]["engine"]["sha256"] = "c" * 64
        self._write_evidence("arm64", evidence)
        with self.assertRaisesRegex(DockerReleaseError, "fresh evidence"):
            verify_release("29", NEW_VERSION, self.evidence_dir, self.root)

    def test_missing_or_mismatched_native_evidence_does_not_edit(self) -> None:
        payload = self.root / "images/docker/upstream/29/payload.yaml"
        original = payload.read_text(encoding="utf-8")
        (self.evidence_dir / "arm64.json").unlink()
        with self.assertRaisesRegex(DockerReleaseError, "Missing native"):
            apply_release("29", NEW_VERSION, self.evidence_dir, self.root)
        altered = _evidence("arm64")
        altered["components"]["containerd"] = "2.3.7"
        self._write_evidence("arm64", altered)
        with self.assertRaisesRegex(DockerReleaseError, "differs"):
            apply_release("29", NEW_VERSION, self.evidence_dir, self.root)
        self.assertEqual(payload.read_text(encoding="utf-8"), original)

    def test_rejects_wrong_arch_url_checksum_and_engine_version(self) -> None:
        evidence = _evidence("amd64")
        evidence["archives"]["engine"]["url"] = evidence["archives"]["engine"]["url"].replace("x86_64", "aarch64")
        with self.assertRaisesRegex(DockerReleaseError, "URL or SHA256"):
            _validate_evidence(evidence, "29", NEW_VERSION, "amd64")
        evidence = _evidence("amd64")
        evidence["archives"]["engine"]["sha256"] = "x" * 64
        with self.assertRaisesRegex(DockerReleaseError, "URL or SHA256"):
            _validate_evidence(evidence, "29", NEW_VERSION, "amd64")
        evidence = _evidence("amd64")
        evidence["components"]["cli"] = OLD_VERSION
        with self.assertRaisesRegex(DockerReleaseError, "Engine and CLI"):
            _validate_evidence(evidence, "29", NEW_VERSION, "amd64")

    def test_line_crossing_and_downgrade_are_rejected(self) -> None:
        with self.assertRaisesRegex(DockerReleaseError, "does not belong"):
            apply_release("29", "30.0.0", self.evidence_dir, self.root)
        with self.assertRaisesRegex(DockerReleaseError, "does not belong"):
            apply_release("20.10", "20.11.1", self.evidence_dir, self.root)
        for arch in ARCHES:
            evidence = _evidence(arch)
            evidence["version"] = "29.8.0"
            evidence["components"]["engine"] = "29.8.0"
            evidence["components"]["cli"] = "29.8.0"
            for archive in evidence["archives"].values():
                archive["url"] = archive["url"].replace(NEW_VERSION, "29.8.0")
            self._write_evidence(arch, evidence)
        with self.assertRaisesRegex(DockerReleaseError, "must advance"):
            apply_release("29", "29.8.0", self.evidence_dir, self.root)

    def test_selected_archive_paths_must_be_regular_and_safe(self) -> None:
        archive = self.root / "test.tgz"
        destination = self.root / "bin"
        destination.mkdir()
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo("docker/dockerd")
            member.type = tarfile.SYMTYPE
            member.linkname = "/bin/sh"
            tar.addfile(member)
        with self.assertRaisesRegex(DockerReleaseError, "Unsafe or duplicate"):
            _extract_selected(archive, destination, ("dockerd",), ("docker",))
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo("docker/../dockerd")
            member.size = 3
            tar.addfile(member, io.BytesIO(b"bad"))
        with self.assertRaisesRegex(DockerReleaseError, "Unsafe Docker archive member"):
            _extract_selected(archive, destination, ("dockerd",), ("docker",))
        self.assertFalse((destination / "dockerd").exists())

    def test_download_hashes_https_bytes_and_rejects_oversized_response(self) -> None:
        class Response(io.BytesIO):
            def geturl(self) -> str:
                return f"https://download.docker.com/linux/static/stable/x86_64/docker-{NEW_VERSION}.tgz"

        url = f"https://download.docker.com/linux/static/stable/x86_64/docker-{NEW_VERSION}.tgz"
        data = b"archive bytes"
        path = self.root / "download.tgz"
        with patch("scripts.docker_release_updates.build_opener") as opener:
            opener.return_value.open.return_value = Response(data)
            self.assertEqual(_download(url, path), hashlib.sha256(data).hexdigest())
        self.assertEqual(path.read_bytes(), data)
        with (
            patch("scripts.docker_release_updates.build_opener") as opener,
            patch("scripts.docker_release_updates.MAX_ARCHIVE_BYTES", 3),
            self.assertRaisesRegex(DockerReleaseError, "exceeds"),
        ):
            opener.return_value.open.return_value = Response(data)
            _download(url, path)
        with self.assertRaisesRegex(DockerReleaseError, "Unexpected Docker archive URL"):
            _download("http://example.com/docker.tgz", path)
        with self.assertRaisesRegex(DockerReleaseError, "redirected outside"):
            _OfficialRedirects().redirect_request(
                Request(url), None, 302, "Found", {}, "https://evil.example/docker.tgz"
            )

    def test_version_process_receives_no_runner_credentials(self) -> None:
        with patch("scripts.docker_release_updates.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="Docker version 29.8.2, build 123abcd")
            _run_version(self.root / "docker")
        _, kwargs = run.call_args
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(self.root)})

    def test_probe_writes_native_evidence_from_selected_archive_binaries(self) -> None:
        def fake_download(url: str, destination: Path) -> str:
            names = ("rootlesskit",) if "rootless-extras" in url else ("dockerd", "docker", "containerd", "runc")
            root = "docker-rootless-extras" if "rootless-extras" in url else "docker"
            with tarfile.open(destination, "w:gz") as tar:
                for name in names:
                    member = tarfile.TarInfo(f"{root}/{name}")
                    member.size = 3
                    tar.addfile(member, io.BytesIO(b"bin"))
            return "b" * 64 if "rootless-extras" in url else "a" * 64

        outputs = {
            "dockerd": f"Docker version {NEW_VERSION}, build 123abcd",
            "docker": f"Docker version {NEW_VERSION}, build 234bcde",
            "containerd": "containerd containerd.io 2.3.6 345cdef",
            "runc": "runc version 1.5.2\ncommit: v1.5.2-0-g456defa",
            "rootlesskit": "rootlesskit version 3.1.1",
        }
        path = self.root / "probe" / "amd64.json"
        with (
            patch("scripts.docker_release_updates.platform.system", return_value="Linux"),
            patch("scripts.docker_release_updates.platform.machine", return_value="x86_64"),
            patch("scripts.docker_release_updates._download", side_effect=fake_download),
            patch(
                "scripts.docker_release_updates._run_version", side_effect=lambda binary: outputs[binary.name]
            ) as run,
        ):
            evidence = probe_release("29", NEW_VERSION, "amd64", path)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), evidence)
        self.assertEqual(evidence["sourceRevision"]["runc"], "456defa")
        self.assertEqual(evidence["archives"]["engine"]["sha256"], "a" * 64)
        self.assertEqual({call.args[0].name for call in run.call_args_list}, set(outputs))

    def test_probe_requires_native_runner_and_requested_engine_cli_versions(self) -> None:
        with (
            patch("scripts.docker_release_updates.platform.machine", return_value="aarch64"),
            self.assertRaisesRegex(DockerReleaseError, "native Linux"),
        ):
            probe_release("29", NEW_VERSION, "amd64", self.root / "amd64.json")
        output = {
            "dockerd": f"Docker version {NEW_VERSION}, build 123abcd",
            "docker": f"Docker version {OLD_VERSION}, build 234bcde",
            "containerd": "containerd containerd.io 2.3.6 345cdef",
            "runc": "runc version 1.5.2\ncommit: v1.5.2-0-g456defa",
            "rootlesskit": "rootlesskit version 3.1.1",
        }
        with self.assertRaisesRegex(DockerReleaseError, "exactly match"):
            _parse_versions(output, NEW_VERSION)

    def test_containerd_official_v2_version_output_is_parsed(self) -> None:
        output = {
            "dockerd": f"Docker version {NEW_VERSION}, build 123abcd",
            "docker": f"Docker version {NEW_VERSION}, build 234bcde",
            "containerd": (
                "containerd github.com/containerd/containerd/v2 v2.3.6 ee2735368117d2eb259779949d5e75cdafec9761"
            ),
            "runc": "runc version 1.5.2\ncommit: v1.5.2-0-g456defa",
            "rootlesskit": "rootlesskit version 3.1.1",
        }
        components, revisions = _parse_versions(output, NEW_VERSION)
        self.assertEqual(components["containerd"], "2.3.6")
        self.assertEqual(revisions["containerd"], "ee2735368117d2eb259779949d5e75cdafec9761")


if __name__ == "__main__":
    unittest.main()
