"""Published build results retain source and checksum pins from private payloads."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts import container_engine as engine


class PayloadResultProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.images = {image["name"]: image for image in engine._load_images()}

    def _published_inputs(self, name: str) -> dict:
        image = self.images[name]
        with tempfile.TemporaryDirectory() as directory:
            result = engine._BuildResult(
                image_name=name,
                image_ref=image["image"],
                version=image["version"],
                source_revision="a" * 40,
                index_digest=f"sha256:{'b' * 64}",
                architecture_digests=dict.fromkeys(("amd64", "arm64"), f"sha256:{'c' * 64}"),
                component_inputs=engine._component_inputs(image),
                tags=["run-1-1"],
                run_id="1",
                run_attempt="1",
            )
            path = engine._write_build_result(Path(directory), result)
            return json.loads(path.read_text(encoding="utf-8"))["componentInputs"]

    def test_podman_source_and_helper_commits_survive_payload_indirection(self) -> None:
        inputs = self._published_inputs("podman-6.1-rootful")
        self.assertIn("FEDORA_IMAGE", inputs)  # Existing consumer inputs remain visible.
        payload = inputs["payload"]
        self.assertEqual(payload["manifest"], "images/podman/payloads/podman-6.1.yaml")
        self.assertEqual(payload["manifestSha256"], hashlib.sha256(Path(payload["manifest"]).read_bytes()).hexdigest())
        declared = yaml.safe_load(Path(payload["manifest"]).read_text())["build"]["args"]
        for key in ("PODMAN_COMMIT", "NETAVARK_COMMIT", "AARDVARK_COMMIT"):
            self.assertEqual(payload["args"][key], declared[key])

    def test_docker_verified_checksums_survive_for_each_architecture(self) -> None:
        inputs = self._published_inputs("docker-29-rootless")
        payload = inputs["payload"]
        self.assertEqual(payload["manifest"], "images/docker/upstream/29/payload.yaml")
        self.assertEqual(payload["manifestSha256"], hashlib.sha256(Path(payload["manifest"]).read_bytes()).hexdigest())
        declared = yaml.safe_load(Path(payload["manifest"]).read_text())["build"]
        self.assertEqual(payload["args"]["ENGINE_VERSION"], declared["args"]["ENGINE_VERSION"])
        for arch in ("amd64", "arm64"):
            for pin in ("ENGINE_SHA256", "ROOTLESS_SHA256"):
                self.assertEqual(payload["architectureArgs"][arch][pin], declared["architectureArgs"][arch][pin])
        self.assertEqual(payload["provenance"]["payloadKind"], "verified-upstream-static-archives")


if __name__ == "__main__":
    unittest.main()
