"""Published build results retain source and checksum pins from private payloads."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(payload["args"]["PODMAN_COMMIT"], "04f3aa430e6df81bea059978bc5bafbc846ba3e7")
        self.assertEqual(payload["args"]["NETAVARK_COMMIT"], "8e91ad1d947ed325327b638f0cb906bea1f7d0ab")
        self.assertEqual(payload["args"]["AARDVARK_COMMIT"], "cd7417681229219059939bdd9f0b3bd9ac9abb08")

    def test_docker_verified_checksums_survive_for_each_architecture(self) -> None:
        inputs = self._published_inputs("docker-29-rootless")
        payload = inputs["payload"]
        self.assertEqual(payload["manifest"], "images/docker/upstream/29/payload.yaml")
        self.assertEqual(payload["manifestSha256"], hashlib.sha256(Path(payload["manifest"]).read_bytes()).hexdigest())
        self.assertEqual(payload["args"]["ENGINE_VERSION"], "29.8.1")
        self.assertEqual(
            payload["architectureArgs"]["amd64"]["ENGINE_SHA256"],
            "d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70",
        )
        self.assertEqual(
            payload["architectureArgs"]["arm64"]["ENGINE_SHA256"],
            "667395fbffab52901b80181dfbb39ea76da2fbd7642c4fbddd24e42146b07b48",
        )
        self.assertEqual(
            payload["architectureArgs"]["amd64"]["ROOTLESS_SHA256"],
            "8f1ed16fc6913241e599af6234a7f30502bde6e73bebbbc7176b17802d967d49",
        )
        self.assertEqual(
            payload["architectureArgs"]["arm64"]["ROOTLESS_SHA256"],
            "3890bed82dc432e9fed7e52efcc18bb82647cd7beae45b03e9e2a2f6c3282c66",
        )
        self.assertEqual(payload["provenance"]["payloadKind"], "verified-upstream-static-archives")


if __name__ == "__main__":
    unittest.main()
