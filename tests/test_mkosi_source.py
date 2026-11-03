"""Verify coherent mkosi source updates without downloading or executing PR code."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import Mock, patch

import yaml

from scripts import mkosi_source as source

COMMIT = "a" * 40
OLD_CHECKSUM = "b" * 64
ARCHIVE = b"synthetic upstream archive; never extracted"
CHECKSUM = hashlib.sha256(ARCHIVE).hexdigest()


def metadata(version: str = "27.1", commit: str = COMMIT, checksum: str = OLD_CHECKSUM) -> str:
    """Prepare synthetic source metadata."""
    return yaml.safe_dump(
        {
            "build": {
                "args": {
                    key: {"value": value}
                    for key, value in (("MKOSI_VERSION", version), ("MKOSI_COMMIT", commit), ("MKOSI_SHA256", checksum))
                }
            }
        },
        sort_keys=False,
    )


def upstream(url: str) -> bytes:
    """Serve fixed synthetic upstream data."""
    if url in (source.API + "ref/tags/v27.1", source.API + "ref/tags/v28"):
        return json.dumps({"object": {"type": "commit", "sha": COMMIT}}).encode()
    if url == source.ARCHIVES + COMMIT:
        return ARCHIVE
    raise AssertionError("Unexpected upstream request: " + url)


class MkosiSourceTests(unittest.TestCase):
    def test_version_commit_and_checksum_are_updated_coherently(self) -> None:
        text = metadata()
        changed = source.synchronize(metadata("26.0", "c" * 40), text, fetch=upstream)
        self.assertEqual(source.pins(changed), ("27.1", COMMIT, CHECKSUM))
        self.assertEqual(changed, text.replace(OLD_CHECKSUM, CHECKSUM))
        self.assertEqual(source.synchronize(text, changed, fetch=upstream), changed)

    def test_major_only_mkosi_release_tags_are_supported(self) -> None:
        updated = source.synchronize(metadata(), metadata("28"), fetch=upstream)
        self.assertEqual(source.pins(updated), ("28", COMMIT, CHECKSUM))

    def test_unchanged_pins_need_no_upstream_request(self) -> None:
        fetch = Mock(side_effect=AssertionError("No network for unrelated updates"))
        self.assertEqual(source.synchronize(metadata(), metadata(), fetch=fetch), metadata())
        fetch.assert_not_called()

    def test_tag_commit_mismatch_refuses_archive_fetch(self) -> None:
        fetch = Mock(return_value=json.dumps({"object": {"type": "commit", "sha": "c" * 40}}).encode())
        with self.assertRaisesRegex(source.MkosiPinError, "commit differ"):
            source.verified_checksum("27.1", COMMIT, fetch=fetch)
        self.assertEqual(fetch.call_count, 1)

    def test_annotated_tag_resolves_only_through_fixed_upstream(self) -> None:
        fetch = Mock(
            side_effect=[
                json.dumps({"object": {"type": "tag", "sha": "d" * 40}}).encode(),
                json.dumps({"object": {"type": "commit", "sha": COMMIT}}).encode(),
                ARCHIVE,
            ]
        )
        self.assertEqual(source.verified_checksum("27.1", COMMIT, fetch=fetch), CHECKSUM)
        self.assertEqual(
            [call.args[0] for call in fetch.call_args_list],
            [
                source.API + "ref/tags/v27.1",
                source.API + "tags/" + "d" * 40,
                source.ARCHIVES + COMMIT,
            ],
        )

    def test_invalid_version_commit_and_tag_chain_fail_closed(self) -> None:
        for version, commit in (("../../other", COMMIT), ("27.1", "main")):
            with self.subTest(version=version, commit=commit), self.assertRaises(source.MkosiPinError):
                source.verified_checksum(version, commit, fetch=Mock())
        fetch = Mock(return_value=json.dumps({"object": {"type": "tag", "sha": "d" * 40}}).encode())
        with self.assertRaisesRegex(source.MkosiPinError, "chain"):
            source.verified_checksum("27.1", COMMIT, fetch=fetch)

    def test_fixed_source_and_bounded_downloads_are_enforced(self) -> None:
        with self.assertRaisesRegex(source.MkosiPinError, "fixed upstream"):
            source.fetch_bytes("https://example.invalid/archive")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.geturl.return_value = source.ARCHIVES + COMMIT
        response.read.return_value = b"x" * (source.LIMIT + 1)
        with (
            patch.object(source.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(source.MkosiPinError, "size limit"),
        ):
            source.fetch_bytes(source.ARCHIVES + COMMIT)
        response.geturl.return_value = "https://example.invalid/archive"
        with (
            patch.object(source.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(source.MkosiPinError, "redirected"),
        ):
            source.fetch_bytes(source.ARCHIVES + COMMIT)


if __name__ == "__main__":
    unittest.main()
