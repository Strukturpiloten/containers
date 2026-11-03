"""Bind mkosi's release tag, immutable source commit and archive checksum."""

# ruff: noqa: TRY003, EM101

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable

import yaml

METADATA_PATH = "images/hardware/strukturbo-hardware-builder/container.yaml"
API = "https://api.github.com/repos/systemd/mkosi/git/"
ARCHIVES = "https://codeload.github.com/systemd/mkosi/tar.gz/"
LIMIT = 16 * 1024 * 1024
Fetcher = Callable[[str], bytes]


class MkosiPinError(ValueError):
    """The selected mkosi source is incomplete or inconsistent."""


def fetch_bytes(url: str) -> bytes:
    """Read only the fixed public upstream; never extract or execute its archive."""
    if not url.startswith((API, ARCHIVES)):
        raise MkosiPinError("mkosi source must use the fixed upstream repository")
    request = urllib.request.Request(url, headers={"User-Agent": "strukturpiloten-containers"})  # noqa: S310 - fixed HTTPS upstream
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed HTTPS upstream
            if not response.geturl().startswith((API, ARCHIVES)):
                raise MkosiPinError("mkosi upstream redirected outside its fixed source")
            value = response.read(LIMIT + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise MkosiPinError("mkosi upstream could not be read") from exc
    if not value or len(value) > LIMIT:
        raise MkosiPinError("mkosi upstream response is empty or exceeds the size limit")
    return value


def pins(text: str) -> tuple[str, str, str]:
    """Read the three exact source inputs without accepting executable instructions."""
    try:
        args = yaml.safe_load(text)["build"]["args"]
        values = tuple(args[key]["value"] for key in ("MKOSI_VERSION", "MKOSI_COMMIT", "MKOSI_SHA256"))
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise MkosiPinError("mkosi metadata requires version, commit and archive checksum") from exc
    for value, pattern in zip(values, (r"\d+(?:\.\d+){0,2}", r"[a-f0-9]{40}", r"[a-f0-9]{64}"), strict=True):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise MkosiPinError("mkosi metadata contains an invalid source pin")
    return values


def verified_checksum(version: str, commit: str, *, fetch: Fetcher | None = None) -> str:
    """Reject a tag/commit mismatch before hashing the commit-specific archive."""
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", version) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise MkosiPinError("mkosi source requires an exact release and commit")
    fetch = fetch or fetch_bytes
    url = API + "ref/tags/v" + version
    for _ in range(4):
        try:
            obj = json.loads(fetch(url))["object"]
            kind, sha = obj["type"], obj["sha"]
        except (ValueError, KeyError, TypeError) as exc:
            raise MkosiPinError("mkosi tag response is invalid") from exc
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise MkosiPinError("mkosi tag has no immutable source identity")
        if kind == "commit":
            if sha != commit:
                raise MkosiPinError("mkosi release tag and selected source commit differ")
            return hashlib.sha256(fetch(ARCHIVES + commit)).hexdigest()
        if kind != "tag":
            raise MkosiPinError("mkosi release does not resolve to a commit")
        url = API + "tags/" + sha
    raise MkosiPinError("mkosi annotated tag chain exceeds the limit")


def synchronize(before: str | None, text: str, *, fetch: Fetcher | None = None) -> str:
    """Complete Renovate's version/commit update in trusted generated-data tooling."""
    version, commit, checksum = pins(text)
    if before is not None and pins(before) == (version, commit, checksum):
        return text
    expected = verified_checksum(version, commit, fetch=fetch)
    if checksum == expected:
        return text
    matches = list(re.finditer(r"(?m)^\s*MKOSI_SHA256:\s*\n\s+value:\s*(?P<checksum>[a-f0-9]{64})(?=\s*\n)", text))
    if len(matches) != 1:
        raise MkosiPinError("mkosi checksum field must occur exactly once")
    start, end = matches[0].span("checksum")
    return text[:start] + expected + text[end:]
