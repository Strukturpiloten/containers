"""Require Grype release and checksum pins to stay aligned across native runners."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

PIN_RE = re.compile(
    r"(?m)^[ \t]*machine=(?P<architecture>amd64|arm64)[ \t]*\n"
    r"[ \t]*release=(?P<release>v\d+\.\d+\.\d+)[ \t]*\n"
    r"[ \t]*expected=(?P<digest>[a-f0-9]{64})[ \t]*$"
)
ACTION = Path(__file__).resolve().parents[1] / ".github/actions/scan-vulnerabilities/action.yml"
ARCHITECTURES = {"amd64", "arm64"}


class GrypePinError(ValueError):
    """The scanner release pins cannot be safely updated together."""


def validate_script(script: str) -> dict[str, tuple[str, str]]:
    """Require exactly one version and SHA-256 per native architecture."""
    matches = list(PIN_RE.finditer(script))
    pins = {match["architecture"]: (match["release"], match["digest"]) for match in matches}
    if len(matches) != len(ARCHITECTURES) or set(pins) != ARCHITECTURES:
        msg = "Grype requires one release and SHA-256 pin for each native architecture."
        raise GrypePinError(msg)
    if len({release for release, _ in pins.values()}) != 1:
        msg = "Grype AMD64 and ARM64 release versions must match."
        raise GrypePinError(msg)
    return pins


def validate_action(path: Path = ACTION) -> dict[str, tuple[str, str]]:
    """Read the installed Grype step and validate its architecture pins."""
    action = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    scripts = [step["run"] for step in steps if step.get("name") == "Install pinned Grype"]
    if len(scripts) != 1:
        msg = "The scanner action must have exactly one pinned Grype install step."
        raise GrypePinError(msg)
    return validate_script(scripts[0])


def main() -> None:
    """Check scanner release pin alignment in CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", type=Path, default=ACTION)
    args = parser.parse_args()
    validate_action(args.action)


if __name__ == "__main__":
    main()
