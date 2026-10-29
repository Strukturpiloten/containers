"""Preflight selected, digest-pinned registry inputs before scheduling container builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts import build_payloads

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
ATTEMPTS = 3
REQUEST_TIMEOUT = 30
TRANSIENT = re.compile(
    r"timeout|timed out|connection reset|temporary|too many requests|\b(?:429|500|502|503|504)\b", re.IGNORECASE
)


class InputError(ValueError):
    """An input cannot be proven available for the requested Linux architectures."""


@dataclass
class ImageInput:
    """A deduplicated registry manifest and its selected consumers."""

    reference: str
    architectures: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


def pinned_reference(value: str) -> str:
    """Remove the descriptive tag while retaining the exact digest and registry port."""
    name, separator, digest = value.rpartition("@")
    if not separator or not DIGEST.fullmatch(digest):
        msg = f"Image input must be pinned to a sha256 digest: {value}"
        raise InputError(msg)
    if name.rfind(":") > name.rfind("/"):
        name = name[: name.rfind(":")]
    return f"{name}@{digest}"


def collect_inputs(root: Path, plan: dict[str, Any]) -> list[ImageInput]:
    """Collect selected image arguments and private payload inputs, once per digest."""
    inputs: dict[str, ImageInput] = {}

    def add(value: str, architectures: set[str], source: str) -> None:
        reference = pinned_reference(value)
        item = inputs.setdefault(reference, ImageInput(reference))
        item.architectures.update(architectures)
        item.sources.add(source)

    architectures: dict[str, set[str]] = {}
    for entry in plan.get("smokeBuildMatrix", {}).get("include", []):
        architectures.setdefault(entry["name"], set()).add(entry["arch"])
    for image in plan["images"]:
        wanted = architectures.get(image["name"], set())
        if not wanted:
            continue
        for name, argument in image["build"].get("args", {}).items():
            if argument.get("type") == "external-image":
                add(argument["value"], wanted, f"{image['metadataFile']}:{name}")
    for entry in plan.get("payloadMatrix", {}).get("include", []):
        manifest = build_payloads.load_manifest(root, entry["manifest"])
        build = manifest["build"]
        arguments = {**build.get("args", {}), **build.get("architectureArgs", {}).get(entry["arch"], {})}
        for name, value in arguments.items():
            if name.endswith("_IMAGE"):
                add(value, {entry["arch"]}, f"{entry['manifest']}:{name}")
    return [inputs[key] for key in sorted(inputs)]


def _inspect(reference: str, *, config: bool = False) -> bytes:
    command = ["skopeo", "inspect", "--raw"]
    if config:
        command.append("--config")
    command.append(f"docker://{reference}")
    for attempt in range(ATTEMPTS):
        try:
            result = subprocess.run(  # noqa: S603 - separate, fixed CLI arguments; registry references are not shell text.
                command, capture_output=True, check=False, timeout=REQUEST_TIMEOUT
            )
        except subprocess.TimeoutExpired:
            error = f"Registry request timed out for {reference}"
        except OSError as exc:
            raise InputError(str(exc)) from exc
        else:
            if result.returncode == 0:
                return result.stdout
            error = result.stderr.decode(errors="replace").strip()
        if not TRANSIENT.search(error) or attempt == ATTEMPTS - 1:
            raise InputError(error)
        time.sleep(2 ** (attempt + 1))
    msg = "Registry inspection exhausted its retry budget."
    raise InputError(msg)


def _document(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        msg = "Registry returned invalid manifest JSON."
        raise InputError(msg) from exc
    if not isinstance(value, dict):
        msg = "Registry manifest must be a JSON object."
        raise InputError(msg)
    return value


def _platforms(item: ImageInput) -> set[str]:
    raw = _inspect(item.reference)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != item.reference.rsplit("@", 1)[1]:
        msg = "Registry manifest bytes do not match the pinned digest."
        raise InputError(msg)
    manifest = _document(raw)
    if "manifests" not in manifest:
        configuration = _document(_inspect(item.reference, config=True))
        return {configuration.get("architecture", "")} if configuration.get("os") == "linux" else set()
    entries = manifest["manifests"]
    if not isinstance(entries, list):
        msg = "Registry index manifests must be a list."
        raise InputError(msg)
    return {
        entry["platform"]["architecture"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("platform"), dict)
        and entry["platform"].get("os") == "linux"
        and isinstance(entry["platform"].get("architecture"), str)
        and DIGEST.fullmatch(str(entry.get("digest", "")))
        and isinstance(entry.get("size"), int)
        and entry["size"] > 0
    }


def check_input(item: ImageInput) -> dict[str, Any]:
    """Return report evidence for one pinned input, including a permanent failure reason."""
    report: dict[str, Any] = {
        "reference": item.reference,
        "architectures": sorted(item.architectures),
        "sources": sorted(item.sources),
    }
    try:
        available = _platforms(item)
    except InputError as exc:
        report.update(status="failed", error=str(exc))
    else:
        missing = item.architectures - available
        if missing:
            report.update(
                status="failed", error=f"Pinned manifest lacks Linux platform(s): {', '.join(sorted(missing))}."
            )
        else:
            report.update(status="passed", availableArchitectures=sorted(available))
    return report


def preflight(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    """Check only selected inputs; failures in unrelated catalogue entries cannot block CI."""
    inputs = collect_inputs(root, plan)
    with ThreadPoolExecutor(max_workers=4) as pool:
        checks = list(pool.map(check_input, inputs))
    return {"schemaVersion": 1, "checks": checks, "passed": all(item["status"] == "passed" for item in checks)}


def main() -> int:
    """Write preflight evidence even when a selected input cannot be built."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text())
        report = preflight(Path.cwd(), plan)
    except (InputError, build_payloads.PayloadError, ValueError, OSError) as exc:
        report = {"schemaVersion": 1, "checks": [], "passed": False, "error": str(exc)}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    for check in report["checks"]:
        if check["status"] == "failed":
            sys.stderr.write(f"image-inputs: {check['reference']}: {check['error']} ({', '.join(check['sources'])})\n")
    if report.get("error"):
        sys.stderr.write(f"image-inputs: {report['error']}\n")
    sys.stdout.write(
        f"Preflight checked {len(report['checks'])} unique pinned image inputs; passed={report['passed']}.\n"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
