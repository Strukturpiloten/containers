"""Validate installed files and versions, then retain the wheel checksum."""
# ruff: noqa: INP001

import hashlib
import importlib.metadata
import json
from pathlib import Path

path = Path("/usr/share/strukturpiloten/strukturbo-nautobot.json")
record = json.loads(path.read_text())
distribution = importlib.metadata.distribution("nautobot-strukturbo")
actual = {
    str(p): hashlib.sha256(Path(distribution.locate_file(p)).read_bytes()).hexdigest()
    for p in distribution.files
    if str(p).startswith("nautobot_strukturbo/") and str(p).endswith((".py", ".html"))
}
if actual != record["package_files"]:
    msg = "Installed registry package differs from the qualified source"
    raise ValueError(msg)
for package, version in record["versions"].items():
    if importlib.metadata.version(package) != version:
        msg = f"Installed package version differs: {package}"
        raise ValueError(msg)
wheels = list(Path("/tmp/registry-wheels").glob("*.whl"))  # noqa: S108
if len(wheels) != 1:
    msg = "Expected exactly one registry wheel"
    raise ValueError(msg)
record["wheel_sha256"] = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
