"""Read the canonical configuration shared by generated workflows and the planner."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

CONFIG_PATH = Path(".github/automation.yml")


def load_config(root: Path) -> dict[str, str]:
    """Reject incomplete or unsafe values before generating literal workflow YAML."""
    config = yaml.safe_load((root / CONFIG_PATH).read_text())
    patterns = {
        "AMD64_RUNNER": r"ubuntu-\d{2}\.\d{2}",
        "ARM64_RUNNER": r"ubuntu-\d{2}\.\d{2}-arm",
        "PYTHON_VERSION": r"\d+\.\d+(?:\.\d+)?",
        "UV_VERSION": r"v?\d+\.\d+\.\d+",
        "ACTIONLINT_VERSION": r"v?\d+\.\d+\.\d+",
        "SYFT_VERSION": r"v?\d+\.\d+\.\d+",
    }
    if not isinstance(config, dict) or set(config) != set(patterns):
        message = f"{CONFIG_PATH} must define exactly {', '.join(patterns)}."
        raise ValueError(message)
    for name, pattern in patterns.items():
        if not isinstance(config[name], str) or re.fullmatch(pattern, config[name]) is None:
            message = f"{CONFIG_PATH} contains an invalid {name}."
            raise ValueError(message)
    return config


CONFIG = load_config(Path(__file__).resolve().parents[1])
RUNNERS = {"amd64": CONFIG["AMD64_RUNNER"], "arm64": CONFIG["ARM64_RUNNER"]}
