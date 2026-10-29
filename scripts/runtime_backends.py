"""Explicit outer-runtime selection and isolated backend configuration.

Image runtime profiles describe the inner workload. Outer-runtime selection is a
caller policy, never an inference from an image name or an inner root mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def select_outer_engine(selection: str, profile: str) -> str:
    """Resolve the closed caller policy without contacting either runtime."""
    profiles = {"docker": "docker", "podman": "podman", "phpFpm": "podman", "notifyPush": "podman"}
    if profile not in profiles:
        msg = f"unsupported runtime profile {profile}"
        raise ValueError(msg)
    if selection not in {"podman", "docker", "profile"}:
        msg = f"unsupported outer engine selection {selection}"
        raise ValueError(msg)
    return profiles[profile] if selection == "profile" else selection


@dataclass(frozen=True)
class PodmanBackend:
    """Preserve the existing invocation-owned Podman store and command prefix."""

    directory: Path
    sudo: tuple[str, ...]
    configuration: Path

    def initialize(self) -> None:
        """Create only the three directories belonging to this invocation."""
        for part in ("root", "runroot", "tmp"):
            (self.directory / part).mkdir()

    def command_prefix(self) -> list[str]:
        """Bind every command to this store, not the caller's ambient store."""
        return [
            *self.sudo,
            "env",
            f"CONTAINERS_CONF_OVERRIDE={self.configuration}",
            "podman",
            "--root",
            str(self.directory / "root"),
            "--runroot",
            str(self.directory / "runroot"),
            "--tmpdir",
            str(self.directory / "tmp"),
        ]
