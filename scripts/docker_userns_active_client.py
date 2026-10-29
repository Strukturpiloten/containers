"""Unprivileged native client for the isolated issue527 qualification candidate."""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scripts.docker_userns_active_bootstrap_bundle import context
from scripts.docker_userns_qualification import NativeBinding

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext

STAGE_PATTERN = r"/run/containers-userns-active\.[0-9a-f]{32}"


class ActiveClient:
    """Bind native phase evidence to a separately admitted root-private helper."""

    def __init__(self, ctx: RuntimeContext, stage: str, identity: dict[str, str]) -> None:
        """Prepare one lease only after the archive and private runtime are proven."""
        if not re.fullmatch(STAGE_PATTERN, stage):
            reason = "invalid active qualification stage"
            raise ValueError(reason)
        self.ctx, self.stage = ctx, Path(stage)
        self.provenance = context(dict(os.environ), ctx.architecture)
        backend = ctx.backend
        self.binding = NativeBinding(
            candidate=os.environ.get("GITHUB_SHA", ""),
            run=os.environ.get("GITHUB_RUN_ID", ""),
            attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            job=os.environ.get("GITHUB_JOB", ""),
            architecture=ctx.architecture,
            phase=ctx.runtime_phase,
            image=ctx.name,
            archive_sha256=identity["archiveSha256"],
            manifest_digest=identity["manifestDigest"],
            config_digest=identity["configDigest"],
            owner=backend.owner,
            runtime_slice=backend.slice,
            slice_identity=backend.slice_identity,
            deadline_ns=int(ctx.runtime_deadline * 1_000_000_000),
        )
        self.binding.validate()
        self.name = "new"
        self.evidence: dict[str, Any] = {}

    def prepare(self) -> None:
        """Acquire authority only after the backend records this pending client."""
        backend = self.ctx.backend
        self.evidence = self.rpc(
            "prepare",
            {
                "binding": asdict(self.binding),
                "daemonDirectory": str(backend.directory),
                "timeoutExecutable": backend.timeout_executable(),
                "coordinatorPid": os.getpid(),
            },
        )
        self.name = self.evidence["lease"]

    def rpc(self, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        """Use the native bounded command path and closed root-side JSON protocol."""
        raw = base64.b64encode(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        command = [
            "/usr/bin/python3.14",
            "-I",
            "-B",
            "-S",
            str(self.stage / "scripts/docker_userns_active.py"),
            operation,
            str(self.stage),
            self.name,
            "--request",
            raw,
        ]
        result = self.ctx.command(
            "scoped userns profile " + operation, self.ctx.backend.privileged(command, 45), timeout=45
        )
        value = json.loads(result)
        if (
            value.get("bindingSha256") != self.binding.digest()
            or value.get("retained") is not False
            or value.get("validationProfile") != self.provenance["validationProfile"]
            or value.get("validationProfileRequested") != self.provenance["validationProfileRequested"]
        ):
            reason = "active qualification response refused"
            raise ValueError(reason)
        return value

    def create_options(self) -> tuple[str, ...]:
        """Persist one create intent before adding the exact scoped label and profile."""
        self.evidence = self.rpc("create-intent", {"bindingSha256": self.binding.digest(), "container": None})
        return (
            "--security-opt",
            "apparmor=" + self.evidence["profileName"],
            "--label",
            "io.strukturpiloten.userns-profile=" + self.name,
        )

    def bind(self, container: str) -> None:
        """Require held-task profile proof after the one owned systemd guest starts."""
        self.evidence = self.rpc("bind", {"bindingSha256": self.binding.digest(), "container": container})

    def close(self) -> None:
        """Prove guest/profile absence before native private daemon teardown."""
        if self.name == "new":
            reason = "unacknowledged active qualification retains private runtime"
            raise ValueError(reason)
        self.evidence = self.rpc("close", {"bindingSha256": self.binding.digest(), "container": None})
