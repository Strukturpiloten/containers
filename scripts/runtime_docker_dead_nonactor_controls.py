"""Mandatory, test-only dead-nonactor controls for the current native invocation.

The coordinator captures one exact-candidate Git blob, separately from the fixed
production helper closure. Only captured code and the authenticated immutable
stage enter the existing privileged watchdog. No mutable checkout is imported.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import TYPE_CHECKING

from scripts import docker_userns_bootstrap_bundle as git
from scripts.runtime_errors import ProbeError

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext

FIXTURE = "tests/native_docker_dead_nonactor_fixture.py"
MAX_SOURCE = 65536
MAX_RESULT = 8192
COMMAND_SECONDS = 6
WORK_NS = 3_000_000_000
CLEANUP_NS = 1_000_000_000
CONTROLS = (
    "certified-view",
    "retained-positive",
    "reaped-refusal",
    "numeric-reuse",
    "replacement-positive",
    "reserved-refusal",
    "leader-live-refusal",
    "last-thread-positive",
)
ASSOCIATION_KEYS = {"candidate", "run", "attempt", "job", "bindingSha256", "sourceSha256"}


def _require(value: object) -> None:
    if not value:
        message = "required native dead-nonactor controls refused"
        raise ProbeError(message)


def capture(candidate: str) -> bytes:
    """Read the fixed fixture through authenticated, finite, local Git objects."""
    _require(re.fullmatch(r"[0-9a-f]{40}", candidate))
    header = git.git_object("commit", candidate).split(b"\n", 1)[0]
    _require(re.fullmatch(rb"tree [0-9a-f]{40}", header))
    tree = header[5:].decode("ascii")
    for index, name in enumerate(FIXTURE.split("/")):
        mode, identifier = git.tree_entries(git.git_object("tree", tree))[name]
        if index == 0:
            _require(mode == "40000")
            tree = identifier
        else:
            _require(mode == "100644")
    raw = git.git_object("blob", identifier)
    _require(0 < len(raw) <= MAX_SOURCE)
    raw.decode("utf-8", "strict")
    return raw


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        _require(key not in value)
        value[key] = item
    return value


def parse(raw: bytes, association: dict, architecture: str) -> dict:
    """Retain only closed associated outcomes, including explicit native refusal."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESULT)
    value = json.loads(raw, object_pairs_hook=_unique)
    _require(
        type(value) is dict
        and set(value)
        == {"schemaVersion", "association", "architecture", "kernel", "controls", "status", "complete", "cleanup"}
        and type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 1
        and type(value["association"]) is dict
        and set(value["association"]) == ASSOCIATION_KEYS
        and value["association"] == association
        and value["architecture"] == architecture
        and architecture in {"amd64", "arm64"}
        and type(value["kernel"]) is str
        and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", value["kernel"])
        and type(value["controls"]) is dict
        and set(value["controls"]) == set(CONTROLS)
        and all(value["controls"][name] in {"passed", "not-run", "failed", "unavailable"} for name in CONTROLS)
        and value["status"] in {"passed", "failed", "unavailable"}
        and type(value["complete"]) is bool
        and type(value["cleanup"]) is bool
        and (value["status"] == "passed") == value["complete"]
    )
    if value["complete"]:
        _require(value["cleanup"] and all(value["controls"][name] == "passed" for name in CONTROLS))
    _require(value["kernel"] == os.uname().release)
    return value


def validate(raw: bytes, association: dict, architecture: str) -> dict:
    """Authorize only complete successful observations and verified cleanup."""
    value = parse(raw, association, architecture)
    _require(value["status"] == "passed")
    return value


def require_controls(ctx: RuntimeContext) -> None:
    """Run once before ready; failed, missing or mismatched results never authorize it."""
    try:
        backend, profile = ctx.backend, ctx.backend.scoped_profile
        binding = profile.binding
        binding.validate()
        _require(profile.ctx is ctx and backend.scoped_stage == profile.stage and not profile.failures)
        _require(profile._bootstrap_anchor is not None and profile._bootstrap_anchor[0] == profile.stage)  # noqa: SLF001
        raw = capture(binding.candidate)
        association = {
            "candidate": binding.candidate,
            "run": binding.run,
            "attempt": binding.attempt,
            "job": binding.job,
            "bindingSha256": binding.digest(),
            "sourceSha256": hashlib.sha256(raw).hexdigest(),
        }
        cached = vars(backend).get("_dead_nonactor_controls")
        if cached is not None:
            validate(json.dumps(cached, separators=(",", ":")).encode(), association, ctx.architecture)
            return
        allowance = backend.command_timeout(COMMAND_SECONDS)
        # Leave watchdog scheduling/kill allowance outside this original work+cleanup
        # boundary. Neither the fixture nor any child may renew these boundaries.
        now = time.monotonic_ns()
        until = min(now + WORK_NS, now + int((allowance - 2) * 1_000_000_000) - CLEANUP_NS)
        _require(until > now and ctx.architecture == binding.architecture)
        command = [
            "/usr/bin/python3.14",
            "-I",
            "-B",
            "-S",
            "-c",
            raw.decode("utf-8"),
            str(profile.stage),
            json.dumps(association, sort_keys=True, separators=(",", ":")),
            str(until),
        ]
        with ctx.private_native_controls_response() as response:
            ctx.reset_native_controls_response(response)
            command_failed = False
            try:
                ctx.command(
                    "required native dead-nonactor controls",
                    backend.privileged(command, allowance),
                    timeout=allowance,
                    stdout=response,
                )
            except Exception:  # noqa: BLE001 - consume only a valid closed refusal, never exception operands.
                command_failed = True
            result = parse(ctx.read_native_controls_response(response, MAX_RESULT), association, ctx.architecture)
        if command_failed or result["status"] != "passed":
            ctx.checks.append(
                {"name": "native dead-nonactor mechanism controls", "status": "failed", "observations": result}
            )
            _require(value=False)
        backend.check_deadline()
        backend._dead_nonactor_controls = result  # noqa: SLF001 - per-backend invocation-only cache.
        ctx.checks.append(
            {"name": "native dead-nonactor mechanism controls", "status": "passed", "observations": result}
        )
    except Exception:  # noqa: BLE001 - fixed public failure, private streams and source never escape.
        # RuntimeContext's binary response path suppresses both raw streams. Never
        # propagate source, stage, command or exception details to public logs.
        message = "required native dead-nonactor controls failed; native qualification refused"
        raise ProbeError(message) from None
