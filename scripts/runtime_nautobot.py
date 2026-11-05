"""Qualify the installed artifact with its commit-pinned bootstrap fixture harness."""

# Fixed, owned source paths and OCI identities; no deployment credentials.
# ruff: noqa: EM101, SLF001, TRY003
from __future__ import annotations

import json
import os
from contextlib import ExitStack
from typing import TYPE_CHECKING

import yaml

from scripts.nautobot_source import ROOT, verify

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext


def run(ctx: RuntimeContext) -> None:
    """Use separate disposable databases; never inject app source into the image."""
    with ExitStack() as fixtures:
        _run(ctx, fixtures)


def _fixture_compatibility(ctx: RuntimeContext) -> list[str]:
    """Keep the Ubuntu runner workaround explicit and confined to CI fixtures."""
    if not ctx._sudo or os.environ.get("GITHUB_ACTIONS") != "true":
        return []
    security = json.loads(ctx.podman("inspect fixture confinement", "info", "--format", "{{json .Host.Security}}"))
    if not security.get("apparmorEnabled"):
        return []
    profile = ctx.podman(
        "inspect fixture AppArmor stacking",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--entrypoint=/bin/cat",
        ctx.image_ref,
        "/proc/1/attr/current",
    )
    if not profile.strip().startswith("containers-default-0.66.0//&crun"):
        return []
    ctx.skip(
        "fixture AppArmor enforcement",
        "GitHub Ubuntu stacked crun profiles block PostgreSQL signals; disposable fixtures use unconfined AppArmor",
    )
    return ["--fixture-apparmor-unconfined"]


def _run(ctx: RuntimeContext, fixtures: ExitStack) -> None:
    """Release dependency images through Podman before deleting mapped-UID stores."""
    staged = verify()
    metadata = yaml.safe_load((ROOT / "images/strukturbo/strukturbo-nautobot/container.yaml").read_text())
    arguments = metadata["build"]["args"]
    database = arguments["DATABASE_IMAGE"]["value"]
    redis = arguments["REDIS_IMAGE"]["value"]
    for name, image in (("PostgreSQL", database), ("Redis", redis)):
        ctx.podman(f"acquire disposable {name} fixture", "pull", "--quiet", image, timeout=180)
        fixtures.callback(ctx.podman, f"release disposable {name} fixture", "image", "rm", image, timeout=120)
    bootstrap = staged / "bootstrap"
    ctx.command(
        "install locked qualification tooling",
        ["uv", "sync", "--project", str(bootstrap), "--frozen", "--no-dev"],
        timeout=180,
    )
    inspected = json.loads(ctx.podman("inspect candidate identity", "image", "inspect", ctx.image_ref))[0]
    image = "sha256:" + inspected["Id"].removeprefix("sha256:")
    ctx.assert_equal("no implicit migration entrypoint", json.dumps(inspected["Config"].get("Entrypoint") or []), "[]")
    ctx.assert_equal(
        "direct Nautobot startup",
        json.dumps(inspected["Config"]["Cmd"]),
        json.dumps(["nautobot-server", "start", "--ini", "/opt/nautobot/uwsgi.ini"]),
    )
    command = [
        *ctx._sudo,
        "env",
        f"CONTAINERS_CONF_OVERRIDE={ROOT / '.github/actions/build-arch-image/podman-smoke-containers.conf'}",
        str(bootstrap / ".venv/bin/python"),
        str(bootstrap / "scripts/qualify_access_registry.py"),
        "--installed",
        "--image",
        image,
        "--database-image",
        database,
        "--redis-image",
        redis,
    ]
    command.extend(_fixture_compatibility(ctx))
    command.extend("--podman-arg=" + argument for argument in ctx._podman[ctx._podman.index("podman") + 1 :])
    output = ctx.command("installed registry, HTTPS, TLS, login, workers and queue", command, timeout=1200)
    record = json.loads((staged / "provenance.json").read_text())
    version = record["appVersion"]
    if version == "0.1.0":
        marker = "Qualified installed registry source SHA-256: "
        if marker not in output:
            raise ValueError("Installed-artifact qualification marker missing")
        ctx.assert_equal(
            "qualified installed source", output.split(marker)[-1].strip(), record["qualified_source_sha256"]
        )
    elif version in ("0.2.0", "0.3.0"):
        marker = "Installed app qualified against its image-recorded package files and dependency contract."
        if marker not in output:
            raise ValueError("Installed Strukturbo app qualification marker missing")
        installed = json.loads(
            ctx.podman(
                "read installed app provenance",
                "run",
                "--rm",
                "--network=none",
                "--entrypoint=/bin/cat",
                ctx.image_ref,
                "/usr/share/strukturpiloten/strukturbo-nautobot.json",
            )
        )
        for field in (
            "appVersion",
            "repository",
            "sourceRef",
            "sourceCommit",
            "qualified_source_sha256",
            "versions",
            "package_files",
        ):
            ctx.assert_equal(
                "installed provenance " + field,
                json.dumps(installed[field], sort_keys=True),
                json.dumps(record[field], sort_keys=True),
            )
    else:
        raise ValueError("Unsupported installed Nautobot app contract")
