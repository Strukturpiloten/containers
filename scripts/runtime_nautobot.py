"""Qualify the installed artifact with its commit-pinned bootstrap fixture harness."""

# Fixed, owned source paths and OCI identities; no deployment credentials.
# ruff: noqa: EM101, SLF001, TRY003
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import yaml

from scripts.nautobot_source import ROOT, verify

if TYPE_CHECKING:
    from scripts.runtime_tests import RuntimeContext


def run(ctx: RuntimeContext) -> None:
    """Use separate disposable databases; never inject app source into the image."""
    staged = verify()
    metadata = yaml.safe_load((ROOT / "images/strukturbo/strukturbo-nautobot/container.yaml").read_text())
    arguments = metadata["build"]["args"]
    database = arguments["DATABASE_IMAGE"]["value"]
    redis = arguments["REDIS_IMAGE"]["value"]
    for name, image in (("PostgreSQL", database), ("Redis", redis)):
        ctx.podman(f"acquire disposable {name} fixture", "pull", "--quiet", image, timeout=180)
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
    command.extend("--podman-arg=" + argument for argument in ctx._podman[ctx._podman.index("podman") + 1 :])
    output = ctx.command("installed registry, HTTPS, TLS, login, workers and queue", command, timeout=1200)
    marker = "Qualified installed registry source SHA-256: "
    if marker not in output:
        raise ValueError("Installed-artifact qualification marker missing")
    expected = json.loads((staged / "provenance.json").read_text())["qualified_source_sha256"]
    ctx.assert_equal("qualified installed source", output.split(marker)[-1].strip(), expected)
