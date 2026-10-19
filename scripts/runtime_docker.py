"""Native, bounded Docker daemon checks using the isolated outer Podman context."""

# The synthetic resource names and shell commands are intentionally explicit in evidence.
# ruff: noqa: EM101, EM102, PLR0915, S108, TRY003

from __future__ import annotations

import json
import socket
import time
from typing import TYPE_CHECKING, Any

from scripts import runtime_docker_systemd
from scripts.runtime_errors import ProbeError
from scripts.runtime_resource_budgets import (
    IsolatedStoreDiskBudget,
    outer_container_limits,
    verify_outer_container_limits,
)

MAX_HTTP_RESPONSE = 8192
LEGACY_ROOTLESS_OOM_PROFILES = ("docker-debian-11-rootless",)


if TYPE_CHECKING:
    from pathlib import Path

    from scripts.runtime_tests import RuntimeContext


def _wait_http(port: int, marker: bytes, *, timeout: int = 20) -> None:
    deadline = time.monotonic() + timeout
    last_result = "no connection"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                response = bytearray()
                while len(response) < MAX_HTTP_RESPONSE:
                    try:
                        chunk = connection.recv(MAX_HTTP_RESPONSE - len(response))
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    response.extend(chunk)
                    if marker in response:
                        return
            last_result = repr(response[:200])
        except OSError as error:
            last_result = str(error)
        time.sleep(0.5)
    raise ProbeError(f"published nested Docker port {port} did not serve the synthetic marker: {last_result}")


def _checked_exec(
    ctx: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    name: str,
    container: str,
    *args: str,
    timeout: float | None = None,
) -> str:
    budget.checkpoint()
    options = {} if timeout is None else {"timeout": timeout}
    output = ctx.exec(name, container, *args, **options)
    budget.checkpoint()
    return output


def _wait_for_systemd_api(
    ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, deadline: float
) -> None:
    # Only an ordinary daemon-not-ready result is retried. The unchanged strict
    # exec guard surrounds every sample; guard/OCI/IO failures propagate directly.
    for _sample in range(runtime_docker_systemd.STARTUP_SECONDS):
        marker = _checked_exec(
            ctx,
            budget,
            "wait for Docker daemon API",
            container,
            "sh",
            "-euc",
            "if docker info >/dev/null 2>&1; then printf API_READY; else printf API_PENDING; fi",
            timeout=runtime_docker_systemd.startup_remaining(ctx, deadline),
        )
        runtime_docker_systemd.startup_remaining(ctx, deadline)
        if marker == "API_READY":
            return
        if marker != "API_PENDING":
            raise ProbeError("systemd Docker API readiness returned an invalid marker")
        time.sleep(min(1, runtime_docker_systemd.startup_remaining(ctx, deadline)))
    raise ProbeError("systemd Docker API exceeded its bounded startup sample count")


def _docker(ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, container: str, name: str, *args: str) -> str:
    return _checked_exec(ctx, budget, name, container, "docker", *args)


def run_docker(
    ctx: RuntimeContext,
    profile: dict[str, Any],
    *,
    archive: Path,  # noqa: ARG001 - interface shared with other runtime probes
    allow_privileged: bool,
    skip_nested: bool,
) -> None:
    """Exercise CLI, daemon API, storage, network, mounts, ports, and owned cleanup."""
    mode = profile["mode"]
    systemd = profile.get("launcher", "direct") == "systemd"
    if systemd and profile["outerPrivilege"] != "privileged":
        raise ProbeError("systemd Docker profile requires a privileged rootful outer runtime")
    expected_uid = "1000" if mode == "rootless" and not systemd else "0"
    cli = ctx.podman(
        "Docker CLI, identity and payload provenance",
        "run",
        "--rm",
        "--security-opt",
        "label=disable",
        *outer_container_limits(),
        ctx.image_ref,
        "sh",
        "-euc",
        'test "$(id -u)" = "$1"; '
        "provenance=/usr/share/strukturpiloten/docker; "
        'test -s "$provenance/engine-version"; '
        'if test -s "$provenance/engine-archive-sha256"; then :; '
        'else test "$(cat "$provenance/provenance-kind")" = distro-package; '
        "for item in package-version vendor-source os-packages docker-version dockerd-version; do "
        'test -s "$provenance/$item"; done; '
        'test "$(docker --version)" = "$(cat "$provenance/docker-version")"; '
        'test "$(dockerd --version)" = "$(cat "$provenance/dockerd-version")"; '
        "fi; docker --version; dockerd --version",
        "--",
        expected_uid,
    )
    if "Docker version" not in cli:
        raise ProbeError("Docker CLI did not report its version")
    if mode == "rootless" and ctx.name.startswith("docker-opensuse-"):
        ctx.podman(
            "rootless UID mapping helpers use setuid only",
            "run",
            "--rm",
            "--security-opt",
            "label=disable",
            *outer_container_limits(),
            ctx.image_ref,
            "sh",
            "-euc",
            """test "$(cat /usr/share/strukturpiloten/docker/uidmap-helper-mode)" = setuid-only;
for helper in /usr/bin/newuidmap /usr/bin/newgidmap; do
    test "$(stat -c '%u:%g %a' "$helper")" = '0:0 4755';
    helper_caps="$(getcap "$helper")";
    test -z "$helper_caps";
done;
echo setuid-only""",
        )
    if skip_nested or profile.get("nestedRuntime", True) is False:
        ctx.skip("nested Docker runtime", "disabled by CLI" if skip_nested else "disabled in metadata")
        return
    if profile["outerPrivilege"] == "privileged" and not allow_privileged:
        ctx.skip("nested Docker runtime", "privileged test requires trusted context")
        return

    with IsolatedStoreDiskBudget(ctx) as budget:
        _run_nested_docker(ctx, profile, expected_uid, budget)


def _outer_options(ctx: RuntimeContext, profile: dict[str, Any], fixture: Path) -> tuple[str, ...]:
    outer_args = [
        *outer_container_limits(),
        "--device",
        "/dev/fuse",
        "--volume",
        f"{fixture}:/tmp/docker-native-fixture.tar:ro",
        "--publish",
        "127.0.0.1::18080",
    ]
    if profile.get("launcher", "direct") == "systemd":
        outer_args.extend(runtime_docker_systemd.SYSTEMD_OPTIONS)
    legacy_rootless = ctx.name in LEGACY_ROOTLESS_OOM_PROFILES
    if legacy_rootless:
        # Native Bullseye Docker 20.10.5 predates the OOM-score fix in Moby #46626.
        # With an inherited positive score, its runc cannot lower a nested container
        # to Docker's default score of zero (Moby #46563). Normalize the privileged
        # outer workload while keeping every inner docker run at its default.
        outer_args.extend(["--oom-score-adj", "0"])
    if profile["outerPrivilege"] == "privileged":
        outer_args.append("--privileged")
    else:
        outer_args.extend(["--security-opt", "apparmor=unconfined"])
    return tuple(outer_args)


def _stop_owned_daemon(ctx: RuntimeContext, container: str, *, systemd: bool) -> None:
    if systemd:
        runtime_docker_systemd.stop_guest(ctx, container)
    else:
        ctx.podman("signal owned Docker daemon PID 1", "exec", container, "sh", "-c", "kill -TERM 1", check=False)
        ctx.podman("wait for owned Docker daemon exit", "wait", container, timeout=30)


def _prepare_started_daemon(
    ctx: RuntimeContext,
    budget: IsolatedStoreDiskBudget,
    container: str,
    profile: dict[str, Any],
    deadline: float | None,
) -> None:
    systemd = profile.get("launcher", "direct") == "systemd"
    legacy_rootless = ctx.name in LEGACY_ROOTLESS_OOM_PROFILES
    if systemd and deadline is None:
        raise ProbeError("systemd startup deadline was missing")
    if systemd:
        runtime_docker_systemd.wait_for_placement(ctx, budget, container, deadline)
        ctx.exec_guard = runtime_docker_systemd.guarded_command()
        verify_outer_container_limits(ctx, container, timeout=runtime_docker_systemd.startup_remaining(ctx, deadline))
        runtime_docker_systemd.startup_remaining(ctx, deadline)
    else:
        verify_outer_container_limits(ctx, container)
    if legacy_rootless:
        score = _checked_exec(
            ctx, budget, "read legacy Docker outer OOM score", container, "cat", "/proc/1/oom_score_adj"
        )
        ctx.assert_equal("legacy Docker outer OOM score", score, "0")
    budget.checkpoint()
    if systemd:
        _wait_for_systemd_api(ctx, budget, container, deadline)
    else:
        _checked_exec(
            ctx,
            budget,
            "wait for Docker daemon API",
            container,
            "sh",
            "-euc",
            "for n in $(seq 1 45); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1",
        )


def _run_nested_docker(
    ctx: RuntimeContext, profile: dict[str, Any], expected_uid: str, budget: IsolatedStoreDiskBudget
) -> None:
    mode = profile["mode"]
    systemd = profile.get("launcher", "direct") == "systemd"
    if systemd:
        runtime_docker_systemd.verify_runtime(ctx)
    # The exact built image is an offline fixture; no host Docker socket is used.
    fixture = ctx.directory / "docker-native-fixture.tar"
    budget.checkpoint()
    ctx.podman(
        "save synthetic Docker fixture",
        "save",
        "--format",
        "docker-archive",
        "--output",
        str(fixture),
        ctx.image_ref,
        timeout=180,
    )
    budget.checkpoint()
    outer_args = _outer_options(ctx, profile, fixture)
    budget.checkpoint()
    deadline = runtime_docker_systemd.startup_deadline(ctx) if systemd else None
    launch_timeout = {} if deadline is None else {"timeout": runtime_docker_systemd.startup_remaining(ctx, deadline)}
    container = ctx.start("start nested Docker daemon", options=tuple(outer_args), **launch_timeout)
    try:
        budget.checkpoint()
        _prepare_started_daemon(ctx, budget, container, profile, deadline)
        if not systemd:
            uid = _checked_exec(ctx, budget, "inspect inner daemon user", container, "id", "-u")
            ctx.assert_equal("inner daemon user", uid, expected_uid)
        version_text = _docker(
            ctx, budget, container, "read Docker API versions", "version", "--format", "{{json .Server}}"
        )
        version = json.loads(version_text)
        engine_version = _checked_exec(
            ctx,
            budget,
            "read verified Engine version",
            container,
            "cat",
            "/usr/share/strukturpiloten/docker/engine-version",
        )
        ctx.assert_equal("daemon Engine version", version["Version"], engine_version)
        if not version.get("ApiVersion") or not version.get("MinAPIVersion"):
            raise ProbeError("daemon did not report API version range")
        info_text = _docker(
            ctx, budget, container, "inspect Docker storage and security", "info", "--format", "{{json .}}"
        )
        info = json.loads(info_text)
        if not info.get("Driver"):
            raise ProbeError("daemon did not initialize a storage driver")
        security = [str(value) for value in info.get("SecurityOptions", [])]
        rootless = any("rootless" in value for value in security)
        ctx.assert_equal("daemon rootless security", str(rootless).lower(), str(mode == "rootless").lower())
        if systemd:
            runtime_docker_systemd.verify_guest(ctx, budget, container, mode, info)

        _docker(
            ctx, budget, container, "load synthetic nested image", "load", "--input", "/tmp/docker-native-fixture.tar"
        )
        nested = ctx.image_ref
        if systemd:
            runtime_docker_systemd.verify_inner_limits(ctx, budget, container, mode=mode)
        _docker(ctx, budget, container, "create isolated Docker network", "network", "create", "docker-native-probe")
        _docker(ctx, budget, container, "create isolated Docker volume", "volume", "create", "docker-native-probe")
        _checked_exec(
            ctx,
            budget,
            "create synthetic bind source",
            container,
            "sh",
            "-euc",
            "mkdir -p /tmp/docker-native-bind; echo bind-ok > /tmp/docker-native-bind/marker",
        )
        try:
            _docker(
                ctx,
                budget,
                container,
                "write named volume in nested container",
                "run",
                "--rm",
                "--user",
                "0",
                "--mount",
                "type=volume,source=docker-native-probe,target=/probe",
                nested,
                "sh",
                "-euc",
                "echo volume-ok > /probe/marker",
            )
            marker = _docker(
                ctx,
                budget,
                container,
                "read bind and named volume mounts",
                "run",
                "--rm",
                "--mount",
                "type=volume,source=docker-native-probe,target=/volume",
                "--mount",
                "type=bind,source=/tmp/docker-native-bind,target=/bind,readonly",
                nested,
                "sh",
                "-euc",
                "cat /volume/marker; cat /bind/marker",
            )
            ctx.assert_equal("nested mount content", marker, "volume-ok\nbind-ok")
            _docker(
                ctx,
                budget,
                container,
                "start healthy published-port container",
                "run",
                "--detach",
                "--name",
                "docker-native-web",
                "--network",
                "docker-native-probe",
                "--publish",
                "18080:8080",
                "--restart",
                "unless-stopped",
                "--health-cmd",
                "busybox wget -q -O /dev/null http://127.0.0.1:8080/",
                "--health-interval",
                "2s",
                "--health-retries",
                "3",
                nested,
                "sh",
                "-euc",
                "cat > /tmp/serve-http <<'EOF'\n"
                "#!/bin/sh\n"
                "printf 'HTTP/1.0 200 OK\\r\\nContent-Length: 17\\r\\n\\r\\ndocker-native-ok\\n'\n"
                "EOF\n"
                "chmod 0755 /tmp/serve-http; "
                "if busybox nc --help 2>&1 | grep -q -- '-lk'; then "
                "exec busybox nc -lk -p 8080 -e /tmp/serve-http; "
                "else exec busybox nc -ll -p 8080 -e /tmp/serve-http; fi",
            )
            _checked_exec(
                ctx,
                budget,
                "wait for synthetic HTTP container",
                container,
                "sh",
                "-euc",
                "for n in $(seq 1 15); do "
                'test "$(docker inspect --format "{{.State.Health.Status}}" docker-native-web)" = healthy && exit 0; '
                "sleep 1; done; docker logs docker-native-web; exit 1",
            )
            settings = _docker(
                ctx,
                budget,
                container,
                "read health and restart settings",
                "inspect",
                "--format",
                "{{.HostConfig.RestartPolicy.Name}} {{.Config.Healthcheck.Test}}",
                "docker-native-web",
            )
            if "unless-stopped" not in settings or "wget" not in settings:
                raise ProbeError(f"nested health/restart settings were not retained: {settings}")
            _docker(
                ctx,
                budget,
                container,
                "verify synthetic Docker network DNS",
                "run",
                "--rm",
                "--network",
                "docker-native-probe",
                nested,
                "sh",
                "-euc",
                "busybox wget -q -O - http://docker-native-web:8080/ | grep -F docker-native-ok",
            )
            budget.checkpoint()
            outer_port = ctx.port(container, 18080)
            budget.checkpoint()
            _wait_http(outer_port, b"docker-native-ok")
            budget.checkpoint()
            ctx.checks.append({"name": "host published port", "status": "passed", "port": outer_port})
            verify_outer_container_limits(ctx, container)
        finally:
            ctx.exec(
                "remove owned nested Docker resources",
                container,
                "sh",
                "-euc",
                "docker rm -f docker-native-web >/dev/null 2>&1 || true; "
                "docker network rm docker-native-probe >/dev/null 2>&1 || true; "
                "docker volume rm -f docker-native-probe >/dev/null 2>&1 || true; "
                "rm -rf /tmp/docker-native-bind",
            )
            ctx.exec(
                "verify nested Docker cleanup readback",
                container,
                "sh",
                "-euc",
                'test -z "$(docker ps -aq --filter name=docker-native-web)"; '
                "! docker network inspect docker-native-probe >/dev/null 2>&1; "
                "! docker volume inspect docker-native-probe >/dev/null 2>&1",
            )
    finally:
        try:
            ctx.logs(container)
        finally:
            _stop_owned_daemon(ctx, container, systemd=systemd)
