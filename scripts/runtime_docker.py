"""Native, bounded Docker daemon checks using the isolated outer Podman context."""

# The synthetic resource names and shell commands are intentionally explicit in evidence.
# ruff: noqa: EM101, EM102, PLR0915, S108, TRY003

from __future__ import annotations

import json
import socket
import time
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from scripts.runtime_resource_budgets import (
    IsolatedStoreDiskBudget,
    outer_container_limits,
    verify_outer_container_limits,
)
from scripts.runtime_tests import ProbeError

MAX_HTTP_RESPONSE = 8192


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


def _checked_exec(ctx: RuntimeContext, budget: IsolatedStoreDiskBudget, name: str, container: str, *args: str) -> str:
    budget.checkpoint()
    output = ctx.exec(name, container, *args)
    budget.checkpoint()
    return output


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
    expected_uid = "1000" if mode == "rootless" else "0"
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
    if skip_nested or profile.get("nestedRuntime", True) is False:
        ctx.skip("nested Docker runtime", "disabled by CLI" if skip_nested else "disabled in metadata")
        return
    if profile["outerPrivilege"] == "privileged" and not allow_privileged:
        ctx.skip("nested Docker runtime", "privileged test requires trusted context")
        return

    with IsolatedStoreDiskBudget(ctx) as budget:
        _run_nested_docker(ctx, profile, expected_uid, budget)


def _run_nested_docker(
    ctx: RuntimeContext, profile: dict[str, Any], expected_uid: str, budget: IsolatedStoreDiskBudget
) -> None:
    mode = profile["mode"]
    # A Docker archive of the exact built image is a version-pinned, offline fixture.
    # The inner daemon receives no host Docker socket and the outer launcher stays Podman.
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
    outer_args = [
        *outer_container_limits(),
        "--device",
        "/dev/fuse",
        "--volume",
        f"{fixture}:/tmp/docker-native-fixture.tar:ro",
        "--publish",
        "127.0.0.1::18080",
    ]
    if ctx.name == "docker-debian-11-rootless":
        # Native Bullseye Docker 20.10.5 predates the OOM-score fix in Moby #46626.
        # With an inherited positive score, its runc cannot lower a nested container
        # to Docker's default score of zero (Moby #46563). Normalize the privileged
        # outer workload while keeping every inner docker run at its default.
        outer_args.extend(["--oom-score-adj", "0"])
    if profile["outerPrivilege"] == "privileged":
        outer_args.append("--privileged")
    else:
        outer_args.extend(["--security-opt", "apparmor=unconfined"])
    if mode == "rootless":
        # Preserve helper and process state even if RootlessKit exits before podman exec can attach.
        ctx.podman(
            "inspect rootless UID mapping helpers",
            "run",
            "--rm",
            "--security-opt",
            "label=disable",
            *outer_args,
            ctx.image_ref,
            "sh",
            "-euc",
            "id; "
            "stat -c 'helper %n owner=%u:%g mode=%a' /usr/bin/newuidmap /usr/bin/newgidmap; "
            "printf 'helper capabilities: '; "
            "if command -v getcap >/dev/null 2>&1; then "
            "getcap -v /usr/bin/newuidmap /usr/bin/newgidmap || :; "
            "elif command -v getfattr >/dev/null 2>&1; then "
            "getfattr -n security.capability -e hex /usr/bin/newuidmap /usr/bin/newgidmap 2>&1 || :; "
            "else printf 'getcap and getfattr unavailable\n'; fi; "
            "printf 'uid_map:\n'; cat /proc/self/uid_map; "
            "printf 'gid_map:\n'; cat /proc/self/gid_map; "
            "printf 'process status:\n'; cat /proc/self/status; "
            "printf 'process procfs ownership: '; stat -c '%u:%g %a' /proc/$$; "
            "if command -v setpriv >/dev/null 2>&1; then "
            "printf 'securebits and privileges:\n'; setpriv --dump || :; fi; "
            "if command -v python3 >/dev/null 2>&1; then "
            "python3 -c 'import ctypes; print(\"dumpable:\", ctypes.CDLL(None).prctl(3))' || :; fi",
        )
    budget.checkpoint()
    container = ctx.start("start nested Docker daemon", options=tuple(outer_args))
    try:
        budget.checkpoint()
        verify_outer_container_limits(ctx, container)
        if ctx.name == "docker-debian-11-rootless":
            score = _checked_exec(
                ctx, budget, "read legacy Docker outer OOM score", container, "cat", "/proc/1/oom_score_adj"
            )
            ctx.assert_equal("legacy Docker outer OOM score", score, "0")
        budget.checkpoint()
        _checked_exec(
            ctx,
            budget,
            "wait for Docker daemon API",
            container,
            "sh",
            "-euc",
            "for n in $(seq 1 45); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1",
        )
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

        _docker(
            ctx, budget, container, "load synthetic nested image", "load", "--input", "/tmp/docker-native-fixture.tar"
        )
        nested = ctx.image_ref
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
        _checked_exec(
            ctx,
            budget,
            "diagnostic inherited OOM and namespace limits",
            container,
            "sh",
            "-euc",
            "for proc in /proc/[0-9]*; do "
            'name=$(cat "$proc/comm" 2>/dev/null) || continue; '
            'case "$name" in rootlesskit|dockerd|containerd|containerd-shim*) '
            'score=$(cat "$proc/oom_score_adj" 2>/dev/null) || continue; '
            'printf "%s %s %s\n" "${proc##*/}" "$name" "$score";; esac; '
            "done; "
            'printf "max_user_namespaces=%s pid_max=%s pids_current=%s\n" '
            '"$(cat /proc/sys/user/max_user_namespaces)" '
            '"$(cat /proc/sys/kernel/pid_max)" '
            '"$(cat /sys/fs/cgroup/pids.current)"',
        )
        try:
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
            except RuntimeError:
                # The probe entrypoint runs as __main__, so its ProbeError has a distinct module identity.
                with suppress(RuntimeError):
                    _docker(
                        ctx,
                        budget,
                        container,
                        "diagnostic named volume with raised OOM score",
                        "run",
                        "--rm",
                        "--oom-score-adj=1000",
                        "--user",
                        "0",
                        "--mount",
                        "type=volume,source=docker-native-probe,target=/probe",
                        nested,
                        "sh",
                        "-euc",
                        "echo volume-ok > /probe/marker",
                    )
                raise
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
            ctx.podman(
                "signal owned Docker daemon PID 1",
                "exec",
                container,
                "sh",
                "-c",
                "kill -TERM 1",
                check=False,
            )
            ctx.podman("wait for owned Docker daemon exit", "wait", container, timeout=30)
