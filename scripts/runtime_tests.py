"""Bounded, metadata-driven runtime probes for locally built and CI OCI images."""

# The harness records command-specific failures verbatim and captures all exceptions so
# evidence survives cancellation. Protocol constants and disposable test bind paths
# are intentional; keeping those diagnostics explicit is more useful than indirection.
# ruff: noqa: ANN401, BLE001, C901, D102, D103, D107, EM101, EM102, PLR0912, PLR0915, PLR2004, S104, S108, S603, S607, T201, TRY003, TRY301

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

from scripts.metadata_schema import validate_metadata_schema
from scripts.oci_artifacts import archive_identity

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT = 45
MAX_LOG = 4000


class ProbeError(RuntimeError):
    """A runtime assertion or bounded command failed."""


class RuntimeContext:
    """Own one isolated host Podman store and every container started in it."""

    def __init__(self, *, image: str, architecture: str, timeout: int, use_sudo: bool) -> None:
        self.name = image
        self.architecture = architecture
        self.timeout = timeout
        self.directory = Path(tempfile.mkdtemp(prefix="strukturpiloten-runtime-"))
        self.containers: list[str] = []
        self.checks: list[dict[str, Any]] = []
        self.image_ref = f"localhost/{image}:runtime-{os.getpid()}"
        self._sudo = ["sudo", "-n"] if use_sudo else []
        self._podman = [
            *self._sudo,
            "env",
            f"CONTAINERS_CONF_OVERRIDE={ROOT / '.github/actions/build-arch-image/podman-smoke-containers.conf'}",
            "podman",
            "--root",
            str(self.directory / "root"),
            "--runroot",
            str(self.directory / "runroot"),
            "--tmpdir",
            str(self.directory / "tmp"),
        ]
        for part in ("root", "runroot", "tmp"):
            (self.directory / part).mkdir()

    def command(self, name: str, command: list[str], *, timeout: int | None = None, check: bool = True) -> str:
        start = time.monotonic()
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout or self.timeout,
            )
        except subprocess.TimeoutExpired as error:
            self.checks.append(
                {
                    "name": name,
                    "status": "failed",
                    "durationSeconds": round(time.monotonic() - start, 3),
                    "error": f"command timed out after {timeout or self.timeout}s",
                }
            )
            raise ProbeError(f"{name}: command timed out") from error
        output = (result.stdout or "").strip()
        diagnostics = (result.stderr or "").strip()
        record = {
            "name": name,
            "status": "passed" if result.returncode == 0 else "failed",
            "durationSeconds": round(time.monotonic() - start, 3),
            "exitCode": result.returncode,
        }
        if output:
            record["stdout"] = output[-MAX_LOG:]
        if diagnostics:
            record["stderr"] = diagnostics[-MAX_LOG:]
        self.checks.append(record)
        if check and result.returncode:
            raise ProbeError(f"{name}: exit {result.returncode}: {diagnostics[-1000:] or output[-1000:]}")
        return output

    def podman(self, name: str, *args: str, timeout: int | None = None, check: bool = True) -> str:
        return self.command(name, [*self._podman, *args], timeout=timeout, check=check)

    def assert_equal(self, name: str, actual: str, expected: str) -> None:
        passed = actual == expected
        self.checks.append(
            {"name": name, "status": "passed" if passed else "failed", "actual": actual, "expected": expected}
        )
        if not passed:
            raise ProbeError(f"{name}: expected {expected!r}, got {actual!r}")

    def skip(self, name: str, reason: str) -> None:
        self.checks.append({"name": name, "status": "skipped", "reason": reason})

    def load_archive(self, archive: Path) -> dict[str, str]:
        identity = archive_identity(archive, self.architecture)
        self.podman("load OCI archive", "load", "--quiet", "--input", str(archive), timeout=180)
        ids = self.podman("list loaded images", "images", "--quiet", "--no-trunc").splitlines()
        if len(ids) != 1:
            raise ProbeError(f"expected one image in isolated store, got {len(ids)}")
        self.assert_equal("loaded image configuration digest", ids[0], identity["configDigest"])
        self.podman("tag runtime image", "tag", ids[0], self.image_ref)
        actual_arch = self.podman(
            "inspect image architecture", "image", "inspect", "--format", "{{.Architecture}}", self.image_ref
        )
        self.assert_equal("image architecture", actual_arch, self.architecture)
        return identity

    def run(self, name: str, *command: str, options: tuple[str, ...] = (), timeout: int | None = None) -> str:
        return self.podman(
            name, "run", "--rm", "--security-opt", "label=disable", *options, self.image_ref, *command, timeout=timeout
        )

    def start(self, name: str, *command: str, options: tuple[str, ...] = ()) -> str:
        container = self.podman(
            name, "run", "--detach", "--security-opt", "label=disable", *options, self.image_ref, *command
        )
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise ProbeError(f"{name}: no container ID returned")
        self.containers.append(container)
        return container

    def exec(self, name: str, container: str, *args: str) -> str:
        return self.podman(name, "exec", container, *args)

    def port(self, container: str, target: int) -> int:
        mapping = self.podman("inspect published port", "port", container, f"{target}/tcp")
        port = mapping.rsplit(":", 1)[-1]
        if not port.isdecimal():
            raise ProbeError(f"invalid published port: {mapping}")
        return int(port)

    def logs(self, container: str) -> None:
        self.podman("container logs", "logs", "--tail", "80", container, check=False)

    def stop(self, container: str, *, seconds: int = 10) -> None:
        self.podman("graceful container stop", "stop", "--time", str(seconds), container, timeout=seconds + 10)

    def _owned_mounts(self) -> list[str]:
        """Return mounts inside this invocation's unique store, deepest first."""
        root = str(self.directory)
        targets = []
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            raw = line.split(" ", 5)[4]
            target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), raw)
            if target == root or target.startswith(root + os.sep):
                targets.append(target)
        return sorted(targets, key=len, reverse=True)

    def cleanup(self) -> None:
        """Stop only tracked containers and remove the store only after verified teardown."""
        failed: list[str] = []
        for container in reversed(self.containers):
            # Local host Podman cannot always deliver signals into a container. An
            # in-guest signal lets the service exit before the host removes it.
            try:
                running = self.podman(
                    "inspect owned container state",
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    container,
                    timeout=10,
                    check=False,
                )
                if running == "true":
                    self.podman(
                        "signal owned container internally",
                        "exec",
                        container,
                        "sh",
                        "-c",
                        "kill -TERM 1",
                        timeout=10,
                        check=False,
                    )
                    self.podman("wait for owned container", "wait", container, timeout=15, check=False)
            except ProbeError:
                pass
            try:
                self.podman(
                    "cleanup owned container",
                    "rm",
                    "--force",
                    "--volumes",
                    "--time",
                    "2",
                    container,
                    timeout=10,
                    check=False,
                )
            except ProbeError:
                failed.append(container)
            else:
                if self.checks[-1]["status"] != "passed":
                    failed.append(container)
        if failed:
            raise ProbeError(f"cannot remove owned containers {failed}; preserving isolated store {self.directory}")
        self.containers.clear()
        self.podman("unmount isolated containers", "unmount", "--all", timeout=20)
        self.podman("cleanup owned image", "image", "rm", "--force", self.image_ref, timeout=15, check=False)
        for mount in self._owned_mounts():
            try:
                result = subprocess.run(
                    [*self._sudo, "umount", "--", mount],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
            except subprocess.TimeoutExpired:
                raise ProbeError(f"timed out unmounting owned path {mount}") from None
            if result.returncode:
                raise ProbeError(f"cannot unmount owned path {mount}: {result.stderr.strip()}")
        remaining = self._owned_mounts()
        if remaining:
            raise ProbeError(f"refusing to delete mounted isolated store: {remaining}")
        containers = self.podman("audit isolated containers", "ps", "--all", "--quiet", timeout=10)
        if containers:
            raise ProbeError(
                f"refusing to delete isolated store {self.directory} "
                f"with remaining containers: {containers.splitlines()}"
            )
        if self._sudo:
            result = subprocess.run(
                [*self._sudo, "rm", "-rf", "--", str(self.directory)],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            if result.returncode:
                raise ProbeError(f"cannot remove isolated store {self.directory}: {result.stderr.strip()}")
        else:
            shutil.rmtree(self.directory)
        self.checks.append({"name": "cleanup isolated store", "status": "passed"})


def _wait_for_port(port: int, *, timeout: int = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise ProbeError(f"port {port} did not accept a connection within {timeout}s")


def _podman(
    ctx: RuntimeContext, profile: dict[str, Any], *, archive: Path, allow_privileged: bool, skip_nested: bool
) -> None:
    mode = profile["mode"]
    expected_uid = "1000" if mode == "rootless" else "0"
    script = 'test "$(id -u)" = "$1" && test "$(cat /usr/share/containers/podman-mode)" = "$2" && podman --version'
    ctx.run("Podman CLI and mode", "sh", "-euc", script, "--", expected_uid, mode)
    if skip_nested or profile.get("nestedRuntime", True) is False:
        ctx.skip("nested Podman runtime", "disabled by CLI" if skip_nested else "disabled in metadata")
        return
    privileged = profile["outerPrivilege"] == "privileged"
    if privileged and not allow_privileged:
        ctx.skip("nested Podman runtime", "privileged test requires trusted context")
        return
    run_args = ["--device", "/dev/fuse", "--volume", f"{archive}:/tmp/nested-image.tar:ro"]
    if privileged:
        run_args.append("--privileged")
    else:
        run_args.extend(["--security-opt", "apparmor=unconfined"])
    nested = r"""set -eu
test "$(id -u)" = "$1"
test "$(podman info --format '{{.Host.Security.Rootless}}')" = "$2"
podman load --input /tmp/nested-image.tar >/dev/null
ids="$(podman images --quiet --no-trunc)"
test -n "$ids"
test "$(printf '%s\n' "$ids" | wc -l)" -eq 1
podman run --rm "$ids" /bin/sh -c 'exit 0'
"""
    ctx.run(
        "nested Podman runtime",
        "sh",
        "-euc",
        nested,
        "--",
        expected_uid,
        "true" if mode == "rootless" else "false",
        options=tuple(run_args),
        timeout=120,
    )


def _fcgi_record(record_type: int, content: bytes) -> bytes:
    padding = (-len(content)) % 8
    return struct.pack("!BBHHBB", 1, record_type, 1, len(content), padding, 0) + content + b"\0" * padding


def _fcgi_length(length: int) -> bytes:
    return bytes([length]) if length < 128 else struct.pack("!I", length | 0x80000000)


def _fastcgi_request(port: int, script: str) -> str:
    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/runtime-probe.php",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "runtime-tests",
        "REMOTE_ADDR": "127.0.0.1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "9000",
        "CONTENT_LENGTH": "0",
    }
    payload = b"".join(
        _fcgi_length(len(key)) + _fcgi_length(len(value)) + key.encode() + value.encode()
        for key, value in params.items()
    )
    request = (
        _fcgi_record(1, struct.pack("!HB5x", 1, 0))
        + _fcgi_record(4, payload)
        + _fcgi_record(4, b"")
        + _fcgi_record(5, b"")
    )
    data = bytearray()
    deadline = time.monotonic() + 15
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(request)
        while True:
            if time.monotonic() >= deadline:
                raise ProbeError("FastCGI response exceeded 15 seconds")
            header = bytearray()
            while len(header) < 8:
                chunk = connection.recv(8 - len(header))
                if not chunk:
                    break
                header.extend(chunk)
            if len(header) != 8:
                raise ProbeError("incomplete FastCGI response header")
            version, kind, request_id, length, padding, _reserved = struct.unpack("!BBHHBB", header)
            if version != 1 or request_id != 1:
                raise ProbeError("invalid FastCGI response")
            remaining = length + padding
            body = bytearray()
            while remaining:
                chunk = connection.recv(remaining)
                if not chunk:
                    raise ProbeError("truncated FastCGI response")
                body.extend(chunk)
                remaining -= len(chunk)
            if kind == 6:
                data.extend(body[:length])
            if kind == 7 and length:
                raise ProbeError(f"FastCGI stderr: {body[:length].decode(errors='replace')}")
            if kind == 3:
                break
            if len(data) > 65536:
                raise ProbeError("FastCGI response exceeds limit")
    response = data.decode(errors="replace")
    if "\r\n\r\n" not in response:
        raise ProbeError(f"FastCGI response lacks headers: {response[:300]}")
    return response.split("\r\n\r\n", 1)[1]


def _php_fpm(ctx: RuntimeContext, profile: dict[str, Any]) -> None:
    extensions = profile["extensions"]
    stop_signal = ctx.podman(
        "inspect PHP-FPM stop signal", "image", "inspect", "--format", "{{.Config.StopSignal}}", ctx.image_ref
    )
    ctx.assert_equal("PHP-FPM graceful stop signal", stop_signal, "SIGQUIT")
    ctx.run("PHP-FPM configuration", "php-fpm", "-t")
    modules = ctx.run("PHP CLI extensions", "php", "-m")
    missing = sorted(set(extensions) - {line.strip().lower() for line in modules.splitlines()})
    ctx.assert_equal("required PHP CLI extensions", ",".join(missing), "")
    probe = ctx.directory / "runtime-probe.php"
    probe.write_text(
        """<?php
header('Content-Type: application/json');
echo json_encode([
  'uid' => posix_geteuid(),
  'extensions' => array_map('strtolower', get_loaded_extensions()),
  'writable' => is_writable('/tmp/runtime-probe'),
  'write' => file_put_contents('/tmp/runtime-probe/write-test', 'ok') === 2,
]);
""",
        encoding="utf-8",
    )
    probe.chmod(0o644)
    ctx.directory.chmod(0o755)
    scratch = ctx.directory / "scratch"
    scratch.mkdir(mode=0o777)
    scratch.chmod(0o777)
    container = ctx.start(
        "start PHP-FPM",
        options=(
            "--publish",
            "127.0.0.1::9000",
            "--volume",
            f"{probe}:/tmp/runtime-probe.php:ro",
            "--volume",
            f"{scratch}:/tmp/runtime-probe:rw",
        ),
    )
    try:
        port = ctx.port(container, 9000)
        _wait_for_port(port)
        ctx.checks.append({"name": "PHP-FPM startup and listener", "status": "passed", "port": port})
        body = _fastcgi_request(port, "/tmp/runtime-probe.php")
        data = json.loads(body)
        ctx.assert_equal("FastCGI worker is non-root", str(data["uid"] != 0), "True")
        ctx.assert_equal("FastCGI writable directory", str(data["writable"] and data["write"]), "True")
        absent = sorted(set(extensions) - set(data["extensions"]))
        ctx.assert_equal("required FastCGI extensions", ",".join(absent), "")
        ctx.assert_equal("FastCGI file ownership", scratch.joinpath("write-test").read_text(), "ok")
        ctx.exec("send SIGQUIT to PHP-FPM master", container, "sh", "-c", "kill -QUIT 1")
        exit_code = ctx.podman("wait for graceful PHP-FPM exit", "wait", container, timeout=20)
        ctx.assert_equal("PHP-FPM graceful exit code", exit_code, "0")
    except Exception:
        ctx.logs(container)
        raise


def _notify_push(ctx: RuntimeContext) -> None:
    version = ctx.run("notify_push binary version", "/usr/local/bin/notify_push", "--version")
    if not version.startswith("notify_push "):
        raise ProbeError(f"unexpected notify_push version: {version}")
    config = ctx.run(
        "notify_push synthetic config",
        "/usr/local/bin/notify_push",
        "--database-url",
        "sqlite::memory:",
        "--redis-url",
        "redis://127.0.0.1:1",
        "--nextcloud-url",
        "http://127.0.0.1:1",
        "--dump-config",
    )
    if "Sqlite" not in config and "sqlite" not in config:
        raise ProbeError("notify_push did not parse synthetic SQLite configuration")
    # App startup uses SQLite; Redis and Nextcloud are intentionally unavailable. The
    # WebSocket handshake checks the listening service, not full Nextcloud integration.
    args = (
        "/usr/local/bin/notify_push",
        "--database-url",
        "sqlite::memory:",
        "--redis-url",
        "redis://127.0.0.1:1",
        "--nextcloud-url",
        "http://127.0.0.1:1",
        "--bind",
        "0.0.0.0",
    )
    container = ctx.start(
        "start notify_push with synthetic dependencies", *args, options=("--publish", "127.0.0.1::7867")
    )
    try:
        port = ctx.port(container, 7867)
        _wait_for_port(port, timeout=20)
        request = (
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(request.encode())
            response = connection.recv(1024).decode(errors="replace")
        ctx.assert_equal(
            "notify_push WebSocket handshake", response.split("\r\n", 1)[0], "HTTP/1.1 101 Switching Protocols"
        )
        ctx.checks.append(
            {
                "name": "integration scope",
                "status": "skipped",
                "reason": (
                    "synthetic SQLite and unavailable Redis/Nextcloud; authenticated push delivery is not exercised"
                ),
            }
        )
    except Exception:
        ctx.logs(container)
        raise


def _docker(
    ctx: RuntimeContext, profile: dict[str, Any], *, archive: Path, allow_privileged: bool, skip_nested: bool
) -> None:
    from scripts.runtime_docker import run_docker  # noqa: PLC0415

    run_docker(ctx, profile, archive=archive, allow_privileged=allow_privileged, skip_nested=skip_nested)


def _signal_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def run(args: argparse.Namespace) -> dict[str, Any]:
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    if args.metadata:
        metadata_path = Path(args.metadata).resolve()
    else:
        candidates = (
            path
            for path in ROOT.glob("images/**/container.yaml")
            if yaml.safe_load(path.read_text(encoding="utf-8")).get("name") == args.image_name
        )
        metadata_path = next(candidates, None)
        if metadata_path is None:
            raise ProbeError(f"unknown runtime image {args.image_name}")
    metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
    validate_metadata_schema(metadata, schema_path=ROOT / "container.schema.json", display_path=str(metadata_path))
    architecture = args.arch or {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    if architecture not in metadata["build"]["architectures"]:
        raise ProbeError(f"{metadata['name']} does not support linux/{architecture}")
    profiles = metadata.get("tests", {})
    if len(profiles) != 1:
        raise ProbeError(f"{metadata['name']} needs exactly one runtime test profile")
    evidence: dict[str, Any] = {
        "schemaVersion": 1,
        "image": metadata["name"],
        "architecture": architecture,
        "profile": next(iter(profiles)),
        "status": "failed",
        "checks": [],
        "host": {"architecture": platform.machine(), "kernel": platform.release(), "system": platform.system()},
        "runId": os.environ.get("GITHUB_RUN_ID", ""),
        "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    use_sudo = args.sudo or (
        not args.no_sudo
        and subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False, timeout=5).returncode == 0
    )
    ctx: RuntimeContext | None = None
    archive = Path(args.archive).resolve() if args.archive else None
    generated_archive = False
    try:
        ctx = RuntimeContext(image=metadata["name"], architecture=architecture, timeout=args.timeout, use_sudo=use_sudo)
        evidence["checks"] = ctx.checks
        if archive is None:
            archive = ctx.directory / "source-image.tar"
            source_podman = ["podman"]
            ctx.command(
                "export local image",
                [*source_podman, "save", "--format", "oci-archive", "--output", str(archive), args.image_ref],
                timeout=180,
            )
            generated_archive = True
        evidence["imageIdentity"] = ctx.load_archive(archive)
        evidence["host"]["podmanVersion"] = ctx.podman("host Podman version", "--version")
        profile_name, profile = next(iter(profiles.items()))
        if profile_name == "podman":
            _podman(ctx, profile, archive=archive, allow_privileged=args.allow_privileged, skip_nested=args.skip_nested)
        elif profile_name == "phpFpm":
            _php_fpm(ctx, profile)
        elif profile_name == "notifyPush":
            _notify_push(ctx)
        elif profile_name == "docker":
            _docker(ctx, profile, archive=archive, allow_privileged=args.allow_privileged, skip_nested=args.skip_nested)
        else:
            raise ProbeError(f"unsupported runtime profile {profile_name}")
        evidence["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        evidence["error"] = f"{type(error).__name__}: {error}"
    finally:
        # A second cancellation signal must not interrupt owned-resource cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if ctx is not None:
            try:
                ctx.cleanup()
            except (OSError, ProbeError, subprocess.TimeoutExpired) as cleanup_error:
                evidence["status"] = "failed"
                evidence["cleanupError"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        if generated_archive:
            evidence["source"] = "locally exported image"
        evidence_path = Path(args.evidence)
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        signal.signal(signal.SIGTERM, previous_sigterm)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    metadata = parser.add_mutually_exclusive_group(required=True)
    metadata.add_argument("--metadata")
    metadata.add_argument("--image-name")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive")
    source.add_argument("--image-ref")
    parser.add_argument("--arch")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--allow-privileged", action="store_true")
    parser.add_argument("--skip-nested", action="store_true")
    parser.add_argument("--sudo", action="store_true", help="require sudo for the isolated host Podman store")
    parser.add_argument("--no-sudo", action="store_true", help="use rootless host Podman")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("--timeout must be between 1 and 300 seconds")
    signal.signal(signal.SIGTERM, _signal_interrupt)
    evidence = run(args)
    print(json.dumps({key: evidence[key] for key in ("image", "architecture", "profile", "status")}, sort_keys=True))
    if evidence["status"] != "passed":
        print(evidence.get("error", "runtime check failed"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
