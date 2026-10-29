"""Bounded, metadata-driven runtime probes for locally built and CI OCI images."""

# The harness records command-specific failures verbatim and captures all exceptions so
# evidence survives cancellation. Protocol constants and disposable test bind paths
# are intentional; keeping those diagnostics explicit is more useful than indirection.
# ruff: noqa: ANN401, BLE001, C901, D102, D103, D107, EM101, EM102, PLR0912, PLR0915, PLR2004, S104, S108, S603, S607, T201, TRY003, TRY301

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from scripts.metadata_schema import validate_metadata_schema
from scripts.oci_artifacts import archive_identity
from scripts.runtime_backends import PodmanBackend, select_outer_engine
from scripts.runtime_docker import DockerProbePhase
from scripts.runtime_docker_backend import DockerBackend
from scripts.runtime_docker_diagnostics import redact_timeout_provider
from scripts.runtime_errors import ProbeError
from scripts.runtime_resource_budgets import STORE_LIMIT_BYTES, IsolatedStoreDiskBudget, outer_container_limits

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT = 45
MAX_LOG = 4000
CONTROL_SECONDS = 300
SYSTEMD_PAIR_SECONDS = 900


class RuntimeContext:
    """Own one isolated outer-runtime store and every container started in it."""

    def __init__(
        self,
        *,
        image: str,
        architecture: str,
        timeout: int,
        use_sudo: bool,
        outer_engine: str = "podman",
    ) -> None:
        if outer_engine not in {"podman", "docker"}:
            raise ProbeError(f"unsupported resolved outer engine {outer_engine}")
        self.declared_launcher = "direct"
        self._launcher_bound = False
        self.name = image
        self.architecture = architecture
        self.timeout = timeout
        self.directory = Path(tempfile.mkdtemp(prefix="strukturpiloten-runtime-"))
        self.containers: list[str] = []
        self.run_containers: set[str] = set()
        self.container_launchers: dict[str, str] = {}
        self.checks: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.runtime_deadline: float | None = None
        self.runtime_phase = "single"
        self.runtime_disk_budget: IsolatedStoreDiskBudget | None = None
        self.image_ref = f"localhost/{image}:runtime-{os.getpid()}-{uuid.uuid4().hex}"
        self._fixture_archives: dict[int, tuple[BinaryIO, Path, tuple[int, int]]] = {}
        self._sudo = ["sudo", "-n"] if use_sudo else []
        self.outer_engine = outer_engine
        self.backend = (
            PodmanBackend(
                self.directory,
                tuple(self._sudo),
                ROOT / ".github/actions/build-arch-image/podman-smoke-containers.conf",
            )
            if outer_engine == "podman"
            else DockerBackend(self.directory, tuple(self._sudo))
        )
        try:
            self.backend.initialize()
        except (Exception, KeyboardInterrupt) as error:
            try:
                shutil.rmtree(self.directory)
            except OSError as cleanup_error:
                raise ProbeError(f"cannot remove partial owned store {self.directory}: {cleanup_error}") from error
            raise
        self._podman = self.backend.command_prefix() if outer_engine == "podman" else []

    def bind_guest_profile(self, profile: dict[str, Any]) -> None:
        """Bind the validated metadata before work; run flags cannot opt into delegation."""
        if self._launcher_bound or self.containers:
            raise ProbeError("guest launcher metadata cannot be rebound after ownership acquisition")
        launcher = profile.get("launcher", "direct")
        if launcher not in {"direct", "systemd"} or (
            self.outer_engine == "docker"
            and launcher == "systemd"
            and (
                self.name != "docker-29-conformance-rootless"
                or profile.get("mode") != "rootless"
                or profile.get("outerPrivilege") != "privileged"
            )
        ):
            raise ProbeError("unsupported declared outer guest launcher")
        self.declared_launcher = launcher
        self._launcher_bound = True

    def prepare(self) -> dict[str, str]:
        """Observe the selected backend; never substitute another runtime."""
        if isinstance(self.backend, DockerBackend):
            return self.backend.prepare(self)
        version = self.podman("host Podman version", "--version")
        if not version.startswith("podman version "):
            raise ProbeError("outer Podman version observation is invalid")
        rootless = self.podman("host Podman root mode", "info", "--format", "{{.Host.Security.Rootless}}")
        if rootless not in {"true", "false"}:
            raise ProbeError("outer Podman root mode observation is invalid")
        return {
            "engine": "podman",
            "clientVersion": version,
            "rootMode": "rootless" if rootless == "true" else "rootful",
            "storage": "invocation-owned",
        }

    def _prefix(self, timeout: float | None) -> list[str]:
        if isinstance(getattr(self, "backend", None), DockerBackend):
            return self.backend.command_prefix(self.timeout if timeout is None else timeout)
        return self._podman

    @contextmanager
    def private_fixture_archive(self) -> Iterator[BinaryIO]:
        """Hold the sole parent-owned fixture inode without reopening its pathname."""
        path = self.directory / "docker-native-fixture.tar"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w+b", buffering=0) as archive:
            observed = os.fstat(archive.fileno())
            self._fixture_archives[id(archive)] = (archive, path, (observed.st_dev, observed.st_ino))
            try:
                self._fixture_descriptor(archive)
                yield archive
            finally:
                self._fixture_archives.pop(id(archive))

    def _fixture_descriptor(self, archive: BinaryIO) -> int:
        entry = self._fixture_archives.get(id(archive))
        if entry is None or entry[0] is not archive:
            raise ProbeError("binary fixture stream is not an owned held descriptor")
        try:
            descriptor = archive.fileno()
            observed, named = os.fstat(descriptor), entry[1].lstat()
        except OSError, ValueError:
            raise ProbeError("binary fixture descriptor ownership is unverified") from None
        if (
            (observed.st_dev, observed.st_ino) != entry[2]
            or (named.st_dev, named.st_ino) != entry[2]
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
        ):
            raise ProbeError("binary fixture descriptor ownership changed")
        return descriptor

    def _fixture_stream_options(self, stdin: BinaryIO | None, stdout: BinaryIO | None) -> dict[str, Any]:
        if stdin is None and stdout is None:
            return {"capture_output": True}
        if stdin is not None and stdout is not None:
            raise ProbeError("binary fixture command requires one stream direction")
        return {
            "stdin": self._fixture_descriptor(stdin) if stdin is not None else subprocess.DEVNULL,
            "stdout": self._fixture_descriptor(stdout) if stdout is not None else subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }

    def command(  # noqa: PLR0913 - additive stream handles preserve the existing timeout/check call contract.
        self,
        name: str,
        command: list[str],
        *,
        timeout: float | None = None,
        check: bool = True,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> str:
        streams = self._fixture_stream_options(stdin, stdout)
        public_name = redact_timeout_provider(self, name)
        binary_fixture = stdin is not None or stdout is not None
        allowance = self.timeout if timeout is None else timeout
        deadline = getattr(self, "runtime_deadline", None)
        if deadline is not None:
            allowance = min(allowance, deadline - time.monotonic())
        docker = isinstance(getattr(self, "backend", None), DockerBackend)
        if docker:
            allowance = self.backend.command_timeout(allowance)
            command = self.backend.rebudget_command(command, allowance)
        if not math.isfinite(allowance) or allowance <= 0:
            raise ProbeError(f"{name}: command timeout must be finite and positive")
        start = time.monotonic()
        try:
            result = subprocess.run(
                command,
                text=True,
                check=False,
                timeout=allowance,
                **streams,
            )
        except subprocess.TimeoutExpired as error:
            self.checks.append(
                {
                    "name": public_name,
                    "status": "failed",
                    "durationSeconds": round(time.monotonic() - start, 3),
                    "error": f"command timed out after {allowance}s",
                }
            )
            if vars(self).get("_gnu_timeout_provider") is not None or (
                docker and vars(self.backend).get("_gnu_timeout_provider") is not None
            ):
                raise ProbeError(redact_timeout_provider(self, f"{name}: command timed out")) from None
            raise ProbeError(f"{name}: command timed out") from error
        except OSError as error:
            detail = redact_timeout_provider(self, str(error))
            if detail == str(error):
                raise
            self.checks.append(
                {
                    "name": public_name,
                    "status": "failed",
                    "durationSeconds": round(time.monotonic() - start, 3),
                    "error": detail,
                }
            )
            raise ProbeError(f"{public_name}: {detail}") from None
        output = "" if binary_fixture else (result.stdout or "").strip()
        diagnostics = "" if binary_fixture else (result.stderr or "").strip()
        record = {
            "name": public_name,
            "status": "passed" if result.returncode == 0 else "failed",
            "durationSeconds": round(time.monotonic() - start, 3),
            "exitCode": result.returncode,
        }
        if output:
            record["stdout"] = redact_timeout_provider(self, output)[-MAX_LOG:]
        if diagnostics:
            record["stderr"] = redact_timeout_provider(self, diagnostics)[-MAX_LOG:]
        stream_error = None
        if binary_fixture:
            try:
                self._fixture_stream_options(stdin, stdout)
            except ProbeError:
                stream_error = "binary fixture descriptor ownership changed during command"
                record.update({"status": "failed", "error": stream_error})
            if result.returncode:
                record["error"] = "binary fixture stream command failed"
        if docker:
            try:
                self.backend.check_deadline()
            except Exception as error:
                record["status"] = "failed"
                record["error"] = redact_timeout_provider(self, str(error))
                self.checks.append(record)
                if record["error"] != str(error):
                    raise ProbeError(
                        f"{public_name}: command completed after its original aggregate deadline"
                    ) from None
                raise ProbeError(f"{public_name}: command completed after its original aggregate deadline") from error
        self.checks.append(record)
        if stream_error is not None:
            raise ProbeError(stream_error)
        if check and result.returncode:
            detail = (
                "binary fixture stream command failed"
                if binary_fixture
                else redact_timeout_provider(self, diagnostics)[-1000:] or redact_timeout_provider(self, output)[-1000:]
            )
            raise ProbeError(redact_timeout_provider(self, f"{name}: exit {result.returncode}: {detail}"))
        return output

    def podman(
        self,
        name: str,
        *args: str,
        timeout: float | None = None,
        check: bool = True,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> str:
        # Keep this internal compatibility name for existing probe callers; the
        # resolved backend owns the endpoint, option normalization and lifecycle.
        docker = isinstance(getattr(self, "backend", None), DockerBackend)
        streams = {key: value for key, value in (("stdin", stdin), ("stdout", stdout)) if value is not None}
        if docker and args[:1] == ("save",):
            args = self.backend.save_arguments(args)
        if args and args[0] == "run":
            if streams:
                raise ProbeError("binary fixture streams cannot launch a container")
            try:
                image_index = args.index(self.image_ref)
            except ValueError as error:
                raise ProbeError(f"{name}: outer Podman run must use {self.image_ref}") from error
            options = args[1:image_index]
            if any(
                option in ("--name", "--cidfile") or option.startswith(("--name=", "--cidfile=")) for option in options
            ):
                raise ProbeError(f"{name}: outer Podman run must not override owned name or cidfile")
            if any(option == "--rmi" or option.startswith("--rmi=") for option in options):
                raise ProbeError(f"{name}: outer Podman run must not auto-remove its image")
            # Podman removes cidfiles with --rm containers. Keep one-shot containers
            # until our exact-ID cleanup so ownership survives timeout/cancellation.
            options = tuple(option for option in options if option != "--rm" and not option.startswith("--rm="))
            if docker:
                options = self.backend.run_options(options)
            run_id = uuid.uuid4().hex
            container_name = f"strukturpiloten-runtime-{run_id}"
            cidfile = self.directory / f"run-{run_id}.cid"
            self.containers.append(container_name)
            self.run_containers.add(container_name)
            if not hasattr(self, "container_launchers"):
                self.container_launchers = {}
            self.container_launchers[container_name] = (
                "systemd"
                if docker
                and self.declared_launcher == "systemd"
                and "--detach" in options
                and not args[image_index + 1 :]
                else "direct"
                if docker
                else "systemd"
                if "--systemd=always" in options
                else "direct"
            )
            completed = False
            try:
                output = self.command(
                    name,
                    [
                        *self._prefix(timeout),
                        "run",
                        "--name",
                        container_name,
                        "--cidfile",
                        str(cidfile),
                        *options,
                        *args[image_index:],
                    ],
                    timeout=timeout,
                    check=check,
                )
                completed = True
                return output
            finally:
                # The name is registered before spawn; a cidfile promotes ownership
                # to the exact ID even when the CLI times out or is cancelled.
                if cidfile.is_file():
                    container = cidfile.read_text(encoding="utf-8").strip()
                    if not re.fullmatch(r"[a-f0-9]{64}", container):
                        raise ProbeError(f"{name}: invalid Podman cidfile {cidfile}")
                    self.containers[self.containers.index(container_name)] = container
                    self.run_containers.remove(container_name)
                    self.run_containers.add(container)
                    self.container_launchers[container] = self.container_launchers.pop(container_name)
                    if docker and completed and self.checks[-1].get("exitCode") == 0:
                        self.backend.admit_container(self, container)
                elif completed and self.checks[-1].get("exitCode") == 0:
                    raise ProbeError(f"{name}: Podman run succeeded without cidfile {cidfile}")
        return self.command(name, [*self._prefix(timeout), *args], timeout=timeout, check=check, **streams)

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
        if getattr(self, "runtime_deadline", None) is None:
            identity = archive_identity(archive, self.architecture)
        else:
            code = (
                "import json,sys\nfrom pathlib import Path\n"
                "sys.path.insert(0,sys.argv[1])\nfrom scripts.oci_artifacts import archive_identity\n"
                "result=json.dumps(archive_identity(Path(sys.argv[2]),sys.argv[3]))\n"
                "if len(result)>4096: raise ValueError('archive identity exceeded its byte bound')\n"
                "print(result)\n"
            )
            identity = json.loads(
                self.command(
                    "read bounded OCI archive identity",
                    [sys.executable, "-I", "-c", code, str(ROOT), str(archive), self.architecture],
                    timeout=180,
                )
            )
        if isinstance(getattr(self, "backend", None), DockerBackend):
            self.backend.import_archive(self, archive, identity)
        else:
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

    def start(self, name: str, *command: str, options: tuple[str, ...] = (), timeout: float | None = None) -> str:
        timeout_options = {} if timeout is None else {"timeout": timeout}
        container = self.podman(
            name,
            "run",
            "--detach",
            "--security-opt",
            "label=disable",
            *options,
            self.image_ref,
            *command,
            **timeout_options,
        )
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise ProbeError(f"{name}: no container ID returned")
        if container not in self.containers:
            self.containers.append(container)
        return container

    def exec(self, name: str, container: str, *args: str, timeout: float | None = None) -> str:
        options = {} if timeout is None else {"timeout": timeout}
        return self.podman(name, "exec", container, *getattr(self, "exec_guard", ()), *args, **options)

    def load_fixture_archive(self, name: str, container: str, archive: BinaryIO) -> str:
        """Import only through the held container ID and the owned archive stdin."""
        self._fixture_descriptor(archive)
        if re.fullmatch(r"[a-f0-9]{64}", container) is None or container not in self.containers:
            raise ProbeError("binary fixture import requires an exact held container ID")
        if archive.tell() != 0 or os.fstat(archive.fileno()).st_size <= 0:
            raise ProbeError("binary fixture import requires a nonempty archive rewound on its held descriptor")
        return self.podman(
            name, "exec", "--interactive", container, *getattr(self, "exec_guard", ()), "docker", "load", stdin=archive
        )

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
        if isinstance(getattr(self, "backend", None), DockerBackend):
            self.backend.cleanup(self)
            return
        failed: list[str] = []
        shutdown_failures: list[str] = []
        for container in reversed(self.containers):
            if container in getattr(self, "run_containers", set()):
                try:
                    self.podman(
                        "check owned run container existence", "container", "exists", container, timeout=10, check=False
                    )
                except ProbeError:
                    failed.append(container)
                    continue
                observed = self.checks[-1].get("exitCode")
                if observed == 1:
                    # A run cancelled before creation has no container to remove.
                    # Exit 1 is Podman's documented exact-container absence result.
                    self.checks[-1]["status"] = "passed"
                    self.checks[-1]["expectedExitCode"] = 1
                    continue
                if observed != 0:
                    failed.append(container)
                    continue
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
                if getattr(self, "container_launchers", {}).get(container) == "systemd":
                    from scripts.runtime_docker_systemd import stop_guest  # noqa: PLC0415

                    stop_guest(self, container)
                elif running == "true":
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
            except ProbeError as error:
                if getattr(self, "container_launchers", {}).get(container) == "systemd":
                    shutdown_failures.append(container)
                    self.checks.append(
                        {
                            "name": "cleanup owned systemd shutdown",
                            "status": "failed",
                            "container": container,
                            "error": f"{type(error).__name__}: {error}",
                            "errorTraceback": "".join(traceback.format_exception(error)),
                        }
                    )
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
        if hasattr(self, "run_containers"):
            self.run_containers.clear()
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
        if shutdown_failures:
            raise ProbeError(
                f"systemd shutdown was abnormal for {shutdown_failures}; exact owned resources were removed"
            )


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


class _PairCancellation:
    def __init__(self) -> None:
        self.cancelled = False
        self.defer_interrupts = False

    def __call__(self, _signum: int, _frame: Any) -> None:
        self.cancelled = True
        if not self.defer_interrupts:
            raise KeyboardInterrupt


class _ArchiveSnapshot:
    def __init__(self, path: Path, supplied: Path | None) -> None:
        self.path = path
        self.supplied = supplied
        self.handle: BinaryIO | None = None
        self.identity: tuple[int, int, int, int, int] | None = None

    def prepare(self, ctx: RuntimeContext, args: argparse.Namespace) -> None:
        if self.handle is not None:
            self.verify()
            return
        if self.supplied is None:
            ctx.command(
                "export local image",
                ["podman", "save", "--format", "oci-archive", "--output", str(self.path), args.image_ref],
                timeout=180,
            )
        else:
            if not self.supplied.is_file():
                raise ProbeError("supplied OCI archive is not a regular file")
            code = (
                "import sys\n"
                "with open(sys.argv[1],'rb') as source, open(sys.argv[2],'wb') as target:\n"
                " total=0\n"
                " while block:=source.read(1024*1024):\n"
                "  total+=len(block)\n"
                "  if total>int(sys.argv[3]): raise ValueError('source archive exceeds disk budget')\n"
                "  target.write(block)\n"
            )
            ctx.command(
                "snapshot supplied OCI archive",
                [sys.executable, "-I", "-c", code, str(self.supplied), str(self.path), str(STORE_LIMIT_BYTES)],
                timeout=180,
            )
        if not 0 < self.path.stat().st_size <= STORE_LIMIT_BYTES:
            raise ProbeError("owned OCI archive snapshot has an invalid or over-budget size")
        self.path.chmod(0o400)
        self.handle = self.path.open("rb")
        value = os.fstat(self.handle.fileno())
        self.identity = value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
        self.verify()

    def verify(self) -> None:
        value = self.path.stat(follow_symlinks=False)
        current = value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
        if self.identity is not None and current != self.identity:
            raise ProbeError("owned OCI snapshot path changed after its input inode was pinned")

    def load_path(self) -> Path:
        if self.handle is None:
            raise ProbeError("owned OCI snapshot is not pinned")
        return Path(f"/proc/{os.getpid()}/fd/{self.handle.fileno()}")

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()


@dataclass(frozen=True)
class _DockerPhasePlan:
    args: argparse.Namespace
    metadata: dict[str, Any]
    architecture: str
    use_sudo: bool
    archive: _ArchiveSnapshot
    phase: DockerProbePhase
    deadline: float
    cancellation: _PairCancellation
    expected_identity: dict[str, Any] | None


def _phase_error(evidence: dict[str, Any], error: BaseException, *, key: str = "error") -> None:
    evidence["status"] = "failed"
    summary = f"{type(error).__name__}: {error}"
    details = "".join(traceback.format_exception(error))
    if key in evidence:
        evidence.setdefault("additionalErrors", []).append({"kind": key, "error": summary, "traceback": details})
    else:
        evidence[key] = summary
        evidence[key + "Traceback"] = details


def _execute_docker_phase(plan: _DockerPhasePlan) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "phase": plan.phase.value,
        "status": "failed",
        "checks": [],
        "observations": [],
        "cleanupVerified": False,
        "architecture": plan.architecture,
    }
    ctx: RuntimeContext | None = None
    try:
        if plan.cancellation.cancelled or started >= plan.deadline:
            raise ProbeError("required Docker phase cancelled or wall-time budget exhausted before context creation")
        # Ownership acquisition has no native work; latch cancellation until the
        # completed context can be cleaned, rather than losing a partial store.
        plan.cancellation.defer_interrupts = True
        try:
            ctx = RuntimeContext(
                image=plan.metadata["name"],
                architecture=plan.architecture,
                timeout=plan.args.timeout,
                use_sudo=plan.use_sudo,
                outer_engine=select_outer_engine(getattr(plan.args, "outer_engine", "podman"), "docker"),
            )
        finally:
            plan.cancellation.defer_interrupts = False
        result["checks"], result["observations"] = ctx.checks, ctx.observations
        ctx.runtime_phase = plan.phase.value
        ctx.runtime_deadline = plan.deadline
        ctx.bind_guest_profile(plan.metadata["tests"]["docker"])
        result["outerRuntime"] = ctx.prepare()
        if plan.cancellation.cancelled:
            raise KeyboardInterrupt
        _docker_phase_work(plan, ctx, result)
        result["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            plan.cancellation.cancelled = True
        _phase_error(result, error)
    finally:
        plan.cancellation.defer_interrupts = True
        try:
            if ctx is not None:
                ctx.runtime_deadline = None
                try:
                    ctx.cleanup()
                    result["cleanupVerified"] = True
                except (Exception, KeyboardInterrupt) as error:
                    if isinstance(error, KeyboardInterrupt):
                        plan.cancellation.cancelled = True
                    _phase_error(result, error, key="cleanupError")
        finally:
            plan.cancellation.defer_interrupts = False
        finished = time.monotonic()
        result["durationSeconds"] = round(finished - started, 3)
        if plan.cancellation.cancelled:
            _phase_error(result, KeyboardInterrupt("Docker phase cancelled; no subsequent phase may start"))
        elif finished >= plan.deadline:
            _phase_error(result, ProbeError("Docker phase wall-time budget exhausted, including owned cleanup"))
        elif result["status"] == "passed" and (
            not result["checks"] or any(check.get("status") != "passed" for check in result["checks"])
        ):
            _phase_error(result, ProbeError("Docker phase has failed, skipped or unknown admission checks"))
    return _public_timeout_evidence(ctx, result)


def _docker_phase_work(plan: _DockerPhasePlan, ctx: RuntimeContext, result: dict[str, Any]) -> None:
    from scripts.runtime_docker import _run_docker_phase  # noqa: PLC0415

    budget = IsolatedStoreDiskBudget(ctx, source_archive=plan.archive.path)
    if plan.archive.identity is not None:
        budget.bind_source_archive(plan.archive.identity)
    try:
        with budget:
            ctx.runtime_disk_budget = budget
            plan.archive.prepare(ctx, plan.args)
            budget.bind_source_archive(plan.archive.identity)
            budget.checkpoint()
            identity = ctx.load_archive(plan.archive.load_path())
            budget.checkpoint()
            plan.archive.verify()
            result["imageIdentity"] = identity
            result["archiveSnapshot"] = {"fdPinned": True, "identity": list(plan.archive.identity)}
            if plan.expected_identity is not None and identity != plan.expected_identity:
                raise ProbeError("control and enforcement OCI archive identities differ")
            if identity.get("architecture") != plan.architecture:
                raise ProbeError("Docker phase archive architecture differs from the requested native architecture")
            if ctx.outer_engine == "podman":
                result["podmanVersion"] = result["outerRuntime"]["clientVersion"]
            profile = plan.metadata["tests"]["docker"]
            if plan.phase is DockerProbePhase.CLEAN_CONTROL:
                _run_docker_phase(
                    ctx,
                    profile,
                    plan.phase,
                    allow_privileged=plan.args.allow_privileged,
                    skip_nested=False,
                )
            else:
                _docker(
                    ctx,
                    profile,
                    archive=plan.archive.load_path(),
                    allow_privileged=plan.args.allow_privileged,
                    skip_nested=False,
                )
    finally:
        ctx.runtime_disk_budget = None


def _run_systemd_pair(
    args: argparse.Namespace, metadata: dict[str, Any], evidence: dict[str, Any], *, use_sudo: bool
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + SYSTEMD_PAIR_SECONDS
    cancellation = _PairCancellation()
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT)}
    source: tempfile.TemporaryDirectory[str] | None = None
    archive: _ArchiveSnapshot | None = None
    evidence["phases"] = []
    evidence["observations"] = []
    evidence["budgets"] = {
        "controlSeconds": CONTROL_SECONDS,
        "pairWallSeconds": SYSTEMD_PAIR_SECONDS,
        "commandTimeoutSeconds": args.timeout,
        "outerOptions": list(outer_container_limits()),
        "storeMaxBytes": STORE_LIMIT_BYTES,
        "cleanup": "original bounded cleanup commands run even after work expiry; overrun cannot pass",
    }
    try:
        for kind in previous:
            signal.signal(kind, cancellation)
        profile = metadata["tests"]["docker"]
        if args.skip_nested or profile.get("nestedRuntime", True) is False or not args.allow_privileged:
            raise ProbeError("both required systemd Docker phases need enabled privileged nested runtime work")
        cancellation.defer_interrupts = True
        try:
            source = tempfile.TemporaryDirectory(prefix="strukturpiloten-runtime-source-")
            archive = _ArchiveSnapshot(
                Path(source.name) / "source-image.tar",
                Path(args.archive).resolve() if args.archive else None,
            )
            archive.path.touch(mode=0o600, exist_ok=False)
        finally:
            cancellation.defer_interrupts = False
        if not args.archive:
            evidence["source"] = "locally exported image"
        for phase in (DockerProbePhase.CLEAN_CONTROL, DockerProbePhase.ENFORCEMENT):
            if cancellation.cancelled or time.monotonic() >= deadline:
                raise ProbeError("systemd Docker pair cancelled or wall-time budget exhausted before next phase")
            result = _execute_docker_phase(
                _DockerPhasePlan(
                    args=args,
                    metadata=metadata,
                    architecture=evidence["architecture"],
                    use_sudo=use_sudo,
                    archive=archive,
                    phase=phase,
                    deadline=min(deadline, started + CONTROL_SECONDS)
                    if phase is DockerProbePhase.CLEAN_CONTROL
                    else deadline,
                    cancellation=cancellation,
                    expected_identity=evidence.get("imageIdentity"),
                )
            )
            evidence["phases"].append(result)
            evidence["checks"].extend({**check, "phase": phase.value} for check in result["checks"])
            evidence["observations"].extend({**item, "routePhase": phase.value} for item in result["observations"])
            if "imageIdentity" not in evidence and "imageIdentity" in result:
                evidence["imageIdentity"] = result["imageIdentity"]
            if "podmanVersion" in result:
                evidence["host"]["podmanVersion"] = result["podmanVersion"]
            if "outerRuntime" in result:
                evidence["host"]["outerRuntime"] = result["outerRuntime"]
            if result["status"] != "passed" or not result["cleanupVerified"]:
                for key in ("error", "errorTraceback", "cleanupError", "cleanupErrorTraceback", "additionalErrors"):
                    if key in result:
                        evidence[key] = list(result[key]) if key == "additionalErrors" else result[key]
                break
        if len(evidence["phases"]) == 2 and all(phase["status"] == "passed" for phase in evidence["phases"]):
            evidence["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        _phase_error(evidence, error)
    finally:
        cancellation.defer_interrupts = True
        try:
            if archive is not None and archive.identity is not None:
                archive.verify()
        except (Exception, KeyboardInterrupt) as error:
            _phase_error(evidence, error, key="cleanupError")
        finally:
            try:
                if archive is not None:
                    archive.close()
                if source is not None:
                    source.cleanup()
            except (Exception, KeyboardInterrupt) as error:
                _phase_error(evidence, error, key="cleanupError")
            if cancellation.cancelled:
                _phase_error(evidence, KeyboardInterrupt("systemd Docker pair cancelled"))
            finished = time.monotonic()
            evidence["durationSeconds"] = round(finished - started, 3)
            if finished >= deadline:
                _phase_error(evidence, ProbeError("systemd Docker pair wall-time budget exhausted"))
            try:
                evidence_path = Path(args.evidence)
                evidence_path.parent.mkdir(parents=True, exist_ok=True)
                evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            finally:
                for kind, handler in previous.items():
                    signal.signal(kind, handler)
    return evidence


def _public_timeout_evidence(ctx: RuntimeContext | None, value: Any) -> Any:
    """Protect only the admitted provider path in copies of JSON evidence values."""
    if ctx is None:
        return value
    if isinstance(value, str):
        return redact_timeout_provider(ctx, value)
    if isinstance(value, dict):
        return {key: _public_timeout_evidence(ctx, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_public_timeout_evidence(ctx, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_public_timeout_evidence(ctx, item) for item in value)
    return value


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
    selection = getattr(args, "outer_engine", "podman")
    profile_name, profile = next(iter(profiles.items()))
    outer_engine = select_outer_engine(selection, profile_name)
    evidence["host"]["outerEngineSelection"] = selection
    if outer_engine == "docker" and args.archive is None:
        raise ProbeError("private Docker backend requires an explicit OCI archive, not an ambient image reference")
    if (
        next(iter(profiles)) == "docker"
        and profiles["docker"].get("launcher") == "systemd"
        and profiles["docker"].get("mode") == "rootless"
    ):
        return _run_systemd_pair(args, metadata, evidence, use_sudo=use_sudo)
    ctx: RuntimeContext | None = None
    archive = Path(args.archive).resolve() if args.archive else None
    generated_archive = False
    try:
        ctx = RuntimeContext(
            image=metadata["name"],
            architecture=architecture,
            timeout=args.timeout,
            use_sudo=use_sudo,
            outer_engine=outer_engine,
        )
        if profile_name == "docker":
            ctx.bind_guest_profile(profile)
        evidence["checks"] = ctx.checks
        evidence["observations"] = ctx.observations
        evidence["host"]["outerRuntime"] = ctx.prepare()
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
        if outer_engine == "podman":
            evidence["host"]["podmanVersion"] = evidence["host"]["outerRuntime"]["clientVersion"]
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
        evidence["errorTraceback"] = "".join(traceback.format_exception(error))
    finally:
        # A second cancellation signal must not interrupt owned-resource cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if ctx is not None:
            try:
                ctx.cleanup()
            except (Exception, KeyboardInterrupt) as cleanup_error:
                evidence["status"] = "failed"
                evidence["cleanupError"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
                evidence["cleanupErrorTraceback"] = "".join(traceback.format_exception(cleanup_error))
        if generated_archive:
            evidence["source"] = "locally exported image"
        evidence_path = Path(args.evidence)
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        if ctx is not None and isinstance(getattr(ctx, "backend", None), DockerBackend):
            try:
                ctx.backend.check_deadline()
            except Exception as completion_error:
                evidence["status"] = "failed"
                previous = evidence.get("cleanupError", "")
                evidence["cleanupError"] = f"{previous}; {completion_error}".lstrip("; ")
        try:
            # Keep the descriptor for exactly the record we write. If a late
            # completion requires invalidation, never follow a replaced pathname
            # or unlink an unrelated file.
            with evidence_path.open("wb", buffering=0) as record:
                try:
                    body = (json.dumps(_public_timeout_evidence(ctx, evidence), indent=2) + "\n").encode("utf-8")
                    if record.write(body) != len(body):
                        raise OSError("short runtime evidence write")
                    record.flush()
                    if ctx is not None and isinstance(getattr(ctx, "backend", None), DockerBackend):
                        try:
                            ctx.backend.check_deadline()
                        except Exception as completion_error:
                            evidence["status"] = "failed"
                            previous = evidence.get("cleanupError", "")
                            evidence["cleanupError"] = f"{previous}; {completion_error}".lstrip("; ")
                            # Remove the passing body before serializing its
                            # replacement, so even a failed rewrite is invalid.
                            record.seek(0)
                            record.truncate()
                            body = (json.dumps(_public_timeout_evidence(ctx, evidence), indent=2) + "\n").encode(
                                "utf-8"
                            )
                            if record.write(body) != len(body):
                                raise OSError("short failed-evidence rewrite") from completion_error
                            record.flush()
                except Exception, KeyboardInterrupt:
                    # An I/O failure must not leave this invocation's valid
                    # passing body available as evidence. This acts on the held
                    # descriptor, not any possibly replaced output pathname.
                    os.ftruncate(record.fileno(), 0)
                    raise
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
    return _public_timeout_evidence(ctx, evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    metadata = parser.add_mutually_exclusive_group(required=True)
    metadata.add_argument("--metadata")
    metadata.add_argument("--image-name")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive")
    source.add_argument("--image-ref")
    parser.add_argument("--arch")
    parser.add_argument(
        "--outer-engine",
        choices=("podman", "docker", "profile"),
        default="podman",
        help="outer runtime policy; local default is Podman, profile selection is explicit",
    )
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
