"""Invocation-owned Docker daemon, containerd, network and store boundary.

Construction is inert. Only an explicitly selected runtime caller starts these
services. Transient service ownership is independent of a sudo client process,
so cancellation cannot turn killing that client into daemon cleanup evidence.
"""

# Fixed command vocabulary and owned disposable paths are intentional.
# ruff: noqa: EM101, EM102, PLR2004, SLF001, TRY003

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import sys
import tarfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.runtime_docker_diagnostics import qualify_gnu_timeout
from scripts.runtime_oom_diagnostics import MAX_BYTES, SNAPSHOT_SECONDS, DockerOomLedger, _docker_hash, _parent_validate

if TYPE_CHECKING:
    from scripts.docker_userns_active_client import ActiveClient
    from scripts.runtime_tests import RuntimeContext


class DockerBackendError(RuntimeError):
    """The private backend cannot establish or release its exact boundary."""


class DockerBackend:
    """Own private rootful services; never connect to an ambient Docker endpoint."""

    def __init__(self, directory: Path, sudo: tuple[str, ...]) -> None:
        """Allocate ownership tokens without contacting a runtime or service manager."""
        self.directory = directory
        self.sudo = sudo
        self.owner = secrets.token_hex(16)
        self.network = "strukturpiloten-" + self.owner
        self.bridge = "br-" + self.owner[:11]
        self.slice = "strukturpiloten" + self.owner + ".slice"
        self.socket = directory / "docker.sock"
        self.config = directory / "daemon.json"
        self.cli_config = directory / "cli"
        self.units: dict[str, tuple[str, ...]] = {}
        self.network_id: str | None = None
        self.ready = False
        self.deadline: float | None = None
        self.cleaning_up = False
        self.lifecycle_failures: list[str] = []
        self.slice_identity: str | None = None
        self.slice_creation_intent = False
        self.producers_stopped = False
        self.resources_drained = False
        self.oom_ledger: DockerOomLedger | None = None
        self.watchdog: str | None = None
        self.diagnostic_reader_pending = False
        self.scoped_profile: ActiveClient | None = None
        self._gnu_timeout_provider: tuple[str, str, str] | None = None

    @staticmethod
    def _tool(name: str) -> str:
        path = shutil.which(name)
        if path is None:
            raise DockerBackendError(f"private Docker backend requires {name}")
        return path

    def initialize(self) -> None:
        """Create private paths without launching or contacting a daemon."""
        for part in ("root", "runroot", "tmp", "cli", "containerd-root", "containerd-state"):
            (self.directory / part).mkdir()
        (self.cli_config / "config.json").write_text("{}\n", encoding="utf-8")

    def command_timeout(self, requested: float) -> float:
        """Clamp every phase, including cleanup, to the original absolute budget."""
        if not math.isfinite(requested) or requested <= 0:
            raise DockerBackendError("private runtime command has no positive timeout allowance")
        if self.deadline is None:
            return requested
        reserve = 0 if self.cleaning_up else 60
        available = self.deadline - time.monotonic() - reserve
        bounded = min(requested, available - 0.001)
        if bounded <= 0.01:
            raise DockerBackendError("private runtime original aggregate deadline exhausted")
        return bounded

    def check_deadline(self) -> None:
        """Never turn late teardown or command completion into passing evidence."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise DockerBackendError("private runtime original aggregate deadline exhausted")

    def timeout_executable(self) -> str:
        """Return only this invocation's admitted absolute GNU watchdog path."""
        if self._gnu_timeout_provider is None:
            raise DockerBackendError("GNU timeout provider has not been admitted")
        return self._gnu_timeout_provider[0]

    def privileged(self, argv: list[str], seconds: float) -> list[str]:
        """Put the command watchdog under sudo, before the privileged command."""
        seconds = self.command_timeout(seconds)
        kill_allowance = min(1.0, seconds / 4)
        scheduling_allowance = min(0.5, seconds / 4)
        duration = seconds - kill_allowance - scheduling_allowance
        return [
            *self.sudo,
            self.timeout_executable(),
            "--signal=TERM",
            f"--kill-after={kill_allowance}s",
            f"{duration}s",
            *argv,
        ]

    def rebudget_command(self, command: list[str], seconds: float) -> list[str]:
        """Refresh our own root watchdog at the final subprocess launch boundary."""
        if self._gnu_timeout_provider is None:
            return command  # The direct provider preflight cannot require its own uninitialized watchdog.
        prefix = [*self.sudo, self.timeout_executable(), "--signal=TERM"]
        if command[: len(prefix)] != prefix:
            return command
        if len(command) <= len(prefix) + 2 or not command[len(prefix)].startswith("--kill-after="):
            raise DockerBackendError("private runtime root watchdog prefix is invalid")
        return self.privileged(command[len(prefix) + 2 :], seconds)

    def client(self) -> list[str]:
        """Ignore caller credentials, context, endpoint and API-version overrides."""
        environment = ["env"]
        for name in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_API_VERSION",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            environment.extend(("-u", name))
        return [
            *environment,
            self._tool("docker"),
            "--config",
            str(self.cli_config),
            "--host",
            "unix://" + str(self.socket),
            "--tls=false",
        ]

    def command_prefix(self, seconds: float = 45) -> list[str]:
        """Return a bounded client bound only to this invocation's socket."""
        return self.privileged(self.client(), seconds)

    def _call(self, ctx: RuntimeContext, name: str, argv: list[str], seconds: float = 15) -> str:
        seconds = self.command_timeout(seconds)
        result = ctx.command(name, self.privileged(argv, seconds), timeout=seconds)
        self.check_deadline()
        return result

    def _read_state(self, ctx: RuntimeContext, unit: str) -> dict[str, str]:
        raw = self._call(
            ctx,
            "read private runtime service identity",
            [
                "systemctl",
                "show",
                unit,
                "--no-pager",
                "--all",
                (
                    "--property=Id,Names,LoadState,Description,Transient,MainPID,ActiveState,ControlGroup,"
                    "FragmentPath,SourcePath,DropInPaths,UnitFileState,Restart"
                ),
            ],
        )
        return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)

    def _state(self, ctx: RuntimeContext, unit: str) -> dict[str, str]:
        result = self._read_state(ctx, unit)
        if result.get("LoadState") == "not-found":
            return result
        if result.get("Description") != self.owner or result.get("Transient") != "yes":
            raise DockerBackendError("private runtime service ownership changed; retaining store")
        return result

    def _implicit_slice(self, state: dict[str, str]) -> None:
        # systemd synthesizes an inactive slice even before it has a cgroup.
        # A loaded unit is not itself a collision, but configured/transient or
        # aliased slices must never be adopted. Missing evidence fails closed.
        expected = {
            "Id": self.slice,
            "Names": self.slice,
            "LoadState": "loaded",
            "Description": "Slice /" + self.slice.removesuffix(".slice"),
            "Transient": "no",
            "FragmentPath": "",
            "SourcePath": "",
            "DropInPaths": "",
            "UnitFileState": "",
        }
        if any(state.get(key) != value for key, value in expected.items()):
            raise DockerBackendError("private runtime slice is not an unconfigured implicit unit")

    def _unused_slice(self, ctx: RuntimeContext) -> None:
        state = self._read_state(ctx, self.slice)
        if state.get("LoadState") != "not-found":
            self._implicit_slice(state)
            if (
                state.get("ActiveState") != "inactive"
                or state.get("ControlGroup") != ""
                or state.get("MainPID", "") not in {"", "0"}
            ):
                raise DockerBackendError("private runtime slice already exists")
        path = "/sys/fs/cgroup/" + self.slice
        self._call(ctx, "verify private runtime slice cgroup is absent", ["test", "!", "-e", path])
        self._call(ctx, "verify private runtime slice cgroup is not a symlink", ["test", "!", "-L", path])

    def _slice_identity(self, ctx: RuntimeContext) -> str:
        state = self._read_state(ctx, self.slice)
        self._implicit_slice(state)
        if state.get("ActiveState") != "active" or state.get("ControlGroup") != "/" + self.slice:
            raise DockerBackendError("private runtime slice cgroup identity changed")
        identity = self._call(
            ctx, "bind private runtime slice inode", ["stat", "--format=%d:%i", "/sys/fs/cgroup/" + self.slice]
        )
        if not re.fullmatch(r"[0-9]+:[0-9]+", identity):
            raise DockerBackendError("private runtime slice inode observation is invalid")
        return identity

    def _start(self, ctx: RuntimeContext, role: str, argv: tuple[str, ...]) -> None:
        if self.producers_stopped:
            raise DockerBackendError("private runtime producer lifetime is closed")
        unit = f"strukturpiloten-{self.owner}-{role}.service"
        if self._state(ctx, unit).get("LoadState") != "not-found":
            raise DockerBackendError("private runtime service name already exists")
        # Register before spawn: a timed-out sudo client is not evidence that
        # systemd did not create the service.
        self.units[unit] = argv
        if self.deadline is None:
            raise DockerBackendError("private runtime aggregate budget has not started")
        remaining = int(self.deadline - time.monotonic())
        if remaining <= 60:
            raise DockerBackendError("private runtime startup would consume cleanup reserve")
        self._call(
            ctx,
            "start private " + role,
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + unit,
                "--slice=" + self.slice,
                "--property=Description=" + self.owner,
                "--property=Type=exec",
                "--property=Restart=no",
                f"--property=RuntimeMaxSec={remaining}",
                "--property=TimeoutStopSec=10",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                "--property=Delegate=yes",
                "--",
                *argv,
            ],
        )
        observed = self._slice_identity(ctx)
        if self.slice_identity is not None and observed != self.slice_identity:
            raise DockerBackendError("private runtime slice was replaced")
        self.slice_identity = observed

    def _process(
        self, ctx: RuntimeContext, unit: str, *, argv: tuple[str, ...] | None = None, cgroup: str | None = None
    ) -> None:
        state = self._state(ctx, unit)
        pid = state.get("MainPID", "")
        if state.get("ActiveState") != "active" or not pid.isdecimal() or int(pid) <= 0:
            raise DockerBackendError("private runtime service is not active")
        expected_cgroup = cgroup or "/" + self.slice + "/" + unit
        if state.get("ControlGroup") != expected_cgroup:
            raise DockerBackendError("private runtime process escaped the owned slice")
        expected = self.units[unit] if argv is None else argv
        command = self._call(ctx, "verify private runtime process argv", ["cat", f"/proc/{pid}/cmdline"])
        if command.rstrip("\0").split("\0") != list(expected):
            raise DockerBackendError("private runtime process argv does not match owned paths")
        status = self._call(ctx, "verify private runtime process root identity", ["cat", f"/proc/{pid}/status"])
        uids = next((line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")), [])
        if uids != ["0", "0", "0", "0"]:
            raise DockerBackendError("private runtime process is not rootful")

    @staticmethod
    def _routes(raw: str) -> list[ipaddress.IPv4Network]:
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise DockerBackendError("host route census is not an array")
        result = []
        for row in rows:
            if not isinstance(row, dict):
                raise DockerBackendError("host route census contains an invalid entry")
            destination = row.get("dst", "default")
            if destination == "default":
                continue
            network = ipaddress.ip_network(destination, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                result.append(network)
        return result

    def _network(self, ctx: RuntimeContext) -> None:
        before = self._call(
            ctx, "read host IPv4 routes before private network", ["ip", "-j", "-4", "route", "show", "table", "all"]
        )
        routes = self._routes(before)
        candidates = list(ipaddress.ip_network("172.16.0.0/12").subnets(new_prefix=24))
        start = secrets.randbelow(len(candidates))
        subnet = next(
            (
                candidates[(start + offset) % len(candidates)]
                for offset in range(len(candidates))
                if not any(candidates[(start + offset) % len(candidates)].overlaps(route) for route in routes)
            ),
            None,
        )
        if subnet is None:
            raise DockerBackendError("no verified non-overlapping private Docker subnet")
        raw = ctx.podman(
            "create private Docker bridge",
            "network",
            "create",
            "--driver",
            "bridge",
            "--subnet",
            str(subnet),
            "--label",
            "io.strukturpiloten.runtime=" + self.owner,
            "--opt",
            "com.docker.network.bridge.name=" + self.bridge,
            "--opt",
            "com.docker.network.bridge.enable_ip_masquerade=false",
            self.network,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise DockerBackendError("private Docker network did not return an exact ID")
        self.network_id = raw
        observed = json.loads(ctx.podman("verify private Docker network", "network", "inspect", raw))
        if (
            not isinstance(observed, list)
            or len(observed) != 1
            or observed[0].get("Id") != raw
            or observed[0].get("Name") != self.network
            or observed[0].get("Labels", {}).get("io.strukturpiloten.runtime") != self.owner
            or observed[0].get("Driver") != "bridge"
            or observed[0].get("IPAM", {}).get("Config")
            != [{"Subnet": str(subnet), "Gateway": str(subnet.network_address + 1)}]
            or observed[0].get("Options", {}).get("com.docker.network.bridge.name") != self.bridge
        ):
            raise DockerBackendError("private Docker network identity or IPAM changed")
        after = json.loads(
            self._call(
                ctx, "verify private network route separation", ["ip", "-j", "-4", "route", "show", "table", "all"]
            )
        )
        others = [row for row in after if row.get("dev") != self.bridge]
        if any(subnet.overlaps(route) for route in self._routes(json.dumps(others))):
            raise DockerBackendError("private Docker network overlaps another host route")

    def _endpoint_version(self, ctx: RuntimeContext) -> str:
        """Observe only bounded, non-secret fields from the owned endpoint."""
        # The loop, Docker client and watchdog all execute under the same sudo
        # boundary. No ambient host socket or caller-selected Docker context exists.
        raw = self._call(
            ctx,
            "wait for private Docker endpoint",
            [
                "sh",
                "-ec",
                (
                    'until "$@" info --format '
                    '"{{json .DockerRootDir}}|{{json .SecurityOptions}}|{{json .ServerVersion}}"; '
                    "do sleep 0.1; done"
                ),
                "private-docker-ready",
                *self.client(),
            ],
            seconds=30,
        )
        fields = raw.split("|")
        if len(fields) != 3:
            raise DockerBackendError("private Docker endpoint returned invalid bounded metadata")
        root, security, version = (json.loads(value) for value in fields)
        if (
            root != str(self.directory / "root")
            or not isinstance(security, list)
            or any("rootless" in value for value in security)
        ):
            raise DockerBackendError("Docker endpoint is not the owned rootful store")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,79}", version):
            raise DockerBackendError("private Docker server version is invalid")
        return version

    def _start_services(self, ctx: RuntimeContext) -> None:
        """Bind both service data/state roots and Docker's container scopes."""
        containerd_socket = self.directory / "containerd.sock"
        containerd = (
            self._tool("containerd"),
            "--config",
            "/dev/null",
            "--root",
            str(self.directory / "containerd-root"),
            "--state",
            str(self.directory / "containerd-state"),
            "--address",
            str(containerd_socket),
        )
        configuration = {
            "data-root": str(self.directory / "root"),
            "exec-root": str(self.directory / "runroot"),
            "pidfile": str(self.directory / "daemon.pid"),
            "hosts": ["unix://" + str(self.socket)],
            "containerd": str(containerd_socket),
            "containerd-namespace": "moby",
            "containerd-plugins-namespace": "plugins.moby",
            "bridge": "none",
            "iptables": False,
            "ip6tables": False,
            "ip-forward": False,
            "ip-masq": False,
            "userland-proxy": True,
            "features": {"containerd-snapshotter": False},
            "exec-opts": ["native.cgroupdriver=systemd"],
            "cgroup-parent": self.slice,
        }
        self.config.write_text(json.dumps(configuration) + "\n", encoding="utf-8")
        self._start(ctx, "containerd", containerd)
        self._start(ctx, "dockerd", (self._tool("dockerd"), "--config-file", str(self.config)))

    def prepare(self, ctx: RuntimeContext) -> dict[str, str]:
        """Start and prove private services before importing any image."""
        if not self.sudo and os.geteuid() != 0:
            raise DockerBackendError("private Docker backend requires rootful execution")
        for name in ("docker", "dockerd", "containerd", "systemd-run", "systemctl", "ip", "skopeo"):
            self._tool(name)
        if self.deadline is not None:
            raise DockerBackendError("private Docker preparation cannot renew its budget")
        self.deadline = time.monotonic() + 1800
        existing_deadline = vars(ctx).get("runtime_deadline")
        if type(existing_deadline) in {int, float}:
            if not math.isfinite(existing_deadline):
                raise DockerBackendError("existing runtime phase deadline is invalid")
            self.deadline = min(self.deadline, existing_deadline)
        try:
            self._gnu_timeout_provider = qualify_gnu_timeout(ctx)
        except ValueError:
            raise DockerBackendError("GNU timeout prerequisite admission failed") from None
        self._unused_slice(ctx)
        self._prepare_oom_accounting(ctx)
        self._start_services(ctx)
        version = self._endpoint_version(ctx)
        for unit in self.units:
            self._process(ctx, unit)
        self._start_expiry(ctx)
        daemon_unit = next(unit for unit in self.units if unit.endswith("-dockerd.service"))
        daemon_pid = self._call(ctx, "verify owned Docker daemon pidfile", ["cat", str(self.directory / "daemon.pid")])
        if daemon_pid != self._state(ctx, daemon_unit).get("MainPID"):
            raise DockerBackendError("private Docker pidfile does not identify its owned service")
        client_version = ctx.podman("observe private Docker client version", "--version")
        if not client_version.startswith("Docker version "):
            raise DockerBackendError("private Docker client version observation is invalid")
        containerd_version = self._call(
            ctx, "observe private containerd version", [self._tool("containerd"), "--version"]
        )
        systemd_version = self._call(
            ctx, "observe private systemd version", [self._tool("systemd-run"), "--version"]
        ).splitlines()[0]
        self._bind_oom_server(ctx, version, containerd_version)
        self.ready = True
        self._network(ctx)
        return {
            "engine": "docker",
            "clientVersion": client_version,
            "serverVersion": version,
            "containerdVersion": containerd_version,
            "systemdVersion": systemd_version,
            "rootMode": "rootful",
            "endpoint": "private-unix",
            "storage": "invocation-owned",
        }

    def _bind_oom_server(self, ctx: RuntimeContext, server_version: str, containerd_version: str) -> None:
        if self.oom_ledger is not None:
            raw = ctx.podman(
                "observe owned Docker server build",
                "version",
                "--format",
                '{"Version":{{json .Server.Version}},"GitCommit":{{json .Server.GitCommit}}}',
            )
            if len(raw) > MAX_BYTES:
                raise DockerBackendError("owned Docker server build record exceeded its bound")
            server = json.loads(raw)
            if type(server) is not dict or server.get("Version") != server_version:
                raise DockerBackendError("owned Docker server version changed during binding")
            self.oom_ledger.bind_server(server, containerd_version)

    def _prepare_oom_accounting(self, ctx: RuntimeContext) -> None:
        if getattr(ctx, "declared_launcher", "direct") == "systemd":
            # Register intent before dispatch: a timed-out caller is not proof
            # that systemd did not materialize this previously absent slice.
            self.slice_creation_intent = True
            self._call(ctx, "create empty owned runtime slice", ["systemctl", "start", self.slice])
            self.slice_identity = self._slice_identity(ctx)
            baseline = self.parent_oom_snapshot(ctx, "baseline")
            self.oom_ledger = DockerOomLedger(baseline, ctx.oom_accounting_mode)

    def _terminal_oom_accounting(self, ctx: RuntimeContext) -> None:
        if not self.resources_drained:
            raise DockerBackendError("owned resources did not drain")
        self.oom_ledger.reconcile(self.parent_oom_snapshot(ctx, "terminal"))

    def parent_oom_snapshot(self, ctx: RuntimeContext, purpose: str) -> dict[str, object]:
        """Mandatory parent-only host read, independent of daemon/live guest PID."""
        if not self.slice_creation_intent or self.slice_identity is None:
            raise DockerBackendError("owned parent creation custody is missing")
        if purpose not in {"baseline", "terminal"} or self._slice_identity(ctx) != self.slice_identity:
            raise DockerBackendError("owned parent accounting identity changed")
        seconds = self.command_timeout(min(SNAPSHOT_SECONDS, ctx.timeout))
        end = min(time.monotonic() + seconds, self.deadline if self.deadline is not None else 0)
        request = {"owner": self.owner, "purpose": purpose, "sliceIdentity": self.slice_identity, "deadline": end}
        started_ns = time.monotonic_ns()
        raw = self._call(
            ctx,
            "read quiescent owned parent OOM counters",
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).with_name("runtime_oom_diagnostics.py").resolve()),
                "--docker-parent",
                json.dumps(request),
            ],
            seconds=seconds,
        )
        if len(raw) > MAX_BYTES or time.monotonic() >= end or self._slice_identity(ctx) != self.slice_identity:
            raise DockerBackendError("owned parent accounting read is late or changed")
        result = _parent_validate(json.loads(raw), purpose)
        expected = _docker_hash(["/" + self.slice, tuple(map(int, self.slice_identity.split(":")))])
        window = result["sampleWindowMonotonicNs"]
        if result["bindings"]["parent"] != expected or not started_ns <= window[0] <= window[1] <= time.monotonic_ns():
            raise DockerBackendError("owned parent accounting response does not bind this request")
        if time.monotonic() >= end:
            raise DockerBackendError("owned parent accounting validation returned late")
        self.check_deadline()
        return result

    def _start_expiry(self, ctx: RuntimeContext) -> None:
        """Bound the whole slice even if the Python caller is killed outright."""
        if self.deadline is None or self.slice_identity is None:
            raise DockerBackendError("cannot arm expiry without the original budget and cgroup identity")
        unit = "strukturpiloten-" + self.owner + "-expiry.service"
        if self._state(ctx, unit).get("LoadState") != "not-found":
            raise DockerBackendError("private runtime expiry service already exists")
        remaining = int(self.deadline - time.monotonic())
        if remaining <= 60:
            raise DockerBackendError("cannot arm expiry after the cleanup reserve begins")
        argv = (
            sys.executable,
            "-I",
            str(Path(__file__).with_name("runtime_docker_expiry.py")),
            "--slice",
            self.slice,
            "--identity",
            self.slice_identity,
            "--deadline-ns",
            str(int((self.deadline - 60) * 1_000_000_000)),
            "--ready-file",
            str(self.directory / "expiry-ready"),
        )
        self.watchdog = unit
        self._call(
            ctx,
            "arm nonrenewing private runtime slice expiry",
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + unit,
                "--slice=system.slice",
                "--property=Description=" + self.owner,
                "--property=Type=exec",
                "--property=Restart=no",
                f"--property=RuntimeMaxSec={remaining}",
                "--property=TimeoutStopSec=5",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                "--",
                *argv,
            ],
        )
        self._process(ctx, unit, argv=argv, cgroup="/system.slice/" + unit)
        observed = self._call(
            ctx,
            "verify private slice expiry is armed",
            [
                "sh",
                "-ec",
                'until test -f "$1"; do sleep 0.05; done; cat "$1"',
                "private-expiry-ready",
                str(self.directory / "expiry-ready"),
            ],
            seconds=10,
        )
        if observed != self.slice_identity + "|" + str(int((self.deadline - 60) * 1_000_000_000)):
            raise DockerBackendError("private runtime expiry acknowledgement is invalid")

    def run_options(self, options: tuple[str, ...]) -> tuple[str, ...]:
        """Require owned network, labels and cgroup parent for every outer run."""
        if self.producers_stopped:
            raise DockerBackendError("owned parent lifetime is closed to new resources")
        if not self.ready or self.network_id is None:
            raise DockerBackendError("private Docker network is not ready")
        forbidden = ("--network", "--net", "--label", "-l", "--cgroup-parent")
        if any(option in forbidden or any(option.startswith(name + "=") for name in forbidden) for option in options):
            raise DockerBackendError("outer Docker run cannot override private network, ownership or cgroup parent")
        return (
            *options,
            "--network",
            self.network_id,
            "--label",
            "io.strukturpiloten.runtime=" + self.owner,
            "--cgroup-parent",
            self.slice,
        )

    def prepare_scoped_profile(self, ctx: RuntimeContext, stage: str, identity: dict[str, str]) -> None:
        """Record pending authority before attempting the separate root qualification."""
        from scripts.docker_userns_active_client import ActiveClient  # noqa: PLC0415

        if self.scoped_profile is not None:
            raise DockerBackendError("active qualification cannot prepare twice")
        self.scoped_profile = ActiveClient(ctx, stage, identity)
        self.scoped_profile.prepare()

    def scoped_run_options(self, options: tuple[str, ...]) -> tuple[str, ...]:
        """Qualify only the one owned detached systemd guest in this phase."""
        if self.scoped_profile is None:
            return options
        if any("apparmor=" in option for option in options):
            raise DockerBackendError("systemd guest cannot override the qualified scoped profile")
        return (*options, *self.scoped_profile.create_options())

    @staticmethod
    def save_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
        """Docker saves Docker transport; never pass Podman's format switch."""
        values = list(arguments)
        if "--format" in values:
            index = values.index("--format")
            if values[index : index + 2] != ["--format", "docker-archive"]:
                raise DockerBackendError("Docker backend cannot export a non-Docker transport")
            del values[index : index + 2]
        return tuple(values)

    def admit_container(self, ctx: RuntimeContext, identifier: str) -> None:
        """Verify configured placement and any live process's actual host cgroup."""
        raw = ctx.podman(
            "verify owned outer Docker cgroup parent",
            "inspect",
            "--format",
            "{{json .HostConfig.CgroupParent}}|{{.State.Pid}}",
            identifier,
        )
        parent, separator, pid = raw.partition("|")
        if not separator or json.loads(parent) != self.slice or not pid.isdecimal():
            raise DockerBackendError("outer Docker container lost its owned cgroup parent")
        if int(pid) > 0:
            membership = self._call(ctx, "verify live outer Docker slice membership", ["cat", f"/proc/{pid}/cgroup"])
            expected = "0::/" + self.slice + "/docker-" + identifier + ".scope"
            observed = membership.splitlines()
            systemd_guest = self._systemd_guest(ctx, identifier)
            valid = observed == [expected] or (
                systemd_guest
                and len(observed) == 1
                and re.fullmatch(re.escape(expected) + r"(?:/[A-Za-z0-9_.@:-]+)+", observed[0]) is not None
                and not any(part in {".", ".."} for part in observed[0].split("/"))
            )
            if systemd_guest and (self.slice_identity is None or self._slice_identity(ctx) != self.slice_identity):
                raise DockerBackendError("systemd guest lost its original private slice identity")
            if not valid:
                raise DockerBackendError("outer Docker process is outside its exact owned scope")
        if self.scoped_profile is not None and self._systemd_guest(ctx, identifier):
            self.scoped_profile.bind(identifier)

    @staticmethod
    def _systemd_guest(ctx: RuntimeContext, identifier: str) -> bool:
        return (
            ctx.name == "docker-29-conformance-rootless"
            and vars(ctx).get("declared_launcher") == "systemd"
            and vars(ctx).get("container_launchers", {}).get(identifier) == "systemd"
        )

    def import_archive(self, ctx: RuntimeContext, archive: Path, identity: dict[str, str]) -> None:
        """Convert OCI transport, verify unchanged config, then load privately."""
        converted = self.directory / "docker-import.tar"
        ctx.command(
            "convert verified OCI transport for Docker",
            [
                self._tool("skopeo"),
                "copy",
                "--insecure-policy",
                "--override-os",
                "linux",
                "--override-arch",
                ctx.architecture,
                "oci-archive:" + str(archive),
                "docker-archive:" + str(converted) + ":" + ctx.image_ref,
            ],
            timeout=180,
        )
        with tarfile.open(converted, "r:*") as handle:
            member = handle.getmember("manifest.json")
            if not member.isfile() or member.size > 4 * 1024 * 1024:
                raise DockerBackendError("converted Docker manifest is not bounded regular metadata")
            stream = handle.extractfile(member)
            if stream is None:
                raise DockerBackendError("converted Docker manifest is unreadable")
            with stream:
                manifest = json.load(stream)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise DockerBackendError("converted Docker archive must contain one image")
            config = handle.getmember(manifest[0]["Config"])
            if not config.isfile() or config.size > 4 * 1024 * 1024:
                raise DockerBackendError("converted Docker configuration is not bounded regular metadata")
            stream = handle.extractfile(config)
            if stream is None:
                raise DockerBackendError("converted Docker configuration is unreadable")
            with stream:
                digest = "sha256:" + hashlib.sha256(stream.read(4 * 1024 * 1024 + 1)).hexdigest()
            if digest != identity["configDigest"]:
                raise DockerBackendError("OCI conversion changed the verified image configuration")
        ctx.podman("load verified Docker transport", "load", "--quiet", "--input", str(converted), timeout=180)

    def _stop_unit(self, ctx: RuntimeContext, unit: str) -> None:
        state = self._state(ctx, unit)
        if state.get("LoadState") == "not-found":
            return
        if self.oom_ledger is not None and state.get("Restart") != "no":
            raise DockerBackendError("owned producer restart policy is unproved")
        self._call(ctx, "stop owned private runtime service", ["systemctl", "stop", unit], seconds=20)
        state = self._state(ctx, unit)
        if state.get("LoadState") != "not-found" and (
            state.get("ActiveState") != "inactive" or state.get("MainPID") != "0" or state.get("ControlGroup")
        ):
            raise DockerBackendError("private runtime service cgroup is not drained")

    def _stop_slice(self, ctx: RuntimeContext) -> None:
        state = self._read_state(ctx, self.slice)
        if state.get("LoadState") != "not-found" and state.get("ControlGroup"):
            observed = self._slice_identity(ctx)
            if self.slice_identity is None and self.slice_creation_intent:
                self.slice_identity = observed
            if self.slice_identity is None or observed != self.slice_identity:
                raise DockerBackendError("cannot stop an unverified private runtime slice")
            # Includes scopes and shims outside the daemon's service cgroup.
            self._call(ctx, "stop all owned runtime scopes", ["systemctl", "stop", self.slice], seconds=25)
            state = self._read_state(ctx, self.slice)
            if state.get("LoadState") != "not-found" and (
                state.get("ControlGroup") or state.get("ActiveState") != "inactive"
            ):
                raise DockerBackendError("owned runtime slice still contains resources")
        if self.slice_identity is not None or self.slice_creation_intent:
            self._call(ctx, "verify owned runtime cgroup absence", ["test", "!", "-e", "/sys/fs/cgroup/" + self.slice])

    def stop_services(self, ctx: RuntimeContext) -> None:
        """Drain owned service cgroups before permitting store removal."""
        if not self.units and not self.slice_creation_intent:
            return
        failures = []
        for unit in reversed(self.units):
            try:
                self._stop_unit(ctx, unit)
            except Exception as error:  # noqa: BLE001 - attempt both independently owned services.
                failures.append(f"{unit}: {error}")
        self.producers_stopped = True
        if self.oom_ledger is not None:
            try:
                if failures:
                    self.resources_drained = False
                self._terminal_oom_accounting(ctx)
            except Exception as error:  # noqa: BLE001 - accounting never skips exact slice cleanup.
                failures.append("mandatory parent OOM accounting: " + str(error))
        try:
            self._stop_slice(ctx)
        except Exception as error:  # noqa: BLE001 - retain the service and scope failures together.
            failures.append(str(error))
        if failures:
            raise DockerBackendError("; ".join(failures))
        if self.watchdog is not None:
            self._stop_unit(ctx, self.watchdog)

    def _container(self, ctx: RuntimeContext, token: str) -> str | None:
        """Use affirmative exact inventory, never an ambiguous inspect failure."""
        raw = ctx.podman(
            "inventory private Docker containers", "ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"
        )
        found = []
        for line in raw.splitlines():
            identifier, separator, name = line.partition("|")
            if not separator or not re.fullmatch(r"[0-9a-f]{64}", identifier):
                raise DockerBackendError("private Docker container inventory is invalid")
            if token in {identifier, name}:
                found.append(identifier)
        if len(found) > 1:
            raise DockerBackendError("owned Docker container identity is ambiguous")
        if not found:
            return None
        identifier = found[0]
        labels = json.loads(
            ctx.podman(
                "verify owned Docker container label", "inspect", "--format", "{{json .Config.Labels}}", identifier
            )
        )
        if not isinstance(labels, dict) or labels.get("io.strukturpiloten.runtime") != self.owner:
            raise DockerBackendError("Docker container is not owned by this invocation")
        return identifier

    def cleanup(self, ctx: RuntimeContext) -> None:
        """Remove exact resources, drain the full slice, then remove the store."""
        self.cleaning_up = True
        failures = []
        resource_failures = self._cleanup_resources(ctx)
        failures.extend(resource_failures)
        self.resources_drained = not resource_failures
        try:
            self.stop_services(ctx)
        except Exception as error:  # noqa: BLE001 - retain original resource failure too.
            failures.append(str(error))
        if ctx._owned_mounts():
            failures.append("private runtime store still contains mounts")
        if self.network_id is not None:
            links = json.loads(self._call(ctx, "audit private Docker bridge absence", ["ip", "-j", "link", "show"]))
            if any(row.get("ifname") == self.bridge for row in links):
                failures.append("private Docker bridge still exists")
        failures.extend(self._diagnostic_reader_failures())
        if failures:
            raise DockerBackendError("; ".join(failures) + "; retaining private runtime store")
        if self.directory.is_symlink() or self.directory.resolve() != self.directory:
            raise DockerBackendError("private runtime directory identity changed")
        self.check_deadline()
        if self.sudo or self.deadline is not None:
            self._call(ctx, "remove drained private Docker store", ["rm", "-rf", "--", str(self.directory)], seconds=25)
        else:
            # No privileged operation or daemon budget was started. Only the
            # caller-owned initialization directory exists in this branch.
            shutil.rmtree(self.directory)
        self.check_deadline()
        ctx.containers.clear()
        ctx.run_containers.clear()
        ctx.checks.append({"name": "cleanup isolated store", "status": "passed"})
        self._assert_orderly_cleanup()
        if self.oom_ledger is not None:
            self.check_deadline()
            self.oom_ledger.finalize(ctx)
            self.check_deadline()

    def _cleanup_resources(self, ctx: RuntimeContext) -> list[str]:
        """Close scoped custody before touching endpoint dependencies."""
        if self.scoped_profile is None:
            return self._ordinary_resource_cleanup(ctx)
        failures: list[str] = []
        if self.ready:
            try:
                self._remove_containers(ctx)
            except Exception as error:  # noqa: BLE001 - still attempt the independently owned scoped cleanup.
                failures.append(str(error))
            if self.scoped_profile is not None:
                try:
                    self.scoped_profile.close()
                except Exception as error:
                    # Preserve endpoint/store for independent custody. No later
                    # backend teardown may turn uncertainty into apparent absence.
                    raise DockerBackendError("scoped profile cleanup unverified; retaining private runtime") from error
            try:
                self._remove_network(ctx)
                self._remove_images(ctx)
            except Exception as error:  # noqa: BLE001 - service cleanup still runs after affirmative profile absence.
                failures.append(str(error))
        return failures

    def _ordinary_resource_cleanup(self, ctx: RuntimeContext) -> list[str]:
        """Preserve the existing ordinary backend cleanup and failure order."""
        try:
            if self.ready:
                self._remove_containers(ctx)
                self._remove_network(ctx)
                self._remove_images(ctx)
        except Exception as error:  # noqa: BLE001 - service and scope cleanup must still run.
            return [str(error)]
        return []

    def _assert_orderly_cleanup(self) -> None:
        if self.lifecycle_failures:
            raise DockerBackendError(
                "systemd shutdown was abnormal after owned cleanup: " + "; ".join(self.lifecycle_failures)
            )

    def _diagnostic_reader_failures(self) -> list[str]:
        return ["private diagnostic query teardown is unverified"] if self.diagnostic_reader_pending else []

    def _remove_containers(self, ctx: RuntimeContext) -> None:
        for token in reversed(ctx.containers):
            identifier = self._container(ctx, token)
            if identifier is None:
                continue
            if token != identifier and self._systemd_guest(ctx, token):
                ctx.containers[ctx.containers.index(token)] = identifier
                ctx.container_launchers[identifier] = ctx.container_launchers.pop(token)
                if token in ctx.run_containers:
                    ctx.run_containers.remove(token)
                    ctx.run_containers.add(identifier)
            if self._systemd_guest(ctx, identifier):
                from scripts.runtime_docker_systemd import stop_guest  # noqa: PLC0415

                try:
                    stop_guest(ctx, identifier)
                except Exception as error:  # noqa: BLE001 — retain strict shutdown failure after exact cleanup.
                    self.lifecycle_failures.append(str(error))
            else:
                ctx.podman("stop owned outer Docker container", "stop", "--time", "2", identifier, timeout=10)
            ctx.podman("remove owned outer Docker container", "rm", "--force", "--volumes", identifier, timeout=10)
            if self._container(ctx, identifier) is not None:
                raise DockerBackendError("owned Docker container remains after removal")
        if ctx.podman("audit private Docker containers", "ps", "--all", "--quiet", "--no-trunc"):
            raise DockerBackendError("private Docker store contains untracked containers")

    def _remove_network(self, ctx: RuntimeContext) -> None:
        networks = ctx.podman(
            "inventory private Docker networks", "network", "ls", "--no-trunc", "--format", "{{.ID}}|{{.Name}}"
        )
        for row in networks.splitlines():
            identifier, separator, name = row.partition("|")
            if not separator or not re.fullmatch(r"[0-9a-f]{64}", identifier):
                raise DockerBackendError("private Docker network census is invalid")
            if name != self.network:
                if identifier == self.network_id:
                    raise DockerBackendError("held private network name changed")
                continue
            if self.network_id is None or identifier != self.network_id:
                raise DockerBackendError("private network differs from the held creation ID")
            observed = json.loads(
                ctx.podman("verify owned Docker network cleanup identity", "network", "inspect", identifier)
            )
            if (
                not isinstance(observed, list)
                or len(observed) != 1
                or observed[0].get("Id") != identifier
                or observed[0].get("Name") != self.network
                or observed[0].get("Labels", {}).get("io.strukturpiloten.runtime") != self.owner
            ):
                raise DockerBackendError("private network ownership changed")
            ctx.podman("remove owned private Docker network", "network", "rm", identifier)

    @staticmethod
    def _remove_images(ctx: RuntimeContext) -> None:
        images = ctx.podman("inventory private Docker images", "images", "--quiet", "--no-trunc")
        for identifier in set(images.splitlines()):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", identifier):
                raise DockerBackendError("private Docker image inventory is invalid")
            ctx.podman("remove private Docker image", "image", "rm", "--force", identifier)
