"""One-shot root-owned gate effects; never a policy loader or runtime controller.

Only the already source-verified active helper calls this module. Control A has
its own read-only root port and binding; it cannot construct a ProfileLease.
"""

from __future__ import annotations

import json
import os
import re
import select
import stat
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import Namespace
    from types import ModuleType, SimpleNamespace

    from scripts.docker_userns_active import RootPort, Store

from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts import docker_direct_startup_observations as observations

OPERATIONS = frozenset(
    (
        "direct-control-prepare",
        "direct-control-create",
        "direct-gate-prepare",
        "direct-control-bind",
        "direct-preflight",
        "direct-observe",
        "direct-release",
        "direct-control-close",
    )
)
DIRECTORY_MODE = 0o755
SCRIPT_MODE = 0o444
FIFO_MODE = 0o444
IMAGE_CONFIG_FIELDS = 3
MIN_NAMESPACE_DEPTH = 2
GATE_FIELDS = ("directory", "script", "fifo", "released", "releaseIntent", "sourceSha256")


class ControlPort:
    """Borrow only existing bounded private-endpoint readers, not policy effects."""

    def __init__(
        self,
        api: ModuleType,
        source: tuple[Path, dict, SimpleNamespace],
        store: Store,
        record: dict,
    ) -> None:
        """Check actual A identity and the same independently verified root source."""
        stage, bootstrap, modules = source
        self.api, self.stage, self.bootstrap, self.modules, self.store, self.record = (
            api,
            stage,
            bootstrap,
            modules,
            store,
            record,
        )
        self.binding = contract.DirectControlBinding(**record["binding"])
        self.binding.validate()
        self.admission = modules.qualification.admission_document(
            api.root_bytes(stage / ".github/docker-userns-active-admission.json")
        )
        modules.qualification.validate_workflow_context(
            bootstrap["context"], self.admission, self.binding.admission_sha256
        )
        api.require(type(record["schemaVersion"]) is int and record["schemaVersion"] == api.PREREQUISITE_SCHEMA)
        api.require(
            record.get("kind") == "direct-control"
            and record["state"] == "direct-control"
            and record["bindingSha256"] == self.binding.digest()
        )
        api.require(record["bootstrapSha256"] == api.digest(api.root_bytes(stage / "bootstrap.json")))
        context = bootstrap["context"]
        api.require(
            all(
                getattr(self.binding, key) == context[key]
                for key in ("candidate", "run", "attempt", "job", "architecture", "image")
            )
        )
        api.require(self.binding.workflow_context_sha256 == modules.qualification.context_digest(context))
        api.require(self.binding.deadline_ns <= bootstrap["deadlineNs"] and not record["retained"])
        self.provider = record["timeoutExecutable"]
        api.require(self.provider in {"/usr/bin/gnutimeout", "/usr/bin/timeout"})
        self.work_until = self.binding.deadline_ns - api.RESERVE_NS - api.FINALIZER_HEADSTART_NS
        self.cleanup = False
        self.durable = (record.get("lastDurablePhase"), record.get("lastIntent"))

    def point(self, phase: str) -> dict:
        """Record the existing closed diagnostic phase."""
        return self.api.RootPort.point(self, phase)

    def commit(self) -> None:
        """Persist through the existing durable root store."""
        self.api.RootPort.commit(self)

    def query(self, arguments: list[str], *, pass_fds: tuple[int, ...] = ()) -> bytes:
        """Reuse only the existing owned bounded read-only path."""
        return self.api.RootPort.query(self, arguments, pass_fds=pass_fds)

    def docker(self, *arguments: str) -> bytes:
        """Read only this invocation-owned private endpoint."""
        return self.api.RootPort.docker(self, *arguments)

    def docker_logs(self, container: str) -> bytes:
        """Read only owned Docker logs through the bounded merged-stream route."""
        return self.api.RootPort.docker_logs(self, container)

    def docker_arguments(self, *arguments: str) -> list[str]:
        """Build only the existing fixed private-endpoint reader command."""
        return self.api.RootPort.docker_arguments(self, *arguments)

    def daemon(self) -> None:
        """Recheck the live rootful daemon and exact slice."""
        self.api.RootPort.daemon(self)

    def image(self) -> None:
        """Recheck the immutable source image identity."""
        self.api.RootPort.image(self)

    def subject_scope_absent(self, subject: dict) -> None:
        """Prove original recursive scope absence."""
        self.api.RootPort.subject_scope_absent(self, subject)

    def subject_task_absent(self) -> None:
        """Prove original task and scope absence."""
        self.api.RootPort.subject_task_absent(self)


def _identity(path: Path, mode: int, kind: str) -> list[int]:
    info = path.lstat()
    regular = (
        stat.S_ISDIR(info.st_mode)
        if kind == "directory"
        else stat.S_ISFIFO(info.st_mode)
        if kind == "fifo"
        else stat.S_ISREG(info.st_mode)
    )
    contract.require(regular and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode)
    contract.require(kind == "directory" or info.st_nlink == 1)
    return [info.st_dev, info.st_ino]


def verify_gate(port: ControlPort | RootPort, api: ModuleType) -> Path:
    """Recheck each root-owned inode and exact gate bytes before dependent use."""
    record = contract.exact_keys(port.record["directGate"], GATE_FIELDS)
    path = port.store.path / "direct-gate"
    api.require(_identity(path, DIRECTORY_MODE, "directory") == record["directory"])
    api.require({leaf.name for leaf in path.iterdir()} == {"gate", "release"})
    api.require(_identity(path / "gate", SCRIPT_MODE, "script") == record["script"])
    api.require(_identity(path / "release", FIFO_MODE, "fifo") == record["fifo"])
    api.require(api.root_bytes(path / "gate") == gate.GATE_SOURCE and record["sourceSha256"] == gate.GATE_SHA256)
    api.require(type(record["released"]) is bool and type(record["releaseIntent"]) is bool)
    return path


def prepare_gate(port: ControlPort | RootPort, api: ModuleType) -> None:
    """Commit intent before creating fixed root-owned source and token leaves."""
    api.require("directGate" not in port.record and not port.record.get("directGateIntent"))
    port.daemon()
    port.image()
    raw = port.docker(
        "image",
        "inspect",
        "--format",
        "{{json .Config.User}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}",
        port.binding.config_digest,
    )
    fields = raw.decode("ascii").strip().split("|")
    api.require(len(fields) == IMAGE_CONFIG_FIELDS)
    user, entrypoint, command = (json.loads(value, object_pairs_hook=api.unique) for value in fields)
    api.require(user == "docker" and entrypoint in (None, []) and command == list(gate.ORIGINAL_CMD))
    port.record["directGateIntent"] = True
    port.commit()
    path = port.store.path / "direct-gate"
    path.mkdir(mode=DIRECTORY_MODE)
    path.chmod(DIRECTORY_MODE, follow_symlinks=False)
    api.require(stat.S_IMODE(path.lstat().st_mode) == DIRECTORY_MODE)
    api.write_leaf(path, "gate", gate.GATE_SOURCE, SCRIPT_MODE)
    (path / "gate").chmod(SCRIPT_MODE, follow_symlinks=False)
    os.mkfifo(path / "release", FIFO_MODE)
    (path / "release").chmod(FIFO_MODE, follow_symlinks=False)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    port.record["directGate"] = {
        "directory": _identity(path, DIRECTORY_MODE, "directory"),
        "script": _identity(path / "gate", SCRIPT_MODE, "script"),
        "fifo": _identity(path / "release", FIFO_MODE, "fifo"),
        "sourceSha256": gate.GATE_SHA256,
        "released": False,
        "releaseIntent": False,
    }
    port.commit()
    verify_gate(port, api)


def inspect_gate(port: ControlPort | RootPort, api: ModuleType, container: str) -> dict:
    """Inspect only the exact configured original gate and its owned resources."""
    api.require(type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None)
    value = json.loads(port.docker("inspect", "--format", "{{json .}}", container), object_pairs_hook=api.unique)
    api.require(value["Id"] == container and value["Image"] == port.binding.config_digest)
    labels = value["Config"]["Labels"]
    api.require(labels["io.strukturpiloten.runtime"] == port.binding.owner)
    api.require(labels["org.opencontainers.image.revision"] == port.binding.candidate)
    api.require(value["HostConfig"]["CgroupParent"] == port.binding.runtime_slice)
    api.require(value["HostConfig"]["Privileged"] is True)
    api.require(value["HostConfig"]["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0})
    api.require(value["Config"]["User"] == "docker" and value["Config"]["Entrypoint"] == ["/bin/sh"])
    api.require(value["Config"]["Cmd"] == [gate.GUEST_GATE])
    expected_source = str(verify_gate(port, api))
    mounts = [item for item in value["Mounts"] if item.get("Destination") == gate.GUEST_DIRECTORY]
    api.require(
        len(mounts) == 1
        and mounts[0]["Type"] == "bind"
        and mounts[0]["Source"] == expected_source
        and mounts[0]["RW"] is False
    )
    if type(port.binding) is contract.DirectControlBinding:
        api.require(
            "io.strukturpiloten.userns-profile" not in labels and value["AppArmorProfile"] in ("", "unconfined")
        )
    else:
        api.require(type(port.binding) is contract.DirectDiagnosticBinding)
        api.require(labels["io.strukturpiloten.userns-profile"] == port.store.path.name)
        api.require(value["AppArmorProfile"] == port.record["profileName"])
    return value


def actor_snapshot(port: ControlPort | RootPort, api: ModuleType, directory: int, pid: int) -> tuple[dict, dict]:
    """Read bounded actual UID1000 PID1 facts through the original held procfs task."""
    task = api.task_snapshot(directory, pid, 1000)
    raw = api.proc_bytes(directory, "status", contract.HOST_BYTES)
    fields = {}
    wanted = (
        b"NSpid",
        b"Uid",
        b"Gid",
        b"Groups",
        b"CapInh",
        b"CapPrm",
        b"CapEff",
        b"CapBnd",
        b"CapAmb",
        b"NoNewPrivs",
        b"Seccomp",
        b"Seccomp_filters",
    )
    for line in raw.splitlines():
        key, separator, value = line.partition(b":")
        if key in wanted:
            api.require(separator and key not in fields)
            fields[key] = value.split()
    api.require(set(fields) == set(wanted))
    api.require(len(fields[b"NSpid"]) >= MIN_NAMESPACE_DEPTH and fields[b"NSpid"][-1] == b"1")
    api.require(fields[b"NSpid"][0] == str(pid).encode("ascii"))
    api.require(all(re.fullmatch(rb"[1-9][0-9]{0,9}", value) is not None for value in fields[b"NSpid"]))

    api.require(fields[b"Uid"] == [b"1000"] * 4 and fields[b"Gid"] == [b"1000"] * 4)
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        api.require(len(fields[key]) == 1 and re.fullmatch(rb"[0-9a-f]{16}", fields[key][0]) is not None)
    for key in (b"Groups", b"NoNewPrivs", b"Seccomp", b"Seccomp_filters"):
        api.require(all(re.fullmatch(rb"[0-9]{1,10}", value) is not None for value in fields[key]))
    api.require(all(len(fields[key]) == 1 for key in (b"NoNewPrivs", b"Seccomp", b"Seccomp_filters")))
    label = api.proc_bytes(directory, "attr/apparmor/current", contract.RECORD_BYTES)
    expected = (
        b"unconfined\n"
        if type(port.binding) is contract.DirectControlBinding
        else port.record["profileName"].encode() + b" (unconfined)\n"
    )
    api.require(label == expected)
    facts = {key.decode("ascii"): [value.decode("ascii") for value in values] for key, values in fields.items()}
    # Mapping content stays private; expose only bounded hashes. No environment,
    # journal, arbitrary file, child utility or namespace operation is requested.
    for key in ("uid_map", "gid_map"):
        facts[key + "Sha256"] = api.digest(api.proc_bytes(directory, key, contract.GUEST_BYTES))
    facts.pop("NSpid")
    facts["namespaceDepth"] = len(fields[b"NSpid"])
    facts["guestPid"] = 1
    namespaces = {}
    for kind in ("user", "mnt", "pid"):
        observed = os.readlink("ns/" + kind, dir_fd=directory)
        own = str(Path("/proc/self/ns", kind).readlink())
        api.require(re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", observed) is not None)
        api.require((observed == own) is (kind == "user"))
        namespaces[kind] = {
            "sha256": api.digest(observed.encode("ascii")),
            "relationship": "same-host" if kind == "user" else "owned-distinct",
        }
    facts["namespaces"] = namespaces
    return task, facts


def bind_control(port: ControlPort, api: ModuleType, container: str) -> None:
    """Bind A's actual UID1000 PID1 without claiming any policy attachment."""
    api.require("subject" not in port.record and port.record["state"] == "direct-control")
    port.daemon()
    before = inspect_gate(port, api, container)
    pid = before["State"]["Pid"]
    api.require(type(pid) is int and pid > 0 and before["State"]["Running"] is True)
    descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pidfd = os.pidfd_open(pid)
    try:
        task, facts = actor_snapshot(port, api, descriptor, pid)
        api.require(task["cgroup"] == "0::/" + port.binding.runtime_slice + "/docker-" + container + ".scope\n")
        api.require(
            not select.select([pidfd], [], [], 0)[0] and actor_snapshot(port, api, descriptor, pid) == (task, facts)
        )
        after = inspect_gate(port, api, container)
        api.require(after["State"] == before["State"])
        port.record["subject"] = {
            "container": container,
            "pid": pid,
            "startTicks": task["startTicks"],
            "startedAt": before["State"]["StartedAt"],
            "cgroup": task["cgroup"],
        }
        port.record["container"] = container
        port.record["directActor"] = facts
        port.commit()
    finally:
        os.close(pidfd)
        os.close(descriptor)


def release(port: ControlPort | RootPort, api: ModuleType, container: str) -> None:
    """Write exactly one atomic inert token after repeated held-actor checks."""
    api.require(port.record.get("subject", {}).get("container") == container)
    api.require("directExecutables" in port.record)
    path = verify_gate(port, api)
    api.require(not port.record["directGate"]["releaseIntent"] and not port.record["directGate"]["released"])
    before = inspect_gate(port, api, container)
    subject = port.record["subject"]
    pid = subject["pid"]
    api.require(
        before["State"]["Pid"] == pid
        and before["State"]["StartedAt"] == subject["startedAt"]
        and before["State"]["Running"] is True
    )
    descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pidfd = os.pidfd_open(pid)
    writer = None
    try:
        task, facts = actor_snapshot(port, api, descriptor, pid)
        api.require(task["startTicks"] == subject["startTicks"] and task["cgroup"] == subject["cgroup"])
        api.require(not select.select([pidfd], [], [], 0)[0])
        port.record["directReleaseNs"] = api.time.monotonic_ns()
        port.record["directGate"]["releaseIntent"] = True
        port.record["directActor"] = facts
        port.commit()
        writer = os.open(path / "release", os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(writer)
        api.require(stat.S_ISFIFO(info.st_mode) and [info.st_dev, info.st_ino] == port.record["directGate"]["fifo"])
        api.require(len(gate.RELEASE_TOKEN) <= os.fpathconf(writer, "PC_PIPE_BUF"))
        api.require(
            actor_snapshot(port, api, descriptor, pid) == (task, facts) and not select.select([pidfd], [], [], 0)[0]
        )
        current = inspect_gate(port, api, container)["State"]
        api.require(
            current["Pid"] == pid and current["StartedAt"] == subject["startedAt"] and current["Running"] is True
        )
        api.check(port.work_until)
        api.require(os.write(writer, gate.RELEASE_TOKEN) == len(gate.RELEASE_TOKEN))
        port.record["directGate"]["released"] = True
        port.commit()
    finally:
        if writer is not None:
            os.close(writer)
        os.close(pidfd)
        os.close(descriptor)


def remove_gate(port: ControlPort | RootPort, api: ModuleType) -> None:
    """Remove exact gate inodes only after the original subject/scope are absent."""
    port.subject_task_absent()
    path = verify_gate(port, api)
    (path / "release").unlink()
    (path / "gate").unlink()
    path.rmdir()
    port.record["directGateDisposed"] = True
    port.commit()


def _receipt(port: ControlPort | RootPort, api: ModuleType) -> dict:
    value = {
        "schemaVersion": contract.SCHEMA,
        "consumer": contract.CONSUMER,
        "purpose": contract.PURPOSE,
        "qualification": "none",
        "bindingSha256": port.binding.digest(),
        "arm": port.binding.arm,
        "lease": port.store.path.name,
        "state": port.record["state"],
        "gateSha256": gate.GATE_SHA256,
        "released": port.record.get("directGate", {}).get("released") is True,
        "disposed": port.record.get("directGateDisposed") is True,
        "actor": port.record.get("directActor"),
        "executables": port.record.get("directExecutables"),
        "startup": port.record.get("directStartup"),
        "postExecVerified": "directPostExec" in port.record,
    }
    api.require(len(contract.canonical(value)) <= contract.RECORD_BYTES)
    return value


def _close_control(port: ControlPort, api: ModuleType) -> dict:
    api.require(not port.record["readerPending"] and not port.record["childPending"])
    api.require(not port.record.get("directCreateIntent") or port.record.get("subject") is not None)
    port.cleanup = True
    port.daemon()
    api.require(
        port.docker(
            "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=io.strukturpiloten.runtime=" + port.binding.owner
        )
        == b""
    )
    remove_gate(port, api)
    port.record["state"] = "closed"
    port.commit()
    result = _receipt(port, api)
    api.require({leaf.name for leaf in port.store.path.iterdir()} == {"lock", "state.json", "cli"})
    api.require({leaf.name for leaf in (port.store.path / "cli").iterdir()} == {"config.json"})
    api.require(api.root_bytes(port.store.path / "cli/config.json") == b"{}\n")
    for name in ("state.json", "lock", "cli/config.json"):
        api.root_bytes(port.store.path / name)
    (port.store.path / "cli/config.json").unlink()
    (port.store.path / "cli").rmdir()
    (port.store.path / "state.json").unlink()
    (port.store.path / "lock").unlink()
    port.store.path.rmdir()
    return result


def _initialize_control(
    api: ModuleType,
    source: tuple[Path, dict, SimpleNamespace],
    request: dict,
    store: Store,
    progress: dict,
) -> dict:
    _stage, bootstrap, modules = source
    binding = contract.DirectControlBinding(**request["binding"])
    binding.validate()
    record = api.bound_record(
        ({**bootstrap, "stage": str(_stage)}, modules),
        request,
        store.path.name,
        binding,
        progress=progress,
    )
    record.update(kind="direct-control", state="direct-control")
    record.pop("profileName")
    api.initialize_record(store, record, progress)
    (store.path / "cli").mkdir(mode=0o700)
    api.write_leaf(store.path / "cli", "config.json", b"{}\n", 0o600)
    return record


def _operate(
    port: ControlPort | RootPort,
    api: ModuleType,
    route: Namespace,
    request: dict,
    *,
    create: bool,
) -> dict:
    if route.operation in {"direct-control-prepare", "direct-gate-prepare"}:
        api.require(create or (request["container"] is None and port.record["state"] == "loaded"))
        prepare_gate(port, api)
    elif route.operation == "direct-control-create":
        api.require(
            type(port) is ControlPort and request["container"] is None and not port.record.get("directCreateIntent")
        )
        verify_gate(port, api)
        port.record["directCreateIntent"] = True
        port.commit()
    elif route.operation == "direct-control-bind":
        api.require(type(port) is ControlPort and port.record.get("directCreateIntent") is True)
        bind_control(port, api, request["container"])
    elif route.operation == "direct-preflight":
        api.require(type(port) is ControlPort or port.record["state"] == "attached")
        observations.preflight(port, api, request["container"])
    elif route.operation == "direct-observe":
        api.require(type(port) is ControlPort or port.record["state"] == "attached")
        observations.observe(port, api, request["container"])
    elif route.operation == "direct-release":
        api.require(type(port) is ControlPort or port.record["state"] == "attached")
        release(port, api, request["container"])
    else:
        api.require(
            route.operation == "direct-control-close" and type(port) is ControlPort and request["container"] is None
        )
        return _close_control(port, api)
    return _receipt(port, api)


def rpc(api: ModuleType, source: tuple[Path, dict, SimpleNamespace], route: Namespace) -> dict:
    """Dispatch a closed gate route after root source and stage-lock verification."""
    stage, bootstrap, modules = source
    api.require(bootstrap["context"]["purpose"] == contract.PURPOSE)
    request = api.request_value(route.request)
    create = route.operation == "direct-control-prepare"
    name = route.name
    if create:
        api.require(
            name == "new" and set(request) == {"binding", "daemonDirectory", "timeoutExecutable", "coordinatorPid"}
        )
        binding = contract.DirectControlBinding(**request["binding"])
        binding.validate()
        name = api.secrets.token_hex(16)
    route.diagnostic["lease"] = name
    store = api.Store(stage, name, create=create)
    port = None
    try:
        with store.locked():
            if create:
                record = _initialize_control(api, source, request, store, route.diagnostic)
            else:
                api.require(set(request) == {"bindingSha256", "container"})
                record = store.read()
                api.require(request["bindingSha256"] == record["bindingSha256"])
            if record.get("kind") == "direct-control":
                port = ControlPort(api, source, store, record)
                api.preflight_authority(stage, bootstrap, modules, progress=route.diagnostic)
            else:
                port = api.RootPort(stage, bootstrap, modules, store, record)
                api.require(type(port.binding) is contract.DirectDiagnosticBinding)
                port.guard(port.binding)
            route.diagnostic.update(record=record, binding=port.binding)
            return _operate(port, api, route, request, create=create)
    except BaseException:
        if port is not None:
            port.record["retained"] = True
            with suppress(Exception, KeyboardInterrupt):
                port.commit()
        raise
    finally:
        store.close()
