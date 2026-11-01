"""Real private-leaf fault tests with only root UID and kernel/runtime inputs simulated."""

from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_active as control
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts import docker_userns_active as active
from scripts import docker_userns_qualification as qualification
from tests import test_docker_direct_startup_admission as admission_tests
from tests.test_docker_direct_startup_contract import binding, guest


@contextmanager
def fixture() -> Iterator[SimpleNamespace]:
    """Exercise real files/inodes/FIFO modes without privilege or native services."""
    # Only ownership is virtual: tests cannot chown to root. Type, mode, inode,
    # source bytes, exclusive creation, fsync and unlink paths remain real.
    original_lstat, original_fstat = Path.lstat, os.fstat
    foreign: set[Path] = set()

    def root_lstat(path: Path) -> os.stat_result:
        values = list(original_lstat(path))
        values[4] = 1000 if path in foreign else 0
        return os.stat_result(values)

    def root_fstat(descriptor: int) -> os.stat_result:
        values = list(original_fstat(descriptor))
        values[4] = 0
        return os.stat_result(values)

    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary)
        (stage / ".github").mkdir()
        raw = (admission_tests.active_tests.ROOT / ".github/docker-userns-active-admission.json").read_bytes()
        admission = stage / ".github/docker-userns-active-admission.json"
        admission.write_bytes(raw)
        admission.chmod(0o400)
        bootstrap_file = stage / "bootstrap.json"
        bootstrap_file.write_bytes(b'{"inert":true}\n')
        bootstrap_file.chmod(0o400)
        _proof, source, _environment, _event = admission_tests.DirectAdmissionTests().fixture(
            "docker-20.10-rootless", "amd64"
        )
        values = asdict(binding())
        values.update(
            candidate=source["candidate"],
            run=source["run"],
            attempt=source["attempt"],
            admission_sha256=source["admissionSha256"],
            workflow_context_sha256=qualification.context_digest(source),
            variant="direct-uid1000-unprofiled-a",
            phase="direct-control",
            arm="A",
        )
        identity = contract.DirectControlBinding(**values)
        record = {
            "schemaVersion": 4,
            "kind": "direct-control",
            "binding": asdict(identity),
            "bindingSha256": identity.digest(),
            "bootstrapSha256": active.digest(bootstrap_file.read_bytes()),
            "timeoutExecutable": "/usr/bin/gnutimeout",
            "state": "direct-control",
            "retained": False,
            "readerPending": False,
            "childPending": False,
            "container": None,
            "daemonDirectory": "/unused-direct-runtime",
        }
        (stage / "leases").mkdir()
        path = stage / "leases" / ("c" * 32)
        path.mkdir(mode=0o700)
        (path / "cli").mkdir(mode=0o700)
        (path / "cli/config.json").write_bytes(b"{}\n")
        (path / "cli/config.json").chmod(0o600)
        for leaf in ("lock", "state.json"):
            (path / leaf).write_bytes(b"{}\n")
            (path / leaf).chmod(0o600)
        commits = []
        store = SimpleNamespace(path=path, write=lambda value: commits.append(copy.deepcopy(value)))
        bootstrap = {"context": source, "deadlineNs": identity.deadline_ns}
        with patch.object(Path, "lstat", new=root_lstat), patch.object(active.os, "fstat", new=root_fstat):
            port = control.ControlPort(
                active, (stage, bootstrap, SimpleNamespace(qualification=qualification)), store, record
            )
            port.daemon, port.image = Mock(), Mock()
            port.docker = Mock(return_value=b'"docker"|null|["/usr/local/bin/start-dockerd"]')
            yield SimpleNamespace(port=port, path=path, stage=stage, foreign=foreign, commits=commits)


def container_record(port: control.ControlPort) -> dict:
    """Create independent fixed gate configuration and a live original incarnation."""
    return {
        "Id": "a" * 64,
        "Image": port.binding.config_digest,
        "Config": {
            "User": "docker",
            "Entrypoint": ["/bin/sh"],
            "Cmd": [gate.GUEST_GATE],
            "Labels": {
                "io.strukturpiloten.runtime": port.binding.owner,
                "org.opencontainers.image.revision": port.binding.candidate,
            },
        },
        "HostConfig": {
            "CgroupParent": port.binding.runtime_slice,
            "Privileged": True,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
        "AppArmorProfile": "unconfined",
        "State": {"Pid": os.getpid(), "Running": True, "StartedAt": "original"},
        "Mounts": [
            {
                "Destination": gate.GUEST_DIRECTORY,
                "Source": str(port.store.path / "direct-gate"),
                "RW": False,
                "Type": "bind",
            }
        ],
    }


class DirectLeafCustodyTests(unittest.TestCase):
    def test_prepare_commits_intent_before_real_exclusive_source_fifo_and_mode_configuration(self) -> None:
        with fixture() as data:
            control.prepare_gate(data.port, active)
            root = control.verify_gate(data.port, active)
            self.assertTrue(data.commits[0]["directGateIntent"])
            self.assertNotIn("directGate", data.commits[0])
            self.assertEqual((root / "gate").read_bytes(), gate.GATE_SOURCE)
            self.assertEqual(stat.S_IMODE((root / "gate").stat().st_mode), 0o444)
            self.assertTrue(stat.S_ISFIFO((root / "release").stat().st_mode))
            self.assertEqual(stat.S_IMODE((root / "release").stat().st_mode), 0o444)
            original = (root / "gate").stat().st_ino
            with self.assertRaises(active.RefusedError):
                control.prepare_gate(data.port, active)
            self.assertEqual((root / "gate").stat().st_ino, original)

    def test_wrong_original_user_entrypoint_or_command_has_no_gate_creation_intent(self) -> None:
        for response in (
            '"0"|null|["/usr/local/bin/start-dockerd"]',
            '"docker"|["systemd"]|["/usr/local/bin/start-dockerd"]',
            '"docker"|null|["/private-replacement"]',
        ):
            with self.subTest(response=response), fixture() as data:
                data.port.docker.return_value = response.encode()
                with self.assertRaises(active.RefusedError):
                    control.prepare_gate(data.port, active)
                self.assertNotIn("directGateIntent", data.port.record)
                self.assertFalse((data.path / "direct-gate").exists())

    def test_real_inode_type_mode_owner_hardlink_and_source_replacements_refuse(self) -> None:
        def replace_script(root: Path) -> None:
            replacement = root / "replacement"
            replacement.write_bytes(gate.GATE_SOURCE)
            replacement.chmod(0o444)
            replacement.replace(root / "gate")

        def replace_fifo(root: Path) -> None:
            os.mkfifo(root / "other", 0o444)
            (root / "other").replace(root / "release")

        def source_drift(root: Path) -> None:
            (root / "gate").chmod(0o644)
            (root / "gate").write_bytes(b"PRIVATE_SOURCE_CANARY")
            (root / "gate").chmod(0o444)

        mutations = {
            "script-inode": replace_script,
            "fifo-inode": replace_fifo,
            "source": source_drift,
            "directory-mode": lambda root: root.chmod(0o777),
            "script-mode": lambda root: (root / "gate").chmod(0o666),
            "fifo-mode": lambda root: (root / "release").chmod(0o666),
            "script-hardlink": lambda root: os.link(root / "gate", root.parent / "alias"),
            "owner": lambda _root: None,
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), fixture() as data:
                control.prepare_gate(data.port, active)
                root = data.path / "direct-gate"
                mutation(root)
                if name == "owner":
                    data.foreign.add(root / "gate")
                with self.assertRaises((active.RefusedError, contract.DirectDiagnosticError)) as error:
                    control.verify_gate(data.port, active)
                self.assertNotIn("PRIVATE_SOURCE_CANARY", str(error.exception))
                self.assertTrue(root.exists())

    def test_actual_inspect_requires_read_only_original_source_mount_and_exact_identity(self) -> None:
        mutations = (
            lambda value: value["Mounts"][0].update(RW=True),
            lambda value: value["Mounts"][0].update(Source="/private-other-source"),
            lambda value: value["HostConfig"].update(CgroupParent="other.slice"),
            lambda value: value["Config"].update(User="0"),
            lambda value: value.update(AppArmorProfile="other-private-label"),
        )
        with fixture() as data:
            control.prepare_gate(data.port, active)
            value = container_record(data.port)
            data.port.docker.return_value = json.dumps(value).encode()
            self.assertEqual(control.inspect_gate(data.port, active, "a" * 64)["Id"], "a" * 64)
            for mutation in mutations:
                changed = copy.deepcopy(value)
                mutation(changed)
                data.port.docker.return_value = json.dumps(changed).encode()
                with self.subTest(mutation=mutation), self.assertRaises(active.RefusedError):
                    control.inspect_gate(data.port, active, "a" * 64)

    def test_bind_control_uses_real_gate_inspection_and_refuses_actor_or_incarnation_drift(self) -> None:
        for fault in (None, "cgroup", "actor", "incarnation"):
            with self.subTest(fault=fault), fixture() as data:
                control.prepare_gate(data.port, active)
                original = container_record(data.port)
                changed = copy.deepcopy(original)
                if fault == "incarnation":
                    changed["State"]["StartedAt"] = "replacement"
                data.port.docker.side_effect = [json.dumps(original).encode(), json.dumps(changed).encode()]
                task = {
                    "pid": os.getpid(),
                    "startTicks": 1,
                    "cgroup": "0::/" + data.port.binding.runtime_slice + "/docker-" + "a" * 64 + ".scope\n",
                }
                if fault == "cgroup":
                    task["cgroup"] += "/child"
                facts = guest()["actor"]
                after = copy.deepcopy(facts)
                if fault == "actor":
                    after["CapEff"] = ["0000000000000001"]
                pidfd = os.open("/dev/null", os.O_RDONLY)
                with (
                    patch.object(control, "actor_snapshot", side_effect=[(task, facts), (task, after)]) as actor,
                    patch.object(control.os, "pidfd_open", return_value=pidfd, create=True),
                    patch.object(control.select, "select", return_value=([], [], [])),
                ):
                    if fault:
                        with self.assertRaises(active.RefusedError):
                            control.bind_control(data.port, active, "a" * 64)
                        self.assertNotIn("subject", data.port.record)
                    else:
                        control.bind_control(data.port, active, "a" * 64)
                        self.assertEqual(data.port.record["subject"]["container"], "a" * 64)
                        self.assertEqual(actor.call_count, 2)

    def test_verified_task_absence_precedes_any_inode_deletion_and_unknown_absence_keeps_gate(self) -> None:
        for absent in (False, True):
            with self.subTest(absent=absent), fixture() as data:
                control.prepare_gate(data.port, active)
                root = data.path / "direct-gate"

                def check_absence(*, root: Path = root, absent: bool = absent) -> None:
                    self.assertTrue((root / "gate").exists())
                    self.assertTrue(stat.S_ISFIFO((root / "release").stat().st_mode))
                    if not absent:
                        raise active.RefusedError

                data.port.subject_task_absent = Mock(side_effect=check_absence)
                if absent:
                    control.remove_gate(data.port, active)
                    self.assertFalse(root.exists())
                    self.assertTrue(data.port.record["directGateDisposed"])
                else:
                    with self.assertRaises(active.RefusedError):
                        control.remove_gate(data.port, active)
                    self.assertTrue(root.exists())
                    self.assertNotIn("directGateDisposed", data.port.record)

    def test_control_close_retains_unknown_create_pending_reader_child_or_guest_and_closes_only_verified_store(
        self,
    ) -> None:
        for fault in (None, "reader", "child", "unknown-create", "guest", "absence"):
            with self.subTest(fault=fault), fixture() as data:
                control.prepare_gate(data.port, active)
                data.port.docker.return_value = b"a" * 64 if fault == "guest" else b""
                data.port.record["readerPending"] = fault == "reader"
                data.port.record["childPending"] = fault == "child"
                data.port.record["directCreateIntent"] = fault == "unknown-create"
                data.port.subject_task_absent = Mock(
                    side_effect=active.RefusedError("closed") if fault == "absence" else None
                )
                if fault:
                    with self.assertRaises(active.RefusedError):
                        control._close_control(data.port, active)
                    self.assertTrue((data.path / "state.json").exists())
                    self.assertTrue((data.path / "direct-gate/gate").exists())
                    self.assertNotIn("directGateDisposed", data.port.record)
                else:
                    result = control._close_control(data.port, active)
                    self.assertEqual(result["state"], "closed")
                    self.assertTrue(result["disposed"])
                    self.assertEqual(result["qualification"], "none")
                    self.assertFalse(data.path.exists())
