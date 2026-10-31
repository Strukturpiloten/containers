"""Inert direct gate custody, actor, deadline and one-release controls."""

from __future__ import annotations

import copy
import os
import stat
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_active as control
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_gate as gate
from scripts import docker_userns_active as active
from tests.test_docker_direct_startup_contract import binding


class DirectReleaseTests(unittest.TestCase):
    def fixture(self) -> tuple:
        """Hold one synthetic original PID/incarnation without opening any task."""
        cid = "a" * 64
        subject = {"container": cid, "pid": 123, "startTicks": 99, "startedAt": "fixed", "cgroup": "fixed-scope"}
        port = SimpleNamespace(
            binding=binding(),
            work_until=900,
            record={
                "directExecutables": {},
                "subject": subject,
                "directGate": {"releaseIntent": False, "released": False, "fifo": [1, 2]},
            },
            commit=Mock(),
        )
        task = {"pid": 123, "startTicks": 99, "cgroup": "fixed-scope"}
        state = {"State": {"Pid": 123, "StartedAt": "fixed", "Running": True}}
        api = SimpleNamespace(require=active.require, check=Mock(), time=SimpleNamespace(monotonic_ns=lambda: 1))
        return cid, port, task, state, api

    def run_release(self, *, fault: str | None = None) -> tuple:
        """Mock every kernel operation while retaining actual decision ordering."""
        cid, port, task, state, api = self.fixture()
        calls = []
        mutations = {
            "already-released": (port.record["directGate"], "released", True),
            "unacknowledged-prior-write": (port.record["directGate"], "releaseIntent", True),
            "swapped-arm-container": (port.record["subject"], "container", "b" * 64),
            "pid-reused": (task, "startTicks", 100),
            "outside-cgroup": (task, "cgroup", "other-scope"),
        }
        if fault in mutations:
            target, key, value = mutations[fault]
            target[key] = value
        if fault == "deadline":
            api.check.side_effect = active.RefusedError("closed")
        info = SimpleNamespace(st_mode=stat.S_IFIFO | 0o444, st_dev=1, st_ino=2)
        if fault == "fifo-replaced":
            info.st_ino = 3
        final_state = copy.deepcopy(state)
        if fault == "container-restarted":
            final_state["State"]["StartedAt"] = "replacement"
        if fault == "stopped":
            final_state["State"]["Running"] = False
        actor = Mock(return_value=(task, {"Uid": ["1000"] * 4}))
        if fault == "actor-drift":
            actor.side_effect = [(task, {}), (task, {"Uid": ["0"] * 4})]
        write = Mock(
            return_value=len(gate.RELEASE_TOKEN),
            side_effect=lambda *_args: calls.append("write") or len(gate.RELEASE_TOKEN),
        )
        if fault == "short-write":
            write.side_effect = lambda *_args: 0
        commit = port.commit
        commit.side_effect = lambda: calls.append(
            "released-commit" if port.record["directGate"]["released"] else "intent-commit"
        )
        with (
            patch.object(control, "verify_gate", return_value=Path("/fixed-owned-gate")),
            patch.object(control, "inspect_gate", side_effect=[state, final_state]),
            patch.object(control, "actor_snapshot", actor),
            patch.object(control.os, "open", side_effect=[11, 12]) as opened,
            patch.object(control.os, "pidfd_open", return_value=13, create=True),
            patch.object(control.os, "fstat", return_value=info),
            patch.object(control.os, "fpathconf", return_value=512),
            patch.object(control.os, "write", write),
            patch.object(control.os, "close") as closed,
            patch.object(
                control.select, "select", return_value=([13], [], []) if fault == "actor-exited" else ([], [], [])
            ),
        ):
            if fault:
                with self.assertRaises(active.RefusedError):
                    control.release(port, api, cid)
            else:
                control.release(port, api, cid)
            self.assertEqual(write.call_count, int(fault in {None, "short-write"}))
            for call in closed.call_args_list:
                self.assertIn(call.args[0], {11, 12, 13})
        return port, calls, opened, write

    def test_one_atomic_fixed_token_follows_durable_intent_and_repeated_actor_checks(self) -> None:
        port, calls, opened, write = self.run_release()
        self.assertEqual(calls, ["intent-commit", "write", "released-commit"])
        write.assert_called_once_with(12, b"containers-direct-startup-release-v1\n")
        self.assertTrue(opened.call_args_list[-1].args[1] & os.O_NONBLOCK)
        self.assertTrue(opened.call_args_list[-1].args[1] & os.O_NOFOLLOW)
        self.assertTrue(port.record["directGate"]["released"])

    def test_reuse_deadline_exit_restart_subject_or_fifo_drift_never_releases(self) -> None:
        for fault in (
            "already-released",
            "unacknowledged-prior-write",
            "swapped-arm-container",
            "pid-reused",
            "outside-cgroup",
            "deadline",
            "fifo-replaced",
            "container-restarted",
            "stopped",
            "actor-drift",
            "actor-exited",
        ):
            with self.subTest(fault=fault):
                _port, calls, _opened, _write = self.run_release(fault=fault)
                self.assertNotIn("write", calls)

    def test_unknown_partial_write_keeps_intent_and_never_acknowledges_release(self) -> None:
        port, calls, _opened, write = self.run_release(fault="short-write")
        self.assertTrue(port.record["directGate"]["releaseIntent"])
        self.assertFalse(port.record["directGate"]["released"])
        self.assertEqual(write.call_count, 1)
        self.assertNotIn("released-commit", calls)


class DirectActorTests(unittest.TestCase):
    def test_all_uid_gid_cap_nnp_seccomp_pid1_and_namespace_facts_are_held_and_closed(self) -> None:
        status = (
            b"NSpid:\t123\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\n"
            b"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
            b"CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n"
        )
        port = SimpleNamespace(binding=binding(), record={"profileName": "owned-profile"})
        task = {"pid": 123, "startTicks": 99, "cgroup": "owned-scope"}
        own = {"user": Path("user:[11]"), "mnt": Path("mnt:[22]"), "pid": Path("pid:[33]")}
        subject = {"user": "user:[11]", "mnt": "mnt:[44]", "pid": "pid:[55]"}
        for fault in (
            None,
            "uid",
            "gid",
            "not-pid1",
            "caps",
            "seccomp-missing",
            "duplicate",
            "label",
            "userns",
            "mountns",
        ):
            raw = status
            links = dict(subject)
            label = b"owned-profile (unconfined)\n"
            if fault in {"uid", "gid"}:
                key = b"Uid" if fault == "uid" else b"Gid"
                raw = raw.replace(key + b":\t1000\t1000\t1000\t1000", key + b":\t1000\t0\t1000\t1000")
            replacements = {
                "not-pid1": (b"NSpid:\t123\t1", b"NSpid:\t123\t2"),
                "caps": (b"CapEff:\t0000000000000000", b"CapEff:\tPRIVATE_CANARY"),
                "seccomp-missing": (b"Seccomp_filters:\t0\n", b""),
                "duplicate": (b"NoNewPrivs:\t0\n", b"NoNewPrivs:\t0\nNoNewPrivs:\t0\n"),
            }
            if fault in replacements:
                raw = raw.replace(*replacements[fault])
            if fault == "label":
                label = b"other-private-label\n"
            if fault == "userns":
                links["user"] = "user:[66]"
            if fault == "mountns":
                links["mnt"] = "mnt:[22]"
            api = SimpleNamespace(
                require=active.require,
                task_snapshot=Mock(return_value=task),
                digest=active.digest,
                proc_bytes=Mock(
                    side_effect=lambda _fd, name, _limit, raw=raw, label=label: (
                        raw if name == "status" else label if name == "attr/apparmor/current" else b"0 0 4294967295\n"
                    )
                ),
            )
            with (
                self.subTest(fault=fault),
                patch.object(
                    control.os, "readlink", side_effect=lambda path, links=links, **_kwargs: links[path.split("/")[-1]]
                ),
                patch.object(control.Path, "readlink", side_effect=list(own.values())),
            ):
                if fault:
                    with self.assertRaises(active.RefusedError):
                        control.actor_snapshot(port, api, 11, 123)
                else:
                    observed, facts = control.actor_snapshot(port, api, 11, 123)
                    self.assertEqual(observed, task)
                    self.assertEqual(facts["guestPid"], 1)
                    self.assertEqual(facts["namespaces"]["user"]["relationship"], "same-host")
                    self.assertNotIn("private", str(facts))
                api.task_snapshot.assert_called_once_with(11, 123, 1000)

    def test_control_port_exposes_no_policy_or_lease_effects(self) -> None:
        for prohibited in ("admit", "guard", "prepare", "load", "parser", "arm", "clean_owner", "create_intent"):
            with self.subTest(prohibited=prohibited):
                self.assertFalse(hasattr(control.ControlPort, prohibited))
        values = set(control.OPERATIONS)
        self.assertIn("direct-control-create", values)
        self.assertNotIn("prepare", values)
        self.assertEqual(contract.optional_controls()["attempted"], 0)


if __name__ == "__main__":
    unittest.main()


class DirectPolicySubjectTests(unittest.TestCase):
    def test_uid1000_direct_subject_has_exact_cgroup_and_native29_keeps_uid0_descendants(self) -> None:
        import tempfile  # noqa: PLC0415 - isolate the private mismatch-file fixture.

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        direct = binding()
        values = {
            key: value
            for key, value in asdict(direct).items()
            if key not in {"variant", "launcher", "expected_uid", "arm"}
        }
        values.update(image="docker-29-conformance-rootless", phase="enforcement", purpose="maintained-prerequisite")
        native = qualification.NativeBinding(**values)
        for subject, suffix, accepted, uid in (
            (direct, "", True, 1000),
            (direct, "/child", False, 1000),
            (native, "", True, 0),
            (native, "/child", True, 0),
        ):
            with self.subTest(image=subject.image, suffix=suffix), tempfile.TemporaryDirectory() as directory:
                port = active.RootPort.__new__(active.RootPort)
                port.binding, port.modules, port.admission = subject, SimpleNamespace(qualification=qualification), {}
                port.store = SimpleNamespace(path=Path(directory))
                port.record = {"profileName": "owned-profile"}
                port.daemon, port.commit = Mock(), Mock()
                port.inspect = Mock(return_value={"State": {"Pid": os.getpid(), "Running": True, "StartedAt": "fixed"}})
                task = {
                    "pid": os.getpid(),
                    "startTicks": 1,
                    "cgroup": "0::/" + subject.runtime_slice + "/docker-" + "a" * 64 + ".scope" + suffix + "\n",
                }
                pidfd = os.open("/dev/null", os.O_RDONLY)
                with (
                    patch.object(active, "namespace_snapshot", return_value={}),
                    patch.object(active, "task_snapshot", return_value=task) as snapshot,
                    patch.object(active, "proc_bytes", return_value=b"owned-profile (unconfined)\n"),
                    patch.object(active.os, "pidfd_open", return_value=pidfd, create=True),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    if accepted:
                        port.bind_subject("a" * 64, subject)
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.bind_subject("a" * 64, subject)
                    self.assertTrue(snapshot.call_args_list)
                    self.assertTrue(all(call.args[-1] == uid for call in snapshot.call_args_list))

    def test_direct_b_rejects_each_non1000_real_effective_saved_and_fs_uid_with_real_reader(self) -> None:
        import tempfile  # noqa: PLC0415 - private test paths only.

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        subject = binding()
        pid = os.getpid()
        stat_row = str(pid).encode() + b" (held (gate) task) " + b" ".join([b"S", *([b"0"] * 18), b"99"])
        cgroup = ("0::/" + subject.runtime_slice + "/docker-" + "a" * 64 + ".scope\n").encode()
        for wrong_index in (None, 0, 1, 2, 3):
            uids = [b"1000"] * 4
            if wrong_index is not None:
                uids[wrong_index] = b"0"
            status = (
                b"Pid:\t"
                + str(pid).encode()
                + b"\nTgid:\t"
                + str(pid).encode()
                + b"\nUid:\t"
                + b"\t".join(uids)
                + b"\n"
            )
            leaves = {
                "stat": stat_row,
                "status": status,
                "cgroup": cgroup,
                "attr/apparmor/current": b"owned-profile (unconfined)\n",
            }
            with self.subTest(wrong_uid_index=wrong_index), tempfile.TemporaryDirectory() as directory:
                port = active.RootPort.__new__(active.RootPort)
                port.binding, port.modules, port.admission = subject, SimpleNamespace(qualification=qualification), {}
                port.store, port.record = SimpleNamespace(path=Path(directory)), {"profileName": "owned-profile"}
                port.daemon, port.commit = Mock(), Mock()
                port.inspect = Mock(return_value={"State": {"Pid": pid, "Running": True, "StartedAt": "fixed"}})
                pidfd = os.open("/dev/null", os.O_RDONLY)
                with (
                    patch.object(active, "namespace_snapshot", return_value={}),
                    patch.object(
                        active, "proc_bytes", side_effect=lambda _fd, leaf, *_limits, leaves=leaves: leaves[leaf]
                    ),
                    patch.object(active.os, "pidfd_open", return_value=pidfd, create=True),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    if wrong_index is None:
                        port.bind_subject("a" * 64, subject)
                        self.assertIn("subject", port.record)
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.bind_subject("a" * 64, subject)
                        self.assertNotIn("subject", port.record)

    def test_closed_failure_projection_retains_actual_direct_arm_without_native29_alias(self) -> None:
        values = asdict(binding())
        self.assertEqual(active.failure_context(values, "direct-profiled")["image"], "docker-20.10-rootless")
        values.update(arm="A", phase="direct-control", variant="direct-uid1000-unprofiled-a")
        self.assertEqual(active.failure_context(values, "direct-control")["phase"], "direct-control")
        for key, value in (
            ("image", "docker-29-conformance-rootless"),
            ("architecture", "arm64"),
            ("image", []),
            ("job", []),
        ):
            wrong = dict(values)
            wrong[key] = value
            with self.subTest(key=key, value=value):
                self.assertIsNone(active.failure_context(wrong, "direct-control"))
