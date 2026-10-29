"""Tiny offline fixtures for scoped OOM evidence, never native admission."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import runtime_oom_diagnostics as diagnostics
from scripts import runtime_tests
from scripts.evidence_gate import EvidenceError, _runtime_skips
from scripts.runtime_docker_systemd import (
    INNER_PIDS,
    MEMORY_BYTES,
    _assert_orderly_state,
    _hierarchy_evidence,
    _inner_enforcement_state,
    verify_inner_limits,
)
from scripts.runtime_errors import ProbeError
from tests.test_docker_systemd_boundary import (
    allocator_telemetry_fixture,
    hierarchy_fixture,
    memory_association_fixture,
)

CONTAINER = "a" * 64
OUTER = "/machine.slice/libpod-" + CONTAINER + ".scope"
ROOT = OUTER + "/container"
SCOPE = "/user.slice/docker-" + "b" * 64 + ".scope"
EVENTS = {"max": 0, "oom": 0, "oom_kill": 0}


def _group(path: str, inode: int) -> dict:
    return {
        "path": path,
        "inode": inode,
        "availability": "observed",
        "values": {"memory.events": dict(EVENTS), "memory.events.local": dict(EVENTS)},
        "missingFiles": [],
    }


def _snapshot() -> dict:
    return {
        "guestRoot": {"inode": 20, "hostPath": ROOT},
        "guestChain": [_group(SCOPE, 40), _group("/user.slice", 30), _group("/", 20)],
        "hostOuterChain": [_group(ROOT, 20), _group(OUTER, 10)],
    }


def _context() -> MagicMock:
    ctx = MagicMock()
    ctx.containers = [CONTAINER]
    ctx.timeout = 45
    ctx.checks = []
    ctx.observations = []
    ctx._sudo = ["sudo", "-n"]
    ctx.podman.return_value = json.dumps({"Running": True, "OOMKilled": False})
    return ctx


class OomDiagnosticTests(unittest.TestCase):
    def test_docker_retains_state_but_never_fabricates_conmon_custody(self) -> None:
        ctx = _context()
        ctx.outer_engine = "docker"
        state = {"Running": True, "Pid": 123, "OOMKilled": False}
        ctx.podman.return_value = json.dumps(state)
        observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
        observer.snapshot("before-inner-memory", scope=SCOPE, scope_inode=40)
        observer.snapshot("after-inner-memory")
        observer.after_exit(CONTAINER, {"Running": False, "Pid": 0, "OOMKilled": True, "ExitCode": 0})
        ctx.command.assert_not_called()
        self.assertIsNone(observer.custody)
        self.assertEqual(len(ctx.observations), 3)
        self.assertTrue(ctx.observations[-1]["ociState"]["OOMKilled"])
        self.assertEqual([record["availability"] for record in ctx.observations], ["error", "error", "not-sampled"])
        for record in ctx.observations:
            self.assertEqual(record["attribution"], "unresolved")
            self.assertEqual(record["sources"]["conmonMarkers"], "not-applicable")

    def test_counter_fixture_preserves_local_and_hierarchical_fields_and_missing_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / "owned"
            group.mkdir()
            for name in diagnostics.MEMORY_FILES:
                if name != "memory.peak":
                    value = "max" if name.endswith(".max") else "0"
                    if name.startswith("memory.events"):
                        value = "max 2\noom 1\noom_kill 1" if name.endswith(".local") else "max 4\noom 3\noom_kill 2"
                    (group / name).write_text(value)
            observed = diagnostics._memory_group(root, "/owned")
            self.assertEqual(observed["missingFiles"], ["memory.peak"])
            self.assertEqual(observed["values"]["memory.events.local"], {"max": 2, "oom": 1, "oom_kill": 1})
            self.assertEqual(observed["values"]["memory.events"]["oom_kill"], 2)
            self.assertEqual(diagnostics._memory_group(root, "/gone")["availability"], "missing")
            for invalid in ("max 0\noom -1\noom_kill 0", "max 0\noom 0\noom_kill 0\noom 1", "max 0\noom 0"):
                (group / "memory.events").write_text(invalid)
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    diagnostics._memory_group(root, "/owned")

    def test_paths_counts_and_bytes_are_closed(self) -> None:
        for path in ("/../escape", "/a/./b", "relative", "/a//b", "/a;command"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                diagnostics._group_path(path)
        with self.assertRaisesRegex(ValueError, "count bound"):
            diagnostics._chain("/" + "/".join(["a"] * diagnostics.MAX_GROUPS))
        with self.assertRaisesRegex(ValueError, "escaped"):
            diagnostics._chain("/unrelated", stop=OUTER)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded"
            path.write_text("x" * (diagnostics.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "byte bound"):
                diagnostics._text(path)

    def test_host_collector_binds_parent_and_subgroup_separately_without_host_ancestor_walk(self) -> None:
        init = {"cgroup": "0::" + ROOT + "/init.scope", "starttime": "100", "exe": "/usr/lib/systemd/systemd"}
        monitor = {"cgroup": "0::/monitor", "starttime": "99", "exe": "/usr/bin/conmon"}
        inodes = {
            "/proc/100/root/sys/fs/cgroup": 20,
            "/sys/fs/cgroup" + ROOT + "/init.scope": 21,
            "/sys/fs/cgroup" + ROOT: 20,
            "/sys/fs/cgroup" + OUTER: 10,
        }
        request = {
            "container": CONTAINER,
            "state": {"Running": True, "Pid": 100, "ConmonPid": 99, "CgroupPath": OUTER},
            "scope": SCOPE,
            "directory": str(Path(tempfile.gettempdir()) / "fixture-owned-store"),
        }
        with (
            patch.object(diagnostics, "_process", side_effect=[init, monitor, init, monitor]),
            patch.object(diagnostics, "_text", return_value="conmon\0-c\0" + CONTAINER + "\0"),
            patch.object(
                diagnostics,
                "_monitor",
                return_value={
                    **monitor,
                    "pid": 99,
                    "actualVersion": None,
                    "versionAttribution": "unresolved fixture",
                    "watchedCgroupPath": None,
                },
            ),
            patch.object(diagnostics, "_mount", return_value="fixture cgroup2 rw,memory_localevents"),
            patch.object(
                Path, "stat", autospec=True, side_effect=lambda path: SimpleNamespace(st_ino=inodes[str(path)])
            ),
            patch.object(diagnostics, "_memory_group", side_effect=lambda _root, path: _group(path, 1)) as read_group,
            patch("subprocess.run") as execute,
        ):
            result = diagnostics._collect(request)
        self.assertEqual(result["guestRoot"], {"inode": 20, "hostPath": ROOT})
        self.assertEqual([group["path"] for group in result["hostOuterChain"]], [ROOT, OUTER])
        self.assertIn("memory_localevents", result["hostCgroup2Mount"])
        self.assertEqual(result["conmon"]["exe"], "/usr/bin/conmon")
        self.assertIsNone(result["conmon"]["actualVersion"])
        self.assertIn("unresolved", result["conmon"]["versionAttribution"])
        self.assertIsNone(result["conmon"]["watchedCgroupPath"])
        execute.assert_not_called()
        self.assertTrue(
            all(
                str(item.args[0]) in {"/sys/fs/cgroup", "/proc/100/root/sys/fs/cgroup"}
                for item in read_group.call_args_list
            )
        )

    def test_mount_options_are_preserved_and_ambiguous_mounts_are_unresolved(self) -> None:
        row = "29 22 0:27 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw,memory_localevents"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mountinfo"
            path.write_text(row + "\n")
            self.assertEqual(diagnostics._mount(path), row)
            path.write_text(row + "\n" + row + "\n")
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                diagnostics._mount(path)

    def test_invalid_outer_identity_prevents_host_reads(self) -> None:
        with patch.object(diagnostics, "_process") as process:
            for outer in ("/machine.slice/unrelated.scope", OUTER + "/../other", "/"):
                request = {"container": CONTAINER, "state": {"CgroupPath": outer}, "scope": SCOPE}
                with self.subTest(outer=outer), self.assertRaises(ValueError):
                    diagnostics._collect(request)
            process.assert_not_called()

    def test_snapshot_deltas_preserve_missing_leaf_and_never_attribute_oom(self) -> None:
        ctx = _context()
        before = _snapshot()
        after = copy.deepcopy(before)
        after["guestChain"][0] = {"path": SCOPE, "availability": "missing"}
        after["guestChain"][-1]["values"]["memory.events"]["oom_kill"] = 1
        ctx.command.side_effect = [json.dumps(before), json.dumps(after)]
        observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
        observer.snapshot("before-inner-memory", scope=SCOPE, scope_inode=40)
        observer.snapshot("after-inner-memory")
        delta = ctx.observations[-1]["baselineDelta"]["guestChain"]
        self.assertEqual(delta[0]["availability"], "unresolved")
        self.assertEqual(delta[-1]["events"]["memory.events"]["oom_kill"], 1)
        self.assertEqual(delta[-1]["events"]["memory.events.local"]["oom_kill"], 0)
        self.assertTrue(all(item["attribution"] == "unresolved" for item in ctx.observations))
        self.assertIn("separate bounded custody observer", ctx.observations[-1]["limits"])
        self.assertEqual(ctx.checks, [])
        command = ctx.command.call_args.args[1]
        self.assertIn("-I", command)
        self.assertEqual(json.loads(command[-1])["scope"], SCOPE)

    def test_changed_identities_counter_regression_and_command_errors_remain_unresolved(self) -> None:
        for failure in ("inode", "root", "regression", "command"):
            with self.subTest(failure=failure):
                ctx = _context()
                baseline, changed = _snapshot(), _snapshot()
                if failure == "inode":
                    changed["guestChain"][0]["inode"] += 1
                elif failure == "root":
                    changed["guestRoot"]["inode"] += 1
                elif failure == "regression":
                    baseline["guestChain"][0]["values"]["memory.events"]["oom"] = 1
                ctx.command.side_effect = [
                    json.dumps(baseline),
                    RuntimeError("fixture failure") if failure == "command" else json.dumps(changed),
                ]
                observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
                observer.snapshot("before-inner-memory", scope=SCOPE, scope_inode=40)
                observer.snapshot("before-shutdown")
                self.assertEqual(ctx.observations[-1]["availability"], "error")
                self.assertEqual(ctx.observations[-1]["attribution"], "unresolved")
                self.assertNotIn("status", ctx.observations[-1])
                self.assertIn("reason", ctx.observations[-1])
                self.assertEqual(ctx.checks, [])

    def test_shared_snapshot_deadline_and_invalid_container_do_not_expand_scope(self) -> None:
        ctx = _context()
        ctx.command.return_value = json.dumps(_snapshot())
        with patch.object(diagnostics.time, "monotonic", side_effect=[0, 2, 4]):
            diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-inner-memory", scope=SCOPE, scope_inode=40)
        self.assertEqual(ctx.podman.call_args.kwargs["timeout"], 8)
        self.assertEqual(ctx.command.call_args.kwargs["timeout"], 6)
        ctx.reset_mock()
        diagnostics.OomDiagnostics(ctx, "unrelated").snapshot("before-shutdown")
        ctx.podman.assert_not_called()
        ctx.command.assert_not_called()

    def test_failed_inner_wait_still_snapshots_and_preserves_genuine_failure(self) -> None:
        ctx, observer = MagicMock(), MagicMock()
        failure = ProbeError("bounded inner wait failed")
        ctx.exec.side_effect = failure
        with self.assertRaisesRegex(ProbeError, "bounded inner wait failed"):
            _inner_enforcement_state(ctx, MagicMock(), CONTAINER, ("memory", "b" * 64), diagnostics=observer)
        observer.snapshot.assert_called_once_with("after-inner-memory")

    def test_failed_release_samples_before_owned_cleanup_and_preserves_failure(self) -> None:
        ctx, observer = MagicMock(unsafe=True), MagicMock()
        ctx.checks = [_hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")]
        timeline = []
        failure_message = "original allocator release failure"
        failure = ProbeError(failure_message)

        def execute(name: str, *_args: object) -> str:
            timeline.append(name)
            if name == "read exact inner memory cgroup limits":
                raise failure
            return {
                "start bounded inner memory probe": "a" * 64,
                "verify inner memory scope placement and ownership": hierarchy_fixture(kind="scope"),
                "read actual memory allocator swap and namespace association": memory_association_fixture(),
            }.get(name, "")

        ctx.exec.side_effect = execute
        observer.snapshot.side_effect = lambda phase, **_kwargs: timeline.append(phase)
        with self.assertRaisesRegex(ProbeError, "original allocator release failure"):
            verify_inner_limits(ctx, MagicMock(), CONTAINER, diagnostics=observer)
        self.assertLess(timeline.index("after-inner-memory"), timeline.index("remove owned inner memory probe"))
        self.assertNotIn("start bounded inner pids probe", timeline)
        observer.snapshot.assert_any_call("after-inner-memory")

    def test_real_context_optional_command_failures_persist_outside_unchanged_admission_checks(self) -> None:
        for failure in ("inspect", "collector", "unknown"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                store = Path(directory) / "store"
                store.mkdir()
                with patch("scripts.runtime_tests.tempfile.mkdtemp", return_value=str(store)):
                    ctx = runtime_tests.RuntimeContext(image="fixture", architecture="amd64", timeout=5, use_sudo=False)
                ctx.containers.append(CONTAINER)
                ctx.checks.append({"name": "genuine runtime fixture", "status": "passed"})
                ownership = list(ctx.containers), set(ctx.run_containers), dict(ctx.container_launchers)
                results = [subprocess.CompletedProcess([], 0, json.dumps({"Running": True}), "")]
                error = subprocess.CompletedProcess([], 125, "", "optional diagnostic unavailable")
                if failure == "inspect":
                    results = [error]
                else:
                    results.append(error if failure == "collector" else subprocess.CompletedProcess([], 0, "{}", ""))
                with patch("scripts.runtime_tests.subprocess.run", side_effect=results):
                    diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-shutdown")
                record = {"checks": ctx.checks, "observations": ctx.observations}
                _runtime_skips(record, nested_disabled=False, profile="docker")
                self.assertEqual(ctx.checks, [{"name": "genuine runtime fixture", "status": "passed"}])
                self.assertEqual(ownership, (ctx.containers, ctx.run_containers, ctx.container_launchers))
                observation = ctx.observations[-1]
                self.assertEqual(observation["availability"], "error")
                self.assertEqual(observation["attribution"], "unresolved")
                self.assertNotIn("status", observation)
                self.assertEqual(len(observation["commands"]), len(results))
                if failure != "unknown":
                    self.assertEqual(observation["commands"][-1]["status"], "failed")
                    self.assertEqual(observation["commands"][-1]["exitCode"], 125)
                    self.assertEqual(observation["commands"][-1]["stderr"], "optional diagnostic unavailable")
                self._assert_observations_persist(ctx, Path(directory) / "evidence.json")
                with (
                    patch("scripts.runtime_tests.subprocess.run", return_value=error),
                    self.assertRaises(ProbeError),
                ):
                    ctx.command("actual runtime enforcement failed", ["fixed-fixture"])
                with self.assertRaisesRegex(EvidenceError, "failed or invalid check"):
                    _runtime_skips(record, nested_disabled=False, profile="docker")

    def _assert_observations_persist(self, ctx: runtime_tests.RuntimeContext, evidence_path: Path) -> None:
        args = SimpleNamespace(
            metadata=str(
                Path(runtime_tests.__file__).resolve().parents[1] / "images/docker/docker-29-rootless/container.yaml"
            ),
            archive=str(evidence_path.parent / "fixture.tar"),
            arch="amd64",
            evidence=str(evidence_path),
            sudo=False,
            no_sudo=True,
            timeout=5,
            allow_privileged=False,
            skip_nested=False,
        )
        with (
            patch("scripts.runtime_tests.RuntimeContext", return_value=ctx),
            patch.object(ctx, "load_archive", return_value={}),
            patch.object(ctx, "bind_guest_profile"),
            patch.object(ctx, "prepare", return_value={"engine": "podman", "clientVersion": "podman version fixture"}),
            patch.object(ctx, "cleanup"),
            patch("scripts.runtime_tests._docker"),
            patch(
                "scripts.runtime_tests.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "fixture", "")
            ),
        ):
            evidence = runtime_tests.run(args)
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(json.loads(evidence_path.read_text())["observations"], ctx.observations)
        _runtime_skips(evidence, nested_disabled=False, profile="docker")

    def test_unavailable_observation_does_not_excuse_actual_outer_oom(self) -> None:
        ctx = runtime_tests.RuntimeContext.__new__(runtime_tests.RuntimeContext)
        ctx.checks = []
        ctx.observations = [{"availability": "unavailable", "attribution": "unresolved"}]
        state = {
            "Running": False,
            "Status": "exited",
            "ExitCode": 0,
            "OOMKilled": True,
            "Error": "",
            "Pid": 0,
            "Paused": False,
            "Restarting": False,
            "Dead": False,
        }
        with self.assertRaisesRegex(ProbeError, "without OOM"):
            _assert_orderly_state(ctx, state)
        with self.assertRaisesRegex(EvidenceError, "failed or invalid check"):
            _runtime_skips(
                {"checks": ctx.checks, "observations": ctx.observations}, nested_disabled=False, profile="docker"
            )

    def test_snapshot_hooks_bracket_release_wait_and_inspect_without_changing_enforcement(self) -> None:
        ctx, observer = MagicMock(unsafe=True), MagicMock()
        ctx.checks = [_hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")]
        timeline = []

        def execute(name: str, *_args: object) -> str:
            timeline.append(name)
            if name.startswith("start bounded inner"):
                return "a" * 64
            if name.startswith("wait bounded inner"):
                return "137" if "memory" in name else "0"
            if name.startswith("inspect inner"):
                return json.dumps({"OOMKilled": True})
            return {
                "verify inner memory scope placement and ownership": hierarchy_fixture(kind="scope"),
                "verify inner pids scope placement and ownership": hierarchy_fixture(kind="scope"),
                "read exact inner memory cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                "read exact inner pids cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                "read bounded inner PID refusal": "bounded-pid-refusal events-before=0 events-after=1",
                "read actual memory allocator swap and namespace association": memory_association_fixture(),
                "read actual memory allocator self telemetry": allocator_telemetry_fixture(after=False),
            }.get(name, "")

        ctx.exec.side_effect = execute
        observer.snapshot.side_effect = lambda phase, **_kwargs: timeline.append(phase)
        with patch("scripts.runtime_docker_systemd.verify_outer_container_limits"):
            verify_inner_limits(ctx, MagicMock(), CONTAINER, diagnostics=observer)
        self.assertLess(timeline.index("before-inner-memory"), timeline.index("read exact inner memory cgroup limits"))
        self.assertEqual(timeline[timeline.index("inspect inner memory enforcement state") + 1], "after-inner-memory")
        self.assertEqual(observer.snapshot.call_count, 2)
        observer.snapshot.assert_any_call(
            "before-inner-memory", scope="/system.slice/docker-" + "a" * 64 + ".scope", scope_inode=12
        )


class DockerOuterObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.proc = self.directory / "proc"
        self.cgroups = self.directory / "cgroup"
        self.proc.mkdir()
        self.cgroups.mkdir()
        self.slice_name = "strukturpiloten" + "c" * 32 + ".slice"
        self.owned_slice = self.cgroups / self.slice_name
        self.owned_slice.mkdir()
        self.scope = self.owned_slice / ("docker-" + CONTAINER + ".scope")
        self.scope.mkdir()
        (self.scope / "init.scope").mkdir()
        self.pid = 1234567
        self.process = self.proc / str(self.pid)
        self.process.mkdir()
        self.birth = str(123456789)
        self._stat(self.birth)
        self.membership = "/" + self.slice_name + "/docker-" + CONTAINER + ".scope/init.scope"
        (self.process / "cgroup").write_text("0::" + self.membership + "\n")
        collector = self.proc / str(os.getpid())
        collector.mkdir()
        info = self.cgroups.stat()
        self.mount = (
            f"29 22 {os.major(info.st_dev)}:{os.minor(info.st_dev)} / /sys/fs/cgroup rw,nosuid "
            "- cgroup2 cgroup rw,memory_localevents"
        )
        (collector / "mountinfo").write_text(self.mount + "\n")
        self.started = "2026-10-29T01:23:45.123456789Z"
        self.request = {
            "container": CONTAINER,
            "startedAt": self.started,
            "pid": self.pid,
            "sliceName": self.slice_name,
            "slicePath": "/" + self.slice_name,
            "sliceIdentity": f"{self.owned_slice.stat().st_dev}:{self.owned_slice.stat().st_ino}",
            "deadline": time.monotonic() + 5,
        }
        self._counters()
        original = diagnostics._DockerOuterRead.directory

        def directory(reader: diagnostics._DockerOuterRead, path: str, *, parent: int | None = None) -> int:
            mapped = {"/proc": str(self.proc), "/sys/fs/cgroup": str(self.cgroups)}.get(path, path)
            return original(reader, mapped, parent=parent)

        self.patch_directory = patch.object(diagnostics._DockerOuterRead, "directory", new=directory)
        self.patch_directory.start()
        self.addCleanup(self.patch_directory.stop)
        filesystem = patch.object(diagnostics, "_docker_filesystem")
        filesystem.start()
        self.addCleanup(filesystem.stop)

    def _stat(self, birth: str) -> None:
        fields = ["S", *(["0"] * 18), birth]
        (self.process / "stat").write_text(f"{self.pid} (systemd) " + " ".join(fields))

    def _counters(self, hierarchical: int = 0, local: int = 0) -> None:
        for name, value in zip(diagnostics.DOCKER_EVENT_FILES, (hierarchical, local), strict=True):
            (self.scope / name).write_text(
                f"low 0\nhigh 0\nmax {value}\noom {value}\noom_kill {value}\noom_group_kill 0\n"
            )

    def _sample(self) -> dict:
        return diagnostics._collect_docker_outer(self.request)

    def _bound_sample(self) -> dict:
        sample = self._sample()
        sample["bindingChecks"].update({"ownedContainer": True, "containerIncarnation": True})
        return sample

    def _context(self, sample: dict | None = None) -> MagicMock:
        ctx = _context()
        ctx.outer_engine = "docker"
        ctx.runtime_deadline = None
        ctx.backend = SimpleNamespace(
            slice=self.slice_name,
            slice_identity=self.request["sliceIdentity"],
            command_timeout=lambda seconds: seconds,
            privileged=lambda arguments, _seconds: ["private-watchdog", *arguments],
            check_deadline=MagicMock(),
        )
        inspect = json.dumps(
            {
                "id": CONTAINER,
                "parent": self.slice_name,
                "state": {
                    "Running": True,
                    "Pid": self.pid,
                    "StartedAt": self.started,
                    "OOMKilled": True,
                    "ExitCode": 0,
                    "Error": "PRIVATE-STATE-OPERAND",
                    "CgroupPath": self.membership,
                },
            }
        )
        ctx.podman.return_value = inspect
        slice_state = "\n".join(
            (
                "Id=" + self.slice_name,
                "Names=" + self.slice_name,
                "LoadState=loaded",
                "ActiveState=active",
                "ControlGroup=/" + self.slice_name,
            )
        )
        ctx.command.side_effect = [
            slice_state,
            json.dumps(sample if sample is not None else self._sample()),
            slice_state,
        ]
        return ctx

    def test_seven_field_kernel_records_preserve_optional_sock_counter_and_legacy_absence(self) -> None:
        legacy = self._bound_sample()
        self.assertEqual(
            legacy["counters"]["memory.events"]["values"],
            {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0, "oom_group_kill": 0},
        )
        zero = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n"
        (self.scope / "memory.events").write_text(zero)
        (self.scope / "memory.events.local").write_text(zero)
        baseline = self._bound_sample()
        unequal = diagnostics._docker_deltas(legacy, baseline)
        self.assertEqual(unequal["memory.events"], {"availability": "changed"})
        self.assertEqual(unequal["memory.events.local"], {"availability": "changed"})
        (self.scope / "memory.events").write_text(
            "low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\nsock_throttled 7\n"
        )
        after = self._bound_sample()
        self.assertEqual(after["availability"], "observed")
        self.assertEqual(diagnostics._docker_validate_record(after), after)
        delta = diagnostics._docker_deltas(baseline, after)
        self.assertEqual(
            delta["memory.events"],
            {
                "availability": "observed",
                "values": {
                    "low": 1,
                    "high": 2,
                    "max": 3,
                    "oom": 4,
                    "oom_kill": 5,
                    "oom_group_kill": 6,
                    "sock_throttled": 7,
                },
            },
        )
        self.assertEqual(
            delta["memory.events.local"],
            {
                "availability": "observed",
                "values": {
                    "low": 0,
                    "high": 0,
                    "max": 0,
                    "oom": 0,
                    "oom_kill": 0,
                    "oom_group_kill": 0,
                    "sock_throttled": 0,
                },
            },
        )
        for raw in (
            zero + "unknown_counter 0\n",
            zero.replace("sock_throttled 0", "sock_throttled 18446744073709551616"),
        ):
            with self.subTest(raw=raw):
                (self.scope / "memory.events").write_text(raw)
                self.assertEqual(self._sample()["counters"]["memory.events"], {"availability": "malformed"})
        self.assertNotIn("sock_throttled", legacy["counters"]["memory.events"]["values"])

    def test_nonmemory_hooks_are_oci_only_with_no_host_reader_or_new_allowance(self) -> None:
        state = {
            "Running": False,
            "OOMKilled": True,
            "ExitCode": 0,
            "Pid": 0,
            "CgroupPath": "/PRIVATE/host/path",
            "Error": "PRIVATE-ERROR",
            "StartedAt": "PRIVATE-START",
        }
        for phase in (
            "before-ordinary-work",
            "before-shutdown",
            "before-inner-memory-extra",
            "after-inner-memory-extra",
            "after-exit",
            "unknown",
        ):
            with self.subTest(phase=phase):
                ctx = self._context()
                ctx.podman.return_value = json.dumps(state)
                ctx.backend.command_timeout = MagicMock(side_effect=AssertionError("new host allowance"))
                ctx.backend.privileged = MagicMock(side_effect=AssertionError("host command"))
                observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
                with patch.object(diagnostics.time, "monotonic", side_effect=AssertionError("new deadline")):
                    observer.snapshot(phase)
                    observer.before_stop()
                record = ctx.observations[-1]
                self.assertEqual(record["availability"], "not-sampled")
                self.assertEqual(record["ociState"], {"Running": False, "OOMKilled": True, "ExitCode": 0})
                self.assertFalse(any(record["bindingChecks"].values()))
                ctx.command.assert_not_called()
                ctx.backend.command_timeout.assert_not_called()
                ctx.backend.privileged.assert_not_called()
                self.assertEqual(ctx.podman.call_count, 1)
                self.assertEqual(ctx.podman.call_args.args[1:], ("inspect", "--format", "{{json .State}}", CONTAINER))
                self.assertNotIn("PRIVATE", json.dumps(record))
                self.assertEqual(ctx.checks, [])

    def test_after_exit_preserves_stopped_finite_oci_without_any_actor(self) -> None:
        ctx = self._context()
        observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
        observer.after_exit(
            CONTAINER,
            {
                "Running": False,
                "OOMKilled": True,
                "ExitCode": 0,
                "Pid": 0,
                "Error": "PRIVATE-ERROR",
                "CgroupPath": "/PRIVATE/path",
            },
        )
        record = ctx.observations[-1]
        self.assertEqual(record["availability"], "not-sampled")
        self.assertEqual(record["ociState"], {"Running": False, "OOMKilled": True, "ExitCode": 0})
        ctx.podman.assert_not_called()
        ctx.command.assert_not_called()
        self.assertNotIn("PRIVATE", json.dumps(record))

    def test_stopped_memory_hooks_retain_oci_and_skip_live_counter_binding(self) -> None:
        for phase in ("before-inner-memory", "after-inner-memory"):
            with self.subTest(phase=phase):
                ctx = self._context()
                value = json.loads(ctx.podman.return_value)
                value["state"].update({"Running": False, "Pid": 0})
                ctx.podman.return_value = json.dumps(value)
                diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot(phase)
                record = ctx.observations[-1]
                self.assertEqual(record["availability"], "unavailable")
                self.assertEqual(record["ociState"], {"Running": False, "OOMKilled": True, "ExitCode": 0})
                ctx.command.assert_not_called()
                self.assertNotIn("baselineDelta", record)
                self.assertNotIn("PRIVATE-STATE-OPERAND", json.dumps(record))

    def test_live_finite_oci_survives_unavailable_or_malformed_host_binding(self) -> None:
        for availability in ("missing", "unsupported", "malformed", "changed", "timeout", "error"):
            with self.subTest(availability=availability):
                sample = diagnostics._docker_record()
                sample["availability"] = availability
                ctx = self._context(sample)
                diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("after-inner-memory")
                self.assertEqual(ctx.observations[-1]["availability"], availability)
                self.assertEqual(ctx.observations[-1]["ociState"], {"Running": True, "OOMKilled": True, "ExitCode": 0})
        ctx = self._context()
        value = json.loads(ctx.podman.return_value)
        value["state"]["Pid"] = "PRIVATE-invalid-pid"
        ctx.podman.return_value = json.dumps(value)
        diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-inner-memory")
        self.assertEqual(ctx.observations[-1]["availability"], "malformed")
        self.assertEqual(ctx.observations[-1]["ociState"], {"Running": True, "OOMKilled": True, "ExitCode": 0})
        ctx.command.assert_not_called()

    def test_oci_projection_refuses_invalid_public_types_without_restoring_private_fields(self) -> None:
        for field, invalid in (
            ("Running", "false"),
            ("OOMKilled", 1),
            ("ExitCode", False),
            ("ExitCode", -1),
            ("ExitCode", 256),
            ("ExitCode", "0"),
        ):
            with self.subTest(field=field, invalid=invalid):
                ctx = self._context()
                state = {
                    "Running": False,
                    "OOMKilled": True,
                    "ExitCode": 0,
                    "Pid": "PRIVATE-PID",
                    "Error": "PRIVATE-ERROR",
                    "CgroupPath": "/PRIVATE/path",
                    field: invalid,
                }
                ctx.podman.return_value = json.dumps(state)
                observer = diagnostics.OomDiagnostics(ctx, CONTAINER)
                observer.snapshot("before-shutdown")
                observer.after_exit(CONTAINER, state)
                for record in ctx.observations:
                    self.assertEqual(record["availability"], "malformed")
                    self.assertNotIn(field, record.get("ociState", {}))
                    self.assertNotIn("PRIVATE", json.dumps(record))
                ctx.command.assert_not_called()

    def test_oci_only_inspect_failures_and_null_are_closed_without_source_check_mutation(self) -> None:
        for outcome, availability in (
            ("null", "unavailable"),
            ("PRIVATE-STDOUT", "error"),
            (RuntimeError("PRIVATE-OPERAND"), "error"),
        ):
            with self.subTest(availability=availability):
                ctx = self._context()
                ctx.podman.side_effect = [outcome]
                ctx.checks.append({"name": "genuine check", "status": "passed"})
                diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-shutdown")
                self.assertEqual(ctx.observations[-1]["availability"], availability)
                self.assertNotIn("PRIVATE", json.dumps(ctx.observations[-1]))
                self.assertEqual(ctx.checks, [{"name": "genuine check", "status": "passed"}])
                ctx.command.assert_not_called()

    def test_host_reads_exact_outer_not_guest_scope_and_returns_only_closed_values(self) -> None:
        self._counters(3, 0)
        record = self._sample()
        self.assertEqual(record["availability"], "observed")
        self.assertEqual(record["counters"]["memory.events"]["values"]["oom_kill"], 3)
        self.assertEqual(record["counters"]["memory.events.local"]["values"]["oom_kill"], 0)
        self.assertEqual(record["mountSemantics"], {"root": "full-hierarchy", "memoryLocalevents": True})
        self.assertTrue(record["bindingChecks"]["stableRead"])
        self.assertFalse(record["bindingChecks"]["ownedContainer"])
        self.assertFalse(record["bindingChecks"]["containerIncarnation"])
        self.assertEqual(diagnostics._docker_validate_record(record), record)
        for private in (CONTAINER, self.started, self.birth, str(self.pid), self.membership, str(self.directory)):
            self.assertNotIn(private, json.dumps(record))

    def test_hierarchical_positive_local_zero_still_refuses_actual_outer_oom(self) -> None:
        before = self._bound_sample()
        self._counters(1, 0)
        after = self._bound_sample()
        delta = diagnostics._docker_deltas(before, after)
        self.assertEqual(delta["memory.events"]["values"]["oom_kill"], 1)
        self.assertEqual(delta["memory.events.local"]["values"]["oom_kill"], 0)
        ctx = self._context()
        diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("after-inner-memory")
        state = {
            "Running": False,
            "Status": "exited",
            "ExitCode": 0,
            "OOMKilled": True,
            "Error": "",
            "Pid": 0,
            "Paused": False,
            "Restarting": False,
            "Dead": False,
        }
        with self.assertRaisesRegex(ProbeError, "without OOM"):
            _assert_orderly_state(ctx, state)
        with self.assertRaisesRegex(EvidenceError, "failed or invalid check"):
            _runtime_skips(
                {"checks": ctx.checks, "observations": ctx.observations}, nested_disabled=False, profile="docker"
            )

    def test_zero_is_observed_and_missing_null_malformed_oversized_are_distinct(self) -> None:
        self.assertEqual(self._sample()["counters"]["memory.events"]["values"]["oom_kill"], 0)
        path = self.scope / "memory.events"
        for raw, status in (
            ("null", "malformed"),
            ("", "malformed"),
            ("oom -1", "malformed"),
            ("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom 1", "malformed"),
            ("low 0\nhigh 0\nmax 0\noom 0\noom_kill 18446744073709551616", "malformed"),
            ("x" * (diagnostics.MAX_FILE_BYTES + 1), "oversized"),
        ):
            with self.subTest(status=status, length=len(raw)):
                path.write_text(raw)
                counter = self._sample()["counters"]["memory.events"]
                self.assertEqual(counter, {"availability": status})
        path.unlink()
        self.assertEqual(self._sample()["counters"]["memory.events"], {"availability": "missing"})
        self.assertEqual(self._sample()["counters"]["memory.events.local"]["values"]["oom_kill"], 0)

    def test_process_birth_change_discards_comparability(self) -> None:
        original = diagnostics._DockerOuterRead.events

        def events(reader: diagnostics._DockerOuterRead, scope: int) -> dict:
            result = original(reader, scope)
            self._stat("987654321")
            return result

        with patch.object(diagnostics._DockerOuterRead, "events", new=events):
            record = self._sample()
        self.assertEqual(record["availability"], "changed")
        self.assertFalse(record["bindingChecks"]["stableRead"])
        self.assertEqual(record["bindings"], {})

    def test_pid_directory_replacement_is_detected_even_when_birth_and_membership_match(self) -> None:
        original = diagnostics._DockerOuterRead.events

        def events(reader: diagnostics._DockerOuterRead, scope: int) -> dict:
            result = original(reader, scope)
            self.process.rename(self.proc / "retired")
            self.process.mkdir()
            self._stat(self.birth)
            (self.process / "cgroup").write_text("0::" + self.membership)
            return result

        with patch.object(diagnostics._DockerOuterRead, "events", new=events):
            self.assertEqual(self._sample()["availability"], "changed")

    def test_outer_cgroup_replacement_is_detected_even_with_held_original_fd(self) -> None:
        original = diagnostics._DockerOuterRead.events

        def events(reader: diagnostics._DockerOuterRead, scope: int) -> dict:
            result = original(reader, scope)
            self.scope.rename(self.owned_slice / "retired")
            self.scope.mkdir()
            (self.scope / "init.scope").mkdir()
            return result

        with patch.object(diagnostics._DockerOuterRead, "events", new=events):
            self.assertEqual(self._sample()["availability"], "changed")

    def test_process_membership_change_during_read_is_changed_and_never_comparable(self) -> None:
        original = diagnostics._DockerOuterRead.events

        def events(reader: diagnostics._DockerOuterRead, scope: int) -> dict:
            result = original(reader, scope)
            (self.process / "cgroup").write_text("0::/unrelated")
            return result

        with patch.object(diagnostics._DockerOuterRead, "events", new=events):
            record = self._sample()
        self.assertEqual(record["availability"], "changed")
        self.assertFalse(record["bindingChecks"]["stableRead"])
        self.assertEqual(record["bindings"], {})

    def test_pid_in_exact_scope_and_counter_symlink_are_handled_without_following(self) -> None:
        (self.process / "cgroup").write_text("0::" + self.membership.removesuffix("/init.scope"))
        self.assertEqual(self._sample()["availability"], "observed")
        path = self.scope / "memory.events"
        path.unlink()
        path.symlink_to(self.process / "stat")
        record = self._sample()
        self.assertEqual(record["availability"], "error")
        self.assertEqual(record["counters"]["memory.events"], {"availability": "unavailable"})
        self.assertNotIn(str(path), json.dumps(record))

    def test_membership_changes_and_foreign_or_guest_layouts_are_not_followed(self) -> None:
        for group in (SCOPE, self.membership + "/unexpected", "/unrelated"):
            with self.subTest(group=group):
                (self.process / "cgroup").write_text("0::" + group)
                self.assertEqual(self._sample()["availability"], "unsupported")

    def test_mount_root_aliases_nested_mounts_and_changed_slice_are_finite_unavailable(self) -> None:
        mountinfo = self.proc / str(os.getpid()) / "mountinfo"
        for mount in (
            self.mount.replace(" / /sys/", " /private /sys/"),
            self.mount + "\n" + self.mount,
            self.mount + "\n" + self.mount.replace(" /sys/fs/cgroup ", " /sys/fs/cgroup/nested "),
        ):
            with self.subTest(mount=mount):
                mountinfo.write_text(mount)
                self.assertEqual(self._sample()["availability"], "unsupported")
        mountinfo.write_text(self.mount)
        self.request["sliceIdentity"] = "0:1"
        self.assertEqual(self._sample()["availability"], "changed")

    def test_hierarchical_systemd_slice_control_group_is_resolved_without_flat_guess(self) -> None:
        parent = self.cgroups / "owned.slice"
        parent.mkdir()
        self.owned_slice.rename(parent / "owned-task.slice")
        self.owned_slice = parent / "owned-task.slice"
        self.scope = self.owned_slice / ("docker-" + CONTAINER + ".scope")
        self.request.update({"sliceName": "owned-task.slice", "slicePath": "/owned.slice/owned-task.slice"})
        self.membership = "/owned.slice/owned-task.slice/docker-" + CONTAINER + ".scope/init.scope"
        (self.process / "cgroup").write_text("0::" + self.membership)
        self.assertEqual(self._sample()["availability"], "observed")
        self.request["slicePath"] = "/owned-task.slice"
        self.assertEqual(self._sample()["availability"], "unsupported")

    def test_deltas_require_stable_incarnation_fields_nonregression_and_actual_pairs(self) -> None:
        self._counters(2, 1)
        before = self._bound_sample()
        after = self._bound_sample()
        self.assertEqual(diagnostics._docker_deltas(before, after)["memory.events"]["values"]["oom_kill"], 0)
        after["counters"]["memory.events"]["values"]["oom_kill"] = 1
        self.assertEqual(diagnostics._docker_deltas(before, after)["memory.events"], {"availability": "regressed"})
        after["counters"]["memory.events"] = {"availability": "missing"}
        self.assertEqual(diagnostics._docker_deltas(before, after)["memory.events"], {"availability": "unavailable"})
        after["bindings"]["hostProcess"] = "f" * 64
        self.assertEqual(diagnostics._docker_deltas(before, after)["memory.events.local"], {"availability": "changed"})
        after["availability"] = "changed"
        self.assertEqual(
            diagnostics._docker_deltas(before, after)["memory.events.local"], {"availability": "unavailable"}
        )

    def test_backend_uses_original_deadline_private_watchdog_and_sanitizes_all_operands(self) -> None:
        ctx = self._context()
        ctx.runtime_deadline = time.monotonic() + 0.5
        original_deadline = ctx.runtime_deadline
        diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-inner-memory", scope=SCOPE, scope_inode=999)
        record = ctx.observations[-1]
        self.assertEqual(record["availability"], "observed")
        self.assertTrue(all(record["bindingChecks"].values()))
        self.assertEqual(ctx.checks, [])
        self.assertEqual(record["ociState"], {"Running": True, "OOMKilled": True, "ExitCode": 0})
        for call in (*ctx.podman.call_args_list, *ctx.command.call_args_list):
            self.assertLessEqual(call.kwargs["timeout"], 0.5)
        command = ctx.command.call_args_list[1].args[1]
        self.assertEqual(command[:4], ["private-watchdog", sys.executable, "-I", "-B"])
        request = json.loads(command[-1])
        self.assertEqual(request["deadline"], original_deadline)
        self.assertNotIn("scope", request)
        self.assertNotIn(SCOPE, command[-1])
        for private in (CONTAINER, self.membership, self.started, "PRIVATE-STATE-OPERAND", "private-watchdog"):
            self.assertNotIn(private, json.dumps(record))

    def test_collector_stdout_exception_and_timeout_cannot_leak_or_change_source_checks(self) -> None:
        private_operand = "PRIVATE-OPERAND-/private/owned-path"
        for outcome, expected in (
            (private_operand, "error"),
            (json.dumps({"private": private_operand}), "malformed"),
            (RuntimeError(private_operand), "error"),
            (
                subprocess.TimeoutExpired([private_operand], 1, output=private_operand, stderr=private_operand),
                "timeout",
            ),
        ):
            with self.subTest(expected=expected, outcome=type(outcome).__name__):
                ctx = self._context()
                first = ctx.command.side_effect
                slice_state = next(first)
                ctx.command.side_effect = [slice_state, outcome]
                ctx.checks.append({"name": "genuine source check", "status": "failed"})
                diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("after-inner-memory")
                record = ctx.observations[-1]
                self.assertEqual(record["availability"], expected)
                self.assertNotIn(private_operand, json.dumps(record))
                self.assertNotIn("commands", record)
                self.assertEqual(ctx.checks, [{"name": "genuine source check", "status": "failed"}])

    def test_changed_docker_incarnation_and_null_state_cannot_create_deltas(self) -> None:
        for change in ({"Pid": self.pid + 1}, {"StartedAt": "changed"}, None):
            with self.subTest(change=change):
                ctx = self._context()
                first = ctx.podman.return_value
                value = json.loads(first)
                if change is None:
                    value["state"] = None
                else:
                    value["state"].update(change)
                ctx.podman.side_effect = [first, json.dumps(value)]
                diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("after-inner-memory")
                self.assertEqual(ctx.observations[-1]["availability"], "unavailable" if change is None else "changed")
                self.assertNotIn("baselineDelta", ctx.observations[-1])

    def test_expired_original_deadline_never_launches_collector(self) -> None:
        ctx = self._context()
        ctx.runtime_deadline = time.monotonic() - 1
        diagnostics.OomDiagnostics(ctx, CONTAINER).snapshot("before-inner-memory")
        self.assertEqual(ctx.observations[-1]["availability"], "timeout")
        ctx.command.assert_not_called()
        ctx.podman.assert_not_called()

    def test_public_schema_rejects_null_unknown_keys_bad_booleans_and_private_names(self) -> None:
        sample = self._sample()
        variants = [None, {**sample, "raw": "/private"}, {**sample, "counters": None}]
        for key, value in (
            ("bindingChecks", {**sample["bindingChecks"], "stableRead": 1}),
            (
                "counters",
                {**sample["counters"], "memory.events": {"availability": "observed", "values": {"private_value": 0}}},
            ),
        ):
            variants.append({**sample, key: value})
        for value in variants:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                diagnostics._docker_validate_record(value)


if __name__ == "__main__":
    unittest.main()
