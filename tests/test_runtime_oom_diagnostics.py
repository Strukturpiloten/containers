"""Tiny offline fixtures for scoped OOM evidence, never native admission."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
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
        for record in ctx.observations:
            self.assertEqual(record["availability"], "backend-not-applicable")
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


if __name__ == "__main__":
    unittest.main()
