"""Sequential systemd clean control with tiny archives and no native workloads."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import runtime_docker, runtime_tests
from scripts.evidence_gate import _runtime_skips
from scripts.runtime_errors import ProbeError
from scripts.runtime_resource_budgets import IsolatedStoreDiskBudget
from tests import test_oci_artifacts

ROOT = Path(__file__).resolve().parents[1]
REAL_CONTEXT = runtime_tests.RuntimeContext
REAL_RUN = subprocess.run
REAL_MKDTEMP = tempfile.mkdtemp
METADATA = ROOT / "images/docker/docker-29-conformance-rootless/container.yaml"


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.archive = root / "caller.tar"
        self.identity = test_oci_artifacts.ArchiveIdentityTests().fixture(self.archive)
        self.original = self.archive.read_bytes()
        self.contexts = []
        self.loads = []
        self.commands = []
        self.now = 1000.0
        self.failure: str | None = None
        self.on_cleanup = None
        self.on_work = None
        self.args = SimpleNamespace(
            metadata=str(METADATA),
            archive=str(self.archive),
            arch="amd64",
            evidence=str(root / "evidence.json"),
            sudo=False,
            no_sudo=True,
            timeout=45,
            allow_privileged=True,
            skip_nested=False,
            image_ref="local:fixture",
        )

    def directory(self, suffix: str | None = None, prefix: str | None = None, _dir: str | None = None) -> str:
        return REAL_MKDTEMP(suffix=suffix or "", prefix=prefix or "", dir=self.root)

    def context(self, **kwargs: object) -> runtime_tests.RuntimeContext:
        if self.contexts and self.contexts[-1].directory.exists():
            message = "a second store was constructed before the control store was removed"
            raise AssertionError(message)
        ctx = REAL_CONTEXT(**kwargs)
        self.contexts.append(ctx)
        return ctx

    def command(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append((args, kwargs))
        if args[0] == sys.executable:
            return REAL_RUN(args, **kwargs)
        if args[:2] == ["podman", "save"]:
            Path(args[args.index("--output") + 1]).write_bytes(self.original)
        output = self._podman_output(args)
        if "--volumes" in args:
            ctx = next(ctx for ctx in self.contexts if str(ctx.directory / "root") in args)
            if self.on_cleanup is not None:
                self.on_cleanup(ctx)
            if self.failure == "cleanup" and ctx.runtime_phase == "clean-control":
                return subprocess.CompletedProcess(args, 125, "", "fixture removal failed")
            output = args[-1]
        return subprocess.CompletedProcess(args, 0, output, "")

    def _podman_output(self, args: list[str]) -> str:
        output = ""
        if "--version" in args and Path(args[0]).name in {"timeout", "gnutimeout"}:
            output = "timeout (GNU coreutils) 9.5"
        elif "images" in args:
            output = self.identity["configDigest"]
        elif "{{.Architecture}}" in args:
            output = "amd64"
        elif "--version" in args:
            output = "podman version fixture"
        elif "{{.Host.Security.Rootless}}" in args:
            output = "false"
        elif "load" in args:
            source = Path(args[args.index("--input") + 1])
            self.loads.append((str(source), source.stat().st_ino, source.read_bytes()))
        elif "{{.State.Running}}" in args:
            output = "false"
        elif "{{.Id}}" in args:
            output = args[-1]
        elif "{{json .State}}" in args:
            output = json.dumps(
                {
                    "Running": False,
                    "Status": "exited",
                    "ExitCode": 0,
                    "OOMKilled": False,
                    "Error": "",
                    "Pid": 0,
                    "Paused": False,
                    "Restarting": False,
                    "Dead": False,
                }
            )
        return output

    def work(self, ctx: runtime_tests.RuntimeContext, *_args: object, **_kwargs: object) -> None:
        ctx.exec_guard = ("guard", ctx.runtime_phase)
        owned = ("a" if ctx.runtime_phase == "clean-control" else "b") * 64
        ctx.containers.append(owned)
        ctx.container_launchers[owned] = "systemd"
        ctx.checks.append({"name": "ordinary workload fixture", "status": "passed"})
        ctx.observations.append({"phase": "before-shutdown", "availability": "observed", "attribution": "unresolved"})
        if self.on_work is not None:
            self.on_work(ctx)
        if ctx.runtime_phase == "clean-control":
            if self.failure in {"failed", "skipped", "unknown"}:
                ctx.checks[-1]["status"] = self.failure
            elif self.failure == "exception":
                error = ProbeError("control workload failed")
                raise error

    def run(self) -> dict:
        with (
            patch("scripts.runtime_tests.tempfile.mkdtemp", side_effect=self.directory),
            patch("scripts.runtime_tests.RuntimeContext", side_effect=self.context),
            patch("scripts.runtime_tests.subprocess.run", side_effect=self.command),
            patch("scripts.runtime_tests.time.monotonic", side_effect=lambda: self.now),
            patch.object(REAL_CONTEXT, "_owned_mounts", return_value=[]),
            patch("scripts.runtime_docker._run_docker_phase", side_effect=self.work),
            patch("scripts.runtime_tests._docker", side_effect=self.work),
        ):
            return runtime_tests.run(self.args)


class CleanControlTests(unittest.TestCase):
    def test_required_phases_resolve_outer_engine_before_owned_backend_preparation(self) -> None:
        for selection, expected in (("profile", "docker"), ("podman", "podman")):
            for phase in runtime_docker.DockerProbePhase:
                with self.subTest(selection=selection, phase=phase):
                    ctx = MagicMock()
                    ctx.checks, ctx.observations = [], []
                    ctx.outer_engine = expected
                    ctx.backend.scoped_profile = None
                    ctx.prepare.return_value = {"engine": expected, "clientVersion": "observed fixture"}
                    plan = runtime_tests._DockerPhasePlan(
                        args=SimpleNamespace(timeout=45, outer_engine=selection),
                        metadata={
                            "name": "docker-29-conformance-rootless",
                            "tests": {"docker": {"launcher": "systemd"}},
                        },
                        architecture="amd64",
                        use_sudo=True,
                        archive=MagicMock(),
                        phase=phase,
                        deadline=200,
                        cancellation=runtime_tests._PairCancellation(),
                        expected_identity=None,
                    )

                    def work(
                        _plan: object, context: runtime_tests.RuntimeContext, result: dict, engine: str = expected
                    ) -> None:
                        self.assertEqual(context.runtime_deadline, 200)
                        self.assertEqual(result["outerRuntime"]["engine"], engine)
                        context.checks.append({"name": "independent phase work", "status": "passed"})

                    with (
                        patch("scripts.runtime_tests.RuntimeContext", return_value=ctx) as construct,
                        patch("scripts.runtime_tests.time.monotonic", return_value=100),
                        patch("scripts.runtime_tests._docker_phase_work", side_effect=work),
                    ):
                        result = runtime_tests._execute_docker_phase(plan)
                    self.assertEqual(construct.call_args.kwargs["outer_engine"], expected)
                    ctx.bind_guest_profile.assert_called_once_with(plan.metadata["tests"]["docker"])
                    self.assertEqual(result["status"], "passed")
                    self.assertTrue(result["cleanupVerified"])
                    ctx.prepare.assert_called_once_with()
                    ctx.cleanup.assert_called_once_with()

    def test_control_cleanup_precedes_enforcement_with_distinct_lifetimes_and_same_pinned_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            evidence = fixture.run()
            self.assertEqual(evidence["status"], "passed")
            self.assertEqual([phase["phase"] for phase in evidence["phases"]], ["clean-control", "enforcement"])
            self.assertTrue(all(phase["cleanupVerified"] for phase in evidence["phases"]))
            first, second = fixture.contexts
            self.assertNotEqual(first.directory, second.directory)
            self.assertNotEqual(first.image_ref, second.image_ref)
            self.assertIsNot(first.checks, second.checks)
            self.assertIsNot(first.observations, second.observations)
            self.assertNotEqual(first.exec_guard, second.exec_guard)
            self.assertFalse(first.directory.exists() or second.directory.exists())
            self.assertEqual(len(fixture.loads), 2)
            self.assertEqual(fixture.loads[0], fixture.loads[1])
            self.assertEqual(fixture.loads[0][2], fixture.original)
            self.assertIn(f"/proc/{os.getpid()}/fd/", fixture.loads[0][0])
            self.assertFalse(Path(fixture.loads[0][0]).exists())
            self.assertEqual(fixture.archive.read_bytes(), fixture.original)
            self.assertEqual([item["phase"] for item in evidence["observations"]], ["before-shutdown"] * 2)
            self.assertEqual(
                [item["routePhase"] for item in evidence["observations"]], ["clean-control", "enforcement"]
            )
            self.assertTrue(all("phase" in check for check in evidence["checks"]))
            self.assertEqual(evidence["phases"][0]["imageIdentity"], evidence["phases"][1]["imageIdentity"])
            self.assertTrue(
                all(any("sourceArchive" in check for check in phase["checks"]) for phase in evidence["phases"])
            )
            _runtime_skips(evidence, nested_disabled=False, profile="docker")
            self.assertEqual(json.loads(Path(fixture.args.evidence).read_text()), evidence)

    def test_cli_skip_or_privilege_refusal_cannot_disable_required_phases(self) -> None:
        for option in ("skip_nested", "allow_privileged"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                fixture = _Fixture(Path(directory))
                setattr(fixture.args, option, option == "skip_nested")
                evidence = fixture.run()
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(fixture.contexts, [])
                self.assertEqual(evidence["phases"], [])
                self.assertTrue(fixture.archive.exists())

    def test_control_failures_skips_unknowns_and_cleanup_errors_prevent_second_context(self) -> None:
        for failure in ("failed", "skipped", "unknown", "exception", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = _Fixture(Path(directory))
                fixture.failure = failure
                evidence = fixture.run()
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(len(fixture.contexts), 1)
                self.assertEqual(len(evidence["phases"]), 1)
                self.assertEqual(evidence["phases"][0]["cleanupVerified"], failure != "cleanup")
                self.assertTrue(fixture.archive.exists())
                self.assertFalse(list(Path(directory).glob("strukturpiloten-runtime-source-*")))

    def test_signal_during_work_or_intermediate_cleanup_is_latched_and_suppresses_enforcement(self) -> None:
        for location, kind in (("work", signal.SIGTERM), ("cleanup", signal.SIGTERM), ("cleanup", signal.SIGINT)):
            with self.subTest(location=location, kind=kind), tempfile.TemporaryDirectory() as directory:
                fixture = _Fixture(Path(directory))
                previous = signal.getsignal(kind)

                def callback(_ctx: REAL_CONTEXT, *, kind: int = kind) -> None:
                    signal.getsignal(kind)(kind, None)

                if location == "work":
                    fixture.on_work = callback
                else:
                    fixture.on_cleanup = callback
                evidence = fixture.run()
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(len(fixture.contexts), 1)
                self.assertTrue(evidence["phases"][0]["cleanupVerified"])
                self.assertFalse(fixture.contexts[0].directory.exists())
                self.assertIs(signal.getsignal(kind), previous)
                self.assertFalse(list(Path(directory).glob("strukturpiloten-runtime-source-*")))

    def test_control_expiry_during_cleanup_still_removes_store_but_prevents_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            fixture.on_cleanup = lambda _ctx: setattr(fixture, "now", 1000 + runtime_tests.CONTROL_SECONDS + 1)
            evidence = fixture.run()
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(len(fixture.contexts), 1)
            self.assertTrue(evidence["phases"][0]["cleanupVerified"])
            self.assertFalse(fixture.contexts[0].directory.exists())
            self.assertIn("wall-time", evidence["error"])

    def test_cancellation_during_cleanup_preserves_the_original_control_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            fixture.failure = "exception"
            fixture.on_cleanup = lambda _ctx: signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            evidence = fixture.run()
            self.assertEqual(len(fixture.contexts), 1)
            self.assertIn("control workload failed", evidence["error"])
            self.assertTrue(any("cancelled" in item["error"] for item in evidence["additionalErrors"]))
            self.assertTrue(evidence["phases"][0]["cleanupVerified"])

    def test_input_replacement_cannot_change_pinned_loads_and_snapshot_replacement_breaks_accounting(self) -> None:
        for replace_snapshot in (False, True):
            with self.subTest(replace_snapshot=replace_snapshot), tempfile.TemporaryDirectory() as directory:
                fixture = _Fixture(Path(directory))

                def replace(
                    ctx: runtime_tests.RuntimeContext,
                    *,
                    fixture: _Fixture = fixture,
                    replace_snapshot: bool = replace_snapshot,
                ) -> None:
                    if ctx.runtime_phase != "clean-control":
                        return
                    path = ctx.runtime_disk_budget.source_archive if replace_snapshot else fixture.archive
                    path.unlink()
                    path.write_bytes(b"replacement")
                    self.assertEqual(Path(fixture.loads[0][0]).read_bytes(), fixture.original)

                fixture.on_work = replace
                evidence = fixture.run()
                self.assertEqual(evidence["status"], "failed" if replace_snapshot else "passed")
                self.assertEqual(len(fixture.contexts), 1 if replace_snapshot else 2)
                self.assertFalse(list(Path(directory).glob("strukturpiloten-runtime-source-*")))
                self.assertTrue(fixture.archive.exists())

    def test_export_snapshot_copy_cap_and_pair_command_deadlines_are_real(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            fixture.args.archive = None
            evidence = fixture.run()
            self.assertEqual(evidence["status"], "passed")
            self.assertEqual(sum(args[:2] == ["podman", "save"] for args, _kwargs in fixture.commands), 1)
            self.assertFalse(list(Path(directory).glob("strukturpiloten-runtime-source-*")))

    def test_pair_remaining_budget_clips_commands_and_never_abandons_final_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))

            def expire(ctx: runtime_tests.RuntimeContext) -> None:
                if ctx.runtime_phase == "enforcement":
                    fixture.now = 1000 + runtime_tests.SYSTEMD_PAIR_SECONDS - 0.25
                    ctx.command("near pair deadline", ["fixed-fixture"])
                    fixture.now += 1

            fixture.on_work = expire
            evidence = fixture.run()
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(len(fixture.contexts), 2)
            args, options = next(item for item in fixture.commands if item[0] == ["fixed-fixture"])
            self.assertEqual(args, ["fixed-fixture"])
            self.assertEqual(options["timeout"], 0.25)
            self.assertTrue(all(phase["cleanupVerified"] for phase in evidence["phases"]))
            self.assertTrue(all(not ctx.directory.exists() for ctx in fixture.contexts))

    def test_archive_identity_difference_or_wrong_architecture_blocks_enforcement_work(self) -> None:
        load = REAL_CONTEXT.load_archive
        for key in ("archiveSha256", "manifestDigest", "architecture"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                fixture = _Fixture(Path(directory))

                def changed(ctx: REAL_CONTEXT, path: Path, *, key: str = key) -> dict:
                    identity = load(ctx, path)
                    if ctx.runtime_phase == "enforcement":
                        identity[key] = "different"
                    return identity

                with patch.object(REAL_CONTEXT, "load_archive", changed):
                    evidence = fixture.run()
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(len(fixture.contexts), 2)
                self.assertEqual(fixture.contexts[1].containers, [])
                self.assertFalse(
                    any(check["name"] == "ordinary workload fixture" for check in evidence["phases"][1]["checks"])
                )
                self.assertTrue(evidence["phases"][1]["cleanupVerified"])

    def test_one_aggregate_observer_counts_source_and_store_and_rejects_incomplete_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.tar"
            source.write_bytes(b"fixture")
            store = Path(directory) / "store"
            store.mkdir()
            ctx = SimpleNamespace(directory=store, _sudo=[], checks=[])
            budget = IsolatedStoreDiskBudget(ctx, source_archive=source, limit_bytes=250)
            budget._du_once = MagicMock(return_value=(0, f"100\t{store}\n200\t{source}\n", ""))
            budget._measure()
            self.assertEqual(budget.peak_bytes, 300)
            with self.assertRaisesRegex(ProbeError, "exceeded"):
                budget.checkpoint()
            for output in (f"100\t{store}", f"100\t{store}\n100\t{store}", f"100\t{store}\n-1\t{source}"):
                budget._du_once = MagicMock(return_value=(0, output, ""))
                with self.subTest(output=output), self.assertRaises(ProbeError):
                    budget._measure()

    def test_phase_selector_is_closed_and_reuses_the_already_active_observer(self) -> None:
        profile = {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"}
        for phase in runtime_docker.DockerProbePhase:
            ctx = MagicMock()
            ctx.name = "docker-29-conformance-rootless"
            ctx.podman.return_value = "Docker version fixture"
            budget = MagicMock()
            ctx.runtime_disk_budget = budget
            with (
                patch("scripts.runtime_docker.IsolatedStoreDiskBudget") as other,
                patch("scripts.runtime_docker._run_nested_docker") as nested,
            ):
                runtime_docker._run_docker_phase(ctx, profile, phase, allow_privileged=True, skip_nested=False)
            other.assert_not_called()
            self.assertIs(nested.call_args.args[-1], budget)
            self.assertEqual(
                nested.call_args.kwargs,
                {} if phase is runtime_docker.DockerProbePhase.ENFORCEMENT else {"phase": phase},
            )
        with self.assertRaisesRegex(ProbeError, "unknown internal"):
            runtime_docker._run_docker_phase(ctx, profile, "clean-control", allow_privileged=True, skip_nested=False)

    def test_canonical_ordinary_checks_and_shutdown_are_identical_except_intentional_injection(self) -> None:
        results = [self._ordinary_phase(phase) for phase in runtime_docker.DockerProbePhase]
        self.assertEqual(results[0]["commands"], results[1]["commands"])
        self.assertEqual(results[0]["start"], results[1]["start"])
        self.assertEqual([result["injected"] for result in results], [0, 1])
        self.assertIn("verify synthetic Docker network DNS", results[0]["commands"])
        self.assertIn("write named volume in nested container", results[0]["commands"])
        self.assertIn("wait for synthetic HTTP container", results[0]["exec"])

    def _ordinary_phase(self, phase: runtime_docker.DockerProbePhase) -> dict:
        ctx = MagicMock(unsafe=True)
        ctx.directory = Path("owned-fixture-store")
        ctx.image_ref = "local:fixture"
        ctx.timeout = 45
        ctx.name = "docker-29-conformance-rootless"
        ctx.start.return_value = "a" * 64
        ctx.runtime_deadline = 1
        outputs = {
            "read Docker API versions": json.dumps(
                {"Version": "29.8.2", "ApiVersion": "1.53", "MinAPIVersion": "1.44"}
            ),
            "inspect Docker storage and security": json.dumps({"Driver": "overlay2", "SecurityOptions": ["rootless"]}),
            "read bind and named volume mounts": "bind-ok\nvolume-ok",
            "read health and restart settings": "unless-stopped wget",
        }

        def docker(_ctx: object, _budget: object, _container: str, name: str, *_args: object) -> str:
            return outputs.get(name, "")

        def stop(_ctx: object, _container: str, **_kwargs: object) -> None:
            self.assertIsNone(ctx.runtime_deadline)

        with (
            patch("scripts.runtime_docker.runtime_docker_systemd.verify_runtime"),
            patch("scripts.runtime_docker._prepare_started_daemon"),
            patch("scripts.runtime_docker._docker", side_effect=docker) as commands,
            patch("scripts.runtime_docker._checked_exec", return_value="29.8.2") as execute,
            patch("scripts.runtime_docker.runtime_docker_systemd.verify_guest") as guest,
            patch("scripts.runtime_docker.runtime_docker_systemd.verify_inner_limits") as injection,
            patch("scripts.runtime_docker.OomDiagnostics"),
            patch("scripts.runtime_docker._wait_http"),
            patch("scripts.runtime_docker.verify_outer_container_limits"),
            patch("scripts.runtime_docker._stop_owned_daemon", side_effect=stop) as shutdown,
        ):
            runtime_docker._run_nested_docker(
                ctx,
                {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"},
                "0",
                MagicMock(),
                phase=phase,
            )
        guest.assert_called_once()
        shutdown.assert_called_once()
        self.assertEqual(ctx.runtime_deadline, 1)
        self.assertGreater(ctx.start.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(ctx.start.call_args.kwargs["timeout"], 45)
        return {
            "commands": [call.args[3] for call in commands.call_args_list],
            "exec": [call.args[2] for call in execute.call_args_list],
            "start": (ctx.start.call_args.args, ctx.start.call_args.kwargs["options"]),
            "injected": injection.call_count,
        }

    def test_owned_snapshot_copy_cap_fails_without_deleting_caller_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            with patch("scripts.runtime_tests.STORE_LIMIT_BYTES", 1):
                evidence = fixture.run()
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(len(fixture.contexts), 1)
            self.assertEqual(fixture.loads, [])
            self.assertTrue(fixture.archive.exists())
            self.assertFalse(list(Path(directory).glob("strukturpiloten-runtime-source-*")))

    def test_partial_constructor_failure_removes_only_its_exact_pre_native_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "partial-store"
            store.mkdir(mode=0o700)
            original = Path.mkdir

            def mkdir(path: Path, *args: object, **kwargs: object) -> None:
                if path.name == "runroot":
                    error = OSError("fixture mkdir failed")
                    raise error
                original(path, *args, **kwargs)

            with (
                patch("scripts.runtime_tests.tempfile.mkdtemp", return_value=str(store)),
                patch.object(Path, "mkdir", autospec=True, side_effect=mkdir),
                patch("subprocess.run") as native,
                self.assertRaisesRegex(OSError, "fixture mkdir failed"),
            ):
                REAL_CONTEXT(image="fixture", architecture="amd64", timeout=45, use_sudo=False)
            native.assert_not_called()
            self.assertFalse(store.exists())
            self.assertTrue(Path(directory).exists())

    def test_constructor_refuses_unverified_directory_without_backend_or_deletion(self) -> None:
        for kind in ("nonprivate", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "target"
                target.mkdir(mode=0o700)
                sentinel = target / "keep"
                sentinel.write_bytes(b"retained unrelated data")
                store = target
                if kind == "nonprivate":
                    store.chmod(0o755)
                else:
                    store = Path(directory) / "store"
                    store.symlink_to(target, target_is_directory=True)
                with (
                    patch("scripts.runtime_tests.tempfile.mkdtemp", return_value=str(store)),
                    patch("scripts.runtime_tests.PodmanBackend") as podman,
                    patch("scripts.runtime_tests.DockerBackend") as docker,
                    patch("scripts.runtime_tests.subprocess.run") as native,
                    patch("scripts.runtime_tests.shutil.rmtree") as deletion,
                    self.assertRaisesRegex(ProbeError, "directory ownership"),
                ):
                    REAL_CONTEXT(image="fixture", architecture="amd64", timeout=45, use_sudo=False)
                podman.assert_not_called()
                docker.assert_not_called()
                native.assert_not_called()
                deletion.assert_not_called()
                self.assertEqual(sentinel.read_bytes(), b"retained unrelated data")
                self.assertTrue(store.exists())
                self.assertEqual(store.is_symlink(), kind == "symlink")


if __name__ == "__main__":
    unittest.main()
