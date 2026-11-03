"""Exercise canonical diagnostic caller wiring without running a container."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_docker
from scripts.runtime_errors import ProbeError

CID = "a" * 64
WORK_REFUSAL = "authored work refusal"
CONTROLS_REFUSAL = "authored mandatory-control refusal"


class MonitorWiringTests(unittest.TestCase):
    def test_custody_cleanup_failure_still_restores_original_deadline(self) -> None:
        ctx, diagnostics = MagicMock(), MagicMock()
        diagnostics.close.side_effect = OSError("owned diagnostic cleanup failed")
        with self.assertRaisesRegex(OSError, "owned diagnostic cleanup failed"):
            runtime_docker._close_oom_diagnostics(ctx, diagnostics, 17)
        self.assertEqual(ctx.runtime_deadline, 17)

    def test_systemd_stop_passes_only_the_bound_host_observer(self) -> None:
        ctx, diagnostics = MagicMock(), MagicMock()
        with patch.object(runtime_docker.runtime_docker_systemd, "stop_guest") as stop:
            runtime_docker._stop_owned_daemon(ctx, CID, systemd=True, diagnostics=diagnostics)
            stop.assert_called_once_with(ctx, CID, on_exit=diagnostics.after_exit, before_stop=diagnostics.before_stop)
            ctx.podman.assert_not_called()
        with patch.object(runtime_docker.runtime_docker_systemd, "stop_guest") as stop:
            runtime_docker._stop_owned_daemon(ctx, CID, systemd=True)
            stop.assert_called_once_with(ctx, CID)

    def test_direct_stop_never_uses_the_systemd_observer(self) -> None:
        ctx, diagnostics = MagicMock(), MagicMock()
        with patch.object(runtime_docker.runtime_docker_systemd, "stop_guest") as stop:
            runtime_docker._stop_owned_daemon(ctx, CID, systemd=False, diagnostics=diagnostics)
            stop.assert_not_called()
            diagnostics.after_exit.assert_not_called()
            self.assertEqual(ctx.podman.call_count, 2)

    def test_both_phases_capture_before_work_and_retain_observer_on_work_failure(self) -> None:
        for phase in runtime_docker.DockerProbePhase:
            with self.subTest(phase=phase):
                self._failed_work_phase(phase)

    def test_both_phases_controls_failure_blocks_ready_and_work_but_retains_observer(self) -> None:
        for phase in runtime_docker.DockerProbePhase:
            with self.subTest(phase=phase):
                self._failed_work_phase(phase, controls_refused=True)

    def _failed_work_phase(self, phase: runtime_docker.DockerProbePhase, *, controls_refused: bool = False) -> None:
        ctx, budget, diagnostics = MagicMock(unsafe=True), MagicMock(), MagicMock()
        ctx.directory = Path("owned-store-fixture")
        ctx.image_ref = "local:fixture"
        ctx.name = "docker-29-conformance-rootless"
        ctx.timeout = 45
        ctx.runtime_deadline = 1
        ctx.start.return_value = CID
        events = []
        diagnostics.snapshot.side_effect = events.append
        ctx.backend.scoped_profile.witness.side_effect = lambda checkpoint: events.append("witness-" + checkpoint)

        def controls(observed: object) -> None:
            self.assertIs(observed, ctx)
            events.append("native-controls")
            if controls_refused:
                raise ProbeError(CONTROLS_REFUSAL)

        def load_fixture(_name: str, _container: str, _archive: object) -> str:
            events.append("ordinary-work-start")
            raise ProbeError(WORK_REFUSAL)

        ctx.load_fixture_archive.side_effect = load_fixture

        def docker(_ctx: object, _budget: object, _container: str, name: str, *_args: object) -> str:
            if name == "read Docker API versions":
                return json.dumps({"Version": "29.8.2", "ApiVersion": "1.53", "MinAPIVersion": "1.44"})
            if name == "inspect Docker storage and security":
                return json.dumps({"Driver": "overlay2", "SecurityOptions": ["rootless"]})
            if name == "load synthetic nested image":
                events.append("ordinary-work-start")
                raise ProbeError(WORK_REFUSAL)
            unexpected = "unexpected Docker request in bounded wiring fixture"
            raise AssertionError(unexpected)

        with (
            patch.object(runtime_docker.runtime_docker_systemd, "verify_runtime"),
            patch.object(runtime_docker, "_prepare_started_daemon"),
            patch.object(runtime_docker, "_checked_exec", return_value="29.8.2"),
            patch.object(runtime_docker, "_docker", side_effect=docker) as commands,
            patch.object(runtime_docker.runtime_docker_systemd, "verify_guest"),
            patch.object(runtime_docker.runtime_docker_systemd, "verify_inner_limits") as limits,
            patch.object(runtime_docker, "OomDiagnostics", return_value=diagnostics),
            patch("scripts.runtime_docker_dead_nonactor_controls.require_controls", side_effect=controls) as mandatory,
            patch.object(runtime_docker.runtime_docker_systemd, "stop_guest") as stop,
            self.assertRaisesRegex(ProbeError, CONTROLS_REFUSAL if controls_refused else WORK_REFUSAL),
        ):
            runtime_docker._run_nested_docker(
                ctx,
                {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"},
                "0",
                budget,
                phase=phase,
            )
        mandatory.assert_called_once_with(ctx)
        if controls_refused:
            self.assertEqual(events, ["before-ordinary-work", "native-controls", "before-shutdown"])
            ctx.backend.scoped_profile.witness.assert_not_called()
            ctx.load_fixture_archive.assert_not_called()
        else:
            self.assertEqual(
                events,
                ["before-ordinary-work", "native-controls", "witness-ready", "ordinary-work-start", "before-shutdown"],
            )
            ctx.backend.scoped_profile.witness.assert_called_once_with("ready")
            ctx.load_fixture_archive.assert_called_once()
        self.assertEqual(
            [call.args[3] for call in commands.call_args_list],
            ["read Docker API versions", "inspect Docker storage and security"],
        )
        stop.assert_called_once_with(ctx, CID, on_exit=diagnostics.after_exit, before_stop=diagnostics.before_stop)
        diagnostics.close.assert_called_once_with()
        limits.assert_not_called()  # Refused before load, never pretend injection ran.
        self.assertEqual(ctx.runtime_deadline, 1)
