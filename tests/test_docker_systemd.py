"""Offline regressions for the dedicated guest-systemd conformance boundary."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable

from scripts import container_engine
from scripts.metadata_schema import MetadataSchemaError, validate_metadata_schema
from scripts.runtime_docker import (
    _outer_options,
    _prepare_started_daemon,
    _run_nested_docker,
    _wait_for_systemd_api,
    run_docker,
)
from scripts.runtime_docker_systemd import (
    INNER_PIDS,
    MEMORY_BYTES,
    PLACEMENT_GUARD,
    PLACEMENT_READBACK_COMMAND,
    PLACEMENT_SAMPLE_SECONDS,
    RESOURCE_START_FILE,
    SYSTEMD_OPTIONS,
    _hierarchy_evidence,
    _placement_observation,
    guarded_command,
    startup_deadline,
    startup_remaining,
    stop_guest,
    verify_guest,
    verify_inner_limits,
    verify_runtime,
    wait_for_placement,
)
from scripts.runtime_resource_budgets import outer_container_limits
from scripts.runtime_tests import ProbeError, RuntimeContext
from tests.test_docker_systemd_boundary import (
    allocator_telemetry_fixture,
    hierarchy_fixture,
    memory_association_fixture,
)

ROOT = Path(__file__).resolve().parents[1]


class DockerSystemdTests(unittest.TestCase):
    def context(self) -> MagicMock:
        ctx = MagicMock(unsafe=True)
        ctx.name = "docker-29-conformance-rootless"
        ctx.image_ref = "localhost/probe:exact"
        ctx.directory = Path("owned-store")
        ctx._sudo = ["sudo", "-n"]
        ctx.checks = []
        ctx.timeout = 45
        ctx.containers = ["owned"]
        return ctx

    def shutdown_context(self, *, exit_code: int = 0, running: bool = True) -> MagicMock:
        ctx = self.context()
        state = {
            "Running": running,
            "Status": "running" if running else "exited",
            "ExitCode": exit_code,
            "OOMKilled": False,
            "Error": "",
            "Pid": 44 if running else 0,
            "Paused": False,
            "Restarting": False,
            "Dead": False,
        }

        def podman(name: str, *_args: str, **_kwargs: object) -> str:
            if name == "resolve owned systemd guest ID":
                return "a" * 64
            if name == "read owned systemd lifecycle state":
                return json.dumps(state)
            if name == "read owned systemd emergency stop signal":
                return "SIGRTMIN+3"
            if name.startswith("request owned systemd"):
                state.update(Running=False, Status="exited", Pid=0)
            if name == "wait for owned systemd orderly exit":
                return str(exit_code)
            return ""

        def compare(_name: str, actual: str, expected: str) -> None:
            if actual != expected:
                message = "abnormal shutdown"
                raise ProbeError(message)

        ctx.podman.side_effect = podman
        ctx.assert_equal.side_effect = compare
        return ctx

    def test_schema_accepts_launcher_enum_without_changing_legacy_default(self) -> None:
        metadata = yaml.safe_load((ROOT / "images/docker/docker-29-rootless/container.yaml").read_text())
        self.assertNotIn("launcher", metadata["tests"]["docker"])
        for launcher in (None, "direct", "systemd", "invalid"):
            candidate = copy.deepcopy(metadata)
            if launcher is not None:
                candidate["tests"]["docker"]["launcher"] = launcher
            if launcher == "invalid":
                with self.assertRaisesRegex(MetadataSchemaError, "launcher"):
                    validate_metadata_schema(candidate, schema_path=ROOT / "container.schema.json", display_path="test")
            else:
                validate_metadata_schema(candidate, schema_path=ROOT / "container.schema.json", display_path="test")

    def test_single_dedicated_profile_reuses_exact_base_and_payload(self) -> None:
        path = ROOT / "images/docker/docker-29-conformance-rootless/container.yaml"
        self.assertTrue(path.read_text().startswith("---\n"))
        metadata = yaml.safe_load(path.read_text())
        self.assertEqual(
            metadata["tests"]["docker"],
            {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged", "nestedRuntime": True},
        )
        existing = yaml.safe_load((ROOT / "images/docker/docker-debian-13-rootful/container.yaml").read_text())
        self.assertEqual(metadata["build"]["args"]["DISTRO_IMAGE"], existing["build"]["args"]["DISTRO_IMAGE"])
        self.assertEqual(metadata["build"]["payload"], "images/docker/upstream/29/payload.yaml")
        payload = yaml.safe_load((ROOT / metadata["build"]["payload"]).read_text())
        self.assertEqual(metadata["version"], f"v{payload['build']['args']['ENGINE_VERSION']}")
        self.assertEqual(metadata["build"]["architectures"], ["amd64", "arm64"])

    def test_helper_only_edit_selects_one_owner_and_no_direct_profiles(self) -> None:
        images = container_engine._load_images()
        options = container_engine.PlanOptions(
            event_name="push", ref_name="main", default_branch="main", before="a" * 40, sha="b" * 40, max_stages=None
        )
        expected = {"docker-29-conformance-rootless"}
        for changed in ("scripts/runtime_docker_systemd.py", "images/docker/conformance/resource-probe.c"):
            with (
                self.subTest(changed=changed),
                patch("scripts.container_engine._changed_files", return_value=[changed]),
            ):
                selected, _files, reason = container_engine._selected_images(images, options)
                self.assertEqual(selected, expected)
                self.assertEqual(reason, "image-specific or shared runtime input changed")
        with patch("scripts.container_engine._changed_files", return_value=["scripts/runtime_docker.py"]):
            selected, _files, _reason = container_engine._selected_images(images, options)
        self.assertEqual(selected, {image["name"] for image in images})

    def test_systemd_outer_command_retains_caps_and_owned_fixture(self) -> None:
        ctx = self.context()
        ctx.name = "docker-29-conformance-rootless"
        options = _outer_options(
            ctx, {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"}, Path("owned/fixture.tar")
        )
        for item in (*outer_container_limits(), *SYSTEMD_OPTIONS, "--privileged"):
            self.assertIn(item, options)
        self.assertNotIn("run.oci.delegate-cgroup=payload", options)
        self.assertNotIn("--oom-score-adj", options)
        self.assertIn("owned/fixture.tar:/tmp/docker-native-fixture.tar:ro", options)
        self.assertFalse(any("/sys/fs/cgroup:" in item or "docker.sock:" in item for item in options))
        direct = _outer_options(ctx, {"mode": "rootless", "outerPrivilege": "privileged"}, Path("owned/fixture.tar"))
        self.assertNotIn("--systemd=always", direct)

    def test_recipe_boundary_keeps_compilers_in_build_stage_and_rootless_in_user_service(self) -> None:
        directory = ROOT / "images/docker/conformance"
        for recipe in ("upstream.Containerfile",):
            source = (directory / recipe).read_text()
            self.assertIn("FROM ${DISTRO_IMAGE} AS probe", source)
            self.assertIn("COPY --from=probe /probe/docker-resource-probe", source)
            self.assertIn("USER 0\nSTOPSIGNAL SIGRTMIN+3", source)
            self.assertNotIn("\\\\\n", source)
        self.assertNotIn("gcc", (directory / "install-systemd.sh").read_text())
        user_service = (directory / "docker-user.service").read_text()
        self.assertNotIn("User=", user_service)
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", user_service)
        self.assertIn("Delegate=yes", user_service)
        installer = (directory / "install-systemd.sh").read_text()
        self.assertIn("/home/docker/.config/systemd/user/docker.service", installer)
        self.assertIn("docker.service docker.socket containerd.service", installer)
        self.assertIn("mask systemd-sysctl.service systemd-modules-load.service", installer)
        for unit in (
            "systemd-timesyncd.service",
            "systemd-journald-audit.socket",
            "systemd-tmpfiles-setup.service",
            "systemd-tmpfiles-clean.service",
        ):
            self.assertIn(unit, installer)
        journal = (directory / "journal-boundary.conf").read_text()
        self.assertNotIn("\nSockets=", journal)
        self.assertIn("CapabilityBoundingSet=~CAP_AUDIT_CONTROL", journal)
        self.assertNotIn("Audit=no", journal)

    def test_native_build_action_explicitly_installs_required_crun(self) -> None:
        action = yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())
        install = next(step for step in action["runs"]["steps"] if step["name"] == "Install OCI tooling")
        self.assertIn("sudo apt-get install --yes --no-install-recommends buildah crun podman skopeo", install["run"])

    def test_systemd_identity_is_outer_root_even_for_rootless_daemon(self) -> None:
        ctx = self.context()
        ctx.podman.return_value = "Docker version 29.8.2"
        profile = {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"}
        run_docker(ctx, profile, archive=Path("unused"), allow_privileged=False, skip_nested=True)
        self.assertEqual(ctx.podman.call_args.args[-1], "0")
        profile["outerPrivilege"] = "unprivileged"
        with self.assertRaisesRegex(ProbeError, "rootful outer"):
            run_docker(ctx, profile, archive=Path("unused"), allow_privileged=False, skip_nested=True)

    def test_runtime_requires_root_crun_exact_path_version_and_hash(self) -> None:
        for name, version, uid, valid in (
            ("crun", "crun version 1.28", "0", True),
            ("crun", "crun version 1.14.3", "0", True),
            ("crun", "crun version UNKNOWN\ncommit: 1.28", "0", True),
            ("runc", "runc version 1.3.3", "0", False),
            ("crun", "unknown", "0", False),
            ("crun", "crun version 1.28", "1000", False),
        ):
            with self.subTest(name=name, version=version, uid=uid):
                ctx = self.context()
                ctx.command.side_effect = [uid, version, "a" * 64 + "  /usr/bin/crun"]
                ctx.podman.return_value = json.dumps({"name": name, "path": "/usr/bin/crun", "version": version})
                ctx.assert_equal.side_effect = lambda _name, observed, expected: (
                    None if observed == expected else (_ for _ in ()).throw(ProbeError("identity"))
                )
                if valid:
                    verify_runtime(ctx)
                    self.assertEqual(ctx.command.call_args.args[1][-2:], ["sha256sum", "/usr/bin/crun"])
                    if "UNKNOWN" in version:
                        self.assertEqual(ctx.checks[-1]["releaseIdentity"], "unknown")
                        self.assertEqual(ctx.checks[-1]["rawVersionReport"], version)
                else:
                    with self.assertRaises(ProbeError):
                        verify_runtime(ctx)

    def test_safe_exec_guard_checks_empty_root_and_exact_nonroot_pid1_leaf(self) -> None:
        # Execute the real guard with synthetic kernel-file readers; no runtime or cgroup writes.
        for init, current, root_processes, subtree, success in (
            ("/init.scope", "/init.scope", "", "", True),
            ("/init.scope", "/", "", "", False),
            ("/", "/", "", "", False),
            ("/init.scope", "/sibling.scope", "", "", False),
            ("/init.scope", "/init.scope", "44", "", False),
            ("/init.scope", "/init.scope", "MISSING", "", False),
            ("/init.scope", "/init.scope", "", "memory", False),
            ("/init.scope", "/init.scope", "", "MISSING", False),
            ("/../init.scope", "/../init.scope", "", "", False),
            ("/./init.scope", "/./init.scope", "", "", False),
            ("", "", "", "", False),
        ):
            with self.subTest(init=init, current=current, root=root_processes, subtree=subtree):
                prelude = (
                    'cut() { case "$*" in */proc/1/cgroup) printf %s "$INIT";; *) printf %s "$CURRENT";; esac; }; '
                    'cat() { case "$1" in /sys/fs/cgroup/cgroup.procs) value=$ROOT_PROCS;; '
                    '*) value=$SUBTREE;; esac; test "$value" != MISSING; printf %s "$value"; }; '
                )
                result = subprocess.run(  # noqa: S603 - fixed shell harness with literal fixtures in environment.
                    ["/bin/sh", "-euc", prelude + PLACEMENT_GUARD],
                    env={"INIT": init, "CURRENT": current, "ROOT_PROCS": root_processes, "SUBTREE": subtree},
                    capture_output=True,
                    check=False,
                    timeout=2,
                )
                self.assertEqual(result.returncode == 0, success)

    def test_runtime_context_guard_applies_to_every_exec_and_preserves_arguments(self) -> None:
        ctx = object.__new__(RuntimeContext)
        ctx.podman = MagicMock(return_value="output")
        ctx.exec_guard = guarded_command()
        ctx.exec("probe", "owned-id", "printf", "%s", "literal $value")
        self.assertEqual(
            ctx.podman.call_args.args,
            ("probe", "exec", "owned-id", *guarded_command(), "printf", "%s", "literal $value"),
        )

    def test_user_manager_controller_and_service_failures_propagate(self) -> None:
        for failure in ("verify true rootless user manager and bus", "verify Docker service controller delegation"):
            ctx = self.context()

            def run(name: str, _container: str, *_args: str, failure_name: str = failure) -> str:
                if name == failure_name:
                    message = "missing required guest capability"
                    raise ProbeError(message)
                if name == "inspect systemd daemon service main PID":
                    return "44"
                if name == "read delegated Docker service cgroup":
                    return "/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service"
                return ""

            ctx.exec.side_effect = run
            with (
                patch("scripts.runtime_docker_systemd._journal_boundary_evidence", return_value={"status": "passed"}),
                self.assertRaisesRegex(ProbeError, "required guest capability"),
            ):
                verify_guest(
                    ctx,
                    MagicMock(),
                    "owned",
                    "rootless",
                    {
                        "DockerRootDir": "/home/docker/.local/share/docker",
                        "CgroupDriver": "systemd",
                        "CgroupVersion": "2",
                    },
                )

    def test_inner_enforcement_requires_genuine_oom_and_pid_refusal_and_cleans_up(self) -> None:
        for oom, pid_log, success in (
            (True, "bounded-pid-refusal events-before=0 events-after=1", True),
            (False, "bounded-pid-refusal", False),
            (True, "no refusal", False),
        ):
            ctx = self.context()

            def run(name: str, _container: str, *_args: str, oom_state: bool = oom, log: str = pid_log) -> str:
                if "start bounded inner" in name:
                    return "a" * 64
                if "wait bounded inner" in name:
                    return "137" if "memory" in name else "0"
                if "enforcement state" in name:
                    return json.dumps({"OOMKilled": oom_state})
                return {
                    "verify inner memory scope placement and ownership": hierarchy_fixture(kind="scope"),
                    "verify inner pids scope placement and ownership": hierarchy_fixture(kind="scope"),
                    "read exact inner memory cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                    "read exact inner pids cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                    "read bounded inner PID refusal": log,
                    "read actual memory allocator swap and namespace association": memory_association_fixture(),
                    "read actual memory allocator self telemetry": allocator_telemetry_fixture(after=not oom_state),
                }.get(name, "")

            ctx.exec.side_effect = run
            ctx.checks.append(
                _hierarchy_evidence(hierarchy_fixture(), kind="service", mode="rootful", unit="docker.service")
            )
            with patch("scripts.runtime_docker_systemd.verify_outer_container_limits"):
                if success:
                    verify_inner_limits(ctx, MagicMock(), "owned")
                else:
                    with self.assertRaises(ProbeError):
                        verify_inner_limits(ctx, MagicMock(), "owned")
            names = [call.args[0] for call in ctx.exec.call_args_list]
            starts = [call.args for call in ctx.exec.call_args_list if "start bounded inner" in call.args[0]]
            commands = {
                "start bounded inner memory probe": (
                    "docker-resource-probe",
                    "memory",
                    "--wait-for-start",
                    RESOURCE_START_FILE,
                    "--memory-evidence",
                ),
                "start bounded inner pids probe": (
                    "docker-resource-probe",
                    "pids",
                    "--wait-for-start",
                    RESOURCE_START_FILE,
                ),
            }
            for start in starts:
                self.assertEqual(start[start.index("docker-resource-probe") :], commands[start[0]])
                self.assertNotIn("sleep 0.1", start)
            self.assertIn("remove owned inner memory probe", names)
            self.assertIn("read back owned inner memory absence", names)
            if success:
                self.assertIn("daemon responsive after inner pids enforcement", names)

    def test_invalid_scope_aborts_before_probe_and_partial_memory_proof_does_not_admit(self) -> None:
        for mode in ("rootful", "rootless"):
            for failed_kind in ("memory", "pids"):
                with self.subTest(mode=mode, failed_kind=failed_kind):
                    ctx = self.context()
                    valid = hierarchy_fixture(kind="scope", mode=mode)
                    ctx.checks.append(
                        _hierarchy_evidence(
                            hierarchy_fixture(mode=mode), kind="service", mode=mode, unit="docker.service"
                        )
                    )
                    invalid = valid.replace("|domain|cpuset cpu io memory pids|", "|domain|cpuset cpu io pids|")
                    responses = {
                        "start bounded inner memory probe": "a" * 64,
                        "start bounded inner pids probe": "a" * 64,
                        "verify inner memory scope placement and ownership": invalid
                        if failed_kind == "memory"
                        else valid,
                        "verify inner pids scope placement and ownership": invalid,
                        "read exact inner memory cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                        "wait bounded inner memory enforcement": "137",
                        "inspect inner memory enforcement state": json.dumps({"OOMKilled": True}),
                        "read actual memory allocator swap and namespace association": memory_association_fixture(
                            mode=mode
                        ),
                        "read actual memory allocator self telemetry": allocator_telemetry_fixture(mode=mode),
                    }
                    ctx.exec.side_effect = lambda name, *_args, table=responses: table.get(name, "")
                    with (
                        patch("scripts.runtime_docker_systemd.verify_outer_container_limits"),
                        self.assertRaisesRegex(ProbeError, "controller was unavailable"),
                    ):
                        verify_inner_limits(ctx, MagicMock(), "owned", mode=mode)
                    names = [call.args[0] for call in ctx.exec.call_args_list]
                    self.assertNotIn(f"read exact inner {failed_kind} cgroup limits", names)
                    self.assertIn(f"remove owned inner {failed_kind} probe", names)
                    self.assertIn(f"read back owned inner {failed_kind} absence", names)
                    if failed_kind == "pids":
                        self.assertIn("daemon responsive after inner memory enforcement", names)

    def test_memory_diagnostic_failure_or_missing_retained_service_keeps_exact_cleanup_and_gate_boundary(self) -> None:
        for mode in ("rootful", "rootless"):
            association = memory_association_fixture(mode=mode)
            telemetry = allocator_telemetry_fixture(mode=mode)
            service = _hierarchy_evidence(
                hierarchy_fixture(mode=mode), kind="service", mode=mode, unit="docker.service"
            )
            for source, self_read, service_count, released in (
                (association.replace("scope-memory.swap.max=0", "scope-memory.swap.max=bad"), telemetry, 1, False),
                (association, telemetry.replace("allocator-before-pid=1", "allocator-before-pid=99"), 1, True),
                (association, telemetry, 0, False),
                (association, telemetry, 2, False),
            ):
                with self.subTest(mode=mode, service_count=service_count, released=released):
                    ctx = self.context()
                    ctx.checks.extend([service] * service_count)
                    responses = {
                        "start bounded inner memory probe": "a" * 64,
                        "verify inner memory scope placement and ownership": hierarchy_fixture(kind="scope", mode=mode),
                        "read actual memory allocator swap and namespace association": source,
                        "read exact inner memory cgroup limits": f"{MEMORY_BYTES}\n{INNER_PIDS}",
                        "wait bounded inner memory enforcement": "137",
                        "inspect inner memory enforcement state": json.dumps({"OOMKilled": True}),
                        "read actual memory allocator self telemetry": self_read,
                    }
                    ctx.exec.side_effect = lambda name, *_args, table=responses: table.get(name, "")
                    with self.assertRaises(ProbeError):
                        verify_inner_limits(ctx, MagicMock(), "owned", mode=mode)
                    names = [call.args[0] for call in ctx.exec.call_args_list]
                    self.assertEqual("read exact inner memory cgroup limits" in names, released)
                    self.assertNotIn("start bounded inner pids probe", names)
                    self.assertIn("remove owned inner memory probe", names)
                    self.assertIn("read back owned inner memory absence", names)

    def test_failure_after_systemd_start_still_stops_owned_guest(self) -> None:
        ctx = self.shutdown_context()
        ctx.start.return_value = "owned"
        budget = MagicMock()
        budget.checkpoint.side_effect = [None, None, None, ProbeError("disk budget")]
        with patch("scripts.runtime_docker_systemd.verify_runtime"), self.assertRaisesRegex(ProbeError, "disk budget"):
            _run_nested_docker(
                ctx, {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"}, "0", budget
            )
        ctx.stop.assert_not_called()
        ctx.podman.assert_any_call("wait for owned systemd orderly exit", "wait", "a" * 64, timeout=30)
        self.assertFalse(any("kill -TERM 1" in str(call) for call in ctx.podman.call_args_list))

    def test_launch_counts_toward_startup_deadline_and_passive_failure_cleans_owned_guest(self) -> None:
        ctx, clock = self.shutdown_context(), _startup_clock()

        def start(*_args: object, **_kwargs: object) -> str:
            clock.now += 3
            return "owned"

        ctx.start.side_effect = start
        with (
            patch("scripts.runtime_docker_systemd.time", clock),
            patch("scripts.runtime_docker_systemd.verify_runtime"),
            patch(
                "scripts.runtime_docker_systemd.wait_for_placement", side_effect=ProbeError("boot failed")
            ) as passive,
            self.assertRaisesRegex(ProbeError, "boot failed"),
        ):
            _run_nested_docker(
                ctx, {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged"}, "0", MagicMock()
            )
        self.assertEqual(passive.call_args.args[-1], 145)
        self.assertEqual(ctx.start.call_args.kwargs["timeout"], 45)
        ctx.exec.assert_not_called()
        ctx.podman.assert_any_call("wait for owned systemd orderly exit", "wait", "a" * 64, timeout=30)

    def test_stop_uses_non_force_exit_target_self_contained_preguard_and_readback(self) -> None:
        ctx = self.shutdown_context()
        stop_guest(ctx, "owned")
        ctx.stop.assert_not_called()
        request = next(call for call in ctx.podman.call_args_list if call.args[0].startswith("request owned systemd"))
        self.assertEqual(request.args[-3:], ("systemctl", "exit", "0"))
        self.assertIn(PLACEMENT_GUARD, request.args[5])
        self.assertEqual(request.args[5].count(PLACEMENT_GUARD), 1)
        self.assertNotIn("--force", request.args)
        self.assertEqual(request.kwargs, {"timeout": 10})
        ctx.podman.assert_any_call(
            "read owned systemd lifecycle state", "inspect", "--format", "{{json .State}}", "a" * 64
        )
        self.assertFalse(any(call.args[1] == "exec" for call in ctx.podman.call_args_list[4:]))

    def test_forced_exit_is_never_reported_as_orderly_systemd_shutdown(self) -> None:
        for exit_code in (130, 137, 1):
            with self.subTest(exit_code=exit_code):
                ctx = self.shutdown_context(exit_code=exit_code)
                with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission"):
                    stop_guest(ctx, "owned")
                ctx.stop.assert_called_once_with("a" * 64, seconds=30)

    def test_already_stopped_guest_requires_zero_clean_state_without_exec_or_halt(self) -> None:
        for exit_code in (0, 130, 137):
            with self.subTest(exit_code=exit_code):
                ctx = self.shutdown_context(exit_code=exit_code, running=False)
                if exit_code:
                    with self.assertRaisesRegex(ProbeError, "exit exactly zero"):
                        stop_guest(ctx, "owned")
                else:
                    stop_guest(ctx, "owned")
                self.assertFalse(any(call.args[1] == "exec" for call in ctx.podman.call_args_list))
                ctx.stop.assert_not_called()

    def test_stopped_state_rejects_missing_malformed_oom_and_runtime_errors(self) -> None:
        state = {
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
        changes = (
            {"Running": "false"},
            {"Status": "dead"},
            {"ExitCode": False},
            {"OOMKilled": True},
            {"Error": "runtime error"},
            {"Pid": 42},
            {"Dead": True},
            {"Paused": True},
            {"Restarting": True},
        )
        for change in (*changes, *(dict.fromkeys([key]) for key in state)):
            with self.subTest(change=change):
                ctx = self.context()
                ctx.podman.side_effect = ["a" * 64, json.dumps({**state, **change})]
                with self.assertRaises(ProbeError):
                    stop_guest(ctx, "owned")
                ctx.stop.assert_not_called()
        for raw in ("{}", "[]", "invalid JSON"):
            with self.subTest(raw=raw):
                ctx = self.context()
                ctx.podman.side_effect = ["a" * 64, raw]
                with self.assertRaises(ProbeError):
                    stop_guest(ctx, "owned")

    def test_shutdown_request_failure_and_wait_timeout_never_admit_fallback_zero(self) -> None:
        for failure in ("request", "wait"):
            with self.subTest(failure=failure):
                ctx = self.shutdown_context()
                command = ctx.podman.side_effect

                def fail(
                    name: str,
                    *args: str,
                    failure: str = failure,
                    command: Callable[..., str] = command,
                    **kwargs: object,
                ) -> str:
                    if name.startswith(failure):
                        message = "bus request failed or host wait timed out"
                        raise ProbeError(message)
                    return command(name, *args, **kwargs)

                ctx.podman.side_effect = fail
                with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission"):
                    stop_guest(ctx, "owned")
                ctx.stop.assert_called_once_with("a" * 64, seconds=30)
                self.assertFalse(any(check.get("status") == "passed" for check in ctx.checks))

    def test_shutdown_refuses_unowned_or_inconsistent_exact_identity(self) -> None:
        ctx = self.shutdown_context()
        with self.assertRaisesRegex(ProbeError, "not an owned guest"):
            stop_guest(ctx, "unowned")
        ctx.podman.assert_not_called()
        ctx.containers = ["b" * 64]
        with self.assertRaisesRegex(ProbeError, "identity"):
            stop_guest(ctx, "b" * 64)
        self.assertEqual(ctx.podman.call_count, 1)

    def test_cancelled_start_and_guard_failure_keep_guarded_request_and_exact_emergency_cleanup(self) -> None:
        for scenario in ("cancel", "guard"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                ctx = object.__new__(RuntimeContext)
                ctx.directory = Path(directory)
                ctx._podman = ["podman"]
                ctx._sudo = []
                ctx.timeout = 5
                ctx.image_ref = "localhost/probe:exact"
                ctx.containers = []
                ctx.run_containers = set()
                ctx.checks = []
                ctx._owned_mounts = MagicMock(return_value=[])
                owned = "a" * 64
                commands = []

                def command(
                    args: list[str],
                    *_args: object,
                    scenario: str = scenario,
                    commands: list[list[str]] = commands,
                    owned: str = owned,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    commands.append(args)
                    if args[1] == "run":
                        Path(args[args.index("--cidfile") + 1]).write_text(owned)
                        if scenario == "cancel":
                            raise KeyboardInterrupt
                        return subprocess.CompletedProcess(args, 0, owned, "")
                    if args[1] == "exec":
                        return subprocess.CompletedProcess(args, 90, "", "unsafe placement")
                    output = (
                        {
                            "{{.State.Running}}": "true",
                            "{{.Config.StopSignal}}": "SIGRTMIN+3",
                            "{{.State.ExitCode}}": "0",
                            "{{.Id}}": owned,
                        }.get(args[args.index("--format") + 1], "")
                        if "--format" in args
                        else ""
                    )
                    if "{{.State.Running}}" in args and any(item[1] == "stop" for item in commands):
                        output = "false"
                    if "{{json .State}}" in args:
                        running = not any(item[1] == "stop" for item in commands)
                        output = json.dumps(
                            {
                                "Running": running,
                                "Status": "running" if running else "exited",
                                "ExitCode": 0,
                                "OOMKilled": False,
                                "Error": "",
                                "Pid": 44 if running else 0,
                                "Paused": False,
                                "Restarting": False,
                                "Dead": False,
                            }
                        )
                    return subprocess.CompletedProcess(args, 0, output, "")

                with patch("scripts.runtime_tests.subprocess.run", side_effect=command):
                    if scenario == "cancel":
                        with self.assertRaises(KeyboardInterrupt):
                            ctx.podman("start", "run", *SYSTEMD_OPTIONS, ctx.image_ref)
                    else:
                        ctx.start("start", options=SYSTEMD_OPTIONS)
                        ctx.exec_guard = guarded_command()
                        with self.assertRaisesRegex(ProbeError, "unsafe placement"):
                            ctx.exec("guarded helper", owned, "true")
                    before_cleanup = len(commands)
                    self.assertEqual(ctx.container_launchers, {owned: "systemd"})
                    with self.assertRaisesRegex(ProbeError, "systemd shutdown was abnormal"):
                        ctx.cleanup()
                cleanup = commands[before_cleanup:]
                self.assertTrue(any(args[1] == "stop" and args[-1] == owned for args in cleanup))
                self.assertTrue(any(args[1] == "rm" and args[-1] == owned for args in cleanup))
                requests = [args for args in cleanup if args[1] == "exec"]
                self.assertEqual(len(requests), 1)
                self.assertIn(PLACEMENT_GUARD, requests[0][5])
                self.assertEqual(requests[0][-3:], ["systemctl", "exit", "0"])


def _placement_fixture(state: str = "READY", **changes: str) -> str:
    fields = {
        "init": "0::/init.scope",
        "current": "0::/init.scope",
        "root-owner": "0",
        "root-procs": "",
        "root-controllers": "cpu memory pids",
        "root-subtree": "cpu memory pids",
        "leaf-subtree": "",
    }
    if state == "EARLY_ROOT":
        fields.update(init="0::/", current="0::/")
        fields["root-procs"] = "1 22"
        fields["root-subtree"] = ""
    elif state == "EXEC_ROOT":
        fields["current"] = "0::/"
        fields["root-procs"] = "22"
        fields["root-subtree"] = ""
    elif state == "PENDING_DELEGATION":
        fields["root-subtree"] = "cpu pids"
    fields.update(changes)
    return "\n".join(f"{key}={value}" for key, value in fields.items())


def _startup_clock() -> SimpleNamespace:
    clock = SimpleNamespace(now=100.0)
    clock.monotonic = lambda: clock.now
    clock.sleep = lambda seconds: setattr(clock, "now", clock.now + seconds)
    return clock


class SystemdStartupTests(unittest.TestCase):
    def context(self) -> MagicMock:
        ctx = MagicMock()
        ctx.timeout = 45
        ctx.checks = []
        ctx.name = "docker-29-conformance-rootless"
        return ctx

    def test_passive_observation_accepts_only_the_closed_boot_states(self) -> None:
        for state in ("EARLY_ROOT", "EXEC_ROOT", "PENDING_DELEGATION", "READY"):
            with self.subTest(state=state):
                self.assertEqual(_placement_observation(_placement_fixture(state))["state"], state)
        for changes in (
            {"init": "0::/", "current": "0::/init.scope"},
            {"current": "0::/sibling.scope"},
            {"current": "0::/../init.scope"},
            {"root-owner": "1000"},
            {"root-controllers": "cpu pids"},
            {"root-subtree": "cpu io memory pids"},
            {"root-procs": "22"},
            {"root-procs": "0"},
            {"root-procs": "1 1"},
            {"leaf-subtree": "memory"},
            {"root-controllers": "cpu cpu memory pids"},
            {"init": "broken"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ProbeError):
                _placement_observation(_placement_fixture(**changes))

    def test_root_boot_observations_reject_contradictory_domain_and_same_cgroup_readbacks(self) -> None:
        for state in ("EARLY_ROOT", "EXEC_ROOT"):
            with self.subTest(state=state):
                positive = _placement_observation(_placement_fixture(state))
                self.assertTrue(positive["rootProcesses"])
                self.assertEqual(positive["rootSubtree"], [])
                self.assertEqual(positive["leafSubtree"], [])
                with self.assertRaisesRegex(ProbeError, "populated root distributed memory"):
                    _placement_observation(
                        _placement_fixture(state, **{"root-subtree": "memory", "leaf-subtree": "memory"})
                    )
                for mismatch in (
                    {"root-subtree": "", "leaf-subtree": "memory"},
                    {"root-procs": "", "root-subtree": "memory", "leaf-subtree": ""},
                ):
                    with self.subTest(mismatch=mismatch), self.assertRaisesRegex(ProbeError, "readbacks disagreed"):
                        _placement_observation(_placement_fixture(state, **mismatch))

    def test_passive_protocol_rejects_missing_duplicate_unknown_and_byte_overflow_before_parse(self) -> None:
        good = _placement_fixture()
        for malformed in ("", good + "\nunknown=field", good + "\nroot-owner=0", good.replace("root-procs=\n", "")):
            with self.subTest(malformed=malformed), self.assertRaises(ProbeError):
                _placement_observation(malformed)
        with (
            patch("scripts.runtime_docker_systemd._cgroup_path") as parse,
            self.assertRaisesRegex(ProbeError, "byte bound"),
        ):
            _placement_observation("é" * 2001)
        parse.assert_not_called()

    def test_real_passive_reader_propagates_missing_files_and_oversize_without_writes(self) -> None:
        for failure in (None, "missing", "oversize"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for pid in ("1", "self"):
                    (root / "proc" / pid).mkdir(parents=True)
                    (root / "proc" / pid / "cgroup").write_text("0::/init.scope\n")
                group = root / "cgroup"
                (group / "init.scope").mkdir(parents=True)
                for field, value in {
                    "cgroup.procs": "",
                    "cgroup.controllers": "cpu memory pids",
                    "cgroup.subtree_control": "cpu memory pids",
                    "init.scope/cgroup.subtree_control": "",
                }.items():
                    (group / field).write_text(value)
                if failure == "missing":
                    (group / "cgroup.procs").unlink()
                elif failure == "oversize":
                    (group / "cgroup.procs").write_text("\n" * 4001)
                script = "stat() { printf 0; }; " + PLACEMENT_READBACK_COMMAND.replace(
                    "/proc/", str(root / "proc") + "/"
                ).replace("/sys/fs/cgroup", str(group))
                result = subprocess.run(  # noqa: S603 - fixed passive reads against owned temporary fixture files.
                    ["/bin/sh", "-euc", script], capture_output=True, text=True, check=False, timeout=2
                )
                if failure:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(_placement_observation(result.stdout)["state"], "READY")

    def test_one_deadline_bounds_placement_limits_and_guarded_api_without_reset(self) -> None:
        ctx, clock = self.context(), _startup_clock()
        ctx.timeout = 60
        ctx.podman.side_effect = [
            _placement_fixture("EARLY_ROOT"),
            _placement_fixture("EXEC_ROOT"),
            _placement_fixture(),
        ]
        calls = []
        first_api_call = 2

        def execute(name: str, *_args: str, **options: float) -> str:
            self.assertEqual(ctx.exec_guard, guarded_command())
            calls.append((name, options["timeout"]))
            if name == "read outer Docker cgroup limits":
                clock.now += 5
                return "200000 100000\n4294967296\n512"
            clock.now += 2
            return "API_PENDING" if len(calls) == first_api_call else "API_READY"

        ctx.exec.side_effect = execute
        with patch("scripts.runtime_docker_systemd.time", clock), patch("scripts.runtime_docker.time", clock):
            deadline = startup_deadline(ctx)
            self.assertEqual(deadline, 145)
            _prepare_started_daemon(ctx, MagicMock(), "owned", {"launcher": "systemd"}, deadline)
        self.assertEqual([timeout for _name, timeout in calls], [43, 38, 35])
        self.assertEqual(ctx.podman.call_count, 3)
        self.assertTrue(all(call.kwargs["timeout"] <= PLACEMENT_SAMPLE_SECONDS for call in ctx.podman.call_args_list))
        evidence = next(check for check in ctx.checks if check["name"] == "systemd passive placement readiness")
        self.assertEqual(evidence["first"]["state"], "EARLY_ROOT")
        self.assertEqual(evidence["last"]["state"], "READY")

    def test_smaller_timeout_and_expiry_during_read_last_sample_or_api_never_renew(self) -> None:
        ctx, clock = self.context(), _startup_clock()
        ctx.timeout = 3
        with patch("scripts.runtime_docker_systemd.time", clock):
            self.assertEqual(startup_deadline(ctx), 103)
            self.assertEqual(startup_remaining(ctx, 103, maximum=2), 2)
            for invalid in (0, -1, float("nan"), float("inf")):
                ctx.timeout = invalid
                with self.subTest(timeout=invalid), self.assertRaises(ProbeError):
                    startup_deadline(ctx)
        for phase in ("placement-command", "last-pending-sample", "api"):
            with self.subTest(phase=phase):
                ctx, clock = self.context(), _startup_clock()

                def response(
                    *_args: object, clock: SimpleNamespace = clock, phase: str = phase, **_kwargs: object
                ) -> str:
                    clock.now = 101
                    return _placement_fixture() if phase == "placement-command" else "API_READY"

                ctx.podman.side_effect = response
                ctx.exec.side_effect = response
                with (
                    patch("scripts.runtime_docker_systemd.time", clock),
                    patch("scripts.runtime_docker.time", clock),
                    self.assertRaisesRegex(ProbeError, "deadline expired"),
                ):
                    if phase == "api":
                        _wait_for_systemd_api(ctx, MagicMock(), "owned", 101)
                    else:
                        if phase == "last-pending-sample":
                            ctx.podman.side_effect = None
                            ctx.podman.return_value = _placement_fixture("EARLY_ROOT")
                        wait_for_placement(ctx, MagicMock(), "owned", 101)
                self.assertEqual(ctx.exec.call_count if phase == "api" else ctx.podman.call_count, 1)

    def test_passive_failures_are_not_retried_and_frozen_clock_still_has_sample_bound(self) -> None:
        for result in (
            ProbeError("OCI error"),
            ProbeError("read failed"),
            "malformed",
            _placement_fixture(current="0::/wrong"),
        ):
            with self.subTest(result=result):
                ctx, clock = self.context(), _startup_clock()
                ctx.podman.side_effect = result if isinstance(result, ProbeError) else [result]
                with patch("scripts.runtime_docker_systemd.time", clock), self.assertRaises(ProbeError):
                    wait_for_placement(ctx, MagicMock(), "owned", 145)
                self.assertEqual(ctx.podman.call_count, 1)
                ctx.exec.assert_not_called()
                self.assertEqual(ctx.checks[-1]["last"]["state"], "FATAL")
        ctx, clock = self.context(), _startup_clock()
        clock.sleep = lambda _seconds: None
        ctx.podman.return_value = _placement_fixture("EARLY_ROOT")
        with patch("scripts.runtime_docker_systemd.time", clock), self.assertRaisesRegex(ProbeError, "sample count"):
            wait_for_placement(ctx, MagicMock(), "owned", 145)
        self.assertEqual(ctx.podman.call_count, 45)

    def test_after_ready_guard_errors_and_invalid_api_markers_are_immediately_fatal(self) -> None:
        for failure in (ProbeError("guard drift"), ProbeError("OCI error"), "unexpected marker"):
            with self.subTest(failure=failure):
                ctx, clock = self.context(), _startup_clock()
                ctx.podman.return_value = _placement_fixture()
                ctx.exec.side_effect = ["200000 100000\n4294967296\n512", failure]
                with (
                    patch("scripts.runtime_docker_systemd.time", clock),
                    patch("scripts.runtime_docker.time", clock),
                    self.assertRaises(ProbeError),
                ):
                    _prepare_started_daemon(ctx, MagicMock(), "owned", {"launcher": "systemd"}, 145)
                self.assertEqual(ctx.podman.call_count, 1)
                self.assertEqual(ctx.exec.call_count, 2)

    def test_expiry_during_first_limits_never_starts_api_poll(self) -> None:
        ctx, clock = self.context(), _startup_clock()
        ctx.podman.return_value = _placement_fixture()

        def limit_read(*_args: object, **_kwargs: object) -> str:
            clock.now = 145
            return "200000 100000\n4294967296\n512"

        ctx.exec.side_effect = limit_read
        with (
            patch("scripts.runtime_docker_systemd.time", clock),
            self.assertRaisesRegex(ProbeError, "deadline expired"),
        ):
            _prepare_started_daemon(ctx, MagicMock(), "owned", {"launcher": "systemd"}, 145)
        self.assertEqual(ctx.exec.call_count, 1)

    def test_direct_launcher_preserves_default_timeouts_and_original_api_loop(self) -> None:
        ctx = self.context()
        ctx.name = "docker-29-rootful"
        ctx.exec.return_value = "200000 100000\n4294967296\n512"
        with patch("scripts.runtime_docker_systemd.wait_for_placement") as passive:
            _prepare_started_daemon(ctx, MagicMock(), "owned", {"mode": "rootful"}, None)
        passive.assert_not_called()
        self.assertTrue(all(not call.kwargs for call in ctx.exec.call_args_list))
        self.assertIn("seq 1 45", ctx.exec.call_args.args[-1])


if __name__ == "__main__":
    unittest.main()
