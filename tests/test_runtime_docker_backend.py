"""Offline ownership controls for the private Docker backend.

These controls never contact Docker, Podman, systemd or a container runtime.
They are not native lifecycle or network qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_tests
from scripts.runtime_docker_backend import DockerBackend, DockerBackendError
from scripts.runtime_tests import RuntimeContext


class PrivateDockerControls(unittest.TestCase):
    def test_replacement_network_cannot_be_removed_or_authorize_store_deletion(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.ready = True
        backend.network_id = "a" * 64
        replacement = "b" * 64
        ctx = MagicMock()
        ctx.containers = []
        ctx._owned_mounts.return_value = []

        def reply(name: str, *_args: str, **_kwargs: object) -> str:
            if name == "inventory private Docker networks":
                return replacement + "|" + backend.network
            if name == "verify owned Docker network cleanup identity":
                return json.dumps(
                    [
                        {
                            "Id": replacement,
                            "Name": backend.network,
                            "Labels": {"io.strukturpiloten.runtime": backend.owner},
                        }
                    ]
                )
            return ""

        ctx.podman.side_effect = reply
        with (
            patch.object(backend, "stop_services") as stop,
            patch.object(backend, "_call", return_value="[]"),
            patch("shutil.rmtree") as remove,
            self.assertRaisesRegex(DockerBackendError, "held creation ID.*retaining"),
        ):
            backend.cleanup(ctx)
        stop.assert_called_once_with(ctx)
        remove.assert_not_called()
        self.assertFalse(any(call.args[1:3] == ("network", "rm") for call in ctx.podman.call_args_list))

    def test_only_original_network_id_with_matching_name_and_label_can_be_removed(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.network_id = "a" * 64
        ctx = MagicMock()
        ctx.podman.side_effect = [
            backend.network_id + "|" + backend.network,
            json.dumps(
                [
                    {
                        "Id": backend.network_id,
                        "Name": backend.network,
                        "Labels": {"io.strukturpiloten.runtime": backend.owner},
                    }
                ]
            ),
            backend.network_id,
        ]
        backend._remove_network(ctx)
        self.assertEqual(ctx.podman.call_args.args[1:], ("network", "rm", backend.network_id))

    def test_construction_and_initialization_never_probe_or_launch(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("subprocess.run") as run,
            patch("subprocess.Popen") as spawn,
        ):
            backend = DockerBackend(Path(directory), ("sudo", "-n"))
            backend.initialize()
            run.assert_not_called()
            spawn.assert_not_called()
            self.assertFalse(backend.ready)
            self.assertEqual(json.loads((backend.cli_config / "config.json").read_text()), {})

    def test_client_has_no_ambient_endpoint_context_or_credentials(self) -> None:
        with patch.object(DockerBackend, "_tool", return_value="/usr/bin/docker"):
            backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
            command = backend.command_prefix(15)
        self.assertEqual(command[:3], ["sudo", "-n", "timeout"])
        self.assertLess(command.index("timeout"), command.index("/usr/bin/docker"))
        self.assertIn("unix:///owned-runtime/docker.sock", command)
        self.assertIn("DOCKER_CONTEXT", command)
        self.assertIn("DOCKER_HOST", command)
        self.assertIn("DOCKER_TLS_VERIFY", command)
        self.assertNotIn("unix:///var/run/docker.sock", command)
        self.assertNotIn("context", command)

    def test_run_requires_ready_network_and_rejects_ownership_overrides(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        with self.assertRaises(DockerBackendError):
            backend.run_options(())
        backend.ready = True
        backend.network_id = "a" * 64
        for option in ("--network=host", "--net", "--label=other", "--cgroup-parent=system.slice"):
            with self.subTest(option=option), self.assertRaises(DockerBackendError):
                backend.run_options((option,))
        options = backend.run_options(("--privileged",))
        self.assertIn(backend.network_id, options)
        self.assertIn(backend.slice, options)
        self.assertIn("io.strukturpiloten.runtime=" + backend.owner, options)

    def test_export_only_normalizes_the_explicit_docker_transport(self) -> None:
        self.assertEqual(
            DockerBackend.save_arguments(("save", "--format", "docker-archive", "--output", "fixture.tar", "image")),
            ("save", "--output", "fixture.tar", "image"),
        )
        with self.assertRaises(DockerBackendError):
            DockerBackend.save_arguments(("save", "--format", "oci-archive", "image"))

    def test_service_name_collision_cannot_register_or_start_service(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        ctx = MagicMock()
        with (
            patch.object(backend, "_state", return_value={"LoadState": "loaded"}),
            patch.object(backend, "_call") as call,
            self.assertRaises(DockerBackendError),
        ):
            backend._start(ctx, "dockerd", ("/usr/bin/dockerd",))
        call.assert_not_called()
        self.assertFalse(backend.units)

    def test_service_is_owned_before_client_timeout_and_budget_is_not_renewed(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.deadline = 2000
        ctx = MagicMock()
        with (
            patch("time.monotonic", return_value=1000),
            patch.object(backend, "_state", return_value={"LoadState": "not-found"}),
            patch.object(backend, "_call", side_effect=subprocess.TimeoutExpired("systemd-run", 15)),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            backend._start(ctx, "dockerd", ("/usr/bin/dockerd", "--config-file", "/owned-runtime/daemon.json"))
        self.assertEqual(len(backend.units), 1)
        self.assertEqual(backend.deadline, 2000)

    def test_wrong_service_identity_never_receives_stop(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.units["owned.service"] = ("dockerd",)
        ctx = MagicMock()
        with (
            patch.object(
                backend,
                "_read_state",
                return_value={"LoadState": "loaded", "Description": "foreign", "Transient": "yes"},
            ),
            patch.object(backend, "_call") as call,
            self.assertRaises(DockerBackendError),
        ):
            backend.stop_services(ctx)
        self.assertFalse(any("stop" in invocation.args[2] for invocation in call.call_args_list))

    def test_process_outside_owned_slice_is_not_admitted(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.units["owned.service"] = ("dockerd",)
        with (
            patch.object(
                backend,
                "_state",
                return_value={"ActiveState": "active", "MainPID": "123", "ControlGroup": "/system.slice/other.service"},
            ),
            self.assertRaises(DockerBackendError),
        ):
            backend._process(MagicMock(), "owned.service")

    def test_route_overlap_and_unknown_shape_are_not_ignored(self) -> None:
        routes = DockerBackend._routes('[{"dst":"172.16.0.0/16"},{"dst":"default"}]')
        self.assertEqual(str(routes[0]), "172.16.0.0/16")
        for raw in ("{}", "[null]", '[{"dst":"not-a-route"}]'):
            with self.subTest(raw=raw), self.assertRaises((DockerBackendError, ValueError)):
                DockerBackend._routes(raw)

    def test_cleanup_failure_retains_store_and_still_stops_owned_services(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.ready = True
        ctx = MagicMock()
        ctx.containers = ["a" * 64]
        ctx._owned_mounts.return_value = []
        with (
            patch.object(backend, "_container", side_effect=DockerBackendError("original resource failure")),
            patch.object(
                backend, "stop_services", side_effect=DockerBackendError("unverified service cleanup")
            ) as stop,
            patch("shutil.rmtree") as remove,
            self.assertRaisesRegex(
                DockerBackendError, "original resource failure.*unverified service cleanup.*retaining"
            ),
        ):
            backend.cleanup(ctx)
        stop.assert_called_once_with(ctx)
        remove.assert_not_called()

    def test_conversion_checks_config_digest_before_any_docker_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            ctx = MagicMock()
            ctx.architecture = "amd64"
            ctx.image_ref = "localhost/test:owned"
            config = b'{"architecture":"amd64","os":"linux"}'
            with tarfile.open(Path(directory) / "docker-import.tar", "w") as archive:
                for name, data in (("manifest.json", b'[{"Config":"config.json"}]'), ("config.json", config)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            with patch.object(backend, "_tool", return_value="skopeo"):
                with self.assertRaises(DockerBackendError):
                    backend.import_archive(ctx, Path("source.tar"), {"configDigest": "sha256:" + "0" * 64})
                ctx.podman.assert_not_called()
                backend.import_archive(
                    ctx, Path("source.tar"), {"configDigest": "sha256:" + hashlib.sha256(config).hexdigest()}
                )
            ctx.podman.assert_called_once()

    def test_owned_endpoint_rejects_foreign_store_and_rootless_server(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        for root, security in (("/var/lib/docker", []), ("/owned-runtime/root", ["name=rootless"])):
            with (
                self.subTest(root=root, security=security),
                patch.object(backend, "client", return_value=["docker"]),
                patch.object(
                    backend, "_call", return_value="|".join(json.dumps(item) for item in (root, security, "29.8.2"))
                ),
                self.assertRaises(DockerBackendError),
            ):
                backend._endpoint_version(MagicMock())
        with (
            patch.object(backend, "client", return_value=["docker"]),
            patch.object(backend, "_call", return_value='"/owned-runtime/root"|[]|"29.8.2"'),
        ):
            self.assertEqual(backend._endpoint_version(MagicMock()), "29.8.2")

    def test_live_container_membership_must_match_the_entire_owned_scope(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        identifier = "a" * 64
        ctx = MagicMock()
        ctx.podman.return_value = json.dumps(backend.slice) + "|123"
        expected = "0::/" + backend.slice + "/docker-" + identifier + ".scope"
        with patch.object(backend, "_call", return_value=expected):
            backend.admit_container(ctx, identifier)
        for membership in ("0::/system.slice/docker-" + identifier + ".scope", expected + "/extra", "1:cpu:/other"):
            with (
                self.subTest(membership=membership),
                patch.object(backend, "_call", return_value=membership),
                self.assertRaises(DockerBackendError),
            ):
                backend.admit_container(ctx, identifier)

    def test_aggregate_budget_retains_cleanup_reserve(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.deadline = 100
        with patch("time.monotonic", return_value=50), self.assertRaises(DockerBackendError):
            backend.command_prefix(5)
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=50), patch.object(backend, "client", return_value=["docker"]):
            self.assertIn("docker", backend.command_prefix(5))

    def test_cleanup_watchdog_and_python_timeout_fit_the_remaining_deadline(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        backend.deadline = 100
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=98):
            command = backend.privileged(["systemctl", "stop", "owned.service"], 25)
        index = command.index("timeout")
        duration = float(command[index + 3].removesuffix("s"))
        kill = float(command[index + 2].split("=", 1)[1].removesuffix("s"))
        self.assertLess(duration + kill, 2)
        self.assertEqual(command[:3], ["sudo", "-n", "timeout"])
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        with (
            patch("time.monotonic", return_value=90),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run,
        ):
            self.assertEqual(ctx.command("bounded cleanup", ["mock-command"], timeout=25), "ok")
        self.assertLess(run.call_args.kwargs["timeout"], 10)

    def test_zero_or_expired_cleanup_allowance_never_launches_a_command(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.deadline = 100
        backend.cleaning_up = True
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        for now, requested in ((90, 0), (100, 25), (101, 25)):
            with (
                self.subTest(now=now, requested=requested),
                patch("time.monotonic", return_value=now),
                patch("subprocess.run") as run,
                self.assertRaises(DockerBackendError),
            ):
                ctx.command("expired cleanup", ["mock-command"], timeout=requested)
            run.assert_not_called()

    def test_root_watchdog_is_reclamped_if_time_elapses_before_python_launch(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        backend.deadline = 100
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=90):
            earlier = backend.privileged(["systemctl", "stop", "owned.service"], 25)
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        with (
            patch("time.monotonic", return_value=99),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
        ):
            ctx.command("root cleanup after delay", earlier, timeout=25)
        final = run.call_args.args[0]
        index = final.index("timeout")
        duration = float(final[index + 3].removesuffix("s"))
        kill = float(final[index + 2].split("=", 1)[1].removesuffix("s"))
        self.assertLess(duration + kill, 1)
        self.assertLess(run.call_args.kwargs["timeout"], 1)

    def test_successful_exit_after_absolute_deadline_is_a_failed_check(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        backend.deadline = 100
        backend.cleaning_up = True
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        clock = [90]

        def finish_late(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            clock[0] = 101
            return subprocess.CompletedProcess([], 0, "late success", "")

        with (
            patch("time.monotonic", side_effect=lambda: clock[0]),
            patch("subprocess.run", side_effect=finish_late),
            self.assertRaisesRegex(runtime_tests.ProbeError, "original aggregate deadline"),
        ):
            ctx.command("late cleanup", ["mock-command"], timeout=25)
        self.assertEqual(ctx.checks[-1]["status"], "failed")

    def test_expiry_before_store_removal_retains_the_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx._owned_mounts.return_value = []
            clock = [99]

            def expire_on_drain(_ctx: object) -> None:
                clock[0] = 101

            with (
                patch("time.monotonic", side_effect=lambda: clock[0]),
                patch.object(backend, "stop_services", side_effect=expire_on_drain),
                patch.object(backend, "_call") as call,
                patch("shutil.rmtree") as remove,
                self.assertRaisesRegex(DockerBackendError, "aggregate deadline"),
            ):
                backend.cleanup(ctx)
            call.assert_not_called()
            remove.assert_not_called()
            ctx.checks.append.assert_not_called()
            self.assertTrue(Path(directory).is_dir())

    def test_late_store_removal_cannot_emit_a_cleanup_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx._owned_mounts.return_value = []
            clock = [90]

            def finish_late(*_args: object, **_kwargs: object) -> str:
                clock[0] = 101
                return ""

            with (
                patch("time.monotonic", side_effect=lambda: clock[0]),
                patch.object(backend, "stop_services"),
                patch.object(backend, "_call", side_effect=finish_late),
                self.assertRaisesRegex(DockerBackendError, "aggregate deadline"),
            ):
                backend.cleanup(ctx)
            ctx.checks.append.assert_not_called()

    def test_successful_cleanup_drains_services_before_removing_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            ctx = MagicMock()
            ctx._owned_mounts.return_value = []
            events = []
            with (
                patch.object(backend, "stop_services", side_effect=lambda _ctx: events.append("drained")),
                patch("shutil.rmtree", side_effect=lambda _path: events.append("removed")),
            ):
                backend.cleanup(ctx)
            self.assertEqual(events, ["drained", "removed"])
            self.assertEqual(ctx.checks.append.call_args.args[0]["status"], "passed")

    def test_unknown_slice_inode_prevents_stop_and_store_deletion(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ())
        state = {"LoadState": "loaded", "ControlGroup": "/" + backend.slice}
        with (
            patch.object(backend, "_read_state", return_value=state),
            patch.object(backend, "_slice_identity", return_value="1:2"),
            patch.object(backend, "_call") as call,
            self.assertRaises(DockerBackendError),
        ):
            backend._stop_slice(MagicMock())
        call.assert_not_called()

    def test_unstarted_backend_cleanup_never_contacts_a_service_manager(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = DockerBackend(Path(directory), ())
            ctx = MagicMock()
            ctx._owned_mounts.return_value = []
            with patch.object(backend, "_call") as call, patch("shutil.rmtree"):
                backend.cleanup(ctx)
            call.assert_not_called()
            ctx.podman.assert_not_called()


class SelectionIntegrationControls(unittest.TestCase):
    def test_delayed_evidence_write_invalidates_success_and_failed_rewrite_is_not_accepted(self) -> None:
        for rewrite_fails in (False, True):
            with self.subTest(rewrite_fails=rewrite_fails):
                self._assert_delayed_evidence_write(rewrite_fails=rewrite_fails)

    def _assert_delayed_evidence_write(self, *, rewrite_fails: bool) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            args = argparse.Namespace(
                metadata=None,
                image_name="docker-29-rootless",
                arch="amd64",
                evidence=str(output),
                sudo=False,
                no_sudo=True,
                archive="source.tar",
                image_ref=None,
                timeout=5,
                allow_privileged=False,
                skip_nested=True,
                outer_engine="profile",
            )
            backend = DockerBackend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx.backend = backend
            ctx.checks = []
            ctx.prepare.return_value = {"engine": "docker", "clientVersion": "Docker version 29.8.2"}
            ctx.load_archive.return_value = {}
            clock = [90]
            original_open = Path.open
            writes = []

            def delayed_open(path: Path, *open_args: object, **open_kwargs: object) -> object:
                handle = original_open(path, *open_args, **open_kwargs)
                if path != output or open_args[:1] != ("wb",):
                    return handle
                proxy = MagicMock(wraps=handle)
                proxy.__enter__.return_value = proxy
                proxy.__exit__.side_effect = handle.__exit__

                def write(body: bytes) -> int:
                    writes.append(json.loads(body)["status"])
                    if rewrite_fails and len(writes) > 1:
                        msg = "failed evidence rewrite"
                        raise OSError(msg)
                    result = handle.write(body)
                    clock[0] = 101
                    return result

                proxy.write.side_effect = write
                return proxy

            with (
                patch("time.monotonic", side_effect=lambda: clock[0]),
                patch("scripts.runtime_tests.RuntimeContext", return_value=ctx),
                patch("scripts.runtime_tests._docker"),
                patch.object(Path, "open", side_effect=delayed_open, autospec=True),
            ):
                if rewrite_fails:
                    with self.assertRaisesRegex(OSError, "failed evidence rewrite"):
                        runtime_tests.run(args)
                else:
                    result = runtime_tests.run(args)
                    self.assertEqual(result["status"], "failed")
            self.assertEqual(writes, ["passed", "failed"])
            if rewrite_fails:
                self.assertEqual(output.read_text(), "")
            else:
                self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_deadline_expiring_after_cleanup_cannot_publish_a_success_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                metadata=None,
                image_name="docker-29-rootless",
                arch="amd64",
                evidence=str(Path(directory) / "evidence.json"),
                sudo=False,
                no_sudo=True,
                archive="source.tar",
                image_ref=None,
                timeout=5,
                allow_privileged=False,
                skip_nested=True,
                outer_engine="profile",
            )
            backend = DockerBackend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx.backend = backend
            ctx.checks = []
            ctx.prepare.return_value = {"engine": "docker", "clientVersion": "Docker version 29.8.2"}
            ctx.load_archive.return_value = {}
            clock = [90]

            def expire_after_cleanup() -> None:
                clock[0] = 101

            ctx.cleanup.side_effect = expire_after_cleanup
            with (
                patch("time.monotonic", side_effect=lambda: clock[0]),
                patch("scripts.runtime_tests.RuntimeContext", return_value=ctx),
                patch("scripts.runtime_tests._docker"),
            ):
                result = runtime_tests.run(args)
            self.assertEqual(result["status"], "failed")
            self.assertIn("aggregate deadline", result["cleanupError"])
            self.assertEqual(json.loads(Path(args.evidence).read_text())["status"], "failed")

    def test_original_failure_and_unknown_cleanup_failure_both_survive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                metadata=None,
                image_name="docker-29-rootless",
                arch="amd64",
                evidence=str(Path(directory) / "evidence.json"),
                sudo=False,
                no_sudo=True,
                archive="source.tar",
                image_ref=None,
                timeout=5,
                allow_privileged=False,
                skip_nested=True,
                outer_engine="profile",
            )
            ctx = MagicMock()
            ctx.checks = []
            ctx.prepare.side_effect = runtime_tests.ProbeError("original prerequisite failure")
            ctx.cleanup.side_effect = DockerBackendError("cleanup ownership unverified; retain store")
            with patch("scripts.runtime_tests.RuntimeContext", return_value=ctx):
                result = runtime_tests.run(args)
            self.assertEqual(result["status"], "failed")
            self.assertIn("original prerequisite failure", result["error"])
            self.assertIn("cleanup ownership unverified", result["cleanupError"])
            self.assertEqual(json.loads(Path(args.evidence).read_text())["cleanupError"], result["cleanupError"])
            ctx.load_archive.assert_not_called()

    def test_profile_selection_does_not_use_inner_root_mode(self) -> None:
        for image in ("docker-29-rootful", "docker-29-rootless"):
            with self.subTest(image=image), tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(
                    metadata=None,
                    image_name=image,
                    arch="amd64",
                    evidence=str(Path(directory) / "evidence.json"),
                    sudo=False,
                    no_sudo=True,
                    archive="source.tar",
                    image_ref=None,
                    timeout=5,
                    allow_privileged=False,
                    skip_nested=True,
                    outer_engine="profile",
                )
                ctx = MagicMock()
                ctx.checks = []
                ctx.prepare.return_value = {
                    "engine": "docker",
                    "clientVersion": "Docker version 29.8.2",
                    "rootMode": "rootful",
                }
                ctx.load_archive.return_value = {}
                with (
                    patch("scripts.runtime_tests.RuntimeContext", return_value=ctx) as factory,
                    patch("scripts.runtime_tests._docker"),
                ):
                    result = runtime_tests.run(args)
                self.assertEqual(factory.call_args.kwargs["outer_engine"], "docker")
                self.assertEqual(result["status"], "passed")
                self.assertNotIn("podmanVersion", result["host"])
                self.assertEqual(result["host"]["outerRuntime"]["engine"], "docker")

    def test_podman_observation_reports_actual_mode_not_sudo_inference(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("scripts.runtime_tests.tempfile.mkdtemp", return_value=directory),
        ):
            ctx = RuntimeContext(image="test", architecture="amd64", timeout=5, use_sudo=False)
            ctx.podman = MagicMock(side_effect=["podman version 5.4.2", "false"])
            self.assertEqual(ctx.prepare()["rootMode"], "rootful")
            ctx.podman = MagicMock(side_effect=["podman version 5.4.2", "unknown"])
            with self.assertRaisesRegex(runtime_tests.ProbeError, "root mode"):
                ctx.prepare()


if __name__ == "__main__":
    unittest.main()
