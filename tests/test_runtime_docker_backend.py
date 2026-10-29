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

FAKE_GNU_TIMEOUT = "/qualified/gnu-timeout"


def admitted_backend(directory: Path, sudo: tuple[str, ...]) -> DockerBackend:
    """Explicit fake-client admission; never resolve or launch a real provider."""
    backend = DockerBackend(directory, sudo)
    backend._gnu_timeout_provider = (FAKE_GNU_TIMEOUT, "9.7", "prefixed")
    return backend


class PrivateDockerControls(unittest.TestCase):
    def test_systemd_profile_binding_is_closed_and_precedes_native_work(self) -> None:
        cases = (
            ("docker-29-conformance-rootless", "rootless", "privileged", True),
            ("docker-29-rootless", "rootless", "privileged", False),
            ("docker-29-conformance-rootless", "rootful", "privileged", False),
            ("docker-29-conformance-rootless", "rootless", "unprivileged", False),
        )
        for name, mode, privilege, valid in cases:
            with self.subTest(name=name, mode=mode, privilege=privilege), tempfile.TemporaryDirectory() as directory:
                store = Path(directory) / "owned"
                store.mkdir()
                with patch("scripts.runtime_tests.tempfile.mkdtemp", return_value=str(store)):
                    ctx = RuntimeContext(
                        image=name, architecture="amd64", timeout=45, use_sudo=False, outer_engine="docker"
                    )
                profile = {"launcher": "systemd", "mode": mode, "outerPrivilege": privilege}
                if valid:
                    ctx.bind_guest_profile(profile)
                    self.assertEqual(ctx.declared_launcher, "systemd")
                    with self.assertRaisesRegex(runtime_tests.ProbeError, "cannot be rebound"):
                        ctx.bind_guest_profile({"launcher": "direct"})
                else:
                    with self.assertRaisesRegex(runtime_tests.ProbeError, "unsupported declared"):
                        ctx.bind_guest_profile(profile)
                self.assertEqual(ctx.backend.units, {})
                self.assertFalse(ctx.backend.ready)
                self.assertEqual(ctx.containers, [])

    def test_unadmitted_backend_rejects_privileged_watchdogs(self) -> None:
        backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
        with self.assertRaisesRegex(DockerBackendError, "not been admitted"):
            backend.privileged(["unused"], 5)

    def test_gnu_admission_uses_original_deadline_before_any_native_resource(self) -> None:
        for banner, admitted in (("timeout (GNU coreutils) 9.7", True), ("timeout (uutils) 0.10.0", False)):
            backend = DockerBackend(Path("/owned-runtime"), ("sudo", "-n"))
            ctx = RuntimeContext.__new__(RuntimeContext)
            ctx.backend, ctx.timeout, ctx.checks = backend, 45, []

            def version(
                command: list[str], *, backend: DockerBackend = backend, banner: str = banner, **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                self.assertEqual(backend.deadline, 2800)
                self.assertIsNone(backend._gnu_timeout_provider)
                self.assertEqual(command, [FAKE_GNU_TIMEOUT, "--version"])
                return subprocess.CompletedProcess(command, 0, banner, "")

            expected_error = (
                self.assertRaisesRegex(RuntimeError, "stop after admission")
                if admitted
                else self.assertRaisesRegex(DockerBackendError, "prerequisite admission failed")
            )
            with (
                self.subTest(admitted=admitted),
                patch("time.monotonic", return_value=1000),
                patch.object(backend, "_tool", return_value="/unused-tool"),
                patch("scripts.runtime_docker_diagnostics.shutil.which", return_value=FAKE_GNU_TIMEOUT),
                patch.object(Path, "resolve", return_value=Path(FAKE_GNU_TIMEOUT)),
                patch("subprocess.run", side_effect=version) as run,
                patch.object(backend, "_unused_slice", side_effect=RuntimeError("stop after admission")) as slice_check,
                patch.object(backend, "_start_services") as services,
                expected_error,
            ):
                backend.prepare(ctx)
            run.assert_called_once()
            self.assertEqual(slice_check.call_count, int(admitted))
            services.assert_not_called()
            if admitted:
                self.assertEqual(backend.timeout_executable(), FAKE_GNU_TIMEOUT)
                self.assertEqual(backend._gnu_timeout_provider, ctx._gnu_timeout_provider)
            else:
                self.assertIsNone(backend._gnu_timeout_provider)

    @staticmethod
    def implicit_slice_state(backend: DockerBackend) -> dict[str, str]:
        # The smoke receipt observed Description, LoadState, ActiveState,
        # Transient and an empty ControlGroup. The remaining properties are
        # affirmative additional observations required by the corrected probe.
        return {
            "Id": backend.slice,
            "Names": backend.slice,
            "Description": "Slice /" + backend.slice.removesuffix(".slice"),
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "Transient": "no",
            "ControlGroup": "",
            "FragmentPath": "",
            "SourcePath": "",
            "DropInPaths": "",
            "UnitFileState": "",
        }

    def test_receipt_shaped_implicit_slice_requires_explicit_properties_and_absent_cgroup(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        state = self.implicit_slice_state(backend)
        raw = "\n".join(f"{key}={value}" for key, value in state.items())
        ctx = MagicMock()
        with patch.object(backend, "_call", side_effect=[raw, "", ""]) as call:
            backend._unused_slice(ctx)
        show = call.call_args_list[0].args[2]
        self.assertIn("--all", show)
        properties = next(
            argument.removeprefix("--property=") for argument in show if argument.startswith("--property=")
        )
        self.assertTrue(set(state) <= set(properties.split(",")))
        self.assertEqual(
            [invocation.args[2] for invocation in call.call_args_list[1:]],
            [
                ["test", "!", "-e", "/sys/fs/cgroup/" + backend.slice],
                ["test", "!", "-L", "/sys/fs/cgroup/" + backend.slice],
            ],
        )

    def test_slice_collision_or_unknown_properties_fail_before_kernel_admission(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        changes = {
            "Id": "other.slice",
            "Names": backend.slice + " alias.slice",
            "LoadState": "error",
            "Description": "foreign",
            "Transient": "yes",
            "ActiveState": "active",
            "ControlGroup": "/" + backend.slice,
            "MainPID": "123",
            "FragmentPath": "/etc/systemd/system/foreign.slice",
            "SourcePath": "/etc/foreign",
            "DropInPaths": "/etc/systemd/system/slice.d/override.conf",
            "UnitFileState": "static",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                state = self.implicit_slice_state(backend) | {key: value}
                with (
                    patch.object(backend, "_read_state", return_value=state),
                    patch.object(backend, "_call") as call,
                    self.assertRaises(DockerBackendError),
                ):
                    backend._unused_slice(MagicMock())
                call.assert_not_called()
        for key in self.implicit_slice_state(backend):
            with self.subTest(missing=key):
                state = self.implicit_slice_state(backend)
                del state[key]
                with (
                    patch.object(backend, "_read_state", return_value=state),
                    patch.object(backend, "_call") as call,
                    self.assertRaises(DockerBackendError),
                ):
                    backend._unused_slice(MagicMock())
                call.assert_not_called()

    def test_existing_kernel_path_or_symlink_prevents_slice_admission(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        for load_state in ("not-found", "loaded"):
            for failure_index in (0, 1):
                with self.subTest(load_state=load_state, failure_index=failure_index):
                    state = self.implicit_slice_state(backend) | {"LoadState": load_state}
                    replies = [""] * failure_index + [subprocess.CalledProcessError(1, "test")]
                    with (
                        patch.object(backend, "_read_state", return_value=state),
                        patch.object(backend, "_call", side_effect=replies) as call,
                        self.assertRaises(subprocess.CalledProcessError),
                    ):
                        backend._unused_slice(MagicMock())
                    self.assertEqual(call.call_count, failure_index + 1)

    def test_each_created_service_rechecks_slice_configuration_before_inode_binding(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        backend.deadline = 2000
        active = self.implicit_slice_state(backend) | {"ActiveState": "active", "ControlGroup": "/" + backend.slice}
        replaced = active | {"DropInPaths": "/etc/systemd/system/slice.d/foreign.conf"}
        with (
            patch("time.monotonic", return_value=1000),
            patch.object(backend, "_state", return_value={"LoadState": "not-found"}),
            patch.object(backend, "_read_state", side_effect=[active, replaced]),
            patch.object(backend, "_call", return_value="1:2") as call,
        ):
            backend._start(MagicMock(), "containerd", ("/usr/bin/containerd",))
            self.assertEqual(backend.slice_identity, "1:2")
            with self.assertRaisesRegex(DockerBackendError, "unconfigured implicit"):
                backend._start(MagicMock(), "dockerd", ("/usr/bin/dockerd",))
        self.assertEqual(len(backend.units), 2)
        self.assertEqual(backend.slice_identity, "1:2")
        self.assertEqual(sum(invocation.args[2][0] == "stat" for invocation in call.call_args_list), 1)

    def test_replacement_network_cannot_be_removed_or_authorize_store_deletion(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
            backend = admitted_backend(Path(directory), ("sudo", "-n"))
            backend.initialize()
            run.assert_not_called()
            spawn.assert_not_called()
            self.assertFalse(backend.ready)
            self.assertEqual(json.loads((backend.cli_config / "config.json").read_text()), {})

    def test_client_has_no_ambient_endpoint_context_or_credentials(self) -> None:
        with patch.object(DockerBackend, "_tool", return_value="/usr/bin/docker"):
            backend = admitted_backend(Path("/owned-runtime"), ("sudo", "-n"))
            command = backend.command_prefix(15)
        self.assertEqual(command[:3], ["sudo", "-n", FAKE_GNU_TIMEOUT])
        self.assertLess(command.index(FAKE_GNU_TIMEOUT), command.index("/usr/bin/docker"))
        self.assertIn("unix:///owned-runtime/docker.sock", command)
        self.assertIn("DOCKER_CONTEXT", command)
        self.assertIn("DOCKER_HOST", command)
        self.assertIn("DOCKER_TLS_VERIFY", command)
        self.assertNotIn("unix:///var/run/docker.sock", command)
        self.assertNotIn("context", command)

    def test_run_requires_ready_network_and_rejects_ownership_overrides(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
            backend = admitted_backend(Path(directory), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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

    def test_only_declared_reviewed_systemd_guest_admits_owned_descendants(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        backend.slice_identity = "1:2"
        identifier = "a" * 64
        ctx = MagicMock()
        ctx.name = "docker-29-conformance-rootless"
        ctx.declared_launcher = "systemd"
        ctx.container_launchers = {identifier: "systemd"}
        ctx.podman.return_value = json.dumps(backend.slice) + "|123"
        root = "0::/" + backend.slice + "/docker-" + identifier + ".scope"
        with patch.object(backend, "_slice_identity", return_value="1:2"):
            for suffix in ("", "/init.scope", "/container/init.scope"):
                with self.subTest(suffix=suffix), patch.object(backend, "_call", return_value=root + suffix):
                    backend.admit_container(ctx, identifier)
            for suffix in ("-other/init.scope", "/../sibling", "/./init.scope", "//init.scope"):
                with (
                    self.subTest(suffix=suffix),
                    patch.object(backend, "_call", return_value=root + suffix),
                    self.assertRaises(DockerBackendError),
                ):
                    backend.admit_container(ctx, identifier)
            for name, launcher, recorded in (
                ("docker-29-rootless", "systemd", "systemd"),
                ("docker-29-conformance-rootless", "direct", "systemd"),
                ("docker-29-conformance-rootless", "systemd", "direct"),
            ):
                ctx.name, ctx.declared_launcher, ctx.container_launchers[identifier] = name, launcher, recorded
                with (
                    patch.object(backend, "_call", return_value=root + "/init.scope"),
                    self.assertRaises(DockerBackendError),
                ):
                    backend.admit_container(ctx, identifier)
        ctx.name, ctx.declared_launcher, ctx.container_launchers[identifier] = (
            "docker-29-conformance-rootless",
            "systemd",
            "systemd",
        )
        with (
            patch.object(backend, "_slice_identity", return_value="1:3"),
            patch.object(backend, "_call", return_value=root + "/init.scope"),
            self.assertRaisesRegex(DockerBackendError, "slice identity"),
        ):
            backend.admit_container(ctx, identifier)

    def test_private_backend_cannot_extend_existing_fixture_phase_deadline(self) -> None:
        for existing, expected in ((200, 200), (5000, 1900)):
            backend = admitted_backend(Path("/owned-runtime"), ("sudo", "-n"))
            ctx = MagicMock()
            ctx.runtime_deadline = existing
            reason = "stop before native service creation"
            with (
                self.subTest(existing=existing),
                patch("time.monotonic", return_value=100),
                patch.object(backend, "_tool", return_value="/tool"),
                patch(
                    "scripts.runtime_docker_backend.qualify_gnu_timeout",
                    return_value=(FAKE_GNU_TIMEOUT, "9.7", "prefixed"),
                ),
                patch.object(backend, "_unused_slice", side_effect=ValueError(reason)),
                self.assertRaisesRegex(ValueError, reason),
            ):
                backend.prepare(ctx)
            self.assertEqual(backend.deadline, expected)

    def test_abnormal_systemd_shutdown_stays_failed_after_verified_physical_cleanup(self) -> None:
        for token in ("a" * 64, "strukturpiloten-runtime-owned-pending-name"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as directory:
                backend = admitted_backend(Path(directory), ())
                backend.ready = True
                identifier = "a" * 64
                ctx = MagicMock()
                ctx.name = "docker-29-conformance-rootless"
                ctx.declared_launcher = "systemd"
                ctx.container_launchers = {token: "systemd"}
                ctx.containers, ctx.run_containers, ctx.checks = [token], {token}, []
                ctx.podman.return_value = ""
                ctx._owned_mounts.return_value = []
                message = "original strict OOM/orderly shutdown failure"

                def refuse(
                    _ctx: object,
                    exact: str,
                    *,
                    context: MagicMock = ctx,
                    reason: str = message,
                    owned: str = identifier,
                ) -> None:
                    self.assertEqual(exact, owned)
                    self.assertIn(owned, context.containers)
                    raise runtime_tests.ProbeError(reason)

                with (
                    patch.object(backend, "_container", side_effect=[identifier, None]),
                    patch.object(backend, "_remove_network") as network,
                    patch.object(backend, "_remove_images") as images,
                    patch.object(backend, "stop_services") as services,
                    patch("scripts.runtime_docker_systemd.stop_guest", side_effect=refuse) as shutdown,
                    self.assertRaisesRegex(DockerBackendError, "systemd shutdown was abnormal"),
                ):
                    backend.cleanup(ctx)
                shutdown.assert_called_once_with(ctx, identifier)
                network.assert_called_once_with(ctx)
                images.assert_called_once_with(ctx)
                services.assert_called_once_with(ctx)
                self.assertEqual(backend.lifecycle_failures, [message])
                self.assertFalse(Path(directory).exists())
                self.assertEqual(ctx.checks[-1], {"name": "cleanup isolated store", "status": "passed"})
                self.assertTrue(
                    any(call.args[0] == "remove owned outer Docker container" for call in ctx.podman.call_args_list)
                )

    def test_aggregate_budget_retains_cleanup_reserve(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        backend.deadline = 100
        with patch("time.monotonic", return_value=50), self.assertRaises(DockerBackendError):
            backend.command_prefix(5)
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=50), patch.object(backend, "client", return_value=["docker"]):
            self.assertIn("docker", backend.command_prefix(5))

    def test_cleanup_watchdog_and_python_timeout_fit_the_remaining_deadline(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ("sudo", "-n"))
        backend.deadline = 100
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=98):
            command = backend.privileged(["systemctl", "stop", "owned.service"], 25)
        index = command.index(FAKE_GNU_TIMEOUT)
        duration = float(command[index + 3].removesuffix("s"))
        kill = float(command[index + 2].split("=", 1)[1].removesuffix("s"))
        self.assertLess(duration + kill, 2)
        self.assertEqual(command[:3], ["sudo", "-n", FAKE_GNU_TIMEOUT])
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        ctx.observations = []
        with (
            patch("time.monotonic", return_value=90),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run,
        ):
            self.assertEqual(ctx.command("bounded cleanup", ["mock-command"], timeout=25), "ok")
        self.assertLess(run.call_args.kwargs["timeout"], 10)

    def test_zero_or_expired_cleanup_allowance_never_launches_a_command(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        backend.deadline = 100
        backend.cleaning_up = True
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        ctx.observations = []
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
        backend = admitted_backend(Path("/owned-runtime"), ("sudo", "-n"))
        backend.deadline = 100
        backend.cleaning_up = True
        with patch("time.monotonic", return_value=90):
            earlier = backend.privileged(["systemctl", "stop", "owned.service"], 25)
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        ctx.observations = []
        with (
            patch("time.monotonic", return_value=99),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
        ):
            ctx.command("root cleanup after delay", earlier, timeout=25)
        final = run.call_args.args[0]
        index = final.index(FAKE_GNU_TIMEOUT)
        duration = float(final[index + 3].removesuffix("s"))
        kill = float(final[index + 2].split("=", 1)[1].removesuffix("s"))
        self.assertLess(duration + kill, 1)
        self.assertLess(run.call_args.kwargs["timeout"], 1)

    def test_successful_exit_after_absolute_deadline_is_a_failed_check(self) -> None:
        backend = admitted_backend(Path("/owned-runtime"), ())
        backend.deadline = 100
        backend.cleaning_up = True
        ctx = RuntimeContext.__new__(RuntimeContext)
        ctx.backend = backend
        ctx.timeout = 45
        ctx.checks = []
        ctx.observations = []
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
            backend = admitted_backend(Path(directory), ())
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
            backend = admitted_backend(Path(directory), ())
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
            backend = admitted_backend(Path(directory), ())
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
        backend = admitted_backend(Path("/owned-runtime"), ())
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
            backend = admitted_backend(Path(directory), ())
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
            backend = admitted_backend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx.backend = backend
            ctx.checks = []
            ctx.observations = []
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
            backend = admitted_backend(Path(directory), ())
            backend.deadline = 100
            ctx = MagicMock()
            ctx.backend = backend
            ctx.checks = []
            ctx.observations = []
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
            ctx.observations = []
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
                ctx.observations = []
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
