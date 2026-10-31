"""Hermetic active admission/proof/custody negatives; never load host policy."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Self
from unittest.mock import Mock, patch

import yaml

from scripts import docker_userns_active as active
from scripts import docker_userns_active_bootstrap_bundle as producer
from scripts import docker_userns_custody_child as child
from scripts import docker_userns_hosted as host
from scripts import docker_userns_qualification as qualification
from tests.test_docker_userns_qualification import PRIVATE, binding, scoped_receipt, stage_disposal, workflow_context

if TYPE_CHECKING:
    from collections.abc import Iterator

    from scripts.docker_userns_active_client import ActiveClient

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def event_payload(raw: bytes) -> Iterator[None]:
    """Mock only the fixed event, preserving real admission/source reads."""
    original = Path.open

    def opened(path: Path, *args: object, **kwargs: object) -> object:
        if str(path) == "/home/runner/work/_temp/_github_workflow/event.json":
            return io.BytesIO(raw)
        return original(path, *args, **kwargs)

    with patch.object(Path, "open", new=opened):
        yield


def literal_namespace() -> dict[str, object]:
    """Compile definitions from the workflow literal without running its root main."""
    action = yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())
    step = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
    parsed = ast.parse(step["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])
    parsed.body = [item for item in parsed.body if not isinstance(item, ast.If)]
    namespace: dict[str, object] = {"__name__": "hermetic_bootstrap_fixture"}
    exec(compile(parsed, "fixed-active-bootstrap", "exec"), namespace)  # noqa: S102 - definitions only; no main or root call.
    return namespace


class SyntheticProof:
    """Construct an independently framed finite Git object DAG without Git writes."""

    def __init__(
        self,
        admission_raw: bytes | None = None,
        *,
        parents: tuple[str, ...] = (),
        commit_suffix: bytes = (
            b"author Fixture <fixture@example.invalid> 1 +0000\n"
            b"committer Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n"
        ),
    ) -> None:
        """Use independently authored commit parents, inert SDK and fixture manifest."""
        self.objects: dict[str, dict[str, str]] = {}
        self.files = {name: (ROOT / name).read_bytes() for name in producer.FILES}
        if admission_raw is not None:
            self.files[producer.ADMISSION] = admission_raw
        self.sdk = {
            "scripts/native-runner-apparmor.py": b"inert builder",
            "scripts/native_outer_diagnostic_capture.py": b"inert capture",
            "LICENSE": b"inert license",
        }
        manifest = json.loads(self.files[producer.MANIFEST])
        manifest["source"]["files"] = [
            {"path": name, "size": len(raw), "sha256": active.digest(raw)} for name, raw in self.sdk.items()
        ]
        self.files[producer.MANIFEST] = json.dumps(manifest).encode()
        directories: dict[str, dict[str, bytes]] = {}
        for path, raw in self.files.items():
            directory, name = path.split("/")
            directories.setdefault(directory, {})[name] = raw
        root_entries = []
        for directory, files in sorted(directories.items()):
            leaves = [
                b"100644 " + name.encode() + b"\0" + bytes.fromhex(self.add("blob", raw))
                for name, raw in sorted(files.items())
            ]
            identifier = self.add("tree", b"".join(leaves))
            root_entries.append(b"40000 " + directory.encode() + b"\0" + bytes.fromhex(identifier))
        tree = self.add("tree", b"".join(root_entries))
        parent_headers = b"".join(f"parent {identifier}\n".encode() for identifier in parents)
        self.candidate = self.add("commit", f"tree {tree}\n".encode() + parent_headers + commit_suffix)
        self.context = workflow_context(candidate=self.candidate)
        self.context["admissionSha256"] = active.digest(self.files[producer.ADMISSION])

    def add(self, kind: str, raw: bytes) -> str:
        identifier = hashlib.sha1(
            kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
        ).hexdigest()
        self.objects[identifier] = {"oid": identifier, "kind": kind, "data": base64.b64encode(raw).decode()}
        return identifier

    def value(self) -> dict[str, object]:
        return {
            "schemaVersion": 4,
            "consumer": active.CONSUMER,
            "context": self.context,
            "objects": list(self.objects.values()),
            "sdk": {name: base64.b64encode(raw).decode() for name, raw in self.sdk.items()},
        }


class ActiveBootstrapProof(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = literal_namespace()
        self.proof = SyntheticProof()
        # Synthetic SDK fixtures have their own explicit test authority; the
        # production literal's real immutable manifest pin is checked separately.
        self.namespace["SOURCE_MANIFEST_SHA256"] = active.digest(self.proof.files[producer.MANIFEST])

    def verify(self, value: dict[str, object]) -> object:
        return self.namespace["verify_bundle"](json.dumps(value).encode(), self.proof.context)

    def test_finite_connected_proof_and_sdk_digest_validation(self) -> None:
        files, sdk = self.verify(self.proof.value())
        self.assertEqual(files, self.proof.files)
        self.assertEqual(sdk, {Path(name).name: raw for name, raw in self.proof.sdk.items()})
        self.assertEqual(
            literal_namespace()["SOURCE_MANIFEST_SHA256"], active.digest((ROOT / producer.MANIFEST).read_bytes())
        )
        self.assertEqual(tuple(literal_namespace()["CLOSED_FILES"]), producer.FILES)
        self.assertEqual(producer.FILES, active.FILES)

    def test_disconnected_replaced_or_malformed_object_and_sdk_refuse(self) -> None:
        for fault in ("disconnected", "replacement", "kind", "sdk", "workflow", "imageVersion", "consumer", "closure"):
            with self.subTest(fault=fault):
                value = copy.deepcopy(self.proof.value())
                if fault == "disconnected":
                    extra = SyntheticProof()
                    identifier = extra.add("blob", b"disconnected")
                    value["objects"].append(extra.objects[identifier])
                elif fault == "replacement":
                    value["objects"][0]["data"] = base64.b64encode(b"replacement").decode()
                elif fault == "kind":
                    value["objects"][0]["kind"] = "tag"
                elif fault == "sdk":
                    value["sdk"]["LICENSE"] = base64.b64encode(b"wrong").decode()
                elif fault in {"workflow", "imageVersion"}:
                    value["context"][fault] = "wrong"
                elif fault == "consumer":
                    value["consumer"] = "containers-ubuntu26-userns-unused"
                else:
                    value["objects"].pop()
                with self.assertRaises((ValueError, KeyError)):
                    self.verify(value)

    def test_duplicate_keys_and_changed_manifest_authority_refuse(self) -> None:
        with self.assertRaises(ValueError):
            self.namespace["verify_bundle"](b'{"schemaVersion":1,"schemaVersion":1}', self.proof.context)
        self.namespace["SOURCE_MANIFEST_SHA256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.verify(self.proof.value())


class NamespaceAndActor(unittest.TestCase):
    def test_real_non_securityfs_directory_never_passes_filesystem_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(active.RefusedError):
                    active.filesystem_magic(descriptor, 0x73636673)
            finally:
                os.close(descriptor)

    def test_reviewed_admission_reaches_first_guard_with_fresh_actor_namespace_reads(self) -> None:
        admission = json.loads((ROOT / ".github/docker-userns-active-admission.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "apparmor").mkdir()
            (directory / "proc/attr/apparmor").mkdir(parents=True)
            for leaf, raw in ((".ns_name", b"root\n"), (".ns_level", b"0\n"), (".stacked", b"no\n")):
                (directory / "apparmor" / leaf).write_bytes(raw)
            (directory / "proc/attr/apparmor/current").write_bytes(b"unconfined\n")
            original_open = os.open
            opens: list[str] = []
            namespace_reads: list[str] = []
            namespace_inodes = {
                f"/proc/{actor}/ns/{kind}": inode
                for actor in ("self", "1")
                for kind, inode in (("user", 101), ("mnt", 102), ("cgroup", 103))
            }

            def fixture_stat(path: Path, **_kwargs: object) -> SimpleNamespace:
                namespace_reads.append(str(path))
                return SimpleNamespace(st_ino=namespace_inodes[str(path)])

            def fixture_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
                opens.append(str(path))
                if str(path) == "/sys/kernel/security/apparmor":
                    path = directory / "apparmor"
                elif str(path) == f"/proc/{os.getpid()}":
                    path = directory / "proc"
                return original_open(path, flags, *args, **kwargs)

            with (
                patch.object(active.os, "open", side_effect=fixture_open),
                patch.object(active.Path, "stat", autospec=True, side_effect=fixture_stat),
                patch.object(active, "filesystem_magic") as magic,
            ):
                observed = active.namespace_snapshot(SimpleNamespace(), admission)
                self.assertEqual(magic.call_args_list[0].args[1], 0x73636673)
                self.assertEqual(magic.call_args_list[1].args[1], 0x9FA0)
                port = active.RootPort.__new__(active.RootPort)
                port.stage, port.bootstrap, port.modules = directory, {}, SimpleNamespace()
                port.binding, port.work_until, port.cleanup, port.admission = binding(), 1000, False, admission
                port.record = {
                    "bootstrapSha256": active.digest(b"fixture"),
                    "readerPending": False,
                    "childPending": False,
                    "preflight": {},
                    "namespace": observed,
                    "cleanOwnerVerified": True,
                    "ownerReady": True,
                }
                port.preflight, port.verify_owner, port.daemon, port.image = (
                    Mock(return_value={}),
                    Mock(),
                    Mock(),
                    Mock(),
                )
                with (
                    patch.object(active, "check"),
                    patch.object(active, "verify_stage"),
                    patch.object(active, "root_bytes", return_value=b"fixture"),
                ):
                    port.guard(port.binding)
                port.verify_owner.assert_called_once_with("owner")
                self.assertEqual(
                    opens,
                    [
                        "/sys/kernel/security/apparmor",
                        ".ns_name",
                        ".ns_level",
                        ".stacked",
                        f"/proc/{os.getpid()}",
                        "attr/apparmor/current",
                    ]
                    * 2,
                )
                self.assertEqual(
                    namespace_reads,
                    [
                        f"/proc/{actor}/ns/{kind}"
                        for kind in ("user", "mnt", "cgroup")
                        for actor in ("self", "1", "self")
                    ]
                    * 2,
                )
                self.assertEqual(
                    {key: observed[key] for key in ("user", "mnt", "cgroup")}, {"user": 101, "mnt": 102, "cgroup": 103}
                )
                self.assertNotIn(".ns_stacked", opens)
                (directory / "apparmor/.stacked").write_bytes(b"yes\n")
                with self.assertRaises(active.RefusedError):
                    active.namespace_snapshot(SimpleNamespace(), admission)

    def test_first_guard_refuses_denied_or_unavailable_host_namespace_fact(self) -> None:
        import errno  # noqa: PLC0415
        import stat  # noqa: PLC0415

        admission = json.loads((ROOT / ".github/docker-userns-active-admission.json").read_text())
        for error_type, number in ((PermissionError, errno.EACCES), (FileNotFoundError, errno.ENOENT)):
            with self.subTest(error=error_type):
                port = active.RootPort.__new__(active.RootPort)
                port.stage, port.bootstrap, port.modules = Path("/hermetic-stage"), {}, SimpleNamespace()
                port.binding, port.work_until, port.cleanup, port.admission = binding(), 1000, False, admission
                port.record = {
                    "bootstrapSha256": active.digest(b"fixture"),
                    "readerPending": False,
                    "childPending": False,
                    "preflight": {},
                    "cleanOwnerVerified": True,
                    "ownerReady": True,
                }
                port.preflight, port.verify_owner, port.daemon, port.image = (
                    Mock(return_value={}),
                    Mock(),
                    Mock(),
                    Mock(),
                )
                facts = {
                    f"/proc/{actor}/ns/{kind}": SimpleNamespace(st_ino=100)
                    for actor in ("self", "1")
                    for kind in ("user", "mnt", "cgroup")
                }
                facts["/proc/1/ns/user"] = error_type(number, "namespace fact unavailable")

                def fixture_stat(path: Path, *, facts: dict[str, object] = facts, **_kwargs: object) -> SimpleNamespace:
                    fact = facts[str(path)]
                    if isinstance(fact, OSError):
                        raise fact
                    return fact

                with (
                    patch.object(active, "check"),
                    patch.object(active, "verify_stage"),
                    patch.object(active, "root_bytes", return_value=b"fixture"),
                    patch.object(active, "filesystem_magic"),
                    patch.object(active.os, "open", return_value=42),
                    patch.object(active.os, "close"),
                    patch.object(active.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)),
                    patch.object(active.os, "read", side_effect=(b"root\n", b"0\n", b"no\n", b"unconfined\n")),
                    patch.object(active.Path, "stat", autospec=True, side_effect=fixture_stat) as namespace_stat,
                    self.assertRaises(error_type),
                ):
                    port.guard(port.binding)
                self.assertEqual(
                    [str(call.args[0]) for call in namespace_stat.call_args_list],
                    ["/proc/self/ns/user", "/proc/1/ns/user"],
                )
                port.verify_owner.assert_not_called()
                port.daemon.assert_not_called()
                port.image.assert_not_called()

    def test_effective_profile_accepts_only_exact_single_unconfined_label(self) -> None:
        name = "dockerlens-127-upstream-rootless-1-2-" + "f" * 32
        labels = [
            name.encode() + suffix
            for suffix in (b" (unconfined)\n", b" (enforce)\n", b" (complain)\n", b"//&other (unconfined)\n")
        ]
        labels.append(b":nested:" + name.encode() + b" (unconfined)\n")
        for raw in labels:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                port = active.RootPort.__new__(active.RootPort)
                port.binding, port.modules, port.admission = binding(), SimpleNamespace(qualification=qualification), {}
                port.store = SimpleNamespace(path=Path(temporary))
                port.record = {"profileName": name}
                port.daemon, port.commit = Mock(), Mock()
                port.inspect = Mock(return_value={"State": {"Pid": os.getpid(), "Running": True, "StartedAt": "fixed"}})
                task = {
                    "pid": os.getpid(),
                    "startTicks": 1,
                    "cgroup": "0::/" + binding().runtime_slice + "/docker-" + "a" * 64 + ".scope\n",
                }
                descriptor = os.open("/dev/null", os.O_RDONLY)
                with (
                    patch.object(active, "namespace_snapshot", return_value={}),
                    patch.object(active, "task_snapshot", return_value=task),
                    patch.object(active, "proc_bytes", return_value=raw),
                    patch.object(active.os, "pidfd_open", return_value=descriptor, create=True),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    if raw == labels[0]:
                        port.bind_subject("a" * 64, binding())
                        self.assertIn("subject", port.record)
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.bind_subject("a" * 64, binding())
                        self.assertNotIn("subject", port.record)
                        self.assertEqual((Path(temporary) / "profile-mismatch.bin").read_bytes(), raw)
                    observation = port.record["profileObservation"]
                    self.assertEqual(observation["bytes"], len(raw))
                    self.assertEqual(observation["sha256"], active.digest(raw))
                    self.assertNotIn(raw.decode(), json.dumps(observation))


class FinalizerFailure(unittest.TestCase):
    def test_unknown_intent_or_reader_never_grants_emergency_unload(self) -> None:
        for state in ("load-intent", "create-intent", "retained", "loaded", "attached"):
            with self.subTest(state=state):
                record = {
                    "state": state,
                    "readerPending": state == "loaded",
                    "childPending": state == "attached",
                    "retained": False,
                }
                store = Mock()
                store.path = Path("/nonexistent-active-custody-fixture")
                store.read.return_value = record
                store.locked.return_value.__enter__ = Mock(return_value=None)
                store.locked.return_value.__exit__ = Mock(return_value=False)
                port = SimpleNamespace(
                    store=store,
                    binding=binding(),
                    work_until=500,
                    record={},
                    cleanup=False,
                    remove_subject=Mock(),
                    persist=Mock(),
                    unload=Mock(),
                    retain=Mock(),
                )
                with (
                    patch.object(active, "write_leaf"),
                    patch.object(active, "check"),
                    patch.object(active.time, "monotonic_ns", return_value=600),
                    patch.object(active.select, "select", return_value=([], [], [])),
                ):
                    self.assertEqual(active.owner_loop(port, 99, "owner", [False]), 1)
                port.remove_subject.assert_not_called()
                port.unload.assert_not_called()
                port.retain.assert_called_once()


class QualificationEvidence(unittest.TestCase):
    def fixture(self) -> tuple[dict[str, object], dict[str, object]]:
        scoped = scoped_receipt()
        context = binding()
        identity = {
            "archiveSha256": context.archive_sha256,
            "manifestDigest": context.manifest_digest,
            "configDigest": context.config_digest,
            "sourceRevision": context.candidate,
        }
        return {
            "image": context.image,
            "architecture": context.architecture,
            "runId": context.run,
            "runAttempt": context.attempt,
            "producingJob": context.job,
        }, {
            "phase": context.phase,
            "architecture": context.architecture,
            "imageIdentity": identity,
            "scopedProfile": scoped,
        }

    def test_scoped_evidence_requires_actual_host_attachment_and_all_cleanup_proofs(self) -> None:
        from scripts import evidence_gate  # noqa: PLC0415

        record, phase = self.fixture()
        with patch.dict(os.environ, {}, clear=True):
            evidence_gate._scoped_phase(record, phase)
            for key, value in (
                ("state", "loaded"),
                ("retained", True),
                ("readerPending", True),
                ("childPending", True),
                ("cleanOwnerVerified", False),
                ("ownerReady", False),
                ("ownerTerminationVerified", False),
                ("custodyDisposed", False),
                ("guestAbsenceVerified", False),
                ("taskAbsenceVerified", False),
                ("scopeAbsenceVerified", False),
                ("profileAbsenceVerified", False),
            ):
                with self.subTest(key=key):
                    broken = copy.deepcopy(phase)
                    broken["scopedProfile"][key] = value
                    with self.assertRaises(evidence_gate.EvidenceError):
                        evidence_gate._scoped_phase(record, broken)
            for section, key, value in (
                ("profileObservation", "sha256", "0" * 64),
                ("profileObservation", "exactMatch", False),
                ("binding", "architecture", "arm64"),
                ("namespace", "stacked", "0" * 64),
                ("preflight", "kernel", "different"),
                ("parserExecutionNamespace", "measuredPostExec", True),
            ):
                with self.subTest(section=section, key=key):
                    broken = copy.deepcopy(phase)
                    broken["scopedProfile"][section][key] = value
                    with self.assertRaises(evidence_gate.EvidenceError):
                        evidence_gate._scoped_phase(record, broken)
            with (
                patch.dict(os.environ, {"ImageVersion": "20261025.179.1"}),
                self.assertRaises(evidence_gate.EvidenceError),
            ):
                evidence_gate._scoped_phase(record, phase)

    def test_experimental_production_consumer_still_refuses_foreign_current_ci_source(self) -> None:
        from scripts import evidence_gate  # noqa: PLC0415

        record, phase = self.fixture()
        with (
            patch.dict(os.environ, {"GITHUB_SHA": "f" * 40}, clear=True),
            self.assertRaises(evidence_gate.EvidenceError),
        ):
            evidence_gate._scoped_phase(record, phase)

    def test_explicit_requirement_cannot_pass_missing_scoped_receipt(self) -> None:
        from scripts import evidence_gate  # noqa: PLC0415

        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(evidence_gate._active_scoped_required({"scopedProfileRequired": True}))
            self.assertFalse(evidence_gate._active_scoped_required({"image": "other"}))
            with self.assertRaises(evidence_gate.EvidenceError):
                evidence_gate._scoped_phase({"image": "docker-29-conformance-rootless"}, {})


class NativeWiring(unittest.TestCase):
    def test_only_detached_declared_systemd_guest_gets_profile_after_durable_intent(self) -> None:
        import shutil  # noqa: PLC0415

        from scripts.runtime_tests import RuntimeContext  # noqa: PLC0415

        ctx = RuntimeContext(
            image="docker-29-conformance-rootless",
            architecture="amd64",
            timeout=30,
            use_sudo=False,
            outer_engine="docker",
        )
        try:
            events: list[str] = []
            ctx.declared_launcher = "systemd"
            ctx.backend.ready, ctx.backend.network_id = True, "a" * 64
            ctx.backend.scoped_profile = Mock()

            def create_options() -> tuple[str, ...]:
                events.append("durable-create-intent")
                return (
                    "--security-opt",
                    "apparmor=exact-generated-profile",
                    "--label",
                    "io.strukturpiloten.userns-profile=lease",
                )

            ctx.backend.scoped_profile.create_options.side_effect = create_options
            ctx.backend.admit_container = Mock()
            ctx._prefix = Mock(return_value=["docker"])

            def command(_name: str, arguments: list[str], **_kwargs: object) -> str:
                events.append("docker-run")
                cidfile = Path(arguments[arguments.index("--cidfile") + 1])
                first = events.count("docker-run") == 1
                identifier = ("b" if first else "c") * 64
                cidfile.write_text(identifier)
                ctx.checks.append({"status": "passed", "exitCode": 0})
                if first:
                    self.assertIn("apparmor=exact-generated-profile", arguments)
                else:
                    self.assertNotIn("apparmor=exact-generated-profile", arguments)
                return identifier

            ctx.command = command
            ctx.podman("systemd guest", "run", "--detach", ctx.image_ref)
            ctx.podman("direct fixture check", "run", "--detach", ctx.image_ref, "true")
            self.assertEqual(events, ["durable-create-intent", "docker-run", "docker-run"])
            ctx.backend.scoped_profile.create_options.assert_called_once()
        finally:
            shutil.rmtree(ctx.directory)

    def test_endpoint_dependencies_survive_unknown_profile_cleanup_and_later_failures_remain_failures(self) -> None:
        from scripts.runtime_docker_backend import DockerBackend, DockerBackendError  # noqa: PLC0415

        for failure in (None, "guest-removal", "scoped-close"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                backend = DockerBackend(Path(temporary), ())
                backend.ready = True
                backend.scoped_profile = Mock()
                events: list[str] = []

                def effect(name: str, events: list[str] = events, failure: str | None = failure) -> None:
                    events.append(name)
                    if failure == name:
                        raise RuntimeError(name)

                backend._remove_containers = lambda _ctx: effect("guest-removal")
                backend.scoped_profile.close.side_effect = lambda: effect("scoped-close")
                backend._remove_network = lambda _ctx: effect("network-removal")
                backend._remove_images = lambda _ctx: effect("image-removal")
                if failure == "scoped-close":
                    with self.assertRaises(DockerBackendError):
                        backend._cleanup_resources(Mock())
                    self.assertEqual(events, ["guest-removal", "scoped-close"])
                else:
                    failures = backend._cleanup_resources(Mock())
                    self.assertEqual(failures, [failure] if failure else [])
                    self.assertEqual(events, ["guest-removal", "scoped-close", "network-removal", "image-removal"])


class ActiveSourceOwnership(unittest.TestCase):
    def test_active_closure_and_producer_select_conformance_image_and_have_single_pin_owners(self) -> None:
        import fnmatch  # noqa: PLC0415

        from scripts import container_engine  # noqa: PLC0415

        metadata = yaml.safe_load((ROOT / "images/docker/docker-29-conformance-rootless/container.yaml").read_text())
        patterns = (*metadata["inputs"], *container_engine.GLOBAL_IMAGE_INPUTS)
        for name in (
            *active.FILES,
            "scripts/docker_userns_active_client.py",
            "scripts/docker_userns_active_bootstrap_bundle.py",
            "scripts/docker_userns_bootstrap_bundle.py",
        ):
            with self.subTest(path=name):
                self.assertTrue(any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns))
        config = json.loads((ROOT / ".github/renovate.json").read_text())
        managers = [
            item
            for item in config["customManagers"]
            if any("docker-userns-policy-source" in value for value in item["managerFilePatterns"])
        ]
        self.assertEqual({item["datasourceTemplate"] for item in managers}, {"github-digest", "gitlab-tags"})
        self.assertEqual(len(managers), 2)
        self.assertTrue(
            all("active-admission" not in json.dumps(item["managerFilePatterns"]) for item in config["customManagers"])
        )
        rule = next(
            item
            for item in config["packageRules"]
            if item.get("matchFileNames") == [".github/docker-userns-policy-source.json"]
        )
        self.assertTrue(rule["dependencyDashboardApproval"])
        self.assertFalse(rule["automerge"])
        self.assertIn("docker-userns-active-admission.json", rule["description"])
        self.assertEqual(rule["groupName"], "Userns compile and unused source and parser review")

    def test_shared_action_activation_is_exact_candidate_and_literal_has_no_checkout_import(self) -> None:
        import subprocess  # noqa: PLC0415

        action = yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())
        step = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        context = step["env"]["ACTIVE_USERNS_CONTEXT"]
        for token in (
            "workflow_dispatch",
            "refs/heads/TheRealBecks/issue527",
            "docker-rootless-diagnostic",
            "smoke-build",
        ):
            self.assertIn(token, context)
        self.assertIn('[ "${IMAGE_NAME}" = "docker-29-conformance-rootless" ]', step["run"])
        self.assertIn('runtime_args+=(--active-userns-stage "${active_stage}")', step["run"])
        self.assertNotIn("${{", step["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])
        self.assertNotIn("import scripts", step["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])
        self.assertIn("candidate == workflow == checkout", step["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])
        self.assertIn("0o400", step["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])
        self.assertEqual(
            subprocess.run(
                ["/bin/bash", "-n"], input=step["run"], text=True, check=False, capture_output=True, timeout=3
            ).returncode,
            0,
        )

    def test_root_leaf_refuses_symlink_writeable_nonregular_and_overlong_sources(self) -> None:
        import stat  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as temporary:
            leaf = Path(temporary) / "source"
            leaf.write_bytes(b"verified source")
            leaf.chmod(0o400)
            real_fstat, real_lstat = os.fstat, Path.lstat

            def owned(info: os.stat_result) -> os.stat_result:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                patch.object(active.os, "fstat", side_effect=lambda descriptor: owned(real_fstat(descriptor))),
                patch.object(active.Path, "lstat", side_effect=lambda path: owned(real_lstat(path)), autospec=True),
            ):
                self.assertEqual(active.root_bytes(leaf), b"verified source")
                with self.assertRaises(active.RefusedError):
                    active.root_bytes(leaf, 2)
                leaf.chmod(stat.S_IRUSR | stat.S_IWGRP)
                with self.assertRaises(active.RefusedError):
                    active.root_bytes(leaf)
                leaf.chmod(0o400)
                link = Path(temporary) / "link"
                link.symlink_to(leaf)
                with self.assertRaises(OSError):
                    active.root_bytes(link)
                with self.assertRaises(active.RefusedError):
                    active.root_bytes(Path(temporary))


class ConcreteOwnerGuard(unittest.TestCase):
    def port(self) -> tuple[active.RootPort, dict[str, str]]:
        from dataclasses import replace  # noqa: PLC0415

        from scripts.docker_userns_custody import FileIdentity  # noqa: PLC0415

        port = active.RootPort.__new__(active.RootPort)
        port.binding = replace(binding(), deadline_ns=100_000_000_000)
        port.store = SimpleNamespace(path=Path("/run/stage/leases/" + "f" * 32))
        unit = port.owner_unit("owner")
        fields = {
            "LoadState": "loaded",
            "Description": port.binding.digest(),
            "Transient": "yes",
            "ActiveState": "active",
            "MainPID": "123",
            "ControlGroup": "/system.slice/" + unit,
            "KillMode": "control-group",
            "SendSIGKILL": "yes",
            "RemainAfterExit": "yes",
            "Restart": "no",
            "User": "root",
            "Group": "root",
            "Type": "exec",
            "Slice": "system.slice",
            "FragmentPath": "/run/systemd/transient/" + unit,
            "DropInPaths": "",
            "ActiveEnterTimestampMonotonic": "1000000",
            "RuntimeMaxUSec": "50s",
            "TimeoutStopUSec": "1s",
        }
        port.record = {"ownerIntents": {"owner": {"runtimeUs": 50_000_000}}, "owners": {"owner": {"pid": 123}}}
        port.owner_handle = lambda _kind: os.open("/dev/null", os.O_RDONLY)
        port.query = lambda _arguments: "".join(f"{key}={value}\n" for key, value in fields.items()).encode()
        port.modules = SimpleNamespace(
            host=SimpleNamespace(
                read_root=Mock(return_value=(b"fixed fragment", FileIdentity(1, 2, 0, 0o100600, 1, 14, 3, 4)))
            )
        )
        port.commit = Mock()
        return port, fields

    def test_live_exact_owner_and_fragment_positive_and_drift_refusals(self) -> None:
        with patch.object(active.select, "select", return_value=([], [], [])):
            port, _fields = self.port()
            port.verify_owner("owner")
            port.verify_owner("owner")
            self.assertEqual(port.record["ownerFragments"]["owner"]["sha256"], active.digest(b"fixed fragment"))
            port.modules.host.read_root.return_value = (b"changed", port.modules.host.read_root.return_value[1])
            with self.assertRaises(active.RefusedError):
                port.verify_owner("owner")
            for key, value in (
                ("DropInPaths", "/etc/systemd/system/override.conf"),
                ("User", "runner"),
                ("Restart", "always"),
                ("FragmentPath", ""),
                ("Type", "simple"),
                ("Slice", "foreign.slice"),
                ("Transient", "no"),
                ("ActiveEnterTimestampMonotonic", "60000000"),
                ("TimeoutStopUSec", "2s"),
            ):
                with self.subTest(key=key):
                    port, fields = self.port()
                    fields[key] = value
                    with self.assertRaises(active.RefusedError):
                        port.verify_owner("owner")

    def test_duration_and_pidfd_liveness_refuse_unknowns(self) -> None:
        self.assertEqual(active.duration_us("1min 2s 4ms 1us"), 62_004_001)
        for value in ("infinity", "1.5s", "1s 1min", "1s 1s", "garbage", ""):
            with self.subTest(value=value), self.assertRaises(active.RefusedError):
                active.duration_us(value)
        port, _fields = self.port()
        with (
            patch.object(active.select, "select", side_effect=lambda readers, *_args: (readers, [], [])),
            self.assertRaises(active.RefusedError),
        ):
            port.verify_owner("owner")


class ConcreteBoundedOperations(unittest.TestCase):
    def test_reader_ownership_unknown_never_clears_durable_pending_marker(self) -> None:
        for teardown in (True, False):
            with self.subTest(teardown=teardown):
                port = active.RootPort.__new__(active.RootPort)
                port.binding, port.work_until, port.cleanup, port.provider = binding(), 900, False, "/usr/bin/timeout"
                port.record, port.commit = {"readerPending": False}, Mock()
                capture = Mock(
                    return_value={
                        "teardownVerified": teardown,
                        "status": "available",
                        "data": base64.b64encode(b"private").decode(),
                    }
                )
                port.modules = SimpleNamespace(capture=SimpleNamespace(_query_capture=capture))
                with patch.object(active, "check"):
                    if teardown:
                        self.assertEqual(port.query(["/fixed/command"], pass_fds=(11, 12)), b"private")
                    else:
                        with self.assertRaises(active.RefusedError):
                            port.query(["/fixed/command"], pass_fds=(11, 12))
                self.assertEqual(port.record["readerPending"], not teardown)
                self.assertEqual(capture.call_args.kwargs["pass_fds"], (11, 12))
                self.assertEqual(capture.call_args.args[0][:2], ["/usr/bin/env", "-i"])

    def test_held_parser_descriptors_cross_existing_owned_query_guard_without_changing_default_calls(self) -> None:
        from scripts import runtime_docker_diagnostics as capture  # noqa: PLC0415

        with (
            patch.object(capture.time, "monotonic", return_value=10),
            patch.object(capture.subprocess, "Popen") as spawn,
        ):
            capture._spawn_query(
                ["/proc/self/fd/11", "--add", "/proc/self/fd/12"], 100, 90, "/usr/bin/timeout", pass_fds=(11, 12)
            )
            self.assertEqual(spawn.call_args.kwargs["pass_fds"], (11, 12))
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            self.assertEqual(spawn.call_args.args[0][-3:], ["/proc/self/fd/11", "--add", "/proc/self/fd/12"])
            capture._spawn_query(["/fixed/command"], 100, 90, "/usr/bin/timeout")
            self.assertNotIn("pass_fds", spawn.call_args.kwargs)

    def test_actual_private_image_identity_must_match_before_loading(self) -> None:
        port = active.RootPort.__new__(active.RootPort)
        port.record = {}
        port.binding = binding()
        image = {
            "Id": binding().config_digest,
            "Architecture": "amd64",
            "Os": "linux",
            "Config": {"Labels": {"org.opencontainers.image.revision": binding().candidate}},
        }
        port.docker = lambda *_args: json.dumps(image).encode()
        port.image()
        for key, value in (("Id", "sha256:" + "0" * 64), ("Architecture", "arm64"), ("Os", "other")):
            original = image[key]
            image[key] = value
            with self.subTest(key=key), self.assertRaises(active.RefusedError):
                port.image()
            image[key] = original
        image["Config"]["Labels"]["org.opencontainers.image.revision"] = "0" * 40
        with self.assertRaises(active.RefusedError):
            port.image()

    def test_ordinary_cleanup_keeps_original_failure_order_without_active_authority(self) -> None:
        from scripts.runtime_docker_backend import DockerBackend  # noqa: PLC0415

        backend = DockerBackend(Path("/unused-hermetic-runtime"), ())
        backend.ready = True
        backend._remove_containers = Mock(side_effect=RuntimeError("guest removal failed"))
        backend._remove_network, backend._remove_images = Mock(), Mock()
        self.assertEqual(backend._cleanup_resources(Mock()), ["guest removal failed"])
        backend._remove_network.assert_not_called()
        backend._remove_images.assert_not_called()


def candidate_environment(selected: str = "a" * 40) -> dict[str, str]:
    """Supply the existing diagnostic workflow envelope without creating a native job."""
    return {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "GITHUB_REPOSITORY": "Strukturpiloten/containers",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/TheRealBecks/issue527",
        "GITHUB_JOB": "smoke-build",
        "ImageOS": "ubuntu26",
        "GITHUB_WORKFLOW_REF": "Strukturpiloten/containers/.github/workflows/ci.yml@refs/heads/TheRealBecks/issue527",
        "GITHUB_SHA": selected,
        "GITHUB_WORKFLOW_SHA": selected,
        "GITHUB_RUN_ID": "1",
        "GITHUB_RUN_ATTEMPT": "2",
        "ImageVersion": "20261026.180.1",
        "GITHUB_EVENT_PATH": "/home/runner/work/_temp/_github_workflow/event.json",
    }


class DiagnosticCaseScope(unittest.TestCase):
    def test_known_ascii_variants_keep_root_proof_and_raw_client_provenance(self) -> None:

        from scripts.docker_userns_active_client import ActiveClient  # noqa: PLC0415

        for requested in ("docker-rootless-diagnostic", "DOCKER-ROOTLESS-DIAGNOSTIC", "DoCkEr-RoOtLeSs-DiAgNoStIc"):
            with self.subTest(requested=requested):
                proof, root = SyntheticProof(), literal_namespace()
                root["SOURCE_MANIFEST_SHA256"] = active.digest(proof.files[producer.MANIFEST])
                environment = candidate_environment(proof.candidate)
                event = json.dumps({"inputs": {"validation_profile": requested}}).encode()
                with (
                    event_payload(event),
                    patch.dict(os.environ, environment, clear=True),
                ):
                    produced = producer.context(environment, "amd64")
                    self.assertEqual(produced["validationProfileRequested"], requested)
                    self.assertEqual(produced["validationProfile"], "docker-rootless-diagnostic")
                    self.assertEqual(root["validation_profile"](requested), produced["validationProfile"])
                    proof.context = produced
                    self.assertEqual(
                        root["verify_bundle"](json.dumps(proof.value()).encode(), produced)[0], proof.files
                    )
                    fixture = binding()
                    ctx = SimpleNamespace(
                        architecture="amd64",
                        name=fixture.image,
                        runtime_phase=fixture.phase,
                        runtime_deadline=1000,
                        backend=SimpleNamespace(
                            owner=fixture.owner,
                            slice=fixture.runtime_slice,
                            slice_identity=fixture.slice_identity,
                            timeout_executable=lambda: "/usr/bin/timeout",
                            directory=Path(tempfile.gettempdir()) / "strukturpiloten-runtime-fixture",
                            privileged=lambda command, _seconds: command,
                        ),
                    )
                    identity = {
                        "archiveSha256": fixture.archive_sha256,
                        "manifestDigest": fixture.manifest_digest,
                        "configDigest": fixture.config_digest,
                    }
                    client = ActiveClient(ctx, "/run/containers-userns-active." + "f" * 32, identity)
                    response = scoped_receipt(candidate=proof.candidate, requested=requested)
                    response.update(binding=asdict(client.binding), bindingSha256=client.binding.digest())
                    ctx.command = Mock(side_effect=lambda *_args, response=response, **_kwargs: json.dumps(response))
                    client.prepare()
                    self.assertEqual(client.evidence["validationProfileRequested"], requested)
                    response["validationProfileRequested"] = requested.swapcase()
                    with self.assertRaises(ValueError):
                        client.rpc("close", {})

    def test_accepted_upper_and_mixed_requests_cannot_skip_missing_scoped_receipt(self) -> None:
        import io  # noqa: PLC0415

        from scripts import evidence_gate  # noqa: PLC0415

        for requested in ("DOCKER-ROOTLESS-DIAGNOSTIC", "DoCkEr-RoOtLeSs-DiAgNoStIc"):
            for required in (None, False):
                with self.subTest(requested=requested, required=required):
                    record = {
                        "image": binding().image,
                        "imageIdentity": {},
                        "phases": [
                            {"phase": name, "status": "passed", "cleanupVerified": True, "imageIdentity": {}}
                            for name in ("clean-control", "enforcement")
                        ],
                    }
                    if required is not None:
                        record["scopedProfileRequired"] = required
                    event = json.dumps({"inputs": {"validation_profile": requested}}).encode()
                    with (
                        patch.object(
                            Path, "open", side_effect=lambda *_args, event=event, **_kwargs: io.BytesIO(event)
                        ),
                        patch.dict(os.environ, candidate_environment(), clear=True),
                    ):
                        self.assertTrue(evidence_gate._active_scoped_required(record))
                        with self.assertRaisesRegex(evidence_gate.EvidenceError, "lacks scoped qualification evidence"):
                            evidence_gate._systemd_phase_backends(
                                record, "docker", {"launcher": "systemd", "mode": "rootless"}
                            )

    def test_unknown_or_non_ascii_requests_fail_closed_and_full_remains_full(self) -> None:

        from scripts import evidence_gate  # noqa: PLC0415
        from scripts.docker_userns_qualification import QualificationError, validation_profile  # noqa: PLC0415

        root = literal_namespace()
        for requested in (
            "unknown",
            " docker-rootless-diagnostic",
            "docker-rootless-diagnostic\n",
            "D\u041eCKER-ROOTLESS-DIAGNOSTIC",
            None,
            True,
            {},
        ):
            with self.subTest(requested=requested):
                with self.assertRaises(QualificationError):
                    validation_profile(requested)
                with self.assertRaises(ValueError):
                    root["validation_profile"](requested)
                event = json.dumps({"inputs": {"validation_profile": requested}}).encode()
                with (
                    event_payload(event),
                    patch.dict(os.environ, candidate_environment(), clear=True),
                ):
                    with self.assertRaises((QualificationError, ValueError)):
                        producer.context(dict(os.environ), "amd64")
                    with self.assertRaises(evidence_gate.EvidenceError):
                        evidence_gate._active_scoped_required(
                            {"image": binding().image, "scopedProfileRequired": False}
                        )
        for requested in ("full", "FuLl", ""):
            with self.subTest(requested=requested):
                self.assertEqual(validation_profile(requested), "full")
                self.assertEqual(root["validation_profile"](requested), "full")
                event = json.dumps({"inputs": {"validation_profile": requested}}).encode()
                with (
                    event_payload(event),
                    patch.dict(os.environ, candidate_environment(), clear=True),
                ):
                    self.assertFalse(evidence_gate._active_scoped_required({"image": binding().image}))


class ContendedOwnerFixture:
    """Exercise actual nonblocking flock with one held coordinator lock and pipe pidfd stand-in."""

    def __init__(self, *, duration: float = 1.0) -> None:
        """Allocate only disposable files, descriptors and a bounded Python thread."""
        import fcntl  # noqa: PLC0415
        import threading  # noqa: PLC0415
        import time  # noqa: PLC0415
        from contextlib import contextmanager  # noqa: PLC0415
        from dataclasses import replace  # noqa: PLC0415

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        self.scratch = tempfile.TemporaryDirectory()
        self.path = Path(self.scratch.name)
        (self.path / "lock").write_bytes(b"")
        self.store = active.Store.__new__(active.Store)
        self.store.path = self.path
        info = self.path.stat()
        self.store.identity = info.st_dev, info.st_ino
        self.store.descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.store.lock = os.open(self.path / "lock", os.O_RDWR)
        self.holder = os.open(self.path / "lock", os.O_RDWR)
        fcntl.flock(self.holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.coordinator, self.death = os.pipe()
        self.fds = [self.store.descriptor, self.store.lock, self.holder, self.coordinator, self.death]
        self.cancelled = [False]
        self.busy, self.done = threading.Event(), threading.Event()
        self.outcome: list[object] = []
        now = time.monotonic_ns()
        fixture = replace(binding(), deadline_ns=now + int(duration * 1_000_000_000))
        record = {
            "state": "loaded",
            "readerPending": False,
            "childPending": False,
            "retained": False,
            "container": None,
        }
        self.store.write(record)
        self.port = SimpleNamespace(
            store=self.store,
            binding=fixture,
            work_until=now + 20_000_000,
            record=record,
            cleanup=False,
            guard=Mock(),
            remove_subject=Mock(),
            unload=Mock(),
            modules=SimpleNamespace(qualification=qualification),
        )

        def retain() -> None:
            self.port.record.update(state="retained", retained=True)
            self.store.write(self.port.record)

        def persist(state: object, _container: object) -> None:
            self.port.record["state"] = state.value
            self.store.write(self.port.record)

        self.port.retain, self.port.persist = Mock(side_effect=retain), Mock(side_effect=persist)
        original_locked = self.store.locked

        @contextmanager
        def observed_lock() -> Iterator[None]:
            try:
                with original_locked():
                    yield
            except BlockingIOError:
                self.busy.set()
                raise

        self.store.locked = observed_lock
        self.reader = patch.object(
            active, "root_bytes", side_effect=lambda path, _limit=active.MAX_STATE: Path(path).read_bytes()
        )
        self.reader.start()
        self.thread = None

    def __enter__(self) -> Self:
        """Keep the fixture and held coordinator lock alive through assertions."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Never leave a thread or descriptor behind after an assertion fails."""
        self.unlock()
        if self.thread is not None:
            self.thread.join(1)
        self.reader.stop()
        for descriptor in self.fds:
            os.close(descriptor)
        self.scratch.cleanup()

    def unlock(self) -> None:
        """Release only the coordinator's own held lock, never force another actor."""
        import fcntl  # noqa: PLC0415

        fcntl.flock(self.holder, fcntl.LOCK_UN)

    def start(self) -> None:
        """Run the real owner loop without launching any policy or runtime command."""
        import threading  # noqa: PLC0415

        def run() -> None:
            try:
                self.outcome.append(active.owner_loop(self.port, self.coordinator, "owner", self.cancelled))
            except BaseException as error:  # noqa: BLE001 - surface thread failures to the test.
                self.outcome.append(error)
            finally:
                self.done.set()

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def release(self) -> None:
        """Publish the exact close/release handshake while still holding the lock."""
        self.store.write(
            {
                "state": "closed",
                "guestAbsenceVerified": True,
                "profileAbsenceVerified": True,
                "retained": False,
                "readerPending": False,
                "childPending": False,
            }
        )
        active.write_leaf(self.path, "owner-release", (self.port.binding.digest() + "\n").encode())


class FinalizerLockContention(unittest.TestCase):
    def test_cleanup_can_hold_lock_across_work_cutoff_and_complete_release_within_original_deadline(self) -> None:
        with ContendedOwnerFixture() as fixture:
            fixture.start()
            self.assertTrue(fixture.busy.wait(0.3))
            fixture.release()
            self.assertTrue(fixture.done.wait(0.3))
            self.assertEqual(fixture.outcome, [0])
            receipt = json.loads((fixture.path / "owner-closed.json").read_bytes())
            self.assertEqual(receipt["cause"], "normal")
            self.assertEqual(receipt["deadlineNs"], fixture.port.binding.deadline_ns)
            fixture.port.guard.assert_not_called()
            fixture.port.unload.assert_not_called()
            self.assertFalse((fixture.path / "owner-retained.json").exists())
            with self.assertRaises(BlockingIOError), fixture.store.locked():
                self.fail("owner forced coordinator lock release")

    def test_cancellation_or_coordinator_death_is_sticky_during_contention_and_release(self) -> None:
        for cause in ("cancelled", "coordinator-dead"):
            with self.subTest(cause=cause), ContendedOwnerFixture() as fixture:
                if cause == "cancelled":
                    fixture.cancelled[0] = True
                else:
                    os.write(fixture.death, b"x")
                fixture.start()
                self.assertTrue(fixture.busy.wait(0.3))
                fixture.cancelled[0] = False
                fixture.release()
                self.assertTrue(fixture.done.wait(0.3))
                self.assertEqual(fixture.outcome, [1])
                self.assertEqual(json.loads((fixture.path / "owner-retained.json").read_bytes())["cause"], cause)
                self.assertFalse((fixture.path / "owner-closed.json").exists())
                fixture.port.unload.assert_not_called()
                with self.assertRaises(active.RefusedError):
                    fixture.store.read()

    def test_expiry_retries_until_lock_is_released_and_keeps_successful_emergency_cleanup_nonqualifying(self) -> None:
        with ContendedOwnerFixture() as fixture:
            fixture.start()
            self.assertTrue(fixture.busy.wait(0.3))
            fixture.unlock()
            self.assertTrue(fixture.done.wait(0.3))
            self.assertEqual(fixture.outcome, [1])
            fixture.port.guard.assert_called_once_with(fixture.port.binding)
            fixture.port.remove_subject.assert_called_once_with(None)
            fixture.port.unload.assert_called_once()
            fixture.port.retain.assert_called_once()
            self.assertEqual(json.loads((fixture.path / "owner-retained.json").read_bytes())["cause"], "work-expired")

    def test_deadline_exhaustion_retains_without_forcing_lock_and_late_release_cannot_clear_it(self) -> None:
        with ContendedOwnerFixture(duration=0.3) as fixture:
            fixture.start()
            self.assertTrue(fixture.busy.wait(0.2))
            self.assertTrue(fixture.done.wait(0.6))
            self.assertEqual(fixture.outcome, [1])
            marker = json.loads((fixture.path / "owner-retained.json").read_bytes())
            self.assertEqual(marker["cause"], "deadline")
            self.assertEqual(marker["deadlineNs"], fixture.port.binding.deadline_ns)
            fixture.release()
            self.assertFalse((fixture.path / "owner-closed.json").exists())
            fixture.port.guard.assert_not_called()
            fixture.port.unload.assert_not_called()
            with self.assertRaises(active.RefusedError):
                fixture.store.read()
            with self.assertRaises(BlockingIOError), fixture.store.locked():
                self.fail("expired owner forced coordinator lock release")

    def test_cleanup_effect_blocking_error_is_not_retried_as_lock_contention(self) -> None:
        import errno  # noqa: PLC0415

        with ContendedOwnerFixture() as fixture:
            fixture.port.guard.side_effect = BlockingIOError(errno.EAGAIN, "uncertain effect")
            fixture.start()
            self.assertTrue(fixture.busy.wait(0.3))
            fixture.unlock()
            self.assertTrue(fixture.done.wait(0.3))
            self.assertEqual(fixture.outcome, [1])
            fixture.port.guard.assert_called_once()
            fixture.port.retain.assert_called_once()
            fixture.port.unload.assert_not_called()
            self.assertEqual(
                json.loads((fixture.path / "owner-retained.json").read_bytes())["cause"], "cleanup-unverified"
            )


class DurableTerminalCancellation(unittest.TestCase):
    def test_causes_arriving_during_terminal_fsync_make_existing_normal_leaf_inadmissible(self) -> None:
        from scripts import evidence_gate  # noqa: PLC0415

        for late in (None, "cancelled", "coordinator-dead", "deadline"):
            with self.subTest(late=late), ContendedOwnerFixture() as fixture:
                fixture.release()
                result, injected = self._terminal_run(fixture, late)
                self.assertEqual(injected, [late])
                normal = json.loads((fixture.path / "owner-closed.json").read_bytes())
                self.assertEqual(normal["cause"], "normal")
                self.assertEqual(normal["deadlineNs"], fixture.port.binding.deadline_ns)
                if late is None:
                    self.assertEqual(result, 0)
                    self.assertFalse((fixture.path / "owner-retained.json").exists())
                    self.assertEqual(fixture.store.read()["state"], "closed")
                    continue
                self.assertEqual(result, 1)
                marker = json.loads((fixture.path / "owner-retained.json").read_bytes())
                self.assertEqual(marker["cause"], late)
                self.assertEqual(marker["deadlineNs"], fixture.port.binding.deadline_ns)
                with self.assertRaises(active.RefusedError):
                    fixture.store.read()
                fixture.port.guard.assert_not_called()
                fixture.port.unload.assert_not_called()
                self.assert_root_close_refused(fixture, result)
                record, phase = QualificationEvidence().fixture()
                phase["scopedProfile"].update(ownerTerminationVerified=False, custodyDisposed=False, retained=True)
                with patch.dict(os.environ, {}, clear=True), self.assertRaises(evidence_gate.EvidenceError):
                    evidence_gate._scoped_phase(record, phase)

    def _terminal_run(self, fixture: ContendedOwnerFixture, late: str | None) -> tuple[int, list[str | None]]:
        """Inject an event inside the terminal file fsync, rather than before its precheck."""
        original_write, original_fsync = active.write_leaf, os.fsync
        clock = [fixture.port.work_until - 1]
        writing_terminal, injected = [False], []

        def write(directory: Path, name: str, raw: bytes, mode: int = active.IMMUTABLE_FILE) -> None:
            writing_terminal[0] = name == "owner-closed.json"
            try:
                original_write(directory, name, raw, mode)
            finally:
                writing_terminal[0] = False

        def fsync(descriptor: int) -> None:
            original_fsync(descriptor)
            if writing_terminal[0] and not injected:
                injected.append(late)
                if late == "cancelled":
                    # The real SIGTERM/SIGINT owner handler sets this same latch.
                    fixture.cancelled[0] = True
                elif late == "coordinator-dead":
                    os.write(fixture.death, b"x")
                elif late == "deadline":
                    clock[0] = fixture.port.binding.deadline_ns

        with (
            patch.object(active, "write_leaf", side_effect=write),
            patch.object(active.os, "fsync", side_effect=fsync),
            patch.object(active.time, "monotonic_ns", side_effect=lambda: clock[0]),
        ):
            result = active.owner_loop(fixture.port, fixture.coordinator, "owner", fixture.cancelled)
        return result, injected

    def assert_root_close_refused(self, fixture: ContendedOwnerFixture, result: int) -> None:
        """Use the actual root dispose/owner-status guard; a normal leaf alone cannot close custody."""
        port = active.RootPort.__new__(active.RootPort)
        port.binding, port.store = fixture.port.binding, fixture.store
        port.record = {
            "state": "closed",
            "readerPending": False,
            "childPending": False,
            "retained": False,
            "guestAbsenceVerified": True,
            "profileAbsenceVerified": True,
        }
        port.owner_handle = lambda _kind: os.open("/dev/null", os.O_RDONLY)
        port.verify_owner, port.commit = Mock(), Mock()
        properties = {
            "Description": port.binding.digest(),
            "Transient": "yes",
            "MainPID": "0",
            "ActiveState": "active",
            "SubState": "exited",
            "ExecMainCode": "1",
            "ExecMainStatus": str(result),
        }
        port.query = Mock(return_value="".join(f"{key}={value}\n" for key, value in properties.items()).encode())

        def already_released(directory: Path, name: str, raw: bytes) -> None:
            self.assertEqual(name, "owner-release")
            self.assertEqual((directory / name).read_bytes(), raw)

        with (
            patch.object(active, "write_leaf", side_effect=already_released),
            patch.object(active.select, "select", side_effect=lambda readers, *_args: (readers, [], [])),
            self.assertRaises(active.RefusedError),
        ):
            port.dispose()
        self.assertEqual(port.query.call_count, 1)
        self.assertNotIn("ownerTerminationVerified", port.record)
        self.assertNotIn("custodyDisposed", port.record)
        self.assertTrue(fixture.path.is_dir())
        self.assertTrue((fixture.path / "owner-closed.json").is_file())
        self.assertTrue((fixture.path / "owner-retained.json").is_file())


class TrustedOsReleaseAlias(unittest.TestCase):
    def test_reviewed_alias_uses_strict_canonical_read_and_refuses_unsafe_mutable_or_missing_target(self) -> None:
        import stat  # noqa: PLC0415

        from scripts import docker_userns_hosted as host  # noqa: PLC0415

        for fault in (None, "alias-owner", "target-mode", "target-mutation", "alias-mutation", "missing-target"):
            with self.subTest(fault=fault):
                self._alias_case(fault, host, stat)

    def _alias_case(self, fault: str | None, host: object, stat: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc").mkdir()
            (root / "lib").mkdir()
            target = root / "lib/os-release"
            target.write_bytes(b'ID=ubuntu\nVERSION_ID="26.04"\n')
            target.chmod(0o400)
            second = root / "lib/other-release"
            second.write_bytes(b"ID=other\n")
            second.chmod(0o400)
            alias = root / "etc/os-release"
            alias.symlink_to("../lib/os-release")
            self._prepare_alias_fault(fault, target)
            original_lstat, original_fstat = Path.lstat, os.fstat
            original_safe, original_read, original_bytes = host.safe_path, host.read_root, host.child.bytes_at

            def trusted(info: os.stat_result, path: Path | None = None) -> SimpleNamespace:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_uid"] = 1000 if fault == "alias-owner" and path == alias else 0
                if path is not None and path != root and root not in path.parents and stat.S_ISDIR(info.st_mode):
                    fields["st_mode"] &= ~0o022
                return SimpleNamespace(**fields)

            def lstat(path: Path) -> SimpleNamespace:
                return trusted(original_lstat(path), path)

            def resolve(path: Path, *args: object, **kwargs: object) -> Path:
                return original_safe(alias if path == Path("/etc/os-release") else path, *args, **kwargs)

            def bounded(descriptor: int, limit: int, **kwargs: object) -> bytes:
                raw = original_bytes(descriptor, limit, **kwargs)
                if fault == "target-mutation":
                    target.chmod(0o600)
                    target.write_bytes(b"changed\n")
                    target.chmod(0o400)
                return raw

            def read(path: Path, *args: object, **kwargs: object) -> tuple[bytes, object]:
                self.assertEqual(path, target)
                result = original_read(path, *args, **kwargs)
                if fault == "alias-mutation":
                    alias.unlink()
                    alias.symlink_to("../lib/other-release")
                return result

            with (
                patch.object(Path, "lstat", autospec=True, side_effect=lstat),
                patch.object(host.os, "fstat", side_effect=lambda descriptor: trusted(original_fstat(descriptor))),
                patch.object(host, "safe_path", side_effect=resolve),
                patch.object(host, "read_root", side_effect=read),
                patch.object(host.child, "bytes_at", side_effect=bounded),
            ):
                if fault is None:
                    raw, identity = active.os_release(SimpleNamespace(host=host))
                    self.assertEqual(raw, b'ID=ubuntu\nVERSION_ID="26.04"\n')
                    self.assertEqual(identity.owner, 0)
                else:
                    with self.assertRaises(
                        (OSError, active.RefusedError, host.custody.CustodyError, host.child.ChildError)
                    ):
                        active.os_release(SimpleNamespace(host=host))

    @staticmethod
    def _prepare_alias_fault(fault: str | None, target: Path) -> None:
        if fault == "target-mode":
            target.chmod(0o422)
        if fault == "missing-target":
            target.unlink()


def failure_port() -> active.RootPort:
    """Use actual journal persistence/retention with inert external-effect ports."""
    from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

    port = active.RootPort.__new__(active.RootPort)
    port.binding = binding()
    port.record = {
        "state": "prepared",
        "lastDurablePhase": "prepared",
        "lastIntent": None,
        "attemptedPhase": None,
        "generation": 0,
        "readerPending": False,
        "childPending": False,
        "retained": False,
        "diagnostic": {"phase": "admission", "comparisons": {}},
    }
    port.durable = "prepared", None
    port.store = SimpleNamespace(write=Mock())
    port.clean_owner = lambda _binding: None
    port.arm = lambda _binding: port.record.update(ownerReady=True)
    port.guard = lambda _binding: None
    port.load = Mock()
    port.modules = SimpleNamespace(qualification=qualification)
    return port


class BoundedFailureJournal(unittest.TestCase):
    def test_distinct_failure_boundaries_preserve_intent_and_never_authorize_unknown_cleanup(self) -> None:
        for fault, expected_state, expected_intent, phase in (
            ("admission", "prepared", None, "admission"),
            ("owner", "arm-intent", "arm-intent", "owner-active"),
            ("before-load", "armed", "arm-intent", "namespace"),
            ("after-parser", "load-intent", "load-intent", "registry-present"),
        ):
            with self.subTest(fault=fault):
                self._boundary_case(fault, (expected_state, expected_intent, phase))

    def _boundary_case(self, fault: str, expected: tuple[str, str | None, str]) -> None:
        import errno  # noqa: PLC0415

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        expected_state, expected_intent, phase = expected
        port = failure_port()
        parser = Mock()

        def admit(_binding: object) -> None:
            port.point("admission")
            if fault == "admission":
                raise PermissionError(errno.EACCES, PRIVATE)

        def arm(_binding: object) -> None:
            port.point("owner-active")
            port.record["ownerIntents"] = {"owner": {}}
            port.commit()
            if fault == "owner":
                raise FileNotFoundError(errno.ENOENT, PRIVATE)
            port.record["ownerReady"] = True

        def guard(_binding: object) -> None:
            if fault == "before-load":
                port.point("namespace")
                raise active.RefusedError(PRIVATE)

        def load() -> None:
            port.point("parser-add")
            parser()
            active.comparison(port.point("registry-present"), "registry-present", matched=False)

        port.admit, port.arm, port.guard, port.load = admit, arm, guard, load
        lease = qualification.ProfileLease(binding(), port)
        with self.assertRaises((active.RefusedError, OSError)) as raised:
            lease.prepare()
        before = port.record["lastDurablePhase"], port.record["lastIntent"]
        port.retain()
        self.assertEqual(before, (expected_state, expected_intent))
        self.assertEqual((port.record["lastDurablePhase"], port.record["lastIntent"]), before)
        self.assertEqual(port.record["state"], "retained")
        with self.assertRaises(active.RefusedError):
            port.persist(qualification.State.LOADED, None)
        with self.assertRaises(qualification.QualificationError):
            lease.close()
        value = active.failure_receipt(
            {
                "actor": "root",
                "operation": "prepare",
                "binding": binding(),
                "sourceVerified": True,
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                "lease": "f" * 32,
                "record": port.record,
            },
            raised.exception,
        )
        self.assertTrue(active.valid_failure(value))
        self.assertEqual(value["phase"], phase)
        self.assertEqual(value["lastDurablePhase"], expected_state)
        self.assertEqual(value["lastIntent"], expected_intent)
        self.assertFalse(value["cleanupAuthority"])
        self.assertNotIn(PRIVATE, active.encoded(value).decode())
        self.assertEqual(parser.call_count, 1 if fault == "after-parser" else 0)

    def test_partial_preflight_records_only_already_completed_safe_comparisons(self) -> None:
        import errno  # noqa: PLC0415

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        admission = (ROOT / ".github/docker-userns-active-admission.json").read_bytes()
        manifest = (ROOT / ".github/docker-userns-policy-source.json").read_bytes()
        context = SyntheticProof().context
        context.update(candidate="a" * 40, workflow="a" * 40, checkout="a" * 40)
        progress: dict[str, object] = {}
        host = SimpleNamespace(
            safe_path=Mock(return_value=Path("/canonical/os-release")),
            read_root=Mock(
                side_effect=[(b'ID=ubuntu\nVERSION_ID="26.04"\n', None), PermissionError(errno.EACCES, PRIVATE)]
            ),
        )
        modules = SimpleNamespace(
            host=host,
            qualification=SimpleNamespace(
                validation_profile=qualification.validation_profile,
                admission_document=qualification.admission_document,
                active_cohort=qualification.active_cohort,
                validate_workflow_context=qualification.validate_workflow_context,
                QualificationError=qualification.QualificationError,
                observe_controls=Mock(
                    return_value=qualification.HostControls(
                        enabled=True, restricted_userns=1, maximum_userns=1024, legacy_clone=None
                    )
                ),
            ),
        )
        cohort = json.loads(admission)["cohorts"]["amd64"]
        with (
            patch.object(
                active,
                "root_bytes",
                side_effect=lambda path, *_args: admission if path.name.endswith("active-admission.json") else manifest,
            ),
            patch.object(
                active.os, "uname", return_value=SimpleNamespace(machine=cohort["machine"], release=cohort["kernel"])
            ),
            patch.object(active, "check"),
            self.assertRaises(PermissionError),
        ):
            active.root_preflight(ROOT, {"context": context, "deadlineNs": 10**18}, modules, progress=progress)
        self.assertEqual(progress["phase"], "preflight-parser-hash")
        self.assertEqual(
            progress["comparisons"],
            dict.fromkeys(
                (
                    "preflight-source",
                    "preflight-os-release",
                    "preflight-os-values",
                    "preflight-host",
                    "preflight-controls",
                ),
                True,
            ),
        )
        self.assertNotIn(PRIVATE, json.dumps(progress))

    def test_failed_durable_write_preserves_last_acknowledged_intent_and_retention_latch(self) -> None:
        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        port = failure_port()
        port.store.write.side_effect = OSError("private filesystem failure")
        with self.assertRaises(OSError):
            port.persist(qualification.State.ARM_INTENT, None)
        self.assertEqual(port.record["lastDurablePhase"], "prepared")
        self.assertIsNone(port.record["lastIntent"])
        self.assertEqual(port.record["attemptedPhase"], "arm-intent")
        self.assertTrue(port.record["durabilityUnknown"])
        port.store.write.side_effect = None
        port.retain()
        self.assertTrue(port.record["retained"])
        self.assertEqual(port.record["lastDurablePhase"], "prepared")
        self.assertIsNone(port.record["lastIntent"])
        projected = active.failure_receipt(
            {
                "actor": "root",
                "operation": "prepare",
                "binding": binding(),
                "sourceVerified": True,
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                "record": port.record,
            },
            OSError("private fsync failure"),
        )
        self.assertTrue(active.valid_failure(projected))
        self.assertEqual(projected["lastDurablePhase"], "prepared")
        self.assertIsNone(projected["lastIntent"])
        self.assertEqual(projected["attemptedPhase"], "arm-intent")
        self.assertTrue(projected["durabilityUnknown"])
        self.assertFalse(projected["cleanupAuthority"])


def client_fixture(directory: Path) -> ActiveClient:
    """Construct the unprivileged response boundary without launching a root command."""
    from scripts.docker_userns_active_client import ActiveClient  # noqa: PLC0415

    client = ActiveClient.__new__(ActiveClient)
    client.binding, client.stage, client.name = binding(), Path("/run/containers-userns-active." + "e" * 32), "new"
    client.provenance = workflow_context()
    client.evidence, client.failures = {}, []
    client.ctx = SimpleNamespace(
        checks=[],
        scoped_failure_output=directory / "failure.json",
        backend=SimpleNamespace(
            privileged=lambda command, _seconds: command,
            directory=directory,
            timeout_executable=lambda: "/usr/bin/timeout",
        ),
    )
    return client


def bound_root_failure() -> dict[str, object]:
    """Use a real finite failure projection from an unknown load-intent record."""
    record = {
        "state": "retained",
        "lastDurablePhase": "load-intent",
        "lastIntent": "load-intent",
        "attemptedPhase": "load-intent",
        "retained": True,
        "readerPending": True,
        "childPending": False,
        "ownerReady": True,
        "diagnostic": {"phase": "parser-add", "comparisons": {"preflight-source": True}},
    }
    return active.failure_receipt(
        {
            "actor": "root",
            "operation": "prepare",
            "binding": binding(),
            "sourceVerified": True,
            "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
            "record": record,
            "lease": "f" * 32,
        },
        active.RefusedError(PRIVATE),
    )


class FailureTransport(unittest.TestCase):
    def test_nonzero_error_is_captured_before_teardown_and_reporting_lease_grants_no_cleanup(self) -> None:
        from scripts.runtime_docker_backend import DockerBackend, DockerBackendError  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            client = client_fixture(directory)
            value = bound_root_failure()

            def command(_name: str, _command: list[str], **kwargs: object) -> str:
                self.assertFalse(kwargs["check"])
                client.ctx.checks.append(
                    {"exitCode": 1, "status": "failed", "stdout": PRIVATE, "stderr": PRIVATE, "error": PRIVATE}
                )
                return json.dumps(value)

            client.ctx.command = Mock(side_effect=command)
            with self.assertRaises(ValueError):
                client.prepare()
            self.assertEqual(client.name, "new")
            self.assertEqual(client.evidence["failures"][0], value)
            self.assertEqual(value["reportingLease"], "f" * 32)
            self.assertFalse(value["cleanupAuthority"])
            self.assertNotIn(PRIVATE, client.ctx.scoped_failure_output.read_text())
            self.assertNotIn(PRIVATE, json.dumps(client.ctx.checks))
            from scripts import evidence_gate  # noqa: PLC0415

            record, phase = QualificationEvidence().fixture()
            phase["scopedProfile"] = client.evidence
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(evidence_gate.EvidenceError):
                evidence_gate._scoped_phase(record, phase)
            backend = DockerBackend(directory, ())
            backend.ready, backend.scoped_profile = True, client
            backend._remove_containers, backend._remove_network, backend._remove_images, backend.stop_services = (
                Mock(),
                Mock(),
                Mock(),
                Mock(),
            )
            with self.assertRaises(DockerBackendError):
                backend.cleanup(client.ctx)
            client.ctx.command.assert_called_once()
            backend.stop_services.assert_not_called()
            backend._remove_network.assert_not_called()
            self.assertTrue(directory.is_dir())

    def test_malformed_oversized_mismatched_and_error_on_success_exit_all_fail_closed(self) -> None:
        values: list[tuple[object, str]] = [
            (PRIVATE, "malformed-receipt"),
            (PRIVATE * active.MAX_STATE, "oversized-receipt"),
            ([PRIVATE], "malformed-receipt"),
        ]
        for key, replacement in (
            ("bindingSha256", "0" * 64),
            ("sourceManifestSha256", "0" * 64),
            ("operation", "close"),
            ("phase", [PRIVATE]),
            ("comparisons", {PRIVATE: True}),
            ("cleanupAuthority", True),
            ("schemaVersion", True),
        ):
            value = bound_root_failure()
            value[key] = replacement
            values.append((value, "receipt-mismatch"))
        for raw, reason in values:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                client = client_fixture(Path(temporary))
                client.ctx.command = Mock(return_value=raw if type(raw) is str else json.dumps(raw))
                with self.assertRaises(ValueError):
                    client.rpc("prepare", {})
                failure = client.evidence["failures"][0]
                self.assertEqual(failure["actor"], "client")
                self.assertEqual(failure["reason"], reason)
                self.assertNotIn(PRIVATE, client.ctx.scoped_failure_output.read_text())
                self.assertEqual(client.name, "new")
        with tempfile.TemporaryDirectory() as temporary:
            client = client_fixture(Path(temporary))
            client.ctx.command = Mock(return_value=json.dumps(bound_root_failure()))
            client.ctx.checks.append({"exitCode": 0})
            with self.assertRaises(ValueError):
                client.rpc("prepare", {})
            self.assertEqual(client.evidence["status"], "failed")

    def test_producer_and_bootstrap_emit_only_executed_closed_failure_receipts(self) -> None:
        import io  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "failure.json"
            stdout = SimpleNamespace(buffer=io.BytesIO())
            with (
                patch.object(producer, "bundle", side_effect=PermissionError(13, PRIVATE)),
                patch.object(
                    producer.sys,
                    "argv",
                    [
                        "producer",
                        "--architecture",
                        "amd64",
                        "--output",
                        str(Path(temporary) / "bundle.json"),
                        "--failure-output",
                        str(output),
                    ],
                ),
                patch.object(producer.sys, "stdout", stdout),
            ):
                self.assertEqual(producer.main(), 1)
            value = json.loads(output.read_bytes())
            self.assertEqual(value["actor"], "producer")
            self.assertEqual(value["phase"], "producer-context")
            self.assertEqual(value["reason"], "permission-denied")
            self.assertNotIn(PRIVATE, stdout.buffer.getvalue().decode())
            scope = literal_namespace()
            scope["sys"] = SimpleNamespace(stdout=SimpleNamespace(buffer=io.BytesIO()))
            scope["failure"](PermissionError(13, PRIVATE))
            emitted = scope["sys"].stdout.buffer.getvalue()
            value = json.loads(emitted)
            self.assertTrue(active.valid_failure(value))
            self.assertEqual(value["actor"], "root-bootstrap")
            self.assertEqual(value["phase"], "bootstrap-entry")
            self.assertIsNone(value["context"])
            self.assertNotIn(PRIVATE, emitted.decode())


class FailureBoundaryEmission(unittest.TestCase):
    def test_root_catch_emits_bound_journal_without_exception_text(self) -> None:
        import io  # noqa: PLC0415
        from contextlib import nullcontext  # noqa: PLC0415

        stdout = SimpleNamespace(buffer=io.BytesIO())
        context = SyntheticProof().context
        context.update(candidate="a" * 40, workflow="a" * 40, checkout="a" * 40)
        bootstrap = {
            "context": context,
            "files": {".github/docker-userns-policy-source.json": active.SOURCE_MANIFEST_SHA256},
        }

        def refuse(_stage: Path, _bootstrap: object, _modules: object, route: object) -> object:
            route.diagnostic.update(
                binding=binding(),
                lease="f" * 32,
                record={
                    "lastDurablePhase": "arm-intent",
                    "lastIntent": "arm-intent",
                    "readerPending": True,
                    "childPending": False,
                    "retained": True,
                    "diagnostic": {"phase": "owner-active", "comparisons": {"preflight-source": True}},
                },
            )
            raise PermissionError(13, PRIVATE)

        with (
            patch.object(active.sys, "argv", ["root", "prepare", "/run/unused-stage"]),
            patch.object(active.sys, "stdout", stdout),
            patch.object(active, "verify_stage", return_value=bootstrap),
            patch.object(active, "dependencies", return_value=SimpleNamespace()),
            patch.object(active, "stage_lock", return_value=nullcontext()),
            patch.object(active, "root_rpc", side_effect=refuse),
        ):
            self.assertEqual(active.main(), 1)
        value = json.loads(stdout.buffer.getvalue())
        self.assertTrue(active.valid_failure(value))
        self.assertEqual(value["actor"], "root")
        self.assertEqual(value["bindingSha256"], binding().digest())
        self.assertEqual(value["phase"], "owner-active")
        self.assertEqual(value["lastIntent"], "arm-intent")
        self.assertEqual(value["reason"], "permission-denied")
        self.assertNotIn(PRIVATE, stdout.buffer.getvalue().decode())

    def test_always_upload_covers_pre_runtime_producer_and_bootstrap_failure_files(self) -> None:
        action = yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        upload = next(step for step in action["runs"]["steps"] if step.get("name") == "Upload runtime evidence")
        self.assertIn("always()", upload["if"])
        self.assertIn("-userns-failure.json", upload["with"]["path"])
        self.assertIn('--failure-output "${active_failure}"', runtime["run"])
        self.assertIn('if active_stage="$(sudo', runtime["run"])
        self.assertIn("execution-unverified", runtime["run"])
        self.assertIn('value["actor"]!="root-bootstrap"', runtime["run"])
        self.assertIn("failure(error)", runtime["env"]["FIXED_ACTIVE_ROOT_BOOTSTRAP"])


class InitialJournalDurability(unittest.TestCase):
    def test_initial_success_acknowledges_only_after_store_returns(self) -> None:
        record = {"state": "prepared", "lastDurablePhase": "prepared", "lastIntent": None, "durabilityUnknown": False}
        progress: dict[str, object] = {}

        def write(value: dict[str, object]) -> None:
            self.assertIs(progress["record"], value)
            self.assertIsNone(value["lastDurablePhase"])
            self.assertTrue(value["durabilityUnknown"])

        active.initialize_record(SimpleNamespace(write=Mock(side_effect=write)), record, progress)
        self.assertEqual(record["lastDurablePhase"], "prepared")
        self.assertIsNone(record["lastIntent"])
        self.assertFalse(record["durabilityUnknown"])

    def test_initial_replace_then_directory_fsync_failure_keeps_known_record_and_unknown_ack(self) -> None:
        import errno  # noqa: PLC0415
        from dataclasses import asdict  # noqa: PLC0415

        from scripts import docker_userns_qualification as qualification  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            path = stage / "leases" / ("f" * 32)
            path.mkdir(parents=True)
            (path / "lock").write_bytes(b"")
            store = active.Store.__new__(active.Store)
            store.path = path
            info = path.stat()
            store.identity = info.st_dev, info.st_ino
            store.descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            store.lock = os.open(path / "lock", os.O_RDWR)
            record = {
                "binding": asdict(binding()),
                "state": "prepared",
                "lastDurablePhase": "prepared",
                "lastIntent": None,
                "attemptedPhase": None,
                "durabilityUnknown": False,
                "readerPending": False,
                "childPending": False,
                "retained": False,
                "diagnostic": {"phase": "store-open", "comparisons": {}},
            }
            progress = {
                "actor": "root",
                "operation": "prepare",
                "sourceVerified": True,
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
            }
            route = SimpleNamespace(operation="prepare", name="new", request="e30=", diagnostic=progress)
            real_replace, real_fsync = os.replace, os.fsync
            replacements: list[bool] = []

            def replace(*args: object, **kwargs: object) -> None:
                real_replace(*args, **kwargs)
                replacements.append(True)

            def fsync(descriptor: int) -> None:
                if descriptor == store.descriptor and replacements:
                    raise OSError(errno.EIO, PRIVATE)
                real_fsync(descriptor)

            def prepared(*_args: object, **kwargs: object) -> dict[str, object]:
                kwargs["progress"]["binding"] = binding()
                return record

            with (
                patch.object(active, "Store", return_value=store),
                patch.object(active.secrets, "token_hex", return_value="f" * 32),
                patch.object(active, "new_record", side_effect=prepared),
                patch.object(active, "RootPort") as root_port,
                patch.object(active.os, "replace", side_effect=replace),
                patch.object(active.os, "fsync", side_effect=fsync),
                self.assertRaises(OSError) as raised,
            ):
                active.root_rpc(stage, {}, SimpleNamespace(qualification=qualification), route)
            self.assertEqual(replacements, [True])
            self.assertTrue((path / "state.json").is_file())
            self.assertEqual(
                {
                    key: json.loads((path / "state.json").read_bytes())[key]
                    for key in ("lastDurablePhase", "durabilityUnknown")
                },
                {"lastDurablePhase": None, "durabilityUnknown": True},
            )
            self.assertIs(progress["record"], record)
            self.assertEqual(
                (
                    record["durabilityUnknown"],
                    record["lastDurablePhase"],
                    record["lastIntent"],
                    record["attemptedPhase"],
                ),
                (True, None, None, "prepared"),
            )
            root_port.assert_not_called()
            value = active.failure_receipt(progress, raised.exception)
            self.assertTrue(active.valid_failure(value))
            self.assertEqual(value["context"]["phase"], binding().phase)
            self.assertEqual(value["bindingSha256"], binding().digest())
            self.assertTrue(value["durabilityUnknown"])
            self.assertIsNone(value["lastDurablePhase"])
            self.assertIsNone(value["lastIntent"])
            self.assertFalse(value["readerPending"])
            self.assertFalse(value["childPending"])
            self.assertEqual(value["ownerDisposition"], "not-recorded")
            self.assertFalse(value["cleanupAuthority"])
            self.assertNotIn(PRIVATE, active.encoded(value).decode())


class ExistingChildBuildObservation(unittest.TestCase):
    def test_existing_build_exports_exact_lifetimes_and_sealed_finite_failures_without_cleanup(self) -> None:
        from scripts import docker_userns_custody_child as child  # noqa: PLC0415

        for lifetime in (child.Lifetime.NEVER_STARTED, child.Lifetime.UNKNOWN, child.Lifetime.DEAD):
            with self.subTest(lifetime=lifetime):
                self._build_case(child, lifetime)

    def _build_case(self, child: object, lifetime: object) -> None:
        import time  # noqa: PLC0415
        from dataclasses import replace  # noqa: PLC0415

        port = failure_port()
        port.modules = SimpleNamespace(child=child)
        port.record.update(profileName="dockerlens-127-upstream-rootless-1-2-" + "e" * 32, childPending=True)
        port.bootstrap, port.admission = (
            {"uid": 1001, "gid": 1001},
            {"cohorts": {"amd64": {"interpreterSha256": "a" * 64}}},
        )
        port.binding = replace(binding(), deadline_ns=time.monotonic_ns() + 90_000_000_000)
        port.work_until = port.binding.deadline_ns - 60_000_000_000
        observers: list[object] = []

        def preflight(
            _interpreter: object, _sources: object, _lease: object, _clock: object, *, observer: object
        ) -> object:
            self.assertIs(type(observer), child.WorkObserver)
            self.assertIsNone(observer.snapshot())
            observers.append(observer)
            if lifetime is child.Lifetime.NEVER_STARTED:
                with child.work(observer, "CHILD_PARENT", "B_PREFLIGHT_G01", (child.ChildError,)):
                    raise child.ChildError
            return (), 1

        def execute(_arguments: object, observer: object) -> object:
            if lifetime is child.Lifetime.UNKNOWN:
                with child.work(observer, "CHILD_PARENT", "B_CAPTURE_W01", (child.ChildError,)):
                    raise child.ChildError(lifetime=lifetime) from ValueError(PRIVATE)
            return PRIVATE.encode(), PRIVATE.encode(), 111, child.Lifetime.DEAD

        with (
            patch.object(child, "_preflight", side_effect=preflight),
            patch.object(child, "_execute_observed", side_effect=execute) as capture,
            patch.object(child, "_build_status_pair", return_value=("EXIT_NONZERO", "MATCH")),
            patch.object(child, "_declared_guard", return_value="FD_FSTAT_NON_EBADF"),
            self.assertRaises(child.ChildError) as raised,
        ):
            port.build_policy(91, (), port.binding)
        self.assertIs(raised.exception.lifetime, lifetime)
        self.assertEqual(len(observers), 1)
        self.assertIsNotNone(observers[0].snapshot())
        self.assertEqual(capture.call_count, 0 if lifetime is child.Lifetime.NEVER_STARTED else 1)
        port.retain()
        value = active.failure_receipt(
            {
                "actor": "root",
                "operation": "prepare",
                "binding": port.binding,
                "sourceVerified": True,
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                "record": port.record,
            },
            raised.exception,
        )
        self.assertTrue(active.valid_failure(value, child=child))
        self.assertEqual(value["childBuild"]["lifetime"], lifetime.value)
        self.assertTrue(value["childPending"])
        self.assertTrue(value["retained"])
        self.assertFalse(value["cleanupAuthority"])
        from scripts.docker_userns_qualification import State  # noqa: PLC0415

        with self.assertRaises(active.RefusedError):
            port.persist(State.LOADED, None)
        self.assertNotIn(PRIVATE, active.encoded(value).decode())
        if lifetime is child.Lifetime.DEAD:
            self.assertEqual(
                value["childBuild"]["status"], {"schema": 1, "terminationForm": "EXIT_NONZERO", "receiptCheck": "MATCH"}
            )
            self.assertEqual(value["childBuild"]["guard"], {"schema": 1, "category": "FD_FSTAT_NON_EBADF"})
        else:
            self.assertIsNone(value["childBuild"]["status"])
            self.assertIsNone(value["childBuild"]["guard"])

    def test_untrusted_or_malformed_observer_fields_are_never_exported(self) -> None:
        from scripts import docker_userns_custody_child as child  # noqa: PLC0415

        error = child.ChildError(lifetime=child.Lifetime.UNKNOWN)
        authored = SimpleNamespace(
            snapshot=lambda: PRIVATE, status_snapshot=lambda: (PRIVATE, PRIVATE), guard_snapshot=lambda: PRIVATE
        )
        self.assertEqual(
            active.sealed_child_build(child, authored, error),
            {"lifetime": "unknown", "work": None, "status": None, "guard": None},
        )
        observer = child.WorkObserver()
        self.assertEqual(
            active.sealed_child_build(child, observer, error),
            {"lifetime": "unknown", "work": None, "status": None, "guard": None},
        )
        with (
            patch.object(
                child.WorkObserver,
                "snapshot",
                return_value={"schema": 1, "context": PRIVATE, "site": PRIVATE, "failure": PRIVATE},
            ),
            patch.object(child.WorkObserver, "status_snapshot", return_value=(PRIVATE, PRIVATE)),
            patch.object(child.WorkObserver, "guard_snapshot", return_value=PRIVATE),
        ):
            self.assertEqual(
                active.sealed_child_build(child, observer, error),
                {"lifetime": "unknown", "work": None, "status": None, "guard": None},
            )
        error.lifetime = PRIVATE
        self.assertIsNone(active.sealed_child_build(child, authored, error))
        for key in ("lifetime", "work", "status", "guard"):
            value = bound_root_failure()
            value["childBuild"] = {"lifetime": "unknown", "work": None, "status": None, "guard": None}
            value["childBuild"][key] = PRIVATE
            self.assertFalse(active.valid_failure(value, child=child))
            record = {"diagnostic": {"phase": "builder"}, "childBuild": value["childBuild"]}
            self.assertNotIn("childBuild", active.failure_receipt({"record": record}, error))

    def test_valid_child_detail_survives_client_capture_but_still_denies_cleanup(self) -> None:
        from scripts import docker_userns_custody_child as child  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as temporary:
            client = client_fixture(Path(temporary))
            value = bound_root_failure()
            value["childBuild"] = {"lifetime": child.Lifetime.DEAD.value, "work": None, "status": None, "guard": None}
            client.ctx.command = Mock(return_value=json.dumps(value))
            with self.assertRaises(ValueError):
                client.rpc("prepare", {})
            self.assertEqual(client.evidence["failures"][0]["childBuild"], value["childBuild"])
            self.assertEqual(client.name, "new")
            self.assertFalse(client.evidence["cleanupAuthority"])
            with self.assertRaises(ValueError):
                client.close()
            client.ctx.command.assert_called_once()


class ProducerValidationPhases(unittest.TestCase):
    def test_image_os_refusals_classify_only_explicit_values_and_read_once(self) -> None:
        class Environment(dict):
            def get(self, key: str, default: str | None = None) -> str | None:
                if key == "ImageOS":
                    self.reads += 1
                return super().get(key, default)

            reads = 0

        cases = (
            (None, "producer-image-os-missing"),
            ("", "producer-image-os-empty"),
            ("ubuntu20", "producer-image-os-ubuntu20"),
            ("ubuntu22", "producer-image-os-ubuntu22"),
            ("ubuntu24", "producer-image-os-ubuntu24"),
            ("ubuntu20-arm", "producer-image-os-ubuntu20-arm"),
            ("ubuntu22-arm", "producer-image-os-ubuntu22-arm"),
            ("ubuntu24-arm", "producer-image-os-ubuntu24-arm"),
            ("ubuntu26-arm", "producer-image-os-ubuntu26-arm"),
            ("ubuntu20-arm64", "producer-image-os-ubuntu20-arm64"),
            ("ubuntu22-arm64", "producer-image-os-ubuntu22-arm64"),
            ("ubuntu24-arm64", "producer-image-os-ubuntu24-arm64"),
            ("ubuntu26-arm64", "producer-image-os-ubuntu26-arm64"),
            (PRIVATE, "producer-image-os-other"),
            ("ubuntu260", "producer-image-os-other"),
        )
        for actual, expected_phase in cases:
            with self.subTest(phase=expected_phase):
                environment = Environment(candidate_environment())
                if actual is None:
                    del environment["ImageOS"]
                else:
                    environment["ImageOS"] = actual
                progress = {"actor": "producer", "operation": "producer"}
                with self.assertRaises(ValueError) as raised:
                    producer.context(environment, "amd64", progress=progress)
                value = active.failure_receipt(progress, raised.exception)
                self.assertTrue(active.valid_failure(value))
                self.assertEqual(value["phase"], expected_phase)
                self.assertEqual(environment.reads, 1)
                self.assertNotIn(PRIVATE, active.encoded(value).decode())

    def test_each_existing_environment_refusal_has_a_finite_phase_without_values(self) -> None:
        cases = {
            "GITHUB_ACTIONS": "producer-runner-identity",
            "RUNNER_ENVIRONMENT": "producer-runner-identity",
            "RUNNER_OS": "producer-runner-identity",
            "GITHUB_REPOSITORY": "producer-repository",
            "GITHUB_EVENT_NAME": "producer-workflow",
            "GITHUB_REF": "producer-workflow",
            "GITHUB_JOB": "producer-workflow",
            "ImageOS": "producer-image-os-other",
            "GITHUB_WORKFLOW_REF": "producer-workflow-ref",
            "RUNNER_ARCH": "producer-architecture",
            "GITHUB_SHA": "producer-candidate",
            "GITHUB_WORKFLOW_SHA": "producer-candidate",
            "GITHUB_RUN_ID": "producer-run-attempt",
            "GITHUB_RUN_ATTEMPT": "producer-run-attempt",
            "ImageVersion": "producer-image-version",
            "GITHUB_EVENT_PATH": "producer-event-path",
        }
        for key, phase in cases.items():
            with self.subTest(key=key):
                environment = {**candidate_environment(), key: PRIVATE}
                progress = {"actor": "producer", "operation": "producer"}
                with self.assertRaises(ValueError) as raised:
                    producer.context(environment, "amd64", progress=progress)
                value = active.failure_receipt(progress, raised.exception)
                self.assertTrue(active.valid_failure(value))
                self.assertEqual(value["phase"], phase)
                self.assertNotIn(PRIVATE, active.encoded(value).decode())
        progress = {"actor": "producer", "operation": "producer"}
        with self.assertRaises(ValueError):
            producer.context(candidate_environment(), "invalid", progress=progress)
        self.assertEqual(progress["phase"], "producer-architecture")

    def test_event_read_and_choice_failures_remain_distinct_and_arm_expected_values_unchanged(self) -> None:

        progress = {"actor": "producer", "operation": "producer"}
        with patch.object(Path, "open", side_effect=PermissionError(13, PRIVATE)), self.assertRaises(PermissionError):
            producer.context(candidate_environment(), "amd64", progress=progress)
        self.assertEqual(progress["phase"], "producer-event-read")
        raw = json.dumps({"inputs": {"validation_profile": PRIVATE}}).encode()
        with (
            event_payload(raw),
            self.assertRaises(producer.QualificationError),
        ):
            producer.context(candidate_environment(), "amd64", progress=progress)
        self.assertEqual(progress["phase"], "producer-choice")
        environment = {**candidate_environment(), "RUNNER_ARCH": "ARM64", "ImageOS": "ubuntu26-arm64"}
        raw = json.dumps({"inputs": {"validation_profile": "docker-rootless-diagnostic"}}).encode()
        with event_payload(raw):
            accepted = producer.context(environment, "arm64", progress=progress)
        self.assertEqual(accepted["architecture"], "arm64")
        self.assertEqual(accepted["imageOS"], "ubuntu26-arm64")
        self.assertNotIn(PRIVATE, json.dumps(progress))


class ARMReportedProvenance(unittest.TestCase):
    def test_producer_fixed_bootstrap_and_shared_root_agree_on_both_exact_pairs(self) -> None:

        for architecture, image_os, runner_arch in (("amd64", "ubuntu26", "X64"), ("arm64", "ubuntu26-arm64", "ARM64")):
            with self.subTest(architecture=architecture):
                environment = {**candidate_environment(), "ImageOS": image_os, "RUNNER_ARCH": runner_arch}
                event = json.dumps({"inputs": {"validation_profile": "docker-rootless-diagnostic"}}).encode()
                with event_payload(event):
                    produced = producer.context(environment, architecture)
                self.assertEqual(produced["imageOS"], image_os)
                literal = literal_namespace()
                literal["sys"] = SimpleNamespace(
                    argv=[
                        "bootstrap",
                        "handoff",
                        *(environment["GITHUB_SHA"] for _ in range(3)),
                        "1",
                        "2",
                        architecture,
                        environment["ImageVersion"],
                        "1000",
                        "1000",
                        "1000000000",
                        environment["GITHUB_REPOSITORY"],
                        environment["GITHUB_EVENT_NAME"],
                        environment["GITHUB_REF"],
                        environment["GITHUB_WORKFLOW_REF"],
                        environment["GITHUB_JOB"],
                        "docker-29-conformance-rootless",
                        "",
                    ],
                    implementation=SimpleNamespace(name="cpython"),
                    version_info=(3, 14, 4, "final", 0),
                    flags=SimpleNamespace(isolated=1, no_site=1),
                    dont_write_bytecode=True,
                )
                literal["os"] = SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0)
                literal["time"] = SimpleNamespace(monotonic_ns=lambda: 1)
                literal["read_input"] = Mock(return_value=event)
                stop = RuntimeError("stop before root stage creation")
                literal["verify_bundle"] = Mock(side_effect=stop)
                with self.assertRaises(RuntimeError) as raised:
                    literal["main"]()
                self.assertIs(raised.exception, stop)
                provisional = literal["verify_bundle"].call_args.args[1]
                self.assertEqual(
                    provisional,
                    {
                        key: value
                        for key, value in produced.items()
                        if key not in {"admissionRevision", "admissionSha256"}
                    },
                )
                admission = (ROOT / ".github/docker-userns-active-admission.json").read_bytes()
                manifest = (ROOT / producer.MANIFEST).read_bytes()
                with patch.object(
                    active,
                    "root_bytes",
                    side_effect=lambda path, admission=admission, manifest=manifest: (
                        admission if path.name.endswith("active-admission.json") else manifest
                    ),
                ):
                    self.assertEqual(
                        active.preflight_authority(
                            ROOT, {"context": produced}, SimpleNamespace(qualification=qualification)
                        ),
                        json.loads(admission),
                    )
                    crossed = {**produced, "imageOS": "ubuntu26" if architecture == "arm64" else "ubuntu26-arm64"}
                    with self.assertRaises(active.RefusedError):
                        active.preflight_authority(
                            ROOT, {"context": crossed}, SimpleNamespace(qualification=qualification)
                        )

    def test_crossed_missing_whitespace_and_unknown_aliases_refuse(self) -> None:
        for architecture, runner_arch, wrong_values in (
            ("amd64", "X64", (None, "", "ubuntu26-arm64", " ubuntu26", "ubuntu26 ", "ubuntu-26.04")),
            (
                "arm64",
                "ARM64",
                (None, "", "ubuntu26", "ubuntu26-arm", " ubuntu26-arm64", "ubuntu26-arm64 ", "ubuntu-26.04-arm64"),
            ),
        ):
            for wrong in wrong_values:
                with self.subTest(architecture=architecture, missing=wrong is None):
                    environment = {**candidate_environment(), "RUNNER_ARCH": runner_arch}
                    if wrong is None:
                        del environment["ImageOS"]
                    else:
                        environment["ImageOS"] = wrong
                    with self.assertRaises(ValueError):
                        producer.context(environment, architecture)
                    proof, literal = SyntheticProof(), literal_namespace()
                    trusted = {
                        **proof.context,
                        "architecture": architecture,
                        "imageOS": active.REPORTED_IMAGE_OS[architecture],
                    }
                    proof.context = {**trusted, "imageOS": wrong}
                    with self.assertRaises(ValueError):
                        literal["verify_bundle"](json.dumps(proof.value()).encode(), trusted)


def arm_observation_fixture() -> dict[str, object]:
    """Independently authored facts; private IDs are canaries, never observed host fixtures."""
    return {
        "reportedImageOS": "ubuntu26-arm64",
        "imageVersion": "20261027.123.1",
        "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
        "sourceFilesSha256": "6" * 64,
        "sourceManifestSha256": "7" * 64,
        "pythonVersion": [3, 14, 4, "final", 0],
        "pythonImplementation": "cpython",
        "toolTrust": "same-job-root-owned-preinstalled-tool-exception-not-compatibility-admission",
        "osID": "ubuntu",
        "osVersion": "26.04",
        "machine": "aarch64",
        "kernel": "7.0.0-fixture-arm64",
        "parserVersion": "5.0.2",
        "controls": {"enabled": True, "restricted_userns": 1, "maximum_userns": 58304, "legacy_clone": None},
        "files": {
            key: {
                "sha256": character * 64,
                "identity": {
                    "device": 8100000000000000211,
                    "inode": 8100000000000000323 + index,
                    "owner": 0,
                    "mode": 0o100755 if key in {"parserSha256", "interpreterSha256"} else 0o100644,
                    "links": 1,
                    "size": size,
                    "mtime_ns": 8100000000000000437,
                    "ctime_ns": 8100000000000000549,
                },
            }
            for index, (key, character, size) in enumerate(
                (
                    ("parserSha256", "a", 4096),
                    ("abiSha256", "b", 256),
                    ("namespaceMaskSha256", "c", 0),
                    ("policyVersion9Sha256", "d", 0),
                    ("interpreterSha256", "e", 8192),
                )
            )
        },
        "namespace": {
            "name": "1" * 64,
            "level": "2" * 64,
            "stacked": "3" * 64,
            "user": 8100000000000000651,
            "mnt": 8100000000000000763,
            "cgroup": 8100000000000000879,
        },
        "versionChild": {"lifetime": "proven-dead", "custody": "retired"},
    }


class ARMObservationProjection(unittest.TestCase):
    def test_complete_public_shape_and_all_values_are_independently_expected(self) -> None:
        facts = arm_observation_fixture()
        before = copy.deepcopy(facts)
        receipt = active.arm_observation_receipt({}, facts)
        expected = {
            "schemaVersion": 2,
            "consumer": active.CONSUMER,
            "kind": "arm-cohort-observation",
            "purpose": "public-nonqualifying-cohort-observation",
            "qualification": "none",
            "disposition": "ARM_NOT_ADMITTED",
            "activeAuthority": False,
            "cleanupAuthority": False,
            "nativeQualification": False,
            "complete": True,
            "context": None,
            "failure": None,
            "facts": {
                "reportedImageOS": "ubuntu26-arm64",
                "imageVersion": "20261027.123.1",
                "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
                "sourceFilesSha256": "6" * 64,
                "sourceManifestSha256": "7" * 64,
                "pythonVersion": [3, 14, 4, "final", 0],
                "pythonImplementation": "cpython",
                "toolTrust": "same-job-root-owned-preinstalled-tool-exception-not-compatibility-admission",
                "osID": "ubuntu",
                "osVersion": "26.04",
                "machine": "aarch64",
                "kernel": "7.0.0-fixture-arm64",
                "parserVersion": "5.0.2",
                "controls": {"enabled": True, "restricted_userns": 1, "maximum_userns": 58304, "legacy_clone": None},
                "files": {
                    key: {
                        "sha256": character * 64,
                        "metadataSize": size,
                        "rootOwned": True,
                        "regular": True,
                        "singleLink": True,
                        "notGroupOrWorldWritable": True,
                    }
                    for key, character, size in (
                        ("parserSha256", "a", 4096),
                        ("abiSha256", "b", 256),
                        ("namespaceMaskSha256", "c", 0),
                        ("policyVersion9Sha256", "d", 0),
                        ("interpreterSha256", "e", 8192),
                    )
                },
                "namespace": {"name": "1" * 64, "level": "2" * 64, "stacked": "3" * 64},
                "versionChild": {"lifetime": "proven-dead", "custody": "retired"},
            },
        }
        self.assertEqual(receipt, expected)
        self.assertEqual(facts, before)
        raw = active.encoded(receipt).decode()
        for number in (
            8100000000000000211,
            *(8100000000000000323 + index for index in range(5)),
            8100000000000000437,
            8100000000000000549,
            8100000000000000651,
            8100000000000000763,
            8100000000000000879,
        ):
            self.assertNotIn(str(number), raw)
        for key in (
            "identity",
            "device",
            "inode",
            "owner",
            "mtime_ns",
            "ctime_ns",
            "user",
            "mnt",
            "cgroup",
            "uid",
            "gid",
        ):
            self.assertNotIn('"' + key + '"', raw)
        self.assertLessEqual(len(raw), active.MAX_STATE)
        receipt["facts"]["pythonVersion"][0] = 99
        receipt["facts"]["controls"]["enabled"] = False
        receipt["facts"]["files"]["parserSha256"]["sha256"] = "0" * 64
        self.assertEqual(facts, before)

    def test_public_file_checks_are_metadata_derivations_not_assumed_admission(self) -> None:
        facts = arm_observation_fixture()
        facts["files"]["parserSha256"]["identity"].update(owner=42, mode=0o040777, links=2)
        public, _ = active.public_arm_observation(facts)
        self.assertEqual(
            public["files"]["parserSha256"],
            {
                "sha256": "a" * 64,
                "metadataSize": 4096,
                "rootOwned": False,
                "regular": False,
                "singleLink": False,
                "notGroupOrWorldWritable": False,
            },
        )

    def test_partial_facts_and_retained_child_never_claim_complete(self) -> None:
        full = arm_observation_fixture()
        cases = [
            {},
            {"osID": "ubuntu"},
            {"controls": {"enabled": False}},
            {"files": {"parserSha256": full["files"]["parserSha256"]}},
            {"namespace": {"name": "1" * 64}},
            {**full, "versionChild": {"lifetime": "unknown", "custody": "retained"}},
        ]
        for facts in cases:
            with self.subTest(fields=tuple(facts)):
                before = copy.deepcopy(facts)
                receipt = active.arm_observation_receipt({}, facts)
                self.assertFalse(receipt["complete"])
                self.assertIsNotNone(receipt["failure"])
                self.assertEqual(facts, before)
                self.assertFalse(
                    any(receipt[key] for key in ("activeAuthority", "cleanupAuthority", "nativeQualification"))
                )
        receipt = active.arm_observation_receipt({}, full, PermissionError(13, PRIVATE))
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["failure"]["reason"], "permission-denied")
        self.assertNotIn(PRIVATE, active.encoded(receipt).decode())

    def test_unknown_nested_fields_and_malformed_values_fail_closed_without_private_errors(self) -> None:
        mutations = (
            ((), PRIVATE, PRIVATE),
            (("files",), PRIVATE, PRIVATE),
            (("files", "parserSha256"), "raw", PRIVATE),
            (("files", "parserSha256", "identity"), PRIVATE, PRIVATE),
            (("controls",), PRIVATE, PRIVATE),
            (("namespace",), PRIVATE, PRIVATE),
            (("versionChild",), PRIVATE, PRIVATE),
            (("namespace",), "user", True),
            (("files", "parserSha256", "identity"), "owner", True),
            (("files", "parserSha256", "identity"), "size", 16 * 1024 * 1024 + 1),
            (("files", "parserSha256", "identity"), "ctime_ns", PRIVATE),
            (("files", "parserSha256"), "sha256", PRIVATE),
            ((), "pythonVersion", [3, True, 4, "final", 0]),
            ((), "sourceFilesSha256", PRIVATE),
            ((), "kernel", "/private/canary"),
            ((), "toolTrust", PRIVATE),
            (("controls",), "maximum_userns", -1),
            (("versionChild",), "custody", PRIVATE),
        )
        for path, key, value in mutations:
            facts = arm_observation_fixture()
            target = facts
            for part in path:
                target = target[part]
            target[key] = value
            before = copy.deepcopy(facts)
            with self.subTest(path=path, key=key):
                with self.assertRaises(active.RefusedError):
                    active.public_arm_observation(facts)
                receipt = active.arm_observation_receipt({}, facts)
                self.assertFalse(receipt["complete"])
                self.assertEqual(receipt["facts"], {})
                self.assertEqual(facts, before)
                self.assertNotIn(PRIVATE, active.encoded(receipt).decode())

    def test_arbitrary_objects_are_not_formatted_or_inspected(self) -> None:
        class PrivateObject:
            calls = 0

            def __repr__(self) -> str:
                self.calls += 1
                raise AssertionError(PRIVATE)

        canary = PrivateObject()
        for facts in (canary, {"files": {"parserSha256": canary}}, {"namespace": canary}, {"pythonVersion": canary}):
            receipt = active.arm_observation_receipt({}, facts)
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["facts"], {})
            self.assertNotIn(PRIVATE, active.encoded(receipt).decode())
        self.assertEqual(canary.calls, 0)

    def test_unchanged_active_client_rejects_both_observation_versions(self) -> None:
        public = active.arm_observation_receipt({}, arm_observation_fixture())
        historical = {**public, "schemaVersion": 1, "facts": arm_observation_fixture()}
        historical.pop("purpose")
        for receipt in (historical, public):
            with self.subTest(schema=receipt["schemaVersion"]), tempfile.TemporaryDirectory() as directory:
                client = client_fixture(Path(directory))
                client.ctx.command = Mock(return_value=json.dumps(receipt))
                with self.assertRaises(ValueError):
                    client.rpc("prepare", {})
                self.assertEqual(client.evidence["failures"][0]["reason"], "receipt-mismatch")
                self.assertFalse(client.evidence["cleanupAuthority"])
                self.assertEqual(client.name, "new")
                self.assertNotIn(PRIVATE, json.dumps(client.evidence))


class ARMObservationTests(unittest.TestCase):
    def bootstrap(self) -> dict[str, object]:
        context = {**SyntheticProof().context, "architecture": "arm64", "imageOS": "ubuntu26-arm64"}
        return {
            "context": context,
            "files": dict.fromkeys(active.FILES, "a" * 64),
            "stageIdentity": [1, 2],
            "uid": 1000,
            "gid": 1000,
            "deadlineNs": 10**18,
        }

    def observation_case(self, fault: str | None) -> dict[str, object]:
        admission = json.loads((ROOT / ".github/docker-userns-active-admission.json").read_bytes())
        with ExitStack() as stack:
            stack.enter_context(patch.object(active.Path, "iterdir", return_value=iter(())))
            bootstrap = self.bootstrap()
            progress = {
                "actor": "root",
                "operation": "observe-arm",
                "context": bootstrap["context"],
                "sourceVerified": True,
            }
            stack.enter_context(patch.object(active, "preflight_authority", return_value=admission))
            os_release = stack.enter_context(
                patch.object(active, "os_release", return_value=(b'ID=ubuntu\nVERSION_ID="26.10"\n', None))
            )
            if fault == "os":
                os_release.side_effect = PermissionError(13, PRIVATE)
            stack.enter_context(
                patch.object(
                    active.os, "uname", return_value=SimpleNamespace(machine="aarch64", release="7.1.9-arm-actual")
                )
            )

            def controls(_modules: object, _deadline: int, facts: dict[str, object]) -> None:
                facts["enabled"] = False
                if fault == "controls":
                    raise PermissionError(13, PRIVATE)
                facts["maximum_userns"] = 0
                facts["restricted_userns"] = 0
                facts["legacy_clone"] = None

            def files(
                _modules: object, progress: dict[str, object], facts: dict[str, object], _evaluate: object
            ) -> None:
                progress["phase"] = "preflight-parser-hash"
                values = arm_observation_fixture()["files"]
                facts["parserSha256"] = copy.deepcopy(values["parserSha256"])
                if fault == "files":
                    raise PermissionError(13, PRIVATE)
                facts.update(copy.deepcopy(values))

            def version(
                _stage: object,
                _bootstrap: object,
                _modules: object,
                facts: dict[str, object],
                progress: dict[str, object],
            ) -> None:
                progress["phase"] = "observation-parser-version"
                facts["versionChild"] = {"lifetime": "unknown", "custody": "retained"}
                if fault == "version":
                    raise KeyboardInterrupt
                facts.update(parserVersion="5.9.1", versionChild={"lifetime": "proven-dead", "custody": "retired"})

            stack.enter_context(patch.object(active, "observation_controls", side_effect=controls))
            stack.enter_context(patch.object(active, "collect_cohort_files", side_effect=files))
            namespace = stack.enter_context(
                patch.object(active, "namespace_snapshot", return_value=arm_observation_fixture()["namespace"])
            )
            if fault == "namespace":
                namespace.side_effect = PermissionError(13, PRIVATE)
            stack.enter_context(patch.object(active, "observation_version", side_effect=version))
            stack.enter_context(patch.object(active, "check"))
            active_operations = [
                stack.enter_context(patch.object(active, name)) for name in ("root_rpc", "compile_worker", "RootPort")
            ]
            lease = stack.enter_context(patch.object(qualification, "ProfileLease"))
            result = active.observe_arm(ROOT, bootstrap, SimpleNamespace(qualification=qualification), progress)
            for operation in (*active_operations, lease):
                operation.assert_not_called()
            return result

    def test_observation_collects_different_facts_without_admission_and_keeps_partial_errors(self) -> None:
        for fault in (None, "os", "controls", "files", "namespace", "version"):
            with self.subTest(fault=fault):
                result = self.observation_case(fault)
                self.assertEqual(result["complete"], fault is None)
                self.assertEqual(result["disposition"], "ARM_NOT_ADMITTED")
                self.assertEqual(result["qualification"], "none")
                self.assertFalse(
                    any(result[key] for key in ("activeAuthority", "cleanupAuthority", "nativeQualification"))
                )
                self.assertFalse(active.valid_failure(result))
                self.assertLessEqual(len(active.encoded(result)), active.MAX_STATE)
                self.assertNotIn(PRIVATE, active.encoded(result).decode())
                facts = result["facts"]
                if fault == "os":
                    self.assertNotIn("osID", facts)
                else:
                    self.assertEqual((facts["osVersion"], facts["kernel"]), ("26.10", "7.1.9-arm-actual"))
                if fault == "controls":
                    self.assertEqual(facts["controls"], {"enabled": False})
                    self.assertNotIn("files", facts)
                elif fault == "files":
                    self.assertEqual(set(facts["files"]), {"parserSha256"})
                    self.assertNotIn("namespace", facts)
                if fault is None:
                    self.assertEqual(facts["parserVersion"], "5.9.1")

    def test_control_observation_uses_same_fixed_reads_without_compatibility_admission(self) -> None:
        facts = {}
        with (
            patch.object(active, "check"),
            patch.object(
                qualification, "_fixed_read", side_effect=[b"N", b"0", b"0", FileNotFoundError(2, PRIVATE)]
            ) as read,
        ):
            active.observation_controls(SimpleNamespace(qualification=qualification), 100, facts)
        self.assertEqual(facts, {"enabled": False, "restricted_userns": 0, "maximum_userns": 0, "legacy_clone": None})
        self.assertEqual(
            [call.args[0] for call in read.call_args_list],
            [
                qualification.reader.ENABLED,
                qualification.reader.RESTRICT,
                qualification.reader.USERNS,
                qualification.LEGACY_CLONE,
            ],
        )
        facts = {}
        with (
            patch.object(active, "check"),
            patch.object(qualification, "_fixed_read", side_effect=[b"Y", PRIVATE.encode()]),
            self.assertRaises(qualification.QualificationError),
        ):
            active.observation_controls(SimpleNamespace(qualification=qualification), 100, facts)
        self.assertEqual(facts, {"enabled": True})

    def test_closed_observation_dispatch_cannot_replay_active_arguments(self) -> None:
        import io  # noqa: PLC0415

        for extra in ([], ["a" * 32], ["new", "owner"], ["--request", "eyJvcGVyYXRpb24iOiJwcmVwYXJlIn0="]):
            bootstrap = self.bootstrap()
            progress = {"context": bootstrap["context"]}
            observed = active.arm_observation_receipt(progress, {})
            stdout = SimpleNamespace(buffer=io.BytesIO())
            with (
                self.subTest(extra=extra),
                patch.object(active.sys, "argv", ["root", "observe-arm", "/run/unused-stage", *extra]),
                patch.object(active.sys, "stdout", stdout),
                patch.object(active, "verify_stage", return_value=bootstrap),
                patch.object(active, "dependencies", return_value=SimpleNamespace()),
                patch.object(active, "stage_lock", return_value=nullcontext()) as lock,
                patch.object(active, "observe_arm", return_value=observed) as observe,
                patch.object(active, "root_rpc") as rpc,
            ):
                self.assertEqual(active.main(), 1)
            lock.assert_called_once()
            self.assertEqual(observe.call_count, int(not extra))
            rpc.assert_not_called()
            result = json.loads(stdout.buffer.getvalue())
            self.assertEqual(result["kind"], "arm-cohort-observation")
            self.assertFalse(active.valid_failure(result))
            self.assertFalse(result["nativeQualification"])
        bootstrap["context"]["architecture"] = "amd64"
        with patch.object(active, "preflight_authority") as authority:
            self.assertFalse(
                active.observe_arm(ROOT, bootstrap, SimpleNamespace(qualification=qualification), progress)["complete"]
            )
        authority.assert_not_called()

    def test_action_observation_precedes_runtime_and_preserves_non_success_and_artifact(self) -> None:
        action = yaml.safe_load((ROOT / ".github/actions/build-arch-image/action.yml").read_text())
        runtime = next(step for step in action["runs"]["steps"] if step.get("name") == "Verify image runtime")
        upload = next(step for step in action["runs"]["steps"] if step.get("name") == "Upload runtime evidence")
        script = runtime["run"]
        start = script.index(
            'if [ "${IMAGE_ARCH}" = "arm64" ] && [ "${VALIDATION_PROFILE,,}" = docker-rootless-diagnostic ]; then'
        )
        stop = script.index('uv run --frozen --python "${PYTHON_VERSION}" python -m scripts.runtime_tests', start)
        self.assertIn('observe-arm "${active_stage}"', script[start:stop])
        self.assertIn("exit 1", script[start:stop])
        self.assertIn("-userns-observation.json", upload["with"]["path"])
        self.assertIn("always()", upload["if"])

    def test_arm_prepare_still_refuses_before_builder_owner_or_load(self) -> None:
        port = failure_port()
        port.binding = replace(port.binding, architecture="arm64")
        port.record["bindingSha256"] = port.binding.digest()
        port.bootstrap = {
            "context": {
                key: getattr(port.binding, key)
                for key in ("candidate", "run", "attempt", "job", "architecture", "image")
            },
            "deadlineNs": port.binding.deadline_ns,
        }
        port.admission = json.loads((ROOT / ".github/docker-userns-active-admission.json").read_bytes())
        port.preflight = Mock(return_value={})
        port.arm, port.build_policy = Mock(), Mock()
        with self.assertRaises(active.RefusedError):
            qualification.ProfileLease(port.binding, port).prepare()
        for effect in (port.arm, port.build_policy, port.load):
            effect.assert_not_called()
        self.assertFalse(port.record["diagnostic"]["comparisons"]["admission"])


class ARMObservationCustody(unittest.TestCase):
    @contextmanager
    def fixture(self, fault: str | None) -> Iterator[SimpleNamespace]:
        """Use real private files/fsync/markers with explicit fake root ownership and no child execution."""
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            stage = Path(temporary)
            leases = stage / "leases"
            leases.mkdir(mode=0o700)
            bootstrap_path = stage / "bootstrap.json"
            bootstrap_path.write_bytes(b"{}\n")
            bootstrap_path.chmod(0o400)
            interpreter, parser = stage / "python", stage / "parser"
            for path in (interpreter, parser):
                path.write_bytes(b"\x7fELF" + path.name.encode())
                path.chmod(0o500)
            original_fstat, original_lstat, original_open = os.fstat, Path.lstat, os.open

            def trusted(info: os.stat_result) -> SimpleNamespace:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_uid"] = 0
                return SimpleNamespace(**fields)

            def mapped(path: object) -> object:
                return parser if path == Path("/usr/sbin/apparmor_parser") else path

            def open_file(path: object, flags: int, *args: object, **kwargs: object) -> int:
                return original_open(mapped(path), flags, *args, **kwargs)

            stack.enter_context(patch.object(active, "PYTHON", str(interpreter)))
            stack.enter_context(
                patch.object(active.os, "fstat", side_effect=lambda descriptor: trusted(original_fstat(descriptor)))
            )
            stack.enter_context(
                patch.object(
                    active.Path, "lstat", autospec=True, side_effect=lambda path: trusted(original_lstat(mapped(path)))
                )
            )
            stack.enter_context(patch.object(active.os, "open", side_effect=open_file))
            sync = stack.enter_context(patch.object(active.os, "fsync", wraps=os.fsync))
            files = {
                key: {
                    "sha256": active.digest(path.read_bytes()),
                    "identity": asdict(host.identity(trusted(original_lstat(path)))),
                }
                for key, path in (("interpreterSha256", interpreter), ("parserSha256", parser))
            }
            facts = {"files": files}
            bootstrap = ARMObservationTests().bootstrap()
            bootstrap["stageIdentity"] = [stage.lstat().st_dev, stage.lstat().st_ino]
            progress = {}

            fixture = SimpleNamespace(
                leases=leases,
                files=files,
                interpreter=interpreter,
                parser=parser,
                bootstrap=bootstrap,
                sync=sync,
                stage=stage,
                fault=fault,
            )

            fake_child = SimpleNamespace(
                Interpreter=child.Interpreter,
                Build=child.Build,
                Outcome=child.Outcome,
                ChildError=child.ChildError,
                Lifetime=child.Lifetime,
                bytes_at=child.bytes_at,
                probe=Mock(side_effect=lambda *args: self.version_probe(fixture, *args)),
            )
            modules = SimpleNamespace(
                child=fake_child, host=SimpleNamespace(safe_path=lambda path: path, identity=host.identity)
            )
            if fault == "custody-write":
                original_write = active.write_leaf

                def failed_write(*args: object, **kwargs: object) -> None:
                    original_write(*args, **kwargs)
                    raise OSError(5, PRIVATE)

                stack.enter_context(patch.object(active, "write_leaf", side_effect=failed_write))
            yield SimpleNamespace(
                stage=stage,
                leases=leases,
                bootstrap=bootstrap,
                modules=modules,
                facts=facts,
                progress=progress,
                probe=fake_child.probe,
            )

    def version_probe(
        self,
        fixture: SimpleNamespace,
        authority: child.Interpreter,
        _target: int,
        kind: str,
        lease: child.Build,
        _clock: object,
    ) -> child.Outcome:
        leases, files = fixture.leases, fixture.files
        interpreter, parser = fixture.interpreter, fixture.parser
        bootstrap, sync, stage, fault = fixture.bootstrap, fixture.sync, fixture.stage, fixture.fault
        marker = next(leases.iterdir())
        pending = marker / "pending.json"
        record = json.loads(pending.read_bytes())
        self.assertEqual(record["kind"], "arm-observation-pending")
        self.assertEqual(record["qualification"], "none")
        self.assertEqual(record["context"]["architecture"], "arm64")
        self.assertEqual(record["tools"], files)
        self.assertEqual(authority.sha256, active.digest(interpreter.read_bytes()))
        self.assertNotEqual(
            authority.sha256,
            json.loads((ROOT / ".github/docker-userns-active-admission.json").read_bytes())["cohorts"]["amd64"][
                "interpreterSha256"
            ],
        )
        self.assertEqual(kind, "parser-version")
        self.assertLess(lease.deadline_ns, lease.cleanup_deadline_ns)
        self.assertLessEqual(lease.cleanup_deadline_ns, bootstrap["deadlineNs"] - active.RESERVE_NS)
        self.assertGreaterEqual(sync.call_count, 3)
        with self.assertRaises(active.RefusedError):
            active.Store(stage, marker.name)
        if fault == "timeout":
            raise child.ChildError(lifetime=child.Lifetime.UNKNOWN)
        if fault == "never-started":
            raise child.ChildError(lifetime=child.Lifetime.NEVER_STARTED)
        if fault == "cancelled":
            raise KeyboardInterrupt
        if fault == "dead-error":
            raise child.ChildError(lifetime=child.Lifetime.DEAD)
        replacements = {
            "parser-replaced": parser,
            "interpreter-replaced": interpreter,
            "marker-replaced": pending,
            "bootstrap-replaced": stage / "bootstrap.json",
        }
        if fault in replacements:
            changed = replacements[fault]
            mode = changed.stat().st_mode & 0o777
            changed.chmod(0o600)
            changed.write_bytes(b"replacement")
            changed.chmod(mode)
        return child.Outcome(b"AppArmor parser version 5.9.1\n", dead=True)

    def test_proven_death_retires_only_bound_marker_and_reports_actual_version(self) -> None:
        with self.fixture(None) as fixture:
            active.observation_version(
                fixture.stage, fixture.bootstrap, fixture.modules, fixture.facts, fixture.progress
            )
            self.assertEqual(list(fixture.leases.iterdir()), [])
            self.assertEqual(fixture.facts["versionChild"], {"lifetime": "proven-dead", "custody": "retired"})
            self.assertEqual(fixture.facts["parserVersion"], "5.9.1")
            fixture.probe.assert_called_once()
        with self.fixture("dead-error") as fixture, self.assertRaises(child.ChildError):
            active.observation_version(
                fixture.stage, fixture.bootstrap, fixture.modules, fixture.facts, fixture.progress
            )
        self.assertEqual(fixture.facts["versionChild"], {"lifetime": "proven-dead", "custody": "retired"})

    def test_unknown_cancellation_replacement_and_durability_failure_keep_disposal_blocked(self) -> None:
        for fault in (
            "timeout",
            "cancelled",
            "never-started",
            "parser-replaced",
            "interpreter-replaced",
            "marker-replaced",
            "bootstrap-replaced",
            "custody-write",
        ):
            with self.subTest(fault=fault), self.fixture(fault) as fixture:
                with self.assertRaises((child.ChildError, active.RefusedError, OSError, KeyboardInterrupt)):
                    active.observation_version(
                        fixture.stage, fixture.bootstrap, fixture.modules, fixture.facts, fixture.progress
                    )
                self.assertEqual(len(list(fixture.leases.iterdir())), 1)
                self.assertNotEqual(fixture.facts["versionChild"]["custody"], "retired")
                self.assertNotIn("parserVersion", fixture.facts)
                with self.assertRaises(active.RefusedError):
                    active.dispose_stage(fixture.stage, fixture.bootstrap)
                with patch.object(active, "preflight_authority") as authority:
                    replay = active.observe_arm(fixture.stage, fixture.bootstrap, fixture.modules, fixture.progress)
                self.assertFalse(replay["complete"])
                authority.assert_not_called()
                self.assertEqual(fixture.probe.call_count, int(fault != "custody-write"))


if __name__ == "__main__":
    unittest.main()


class MaintainedBootstrapContract(unittest.TestCase):
    def event(self, context: dict[str, str]) -> dict:
        return {
            "inputs": {"validation_profile": context["validationProfileRequested"]},
            "repository": {"full_name": "Strukturpiloten/containers"},
            "workflow": ".github/workflows/ci.yml",
            "ref": context["ref"],
        }

    def root(
        self, proof: SyntheticProof, event: dict, *, architecture: str = "amd64", environment: dict | None = None
    ) -> tuple[dict, Mock]:
        """Run the fixed literal through genuine proof validation, stopping before writes."""
        literal = literal_namespace()
        literal["SOURCE_MANIFEST_SHA256"] = active.digest(proof.files[producer.MANIFEST])
        literal["sys"] = SimpleNamespace(
            argv=[
                "bootstrap",
                "handoff",
                *(proof.candidate for _ in range(3)),
                "1",
                "2",
                architecture,
                proof.context["imageVersion"],
                "1000",
                "1000",
                "1000000000",
                proof.context["repository"],
                proof.context["event"],
                proof.context["ref"],
                proof.context["workflowRef"],
                proof.context["job"],
                proof.context["image"],
                "B" if proof.context["purpose"] == "direct-startup-diagnostic" else "",
            ],
            implementation=SimpleNamespace(name="cpython"),
            version_info=(3, 14, 4, "final", 0),
            flags=SimpleNamespace(isolated=1, no_site=1),
            dont_write_bytecode=True,
        )
        if environment is not None:
            for position, key in {
                2: "GITHUB_SHA",
                3: "GITHUB_WORKFLOW_SHA",
                5: "GITHUB_RUN_ID",
                6: "GITHUB_RUN_ATTEMPT",
                8: "ImageVersion",
                12: "GITHUB_REPOSITORY",
                13: "GITHUB_EVENT_NAME",
                14: "GITHUB_REF",
                15: "GITHUB_WORKFLOW_REF",
                16: "GITHUB_JOB",
            }.items():
                literal["sys"].argv[position] = environment[key]
        literal["os"] = SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0, urandom=lambda _: b"x" * 16)
        literal["time"] = SimpleNamespace(monotonic_ns=lambda: 1)
        literal["read_input"] = Mock(side_effect=[json.dumps(event).encode(), json.dumps(proof.value()).encode()])
        stop = RuntimeError("stop before first stage write")
        with (
            patch.object(Path, "mkdir", side_effect=stop) as mkdir,
            self.assertRaises((RuntimeError, ValueError)) as raised,
        ):
            literal["main"]()
        if isinstance(raised.exception, RuntimeError):
            self.assertIs(raised.exception, stop)
        return literal, mkdir

    def test_full_default_focus_reaches_root_stage_only_after_connected_proof(self) -> None:
        for requested in ("full", "FULL", ""):
            with self.subTest(requested=requested):
                proof = SyntheticProof()
                proof.context = workflow_context(
                    purpose="maintained-prerequisite", candidate=proof.candidate, requested=requested
                )
                event = self.event(proof.context)
                environment = {
                    **candidate_environment(proof.candidate),
                    "GITHUB_REF": proof.context["ref"],
                    "GITHUB_WORKFLOW_REF": proof.context["workflowRef"],
                }
                with event_payload(json.dumps(event).encode()):
                    produced = producer.context(environment, "amd64")
                self.assertEqual(produced, proof.context)
                literal, mkdir = self.root(proof, event)
                mkdir.assert_called_once_with(mode=0o700)
                self.assertTrue(literal["DIAGNOSTIC"]["sourceVerified"])

    def test_root_derives_purpose_and_ref_instead_of_accepting_transport_labels(self) -> None:
        for fault in ("purpose", "ref", "head", "admission", "event", "focus", "arm"):
            with self.subTest(fault=fault):
                proof = SyntheticProof()
                proof.context = workflow_context(purpose="maintained-prerequisite", candidate=proof.candidate)
                event = self.event(proof.context)
                if fault == "purpose":
                    proof.context["purpose"] = "experimental-candidate"
                elif fault == "ref":
                    event["ref"] = "refs/heads/other"
                elif fault == "head":
                    proof.context["checkout"] = "f" * 40
                elif fault == "admission":
                    proof.context["admissionSha256"] = "f" * 64
                elif fault == "event":
                    event["repository"]["full_name"] = "fork/containers"
                elif fault == "focus":
                    event["inputs"]["focused_runtime"] = "mandatory-accounting"
                _, mkdir = self.root(proof, event, architecture="arm64" if fault == "arm" else "amd64")
                mkdir.assert_not_called()

    def test_unsupported_callers_never_receive_maintained_context(self) -> None:
        context = workflow_context(purpose="maintained-prerequisite")
        environment = {
            **candidate_environment(),
            "GITHUB_REF": context["ref"],
            "GITHUB_WORKFLOW_REF": context["workflowRef"],
        }
        for key, values in {
            "GITHUB_EVENT_NAME": ("pull_request", "push", "merge_group", "schedule", "workflow_call"),
            "GITHUB_JOB": ("build", "publish"),
            "GITHUB_REPOSITORY": ("fork/containers",),
            "RUNNER_ENVIRONMENT": ("self-hosted",),
            "GITHUB_ACTIONS": ("false",),
            "RUNNER_ARCH": ("ARM64",),
            "GITHUB_WORKFLOW_SHA": ("f" * 40,),
        }.items():
            for value in values:
                with (
                    self.subTest(key=key, value=value),
                    event_payload(json.dumps(self.event(context)).encode()),
                    self.assertRaises((ValueError, qualification.QualificationError)),
                ):
                    producer.context({**environment, key: value}, "amd64")


class MaintainedStageDisposalContract(unittest.TestCase):
    def test_root_ack_is_emitted_after_removal_and_lock_close_and_failures_never_ack(self) -> None:
        for fault in (None, "remove", "lock-close"):
            events = []
            scoped = scoped_receipt(purpose="maintained-prerequisite", phase="enforcement")
            bootstrap = {
                "context": scoped["workflowContext"],
                "files": {producer.MANIFEST: active.SOURCE_MANIFEST_SHA256},
            }

            @contextmanager
            def locked(_stage: Path, *, events: list = events, fault: str | None = fault) -> Iterator[None]:
                yield
                events.append("lock-close")
                if fault == "lock-close":
                    raise OSError(PRIVATE)

            def removed(*_args: object, events: list = events, fault: str | None = fault) -> None:
                events.append("removed")
                if fault == "remove":
                    raise OSError(PRIVATE)

            output = io.BytesIO()
            with (
                self.subTest(fault=fault),
                patch.object(
                    active.sys, "argv", ["helper", "dispose-stage", "/run/containers-userns-active." + "f" * 32]
                ),
                patch.object(active, "verify_stage", return_value=bootstrap),
                patch.object(active, "dependencies", return_value=SimpleNamespace(qualification=qualification)),
                patch.object(active, "root_bytes", return_value=b"immutable bootstrap"),
                patch.object(active, "stage_lock", side_effect=locked),
                patch.object(active, "dispose_stage", side_effect=removed),
                patch.object(active.sys, "stdout", SimpleNamespace(buffer=output)),
            ):
                status = active.main()
            value = json.loads(output.getvalue())
            if fault is None:
                self.assertEqual(events, ["removed", "lock-close"])
                self.assertEqual(status, 0)
                scoped["bootstrapSha256"] = active.digest(b"immutable bootstrap")
                self.assertEqual(value, stage_disposal(scoped))
            else:
                self.assertEqual(status, 1)
                self.assertNotEqual(value.get("stageDisposed"), True)
                self.assertFalse(value["cleanupAuthority"])

    def test_actual_client_disposal_checks_ack_context_exit_and_original_deadline(self) -> None:
        from scripts import docker_userns_active_client as client_module  # noqa: PLC0415

        for fault in (None, "exit", "deadline", "ack"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                client = client_fixture(Path(directory))
                client.evidence = scoped_receipt(purpose="maintained-prerequisite", phase="enforcement")
                client.binding = qualification.NativeBinding(**client.evidence["binding"])
                client.provenance = client.evidence["workflowContext"]
                ack = stage_disposal(client.evidence)
                if fault == "ack":
                    ack["bootstrapSha256"] = "f" * 64

                def command(
                    *_args: object,
                    client: ActiveClient = client,
                    fault: str | None = fault,
                    ack: dict = ack,
                    **_kwargs: object,
                ) -> str:
                    client.ctx.checks.append({"exitCode": 1 if fault == "exit" else 0})
                    return json.dumps(ack)

                client.ctx.command = Mock(side_effect=command)
                with patch.object(client_module.time, "monotonic_ns", return_value=1000 if fault == "deadline" else 1):
                    if fault is None:
                        self.assertEqual(client.dispose_stage(), ack)
                    else:
                        with self.assertRaises((ValueError, qualification.QualificationError)):
                            client.dispose_stage()
                if fault == "deadline":
                    client.ctx.command.assert_not_called()


class MaintainedRootBindingContract(unittest.TestCase):
    def test_every_root_rpc_rejects_cross_context_and_stage_replay_before_effects(self) -> None:
        admission = (ROOT / ".github/docker-userns-active-admission.json").read_bytes()
        expected = scoped_receipt(purpose="maintained-prerequisite")
        original = qualification.NativeBinding(**expected["binding"])
        bootstrap = {"context": expected["workflowContext"], "deadlineNs": original.deadline_ns}
        mutations = [(None, original)]
        mutations.extend(
            (key, replace(original, **{key: value}))
            for key, value in (
                ("candidate", "f" * 40),
                ("run", "9"),
                ("attempt", "9"),
                ("architecture", "arm64"),
                ("purpose", "experimental-candidate"),
                ("admission_sha256", "0" * 64),
                ("workflow_context_sha256", "0" * 64),
                ("deadline_ns", original.deadline_ns + 1),
            )
        )
        for fault, native in mutations:
            record = {
                "schemaVersion": 4,
                "binding": asdict(native),
                "bindingSha256": native.digest(),
                "bootstrapSha256": active.digest(b"bootstrap"),
                "state": "closed",
                "timeoutExecutable": "/usr/bin/timeout",
            }
            with (
                self.subTest(fault=fault),
                patch.object(
                    active,
                    "root_bytes",
                    side_effect=lambda path: admission if path.name.endswith("admission.json") else b"bootstrap",
                ),
            ):
                if fault is None:
                    port = active.RootPort(
                        ROOT, bootstrap, SimpleNamespace(qualification=qualification), SimpleNamespace(), record
                    )
                    self.assertEqual(port.binding, native)
                else:
                    with self.assertRaises((active.RefusedError, qualification.QualificationError)):
                        active.RootPort(
                            ROOT, bootstrap, SimpleNamespace(qualification=qualification), SimpleNamespace(), record
                        )
        for fault, value in (("schemaVersion", 1), ("bootstrapSha256", "f" * 64), ("bindingSha256", "f" * 64)):
            changed = {**record, "binding": asdict(original), "bindingSha256": original.digest(), fault: value}
            with (
                self.subTest(fault=fault),
                patch.object(
                    active,
                    "root_bytes",
                    side_effect=lambda path: admission if path.name.endswith("admission.json") else b"bootstrap",
                ),
                self.assertRaises(active.RefusedError),
            ):
                active.RootPort(
                    ROOT, bootstrap, SimpleNamespace(qualification=qualification), SimpleNamespace(), changed
                )

    def test_actual_root_receipt_projection_preserves_each_purpose_and_closed_schema(self) -> None:
        admission = qualification.admission_document(
            (ROOT / ".github/docker-userns-active-admission.json").read_bytes()
        )
        for purpose in ("experimental-candidate", "maintained-prerequisite"):
            expected = scoped_receipt(purpose=purpose)
            port = SimpleNamespace(
                binding=qualification.NativeBinding(**expected["binding"]),
                record=expected,
                bootstrap={"context": expected["workflowContext"]},
                store=SimpleNamespace(path=Path(expected["lease"])),
                modules=SimpleNamespace(qualification=qualification),
                admission=admission,
            )
            with self.subTest(purpose=purpose):
                actual = active.receipt(port)
                self.assertEqual(actual, expected)
                self.assertEqual(set(actual), qualification.SCOPED_RECEIPT_KEYS)


class MaintainedDisposalPrivacyTests(unittest.TestCase):
    @staticmethod
    def external(fault: str | None, ack: dict, canary: str) -> subprocess.CompletedProcess[str] | OSError:
        """Replace only the external command; keep actual client and recorder behavior."""
        if fault == "os-error":
            return PermissionError(13, canary)
        output = {
            "malformed": canary,
            "mismatch": json.dumps({**ack, "bootstrapSha256": canary}),
            "nonzero": canary,
            "unicode": canary + "\ud800",
            "oversized": canary * active.MAX_STATE,
        }.get(fault, json.dumps(ack))
        return subprocess.CompletedProcess([], 1 if fault == "nonzero" else 0, output, canary)

    def check_public(
        self, client: ActiveClient, record: dict, fault: str | None, reason: str | None, canary: str
    ) -> None:
        phase = record["phases"][1]
        for check in phase["checks"]:
            self.assertNotIn("stdout", check)
            self.assertNotIn("stderr", check)
        public = {"aggregate": record, "clientEvidence": client.evidence, "failures": client.failures}
        self.assertNotIn(canary, json.dumps(public))
        if fault is None:
            self.assertEqual(record["qualification"], "complete")
        else:
            self.assertEqual(record["qualification"], "none")
            self.assertEqual(phase["qualification"], "none")
            failure = client.failures[-1]
            self.assertTrue(active.valid_failure(failure))
            self.assertEqual(failure["operation"], "dispose-stage")
            self.assertEqual(failure["reason"], reason)
            self.assertNotIn(canary, client.ctx.scoped_failure_output.read_text())

    def test_actual_command_output_and_failures_never_reach_public_phase_pair_or_traceback(self) -> None:
        from scripts import docker_userns_active_client as client_module  # noqa: PLC0415
        from scripts import runtime_tests  # noqa: PLC0415
        from tests.test_evidence_gate import maintained_runtime  # noqa: PLC0415

        canary = "PRIVATE-DISPOSAL-CANARY-/run/root-owned-unvalidated-value"
        for fault, reason in (
            (None, None),
            ("malformed", "malformed-receipt"),
            ("mismatch", "receipt-mismatch"),
            ("nonzero", "receipt-mismatch"),
            ("os-error", "permission-denied"),
            ("unicode", "malformed-receipt"),
            ("oversized", "oversized-receipt"),
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                record = maintained_runtime()
                phase = record["phases"][1]
                client = client_fixture(Path(directory))
                client.evidence = phase["scopedProfile"]
                client.binding = qualification.NativeBinding(**client.evidence["binding"])
                client.provenance = client.evidence["workflowContext"]
                context = runtime_tests.RuntimeContext.__new__(runtime_tests.RuntimeContext)
                context.timeout = 45
                context.runtime_deadline = None
                context.checks = phase["checks"]
                context.backend = client.ctx.backend
                context.scoped_failure_output = Path(directory) / "failure.json"
                client.ctx = context
                ack = stage_disposal(client.evidence)
                external = self.external(fault, ack, canary)
                process = (
                    patch.object(runtime_tests.subprocess, "run", side_effect=external)
                    if isinstance(external, BaseException)
                    else patch.object(runtime_tests.subprocess, "run", return_value=external)
                )
                with process, patch.object(client_module.time, "monotonic_ns", return_value=1):
                    if fault is None:
                        self.assertEqual(client.dispose_stage(), ack)
                    else:
                        try:
                            client.dispose_stage()
                        except ValueError as error:
                            runtime_tests._phase_error(phase, error, key="cleanupError")
                            runtime_tests._phase_error(record, error, key="cleanupError")
                        else:
                            self.fail("unverified disposal unexpectedly succeeded")
                runtime_tests._finish_pair_authority(record)
                self.check_public(client, record, fault, reason, canary)


class AccuratePostImportDiagnosticPhases(unittest.TestCase):
    def test_main_wires_fixed_post_import_lock_and_disposal_phases_without_entering_root(self) -> None:
        """Inspect phase placement only; never invoke main/verify_stage or spoof UID."""
        module = ast.parse(Path(active.__file__).read_text())
        main = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        phases = []
        for node in ast.walk(main):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                phases.extend(
                    (node.lineno, node.value.value)
                    for target in node.targets
                    if isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "progress"
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "phase"
                )
        phases.sort()
        calls = [
            (node.lineno, node.func.id)
            for node in ast.walk(main)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        imported = next(line for line, name in calls if name == "dependencies")
        ready = next(line for line, phase in phases if phase == "helper-ready")
        self.assertGreater(ready, imported)
        for line, name in calls:
            if name in {"stage_lock", "dispose_stage"}:
                expected = "stage-lock" if name == "stage_lock" else "stage-disposal"
                self.assertEqual([phase for before, phase in phases if before < line][-1], expected)
                self.assertGreater(line, ready)

    def test_fixed_phase_and_allowlisted_reason_survive_projection_without_private_values(self) -> None:
        original_uid = os.geteuid()
        for phase in ("helper-import", "helper-ready", "stage-lock", "stage-disposal"):
            with self.subTest(phase=phase):
                value = active.failure_receipt(
                    {"actor": "root", "operation": "dispose-stage", "phase": phase},
                    PermissionError(13, "PRIVATE_PHASE_CANARY"),
                )
                self.assertTrue(active.valid_failure(value))
                self.assertEqual(value["phase"], phase)
                self.assertEqual(value["reason"], "permission-denied")
                self.assertFalse(value["cleanupAuthority"])
                self.assertNotIn("PRIVATE_", json.dumps(value))
        unknown = active.failure_receipt({"phase": "PRIVATE_PHASE_CANARY"}, active.RefusedError())
        self.assertEqual(unknown["phase"], "unknown")
        self.assertNotIn("PRIVATE_", json.dumps(unknown))
        self.assertEqual(os.geteuid(), original_uid)
