"""Hermetic active admission/proof/custody negatives; never load host policy."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Self
from unittest.mock import Mock, patch

import yaml

from scripts import docker_userns_active as active
from scripts import docker_userns_active_bootstrap_bundle as producer
from tests.test_docker_userns_qualification import binding

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).resolve().parents[1]


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

    def __init__(self) -> None:
        """Use inert SDK sources and explicit fixture manifest authority."""
        self.objects: dict[str, dict[str, str]] = {}
        self.files = {name: (ROOT / name).read_bytes() for name in producer.FILES}
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
        self.candidate = self.add(
            "commit", f"tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n".encode()
        )
        self.context = {
            "candidate": self.candidate,
            "workflow": self.candidate,
            "checkout": self.candidate,
            "repository": "Strukturpiloten/containers",
            "event": "workflow_dispatch",
            "ref": "refs/heads/TheRealBecks/issue527",
            "job": "smoke-build",
            "run": "1",
            "attempt": "2",
            "architecture": "amd64",
            "image": "docker-29-conformance-rootless",
            "imageOS": "ubuntu26",
            "imageVersion": "20261026.180.1",
            "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
            "validationProfile": "docker-rootless-diagnostic",
            "validationProfileRequested": "docker-rootless-diagnostic",
        }

    def add(self, kind: str, raw: bytes) -> str:
        identifier = hashlib.sha1(
            kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
        ).hexdigest()
        self.objects[identifier] = {"oid": identifier, "kind": kind, "data": base64.b64encode(raw).decode()}
        return identifier

    def value(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
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
                port.binding, port.modules, port.admission = binding(), SimpleNamespace(), {}
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
        from dataclasses import asdict  # noqa: PLC0415

        admission = json.loads((ROOT / ".github/docker-userns-active-admission.json").read_text())
        cohort = admission["cohort"]
        context = binding()
        name = "dockerlens-127-upstream-rootless-1-2-" + "f" * 32
        label = (name + " (unconfined)\n").encode()
        facts = {key: cohort[key] for key in ("osID", "osVersion", "machine", "kernel", "parserVersion")}
        facts["files"] = {key: {"sha256": value} for key, value in cohort.items() if key.endswith("Sha256")}
        facts["controls"] = {"enabled": True, "restricted_userns": 1, "maximum_userns": 1024, "legacy_clone": None}
        facts["imageVersion"] = "20261026.180.1"
        scoped = {
            "consumer": active.CONSUMER,
            "qualification": "experimental-candidate-only",
            "binding": asdict(context),
            "bindingSha256": context.digest(),
            "lease": "f" * 32,
            "profileName": name,
            "state": "closed",
            "sourceManifestSha256": admission["sourceManifestSha256"],
            "preflight": facts,
            "namespace": {
                **{key: active.digest(raw.encode()) for key, raw in admission["policyNamespace"].items()},
                "user": 1,
                "mnt": 2,
                "cgroup": 3,
            },
            "cleanOwnerVerified": True,
            "ownerReady": True,
            "ownerTerminationVerified": True,
            "custodyDisposed": True,
            "guestAbsenceVerified": True,
            "taskAbsenceVerified": True,
            "scopeAbsenceVerified": True,
            "profileAbsenceVerified": True,
            "retained": False,
            "readerPending": False,
            "childPending": False,
            "imageVersion": "20261026.180.1",
            "imageVersionKind": "workflow-reported-provenance-not-vm-attestation",
            "validationProfile": "docker-rootless-diagnostic",
            "validationProfileRequested": "docker-rootless-diagnostic",
            "parserExecutionNamespace": admission["parserExecutionNamespace"],
            "profileObservation": {
                "source": "held-task-attr/apparmor/current",
                "exactMatch": True,
                "singleLabel": True,
                "taskIdentityBound": True,
                "timing": "post-create",
                "bytes": len(label),
                "sha256": active.digest(label),
            },
        }
        identity = {
            "archiveSha256": context.archive_sha256,
            "manifestDigest": context.manifest_digest,
            "configDigest": context.config_digest,
            "sourceRevision": context.candidate,
        }
        return {"image": context.image}, {
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
        import io  # noqa: PLC0415

        from scripts.docker_userns_active_client import ActiveClient  # noqa: PLC0415

        for requested in ("docker-rootless-diagnostic", "DOCKER-ROOTLESS-DIAGNOSTIC", "DoCkEr-RoOtLeSs-DiAgNoStIc"):
            with self.subTest(requested=requested):
                proof, root = SyntheticProof(), literal_namespace()
                root["SOURCE_MANIFEST_SHA256"] = active.digest(proof.files[producer.MANIFEST])
                environment = candidate_environment(proof.candidate)
                event = json.dumps({"inputs": {"validation_profile": requested}}).encode()
                with (
                    patch.object(Path, "open", side_effect=lambda *_args, event=event, **_kwargs: io.BytesIO(event)),
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
                    response = {
                        "bindingSha256": client.binding.digest(),
                        "retained": False,
                        "lease": "f" * 32,
                        "validationProfile": produced["validationProfile"],
                        "validationProfileRequested": requested,
                    }
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
        import io  # noqa: PLC0415

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
                    patch.object(Path, "open", side_effect=lambda *_args, event=event, **_kwargs: io.BytesIO(event)),
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
                    patch.object(Path, "open", side_effect=lambda *_args, event=event, **_kwargs: io.BytesIO(event)),
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


if __name__ == "__main__":
    unittest.main()
