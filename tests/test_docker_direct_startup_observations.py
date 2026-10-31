"""Earliest native status, exact existing classifiers and original startup clock."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import docker_direct_startup_active as control
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_observations as observations
from scripts import docker_userns_active as active
from scripts import runtime_docker_diagnostics as diagnostics
from tests.test_docker_direct_startup_contract import binding

EPERM = b"[rootlesskit:parent] error: failed to start the child: fork/exec /proc/self/exe: operation not permitted\n"


def port() -> SimpleNamespace:
    """Keep immutable original incarnation separate from mutable readiness results."""
    owned = SimpleNamespace(
        work_until=300_000_000_000,
        commit=Mock(),
        docker=Mock(return_value=EPERM),
        docker_logs=Mock(return_value=EPERM),
        modules=SimpleNamespace(capture=diagnostics),
        record={
            "directGate": {"released": True},
            "directExecutables": {"engineVersion": "26.1.4"},
            "directReleaseNs": 1_000_000_000,
            "subject": {"pid": 123, "startedAt": "original"},
        },
    )
    owned.point = lambda phase: active.RootPort.point(owned, phase)
    return owned


def api(now: int = 2_000_000_000) -> SimpleNamespace:
    """Use fixed closed checks and a test-local monotonic observation clock."""
    return SimpleNamespace(
        require=active.require,
        comparison=active.comparison,
        digest=active.digest,
        time=SimpleNamespace(monotonic_ns=lambda: now),
    )


class OriginalFailureControls(unittest.TestCase):
    def test_existing_classifier_keeps_exact_nonzero_negative_and_warning_is_not_attribution(self) -> None:
        owned = port()
        owned.docker_logs.return_value = b"rootfs propagation warning /PRIVATE_PATH\n" + EPERM
        result = observations._negative(owned, api(), "a" * 64, 7)
        self.assertEqual(result["kind"], "rootlesskit-child-start-eperm")
        self.assertEqual(result["nativeExitCode"], 7)
        self.assertEqual(result["unclassifiedRecords"], 1)
        self.assertNotIn("PRIVATE_PATH", json.dumps(result))
        self.assertNotIn("kernelAttribution", result)
        self.assertEqual(owned.work_until, 7_000_000_000)

    def test_other_errno_unknown_line_or_zero_exit_is_not_expected_a(self) -> None:
        for raw, code in (
            (EPERM.replace(b"operation not permitted", b"permission denied"), 1),
            (b"[rootlesskit:parent] error: PRIVATE_UNKNOWN\n", 1),
            (EPERM, 0),
        ):
            owned = port()
            owned.docker_logs.return_value = raw
            with self.subTest(raw=raw, code=code):
                result = observations._negative(owned, api(), "a" * 64, code)
                self.assertEqual(result["kind"], "other-failure")
                self.assertEqual(result["nativeExitCode"], code)

    def test_truncation_record_overflow_or_query_failure_preserves_original_status(self) -> None:
        for raw in (
            b"x" * (contract.JOURNAL_BYTES + 1),
            b"x\n" * (contract.JOURNAL_RECORDS + 1),
            b"x" * (contract.RECORD_BYTES + 1),
        ):
            owned = port()
            owned.docker_logs.return_value = raw
            with self.subTest(size=len(raw)):
                result = observations._negative(owned, api(), "a" * 64, 137)
                self.assertEqual(result["kind"], "unknown")
                self.assertIn("diagnosticFailure", result)
            self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 137)
        owned = port()
        owned.docker_logs.side_effect = active.RefusedError
        result = observations._negative(owned, api(), "a" * 64, 1)
        self.assertEqual(result["diagnosticFailure"], "logs-unavailable")
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 1)


class StartupRaceControls(unittest.TestCase):
    def test_stopped_original_task_is_observed_before_any_api_or_postexec_query(self) -> None:
        owned = port()
        state = {"State": {"Pid": 0, "Running": False, "StartedAt": "original", "ExitCode": 1}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness") as readiness,
        ):
            observations.observe(owned, api(), "a" * 64)
        readiness.assert_not_called()
        self.assertEqual(owned.record["directStartup"]["kind"], contract.EXPECTED_A)
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 1)

    def test_fast_exit_during_exec_readiness_preserves_the_rootlesskit_error(self) -> None:
        owned = port()
        before = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        after = {"State": {"Pid": 0, "Running": False, "StartedAt": "original", "ExitCode": 7}}
        with (
            patch.object(control, "inspect_gate", side_effect=[before, after]),
            patch.object(observations, "_readiness", return_value="API_EXEC_UNAVAILABLE"),
        ):
            observations.observe(owned, api(), "a" * 64)
        self.assertEqual(owned.record["directStartup"]["kind"], contract.EXPECTED_A)
        self.assertEqual(owned.record["directStartup"]["nativeExitCode"], 7)

    def test_ready_running_task_never_invents_zero_native_exit_and_needs_postexec_proof(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness", return_value="26.1.4"),
            patch.object(observations, "_post_exec") as proof,
        ):
            observations.observe(owned, api(), "a" * 64)
        self.assertEqual(owned.record["directStartup"]["kind"], "ready")
        self.assertIsNone(owned.record["directStartup"]["nativeExitCode"])
        proof.assert_called_once()

    def test_original45second_release_deadline_is_not_renewed_and_terminal_observation_is_one_shot(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original", "ExitCode": 0}}
        with (
            patch.object(control, "inspect_gate", return_value=state),
            patch.object(observations, "_readiness") as readiness,
        ):
            observations.observe(owned, api(46_000_000_000), "a" * 64)
        readiness.assert_not_called()
        self.assertEqual(owned.record["directStartup"]["kind"], "other-failure")
        self.assertTrue(owned.record["directObservationTerminal"])
        with self.assertRaises(active.RefusedError):
            observations.observe(owned, api(47_000_000_000), "a" * 64)

    def test_replacement_incarnation_is_not_an_original_startup_result(self) -> None:
        owned = port()
        state = {"State": {"Pid": 123, "Running": True, "StartedAt": "replacement", "ExitCode": 0}}
        with patch.object(control, "inspect_gate", return_value=state), self.assertRaises(active.RefusedError):
            observations.observe(owned, api(), "a" * 64)
        self.assertNotIn("directStartup", owned.record)


if __name__ == "__main__":
    unittest.main()


class ExecutablePreflightControls(unittest.TestCase):
    def test_actual_bounded_file_hash_refuses_modes_caps_and_in_read_source_replacement(self) -> None:
        original_fstat, original_stat = os.fstat, os.stat
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )

        def rooted(value: os.stat_result) -> SimpleNamespace:
            result = {name: getattr(value, name) for name in fields}
            result["st_uid"] = 0
            return SimpleNamespace(**result)

        for fault in (None, "writable", "suid", "capabilities", "replaced"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                image = base / "image"
                binary = image / "usr/local/bin/rootlesskit"
                binary.parent.mkdir(parents=True)
                body = b"original fixed executable bytes"
                binary.write_bytes(body)
                binary.chmod(0o755)
                process = base / "held-proc"
                process.mkdir()
                (process / "root").symlink_to(image, target_is_directory=True)
                if fault == "writable":
                    binary.chmod(0o777)
                if fault == "suid":
                    binary.chmod(0o4755)
                query = api()
                query.mark = active.mark
                query.check = Mock()
                if fault == "replaced":

                    def replace(_deadline: int, *, binary: Path = binary, body: bytes = body) -> None:
                        alternate = binary.with_name("replacement")
                        alternate.write_bytes(body)
                        alternate.chmod(0o755)
                        alternate.replace(binary)

                    query.check.side_effect = replace
                directory = os.open(process, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with (
                        patch.object(observations.os, "fstat", side_effect=lambda fd: rooted(original_fstat(fd))),
                        patch.object(
                            observations.os,
                            "stat",
                            side_effect=lambda *args, **kwargs: rooted(original_stat(*args, **kwargs)),
                        ),
                        patch.object(
                            observations.os,
                            "getxattr",
                            return_value=b"file-capability" if fault == "capabilities" else None,
                            side_effect=None if fault == "capabilities" else OSError(errno.ENODATA, "absent"),
                        ),
                    ):
                        if fault:
                            with self.assertRaises(active.RefusedError):
                                observations._image_file(
                                    port(), query, directory, ("usr", "local", "bin", "rootlesskit"), 4096
                                )
                        else:
                            head, digest = observations._image_file(
                                port(), query, directory, ("usr", "local", "bin", "rootlesskit"), 4096
                            )
                            self.assertEqual(head, body)
                            self.assertEqual(digest, hashlib.sha256(body).hexdigest())
                finally:
                    os.close(directory)

    def test_preflight_requires_actual_native_elf_version_and_original_incarnation_before_release(self) -> None:
        for fault in (None, "architecture", "version", "actor", "exited"):
            with self.subTest(fault=fault):
                owned = port()
                owned.binding = SimpleNamespace(architecture="amd64")
                owned.record["subject"].update(container="a" * 64, startTicks=99, cgroup="exact-scope")
                owned.record["directGate"]["releaseIntent"] = False
                owned.record.pop("directExecutables")
                owned.docker.return_value = (
                    b"rootlesskit version 1.2.3\n" if fault != "version" else b"PRIVATE_UNREVIEWED_PROVIDER"
                )
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                header[18:20] = (183 if fault == "architecture" else 62).to_bytes(2, "little")
                files = [(b"#!/bin/sh\n", "a" * 64), (bytes(header), "b" * 64), (b"4.5.6\n", "c" * 64)]
                task = {"startTicks": 99, "cgroup": "exact-scope"}
                changed = {**task, "startTicks": 100} if fault == "actor" else task
                state = {"State": {"Pid": 123, "Running": True, "StartedAt": "original"}}
                with (
                    patch.object(control, "inspect_gate", return_value=state),
                    patch.object(control, "actor_snapshot", side_effect=[(task, {}), (changed, {})]),
                    patch.object(observations, "_image_file", side_effect=files),
                    patch.object(observations.os, "open", return_value=11),
                    patch.object(observations.os, "pidfd_open", return_value=12, create=True),
                    patch.object(observations.os, "close"),
                    patch.object(
                        observations.select,
                        "select",
                        return_value=([12], [], []) if fault == "exited" else ([], [], []),
                    ),
                ):
                    if fault:
                        with self.assertRaises(active.RefusedError):
                            observations.preflight(owned, api(), "a" * 64)
                        self.assertNotIn("directExecutables", owned.record)
                    else:
                        observations.preflight(owned, api(), "a" * 64)
                        self.assertEqual(owned.record["directExecutables"]["rootlesskitVersion"], "1.2.3")
                        self.assertEqual(owned.record["directExecutables"]["engineVersion"], "4.5.6")
                    self.assertTrue(owned.record["directPreflightIntent"])
                    with self.assertRaises(active.RefusedError):
                        observations.preflight(owned, api(), "a" * 64)


class PreflightGuardCheckpoints(unittest.TestCase):
    def setUp(self) -> None:
        self.forbidden = Mock(side_effect=AssertionError("unexpected native/root/subprocess interface"))
        for name in ("Popen", "run", "check_call", "check_output"):
            self.enterContext(patch.object(subprocess, name, self.forbidden))
        self.enterContext(patch.object(active, "main", self.forbidden))
        self.enterContext(patch.object(active, "root_rpc", self.forbidden))
        self.uid = os.getuid()

    def tearDown(self) -> None:
        self.assertEqual(self.forbidden.call_count, 0)
        self.assertEqual(os.getuid(), self.uid)

    def port_class(self, state: SimpleNamespace) -> type:
        class Port:
            def __init__(self, *_args: object) -> None:
                self.record, self.binding, self.store = state.record, state.native, state.store
                self.work_until = 300_000_000_000
                self.commit = Mock()
                if state.fault == "commit":
                    self.commit.side_effect = PermissionError(13, "PRIVATE_COMMIT_CANARY")
                elif state.fault == "final-commit":
                    self.commit.side_effect = [None, PermissionError(13, "PRIVATE_COMMIT_CANARY"), None]
                self.docker = Mock(return_value=b"rootlesskit version 1.2.3\n")
                if state.fault == "version-size":
                    self.docker.return_value = b"x" * (contract.GUEST_BYTES + 1)
                elif state.fault == "version":
                    self.docker.return_value = b"PRIVATE_VERSION_CANARY"
                elif state.fault == "version-query":
                    self.docker.side_effect = PermissionError(13, "PRIVATE_QUERY_CANARY")
                state.holder.append(self)
                if state.fault == "retained":
                    active.require(not state.record["retained"])

            def point(self, phase: str) -> dict:
                return active.RootPort.point(self, phase)

        return Port

    def samples(self, fault: str | None) -> tuple:
        task = {"startTicks": 100 if fault == "task" else 99, "cgroup": "owned"}
        actor = {"owned": "fixed"}
        final_task = {**task, "startTicks": 101} if fault == "actor" else task
        state = {"State": {"Pid": 124 if fault == "subject" else 123, "Running": True, "StartedAt": "original"}}
        final_state = copy.deepcopy(state)
        if fault == "incarnation":
            final_state["State"]["StartedAt"] = "changed"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62 if fault == "elf" else 183).to_bytes(2, "little")
        files = [
            (b"PRIVATE_LAUNCHER" if fault == "launcher" else b"#!/bin/sh\n", "a" * 64),
            (bytes(header), "b" * 64),
            (b"PRIVATE_ENGINE" if fault == "engine" else b"26.1.4\n", "c" * 64),
        ]
        return task, actor, final_task, state, final_state, files

    def execute(self, fault: str | None) -> tuple:
        native = contract.DirectControlBinding(
            **{
                **asdict(binding()),
                "architecture": "arm64",
                "image": "docker-26-rootless",
                "phase": "direct-control",
                "variant": contract.CONTROL_VARIANT,
                "arm": "A",
            }
        )
        native.validate()
        record = {
            "kind": "direct-control",
            "state": "direct-control",
            "retained": fault == "retained",
            "bindingSha256": native.digest(),
            "diagnostic": {"phase": "daemon", "comparisons": {"daemon": True}},
            "directGate": {"releaseIntent": fault == "unreleased", "released": False},
            "subject": {
                "container": "a" * 64,
                "pid": 123,
                "startedAt": "original",
                "startTicks": 99,
                "cgroup": "owned",
            },
            "firstFailureHistory": [{"unchanged": "PRIVATE_HISTORY_CANARY"}],
        }
        if fault == "intent":
            record["directPreflightIntent"] = True
        store = SimpleNamespace(
            path=Path("/unused-stage/" + "e" * 32),
            read=Mock(return_value=record),
            locked=nullcontext,
            close=Mock(),
        )
        holder = []

        port_type = self.port_class(
            SimpleNamespace(native=native, record=record, store=store, fault=fault, holder=holder)
        )

        current = api()
        current.Store = Mock(return_value=store)
        current.RootPort = active.RootPort
        current.request_value = active.request_value

        def authority(_stage: Path, _bootstrap: dict, _modules: object, *, progress: dict) -> None:
            active.comparison(progress, "admission", matched=fault != "authority")

        current.preflight_authority = authority
        request = {"bindingSha256": native.digest(), "container": "a" * 64}
        if fault == "request":
            request["PRIVATE_EXTRA"] = "PRIVATE_VALUE"
        route = SimpleNamespace(
            operation="direct-preflight",
            name="e" * 32,
            request=active.base64.b64encode(json.dumps(request).encode()).decode(),
            diagnostic={
                "actor": "root",
                "operation": "direct-preflight",
                "sourceVerified": True,
                "sourceManifestSha256": active.SOURCE_MANIFEST_SHA256,
                "context": {
                    key: getattr(native, key) for key in ("candidate", "run", "attempt", "job", "image", "architecture")
                },
                "record": record,
            },
        )
        task, actor, final_task, state, final_state, files = self.samples(fault)
        file_index = 0

        def image_file(*_args: object) -> tuple:
            nonlocal file_index
            index = file_index
            file_index += 1
            if fault == ("image-launcher", "image-rootlesskit", "image-engine")[index]:
                raise PermissionError(13, "PRIVATE_IMAGE_CANARY")
            return files[index]

        with (
            patch.object(control, "ControlPort", port_type),
            patch.object(
                control,
                "inspect_gate",
                side_effect=PermissionError(13, "PRIVATE_GATE_CANARY") if fault == "gate" else [state, final_state],
            ),
            patch.object(
                control,
                "actor_snapshot",
                side_effect=PermissionError(13, "PRIVATE_ACTOR_CANARY")
                if fault == "actor-read"
                else [(task, actor), (final_task, actor)],
            ),
            patch.object(observations, "_image_file", side_effect=image_file),
            patch.object(
                observations.os,
                "open",
                side_effect=FileNotFoundError(2, "PRIVATE_PROC_CANARY") if fault == "proc" else None,
                return_value=11,
            ),
            patch.object(observations.os, "pidfd_open", return_value=12, create=True),
            patch.object(observations.os, "close"),
            patch.object(
                observations.select, "select", return_value=([12], [], []) if fault == "liveness" else ([], [], [])
            ),
            patch.object(contract, "RECORD_BYTES", 1 if fault == "reply" else contract.RECORD_BYTES),
        ):
            try:
                result = control.rpc(
                    current,
                    (Path("/unused-stage"), {"context": {"purpose": contract.PURPOSE}}, SimpleNamespace()),
                    route,
                )
                failure = None
            except (OSError, ValueError, active.RefusedError) as error:
                result = None
                failure = active.failure_receipt(route.diagnostic, error)
        self.assertEqual(record["firstFailureHistory"], [{"unchanged": "PRIVATE_HISTORY_CANARY"}])
        self.assertEqual(store.close.call_count, 1)
        return result, failure, record, holder[0] if holder else None

    def test_all_eleven_direct_guards_are_labelled_without_reusing_prior_daemon(self) -> None:
        faults = (
            "intent",
            "unreleased",
            "subject",
            "task",
            "launcher",
            "elf",
            "engine",
            "version-size",
            "version",
            "actor",
            "incarnation",
        )
        for fault in faults:
            with self.subTest(fault=fault):
                _result, failure, _record, owned = self.execute(fault)
                self.assertTrue(active.valid_failure(failure))
                self.assertEqual(failure["phase"], "direct-preflight-" + fault)
                self.assertFalse(failure["comparisons"][failure["phase"]])
                self.assertNotIn("daemon", failure["comparisons"])
                self.assertNotIn("PRIVATE_", json.dumps(failure))
                self.assertFalse(failure["cleanupAuthority"])
                self.assertLessEqual(owned.commit.call_count, 2)

    def test_nested_readers_authority_request_commit_and_reply_have_finite_current_groups(self) -> None:
        for fault in (
            "gate",
            "proc",
            "actor-read",
            "image-launcher",
            "image-rootlesskit",
            "image-engine",
            "version-query",
            "liveness",
            "authority",
            "request",
            "commit",
            "final-commit",
            "reply",
        ):
            expected = (
                "admission"
                if fault == "authority"
                else "direct-preflight-rpc"
                if fault == "request"
                else "direct-preflight-actor"
                if fault == "liveness"
                else "direct-preflight-commit"
                if fault == "final-commit"
                else "direct-preflight-" + fault
            )
            with self.subTest(fault=fault):
                _result, failure, _record, _owned = self.execute(fault)
                self.assertTrue(active.valid_failure(failure))
                self.assertEqual(failure["phase"], expected)
                self.assertNotIn("daemon", failure["comparisons"])
                self.assertNotIn("PRIVATE_", json.dumps(failure))
                self.assertLessEqual(len(active.encoded(failure)), active.MAX_FAILURE)

    def test_retained_record_diagnostics_and_history_are_not_cleared_on_refusal(self) -> None:
        _result, failure, record, owned = self.execute("retained")
        self.assertTrue(active.valid_failure(failure))
        self.assertEqual(failure["phase"], "direct-preflight-rpc")
        self.assertEqual(record["diagnostic"], {"phase": "daemon", "comparisons": {"daemon": True}})
        self.assertTrue(record["retained"])
        self.assertEqual(owned.commit.call_count, 0)

    def test_success_keeps_original_two_commits_and_does_not_release_gate(self) -> None:
        result, failure, record, owned = self.execute(None)
        self.assertIsNone(failure)
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(owned.commit.call_count, 2)
        self.assertFalse(record["directGate"]["released"])
        self.assertEqual(record["diagnostic"]["phase"], "direct-preflight-reply")
        self.assertTrue(all(record["diagnostic"]["comparisons"].values()))

    def test_unknown_or_malformed_diagnostic_values_never_escape(self) -> None:
        owned = port()
        owned.record["diagnostic"] = {"phase": "direct-preflight-rpc", "comparisons": {}}
        with (
            self.assertRaises(active.RefusedError) as raised,
            observations.guard_group(owned, api(), "PRIVATE_PHASE_CANARY"),
        ):
            self.fail("unknown phase was accepted")
        value = active.failure_receipt({"record": owned.record}, raised.exception)
        self.assertEqual(value["phase"], "direct-preflight-rpc")
        malformed = active.failure_receipt({"diagnostic": ["PRIVATE_DIAGNOSTIC"]}, active.RefusedError())
        self.assertEqual(malformed["phase"], "unknown")
        self.assertNotIn("PRIVATE_", json.dumps([value, malformed]))

    def test_nested_image_reader_guard_families_preserve_original_refusals(self) -> None:
        cases = (
            ("directory", "direct-image-directory"),
            ("file", "direct-image-file"),
            ("capability", "direct-image-capability"),
            ("read", "direct-image-read"),
            ("stable", "direct-image-stable"),
        )
        families = (
            ("direct-image", ("usr", "rootlesskit")),
            ("direct-launcher", ("usr", "local", "bin", "start-dockerd")),
            ("direct-rootlesskit", ("usr", "local", "bin", "rootlesskit")),
            ("direct-engine", ("usr", "share", "strukturpiloten", "docker", "engine-version")),
        )
        for (fault, generic_phase), (family, components) in ((case, family) for case in cases for family in families):
            phase = generic_phase.replace("direct-image", family)
            with self.subTest(fault=fault, family=family):
                owned, current = port(), api()
                current.check, current.mark = Mock(), active.mark
                directory = SimpleNamespace(st_uid=0, st_mode=0o40777 if fault == "directory" else 0o40755)
                before = SimpleNamespace(
                    st_dev=1,
                    st_ino=2,
                    st_uid=0,
                    st_gid=0,
                    st_mode=0o100555,
                    st_nlink=2 if fault == "file" else 1,
                    st_size=1,
                    st_mtime_ns=1,
                    st_ctime_ns=1,
                )
                after = SimpleNamespace(**{**vars(before), "st_ino": 3 if fault == "stable" else 2})
                with (
                    patch.object(observations.os, "open", return_value=11),
                    patch.object(observations.os, "close"),
                    patch.object(
                        observations.os, "fstat", side_effect=[*([directory] * (len(components) - 1)), before, after]
                    ),
                    patch.object(observations.os, "stat", return_value=before),
                    patch.object(
                        observations.os,
                        "getxattr",
                        side_effect=OSError(
                            errno.EACCES if fault == "capability" else errno.ENODATA, "PRIVATE_XATTR_CANARY"
                        ),
                    ),
                    patch.object(observations.os, "read", side_effect=[b"xxxxx" if fault == "read" else b"x", b""]),
                    self.assertRaises(active.RefusedError) as raised,
                ):
                    observations._image_file(owned, current, 5, components, 4)
                failure = active.failure_receipt({"record": owned.record}, raised.exception)
                self.assertTrue(active.valid_failure(failure))
                self.assertEqual(failure["phase"], phase)
                self.assertFalse(failure["comparisons"][phase])
                self.assertNotIn("PRIVATE_", json.dumps(failure))
