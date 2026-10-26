"""Synthetic monitor custody fixtures; no runtime, package queries or native OOM."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_docker_systemd as systemd
from scripts import runtime_oom_diagnostics as diagnostics
from scripts import runtime_oom_watch as custody
from scripts.runtime_errors import ProbeError

CID = "a" * 64
OUTER = "/machine.slice/libpod-" + CID + ".scope"
CURRENT = OUTER + "/container/init.scope"


def _terminal(*, oom: bool = False) -> dict:
    return {
        "Running": False,
        "Status": "exited",
        "ExitCode": 0,
        "OOMKilled": oom,
        "Error": "",
        "Pid": 0,
        "Paused": False,
        "Restarting": False,
        "Dead": False,
    }


class MonitorTests(unittest.TestCase):
    def reads(self) -> diagnostics._MonitorReads:
        return diagnostics._MonitorReads(time.monotonic() + 10)

    def fixture(self, root: Path) -> tuple[Path, Path, Path, dict, list[str]]:
        proc, host, store = root / "proc/99", root / "host", root / "store"
        (proc / "fd").mkdir(parents=True)
        (proc / "fdinfo").mkdir()
        (proc / "exe").write_bytes(b"authored-monitor-not-an-executable")
        persist, bundle = store / "persist" / CID, store / "bundles" / CID / "userdata"
        persist.mkdir(parents=True)
        bundle.mkdir(parents=True)
        (proc / "cmdline").write_bytes(
            ("conmon\0-c\0" + CID + "\0--persist-dir\0" + str(persist) + "\0-b\0" + str(bundle) + "\0").encode()
        )
        paths = [CURRENT, OUTER + "/container", OUTER]
        for path in paths:
            group = host / path.lstrip("/")
            group.mkdir(parents=True, exist_ok=True)
            (group / "memory.events").write_text("max 0\noom 0\noom_kill 0\n")
        watched = (host / OUTER.lstrip("/") / "memory.events").stat()
        device = (os.major(watched.st_dev) << 20) | os.minor(watched.st_dev)
        (proc / "fd/7").symlink_to("anon_inode:inotify")
        (proc / "fdinfo/7").write_text(
            f"pos:\t0\ninotify wd:1 ino:{watched.st_ino:x} sdev:{device:x} mask:2 ignored_mask:0\n"
        )
        identity = {"starttime": "100", "cgroup": "0::/monitor", "exe": "/usr/bin/conmon"}
        return proc, host, store, identity, paths

    def capture(self, _root: Path, fixture: tuple, previous: dict | None = None) -> dict:
        proc, host, store, identity, paths = fixture

        def mapped(value: str) -> Path:
            return {"/proc": proc.parent, "/sys/fs/cgroup": host}.get(value, Path(value))

        with (
            patch.object(diagnostics, "Path", side_effect=mapped),
            patch.object(diagnostics, "_process", return_value=identity),
            patch.object(diagnostics, "_installed_package", return_value={"availability": "unresolved fixture"}),
        ):
            request = {
                "container": CID,
                "state": {"ConmonPid": 99, "CgroupPath": OUTER},
                "directory": str(store),
                "monitor": previous,
            }
            return diagnostics._monitor(request, identity, paths, self.reads())

    def test_live_monitor_hash_watch_and_actual_marker_arguments_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch("subprocess.run") as execute:
            root = Path(temporary)
            fixture = self.fixture(root)
            first = self.capture(root, fixture)
            self.assertEqual(
                first["executable"]["sha256"], hashlib.sha256((fixture[0] / "exe").read_bytes()).hexdigest()
            )
            self.assertEqual(first["watchedCgroupPath"], OUTER)
            self.assertNotEqual(first["watchedCgroupPath"], CURRENT)
            self.assertEqual(first["watch"]["file"], "memory.events")
            self.assertIsNone(first["actualVersion"])
            self.assertIn("unresolved", first["versionAttribution"])
            self.assertTrue(first["identityVerified"])
            markers = first["markers"]["observations"]
            self.assertEqual([item["availability"] for item in markers], ["missing", "missing"])
            self.assertEqual(markers[0]["path"], str(fixture[2] / "persist" / CID / "oom"))
            Path(markers[0]["path"]).write_bytes(b"")
            second = self.capture(root, fixture, first)
            self.assertEqual(second["markers"]["observations"][0]["availability"], "present")
            execute.assert_not_called()

    def test_raw_kernel_device_uses_twenty_minor_bits_not_userspace_encoding(self) -> None:
        major, minor = 259, 0x12345
        raw = (major << 20) | minor
        self.assertEqual(diagnostics._watch_device(f"{raw:x}"), (major, minor))
        device = os.makedev(major, minor)
        candidate = {"path": OUTER, "inode": 123, "major": os.major(device), "minor": os.minor(device)}
        watch = {"inode": 123, "major": major, "minor": minor, "fd": 7, "wd": 1}
        self.assertEqual(diagnostics._match_watch([watch], [candidate])["path"], OUTER)
        for candidates in ([], [candidate, dict(candidate)], [{**candidate, "minor": minor + 1}]):
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                diagnostics._match_watch([watch], candidates)
        for unsupported in ("-1", "xyz", "100000000"):
            with self.assertRaises(ValueError):
                diagnostics._watch_device(unsupported)

    def test_missing_or_changed_watch_never_assumes_current_cgroup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            (fixture[0] / "fdinfo/7").write_text("inotify wd:1 ino:1 sdev:1 mask:2 ignored_mask:0\n")
            result = self.capture(root, fixture)
            self.assertIsNone(result["watchedCgroupPath"])
            self.assertEqual(result["watch"]["availability"], "unresolved")
            self.assertIn("missing or ambiguous", result["watch"]["reason"])

    def test_watch_and_binary_changes_are_not_hidden_by_previous_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            baseline = self.capture(root, fixture)
            watches = diagnostics._inotify(fixture[0], self.reads())
            with patch.object(diagnostics, "_inotify", side_effect=[watches, [{**watches[0], "wd": 2}]]):
                changed = self.capture(root, fixture, baseline)
            self.assertIsNone(changed["watchedCgroupPath"])
            self.assertIn("watch identity changed", changed["watch"]["reason"])
            (fixture[0] / "exe").write_bytes(b"different authored monitor")
            with self.assertRaisesRegex(ValueError, "executable changed"):
                self.capture(root, fixture, baseline)

    def test_internally_stable_changed_watch_descriptor_is_unresolved_across_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            baseline = self.capture(root, fixture)
            fdinfo = fixture[0] / "fdinfo/7"
            fdinfo.write_text(fdinfo.read_text().replace("wd:1 ", "wd:2 "))
            changed = self.capture(root, fixture, baseline)
            self.assertIsNone(changed["watchedCgroupPath"])
            self.assertEqual(changed["watch"]["availability"], "unresolved")
            self.assertIn("identity changed across snapshots", changed["watch"]["reason"])
            self.assertEqual(changed["watch"]["observedCandidate"]["wd"], 2)
            self.assertEqual(changed["watch"]["expectedObservedWatch"], baseline["watch"])
            again = self.capture(root, fixture, changed)
            self.assertEqual(again["watch"]["availability"], "unresolved")
            self.assertEqual(again["watch"]["expectedObservedWatch"], baseline["watch"])

    def test_internally_stable_changed_candidate_path_is_unresolved_across_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            baseline = self.capture(root, fixture)
            moved = (fixture[1] / CURRENT.lstrip("/") / "memory.events").stat()
            device = (os.major(moved.st_dev) << 20) | os.minor(moved.st_dev)
            (fixture[0] / "fdinfo/7").write_text(
                f"pos:\t0\ninotify wd:1 ino:{moved.st_ino:x} sdev:{device:x} mask:2 ignored_mask:0\n"
            )
            changed = self.capture(root, fixture, baseline)
            self.assertIsNone(changed["watchedCgroupPath"])
            self.assertEqual(changed["watch"]["availability"], "unresolved")
            self.assertIn("identity changed across snapshots", changed["watch"]["reason"])
            self.assertEqual(changed["watch"]["observedCandidate"]["path"], CURRENT)
            self.assertEqual(changed["watch"]["expectedObservedWatch"]["path"], OUTER)

    def test_event_candidates_never_walk_host_ancestors_or_descendants(self) -> None:
        with patch.object(Path, "stat") as read_stat:
            with self.assertRaisesRegex(ValueError, "escaped"):
                diagnostics._event_candidates(Path("/sys/fs/cgroup"), OUTER, ["/"], self.reads())
            with self.assertRaisesRegex(ValueError, "count"):
                diagnostics._event_candidates(
                    Path("/sys/fs/cgroup"), OUTER, [OUTER] * (diagnostics.MAX_GROUPS + 1), self.reads()
                )
            read_stat.assert_not_called()

    def test_binary_fd_and_source_read_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc, *_rest = self.fixture(root)
            with patch.object(diagnostics, "MAX_BINARY_BYTES", 4), self.assertRaisesRegex(ValueError, "size bound"):
                diagnostics._executable(proc, self.reads())
            for number in range(diagnostics.MAX_MONITOR_FDS + 1):
                (proc / "fd" / str(100 + number)).symlink_to("/dev/null")
            with self.assertRaisesRegex(ValueError, "FD count"):
                diagnostics._inotify(proc, self.reads())
            reads = self.reads()
            reads.calls = diagnostics.MAX_MONITOR_READS
            with self.assertRaisesRegex(ValueError, "read count"):
                reads.file(proc / "cmdline")
            reads = self.reads()
            reads.bytes = diagnostics.MAX_MONITOR_BYTES
            with self.assertRaisesRegex(ValueError, "aggregate byte"):
                reads.file(proc / "cmdline")
            with (
                patch.object(diagnostics.time, "monotonic", return_value=100),
                self.assertRaisesRegex(ValueError, "deadline"),
            ):
                diagnostics._MonitorReads(99).check()
            with patch.object(diagnostics.time, "monotonic", return_value=100):
                reads = diagnostics._MonitorReads(110)
                self.assertEqual(reads.deadline, 110 - diagnostics.MONITOR_CLEANUP_SECONDS)

    def test_argument_identity_and_marker_custody_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            baseline = self.capture(root, fixture)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                self.capture(root, fixture, {**baseline, "starttime": "101"})
            for arguments in (["-c", CID, "--cid", CID], ["-c"]):
                with self.assertRaises(ValueError):
                    diagnostics._argument(arguments, {"-c", "--cid"})
            marker = Path(baseline["markers"]["candidates"][0]["path"])
            marker.symlink_to(root / "outside")
            with self.assertRaises(OSError):
                diagnostics._markers(baseline["markers"], self.reads())
            marker.unlink()
            marker.write_bytes(b"x" * (diagnostics.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size"):
                diagnostics._markers(baseline["markers"], self.reads())
            marker.unlink()
            parent = marker.parent
            parent.rename(parent.with_name("old-parent"))
            parent.mkdir()
            with self.assertRaisesRegex(ValueError, "parent identity changed"):
                diagnostics._markers(baseline["markers"], self.reads())
            for bad in (str(root / "elsewhere/oom"), str(fixture[2] / "../escape/oom")):
                with self.assertRaises(ValueError):
                    diagnostics._owned_parts(str(fixture[2]), bad)

    def test_fixed_package_metadata_is_separate_from_verified_inode_hash_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc, *_rest = self.fixture(root)
            executable = diagnostics._executable(proc, self.reads())
            installed = str(proc / "exe")
            metadata = "conmon\t2.1.13-1ubuntu1\tconmon\t2.1.13-1ubuntu1\tamd64"
            with (
                patch.object(diagnostics, "INSTALLED_MONITOR", installed),
                patch.object(diagnostics, "_package_query", side_effect=["conmon: " + installed, metadata]) as query,
                patch.object(
                    diagnostics._MonitorReads,
                    "file",
                    return_value=("1" * 32 + "  " + installed.lstrip("/") + "\n").encode(),
                ),
            ):
                observed = diagnostics._installed_package({"exe": installed}, executable, self.reads())
                self.assertEqual(query.call_count, 2)
                self.assertEqual(query.call_args_list[0].args[0], "owner")
                self.assertEqual(query.call_args_list[1].args[0], "version")
                self.assertEqual(observed["availability"], "observed-unverified-metadata")
                self.assertEqual(observed["packageClaim"]["sourceVersion"], "2.1.13-1ubuntu1")
                self.assertIn("unresolved", observed["sourceAttribution"])
                self.assertIn("not authenticity", observed["packageRecordedChecksum"]["verification"])
                diagnostics._installed_package({"exe": installed}, executable, self.reads(), observed)
                self.assertEqual(query.call_count, 2)  # No renewed package campaign.
                changed = {**executable, "sha256": "0" * 64}
                failed = diagnostics._installed_package({"exe": installed}, changed, self.reads())
                self.assertEqual(failed["availability"], "unresolved")
                self.assertEqual(query.call_count, 2)

    def test_fixed_package_query_timeout_and_overflow_kill_and_reap_within_budget(self) -> None:
        for overflow in (False, True):
            with self.subTest(overflow=overflow):
                process = MagicMock()
                process.__enter__.return_value = process
                process.stdout.fileno.return_value = 7
                process.poll.return_value = None
                process.wait.return_value = 0
                ready = ([7], [], []) if overflow else ([], [], [])
                with (
                    patch.object(diagnostics.subprocess, "Popen", return_value=process) as spawn,
                    patch.object(diagnostics.os, "set_blocking"),
                    patch.object(diagnostics.select, "select", return_value=ready),
                    patch.object(
                        diagnostics._MonitorReads, "read", return_value=b"x" * (diagnostics.MAX_PACKAGE_BYTES + 1)
                    ),
                    self.assertRaises(ValueError),
                ):
                    diagnostics._package_query("owner", self.reads())
                self.assertEqual(spawn.call_args.args[0], ["/usr/bin/dpkg-query", "-S", "/usr/bin/conmon"])
                process.kill.assert_called_once()
                process.wait.assert_called_once()
                self.assertLessEqual(process.wait.call_args.kwargs["timeout"], diagnostics.SNAPSHOT_SECONDS)
        with patch.object(diagnostics.subprocess, "Popen") as spawn, self.assertRaises(ValueError):
            diagnostics._package_query("arbitrary-provider", self.reads())
        spawn.assert_not_called()

    def test_post_exit_uses_retained_parent_custody_without_proc_or_guest_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            baseline = self.capture(root, fixture)
            marker = Path(baseline["markers"]["candidates"][1]["path"])
            marker.write_bytes(b"")
            request = {
                "container": CID,
                "state": _terminal(oom=True),
                "monitor": baseline,
                "directory": str(fixture[2]),
                "deadline": time.monotonic() + 10,
            }
            with patch.object(diagnostics, "_process") as process, patch("subprocess.run") as execute:
                result = diagnostics._collect_after_exit(request)
            process.assert_not_called()
            execute.assert_not_called()
            self.assertEqual(result["markers"]["observations"][1]["availability"], "present")
            request["container"] = "b" * 64
            with self.assertRaises(ValueError):
                diagnostics._collect_after_exit(request)

    def test_after_exit_is_once_only_host_command_and_optional(self) -> None:
        ctx = MagicMock()
        ctx.containers, ctx.observations, ctx.checks = [CID], [], []
        ctx.timeout, ctx.directory, ctx._sudo = 45, Path(tempfile.gettempdir()) / "fixture-owned", []
        ctx.command.return_value = "{}"
        observer = diagnostics.OomDiagnostics(ctx, CID)
        observer.monitor_context = {"retained": "live-only"}
        observer.after_exit(CID, _terminal(oom=True))
        observer.after_exit(CID, _terminal())
        ctx.command.assert_called_once()
        ctx.exec.assert_not_called()
        ctx.podman.assert_not_called()
        self.assertIn("--after-exit", ctx.command.call_args.args[1])
        self.assertEqual(ctx.command.call_args.kwargs["timeout"], 10)
        self.assertEqual(ctx.checks, [])
        self.assertEqual(ctx.observations[0]["attribution"], "unresolved")
        ctx.observations.clear()
        diagnostics.OomDiagnostics(ctx, CID).after_exit(CID, _terminal())
        self.assertEqual(ctx.observations[0]["availability"], "error")

    def test_clean_workload_can_retain_live_monitor_without_inner_oom_baseline(self) -> None:
        ctx = MagicMock()
        ctx.containers, ctx.observations, ctx.checks = [CID], [], []
        ctx.timeout, ctx.directory, ctx._sudo = 45, Path(tempfile.gettempdir()) / "fixture-owned", []
        ctx.podman.return_value = json.dumps({"Running": True})
        monitor = {"identityVerified": True, "container": CID, "starttime": "100"}
        ctx.command.side_effect = [json.dumps({"conmon": monitor, "guestChain": [{"availability": "observed"}]}), "{}"]
        observer = diagnostics.OomDiagnostics(ctx, CID)
        observer.snapshot("before-ordinary-work")
        self.assertEqual(observer.monitor_context, monitor)
        self.assertIsNone(observer.baseline)
        observer.after_exit(CID, _terminal())
        self.assertEqual(ctx.command.call_count, 2)
        request = json.loads(ctx.command.call_args.args[1][-1])
        self.assertEqual(request["monitor"], monitor)
        self.assertEqual(ctx.checks, [])


class ExitObserverTests(unittest.TestCase):
    def context(self, state: dict, *, running: bool = False, request_error: bool = False) -> MagicMock:
        ctx = MagicMock(unsafe=True)
        ctx.containers, ctx.observations, ctx.checks = [CID], [], []
        values = [CID, json.dumps({"Running": True}) if running else json.dumps(state)]
        if running:
            values.extend(["RTMIN+3", ProbeError("original request failure") if request_error else ""])
            if not request_error:
                values.append("0")
            values.extend([json.dumps(state), json.dumps(state)])
        ctx.podman.side_effect = values
        return ctx

    def test_already_exited_observer_mutation_cannot_excuse_actual_oom(self) -> None:
        for actual in (_terminal(oom=True), {**_terminal(), "ExitCode": 17}):
            with self.subTest(actual=actual):
                ctx = self.context(actual)

                def mutate(_cid: str, state: dict, *, context: MagicMock = ctx) -> None:
                    self.assertEqual(context.checks, [])
                    state["OOMKilled"], state["ExitCode"] = False, 0

                with self.assertRaisesRegex(ProbeError, "without OOM"):
                    systemd.stop_guest(ctx, CID, on_exit=mutate)
                self.assertEqual(ctx.checks[-1]["actual"], actual)

    def test_observer_errors_or_mutations_do_not_reject_clean_exit(self) -> None:
        for raises in (False, True):
            with self.subTest(raises=raises):
                ctx = self.context(_terminal())

                def observe(_cid: str, state: dict, *, fail: bool = raises) -> None:
                    state["OOMKilled"], state["ExitCode"] = True, 9
                    if fail:
                        message = "optional fixture failure"
                        raise RuntimeError(message)

                systemd.stop_guest(ctx, CID, on_exit=observe)
                self.assertEqual(ctx.checks[-1]["status"], "passed")
                self.assertEqual(len(ctx.observations), int(raises))

    def test_running_oom_observed_once_before_unchanged_failure_and_fallback(self) -> None:
        ctx, observer = self.context(_terminal(oom=True), running=True), MagicMock()
        with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission"):
            systemd.stop_guest(ctx, CID, on_exit=observer)
        observer.assert_called_once()
        self.assertTrue(observer.call_args.args[1]["OOMKilled"])
        ctx.stop.assert_called_once_with(CID, seconds=30)
        commands = [call.args[1] for call in ctx.podman.call_args_list]
        self.assertEqual(commands.count("exec"), 1)
        self.assertNotIn("exec", commands[commands.index("exec") + 1 :])

    def test_successful_running_exit_observer_is_once_and_host_only(self) -> None:
        ctx, observer = self.context(_terminal(), running=True), MagicMock()
        systemd.stop_guest(ctx, CID, on_exit=observer)
        observer.assert_called_once_with(CID, _terminal())
        self.assertEqual(ctx.checks[-1]["status"], "passed")
        ctx.stop.assert_not_called()
        commands = [call.args[1] for call in ctx.podman.call_args_list]
        self.assertNotIn("exec", commands[commands.index("exec") + 1 :])

    def test_original_shutdown_error_survives_optional_observer_failure(self) -> None:
        ctx = self.context(_terminal(), running=True, request_error=True)
        observer = MagicMock(side_effect=RuntimeError("optional fixture failure"))
        with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission") as raised:
            systemd.stop_guest(ctx, CID, on_exit=observer)
        self.assertEqual(str(raised.exception.__cause__), "original request failure")
        observer.assert_called_once()
        self.assertEqual(ctx.observations[-1]["availability"], "error")

    def test_before_stop_observer_brackets_only_the_actual_request(self) -> None:
        for failure in (False, True):
            with self.subTest(failure=failure):
                ctx, observer = self.context(_terminal(), running=True, request_error=failure), MagicMock()
                observer.side_effect = lambda context=ctx: self.assertEqual(context.podman.call_count, 3)
                if failure:
                    with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission"):
                        systemd.stop_guest(ctx, CID, before_stop=observer)
                else:
                    systemd.stop_guest(ctx, CID, before_stop=observer)
                observer.assert_called_once_with()
        ctx, observer = self.context(_terminal()), MagicMock()
        systemd.stop_guest(ctx, CID, before_stop=observer)
        observer.assert_not_called()

    def test_before_stop_observer_failure_never_excuses_outer_oom(self) -> None:
        ctx = self.context(_terminal(oom=True), running=True)
        observer = MagicMock(side_effect=OSError("authored observer failure"))
        with self.assertRaisesRegex(ProbeError, "emergency halt is not native admission"):
            systemd.stop_guest(ctx, CID, before_stop=observer)
        self.assertEqual(ctx.observations[0]["availability"], "error")
        self.assertEqual(ctx.checks[-1]["status"], "failed")


class MarkerCustodyTests(unittest.TestCase):
    """Exercise actual local inotify/pidfd identities without a container."""

    def fixture(self, root: Path, *, pid: int | None = None) -> tuple[dict, Path, Path]:
        store = root / "store"
        persist, bundle = store / "persist" / CID, store / "bundle" / CID
        persist.mkdir(parents=True)
        bundle.mkdir(parents=True)
        group = root / "cgroup"
        group.mkdir()
        for name in ("memory.events", "memory.events.local"):
            (group / name).write_text("max 0\noom 0\noom_kill 0\n")
        markers = diagnostics._markers(
            {
                "directory": str(store),
                "candidates": [
                    {"path": str(persist / "oom")},
                    {"path": str(bundle / "oom")},
                ],
            },
            diagnostics._MonitorReads(time.monotonic() + 10),
        )
        info = (group / "memory.events").stat()
        original_pid = os.getpid() if pid is None else pid
        request = {
            "pid": original_pid,
            "starttime": custody._birth(original_pid),
            "deadline": time.monotonic() + 10,
            "markers": markers,
            "watch": {
                "availability": "observed",
                "path": "/owned",
                "inode": info.st_ino,
                "major": os.major(info.st_dev),
                "minor": os.minor(info.st_dev),
                "directoryIdentity": {"dev": group.stat().st_dev, "ino": group.stat().st_ino},
                "fd": 7,
                "wd": 1,
            },
        }
        return request, persist / "oom", group

    def observer(self, request: dict, group: Path) -> custody.MarkerCustody:
        original = custody._directory

        def mapped(path: Path) -> int:
            return original(group if path == Path("/sys/fs/cgroup/owned") else path)

        with patch.object(custody, "_directory", side_effect=mapped):
            observer = custody.MarkerCustody(request)
        self.addCleanup(observer.close)
        return observer

    def test_kernel_creation_binds_original_inode_pidfd_and_counter_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            self.assertFalse(select.select([observer.pidfd], [], [], 0)[0])
            (group / "memory.events").write_text("max 1\noom 1\noom_kill 1\n")
            marker.write_bytes(b"authored marker")
            record = observer.sample("after-inner-memory")
            created = next(event for event in record["events"] if event["mask"] & custody.IN_CREATE)
            self.assertEqual(created["fileIdentity"]["ino"], marker.stat().st_ino)
            self.assertTrue(created["originalPidAlive"])
            self.assertEqual(created["counters"]["memory.events"]["oom_kill"], 1)
            self.assertEqual(created["counters"]["memory.events.local"]["oom_kill"], 0)
            self.assertEqual(record["markers"][0]["sha256"], hashlib.sha256(b"authored marker").hexdigest())
            self.assertEqual(record["originalConmonWatch"], request["watch"])
            self.assertEqual(record["attribution"], "unresolved")
            self.assertEqual(record["uncertainty"], [])
            held = list(observer.fds)
            observer.close()
            for descriptor in held:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_marker_removed_with_parent_retains_creation_but_stays_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            marker.touch()
            original = observer.sample("after-inner-memory")["events"][0]["fileIdentity"]
            marker.unlink()
            marker.parent.rmdir()
            record = observer.sample("before-stop-request")
            self.assertEqual(record["events"][0]["fileIdentity"], original)
            self.assertEqual(record["markers"][0]["availability"], "unresolved")
            self.assertTrue(record["uncertainty"])
            self.assertTrue(record["originalPidAlive"])

    def test_replaced_marker_and_parent_never_become_new_baselines(self) -> None:
        for replacement in ("marker", "parent"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                request, marker, group = self.fixture(Path(directory))
                observer = self.observer(request, group)
                marker.touch()
                old = observer.sample("after-inner-memory")["events"][0]["fileIdentity"]
                if replacement == "marker":
                    marker.unlink()
                else:
                    marker.parent.rename(marker.parent.with_name("old-parent"))
                    marker.parent.mkdir()
                marker.write_bytes(b"replacement")
                record = observer.sample("before-stop-request")
                self.assertEqual(record["events"][0]["fileIdentity"], old)
                self.assertEqual(record["markers"][0]["availability"], "unresolved")
                self.assertEqual(len(record["markers"][0]["completedContents"]), 1)
                self.assertTrue(record["uncertainty"])

    def test_original_pid_exit_is_held_and_only_bracketed_request_is_recorded(self) -> None:
        for before_stop in (False, True):
            with (
                self.subTest(before_stop=before_stop),
                tempfile.TemporaryDirectory() as directory,
                subprocess.Popen(
                    [sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read()"],
                    stdin=subprocess.PIPE,
                ) as child,
            ):
                request, _marker, group = self.fixture(Path(directory), pid=child.pid)
                observer = self.observer(request, group)
                if before_stop:
                    self.assertTrue(observer.sample("before-stop-request")["originalPidAlive"])
                child.stdin.close()
                child.wait(timeout=2)
                record = observer.sample("after-exit")
                self.assertFalse(record["originalPidAlive"])
                self.assertIsInstance(record["exitObservedMonotonicNs"], int)
                self.assertEqual(record["beforeStopBoundaryObserved"], before_stop)
                self.assertIn("precedes command dispatch", record["stopDelivery"])
                self.assertEqual(bool(record["uncertainty"]), not before_stop)

    def test_invalid_binding_partial_events_and_expiry_are_not_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            request["starttime"] = "0"
            with self.assertRaisesRegex(ValueError, "original PID changed"):
                self.observer(request, group)
            request["starttime"] = custody._birth(os.getpid())
            request["watch"]["inode"] += 1
            with self.assertRaisesRegex(ValueError, "event inode changed"):
                self.observer(request, group)
            request["watch"]["inode"] -= 1
            observer = self.observer(request, group)
            with patch.object(custody.os, "read", return_value=b"short"), self.assertRaisesRegex(ValueError, "partial"):
                observer.drain()
            observer.deadline = time.monotonic() - 1
            marker.touch()
            with self.assertRaisesRegex(ValueError, "deadline expired"):
                observer.sample("after-inner-memory")

    def test_oversize_marker_and_preexisting_marker_remain_unresolved(self) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                request, marker, group = self.fixture(Path(directory))
                if existing:
                    marker.touch()
                observer = self.observer(request, group)
                marker.write_bytes(b"x" * (custody.MAX_FILE + 1))
                record = observer.sample("after-inner-memory")
                self.assertEqual(record["markers"][0]["availability"], "unresolved")
                self.assertTrue(record["uncertainty"])
                self.assertLess(len(json.dumps(record)), custody.MAX_BYTES)

    def test_disappeared_conmon_watch_is_sticky_and_retains_original_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, _marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            observer.observe_watch({"availability": "unresolved"})
            observer.observe_watch(request["watch"])
            record = observer.sample("after-inner-memory")
            self.assertEqual(record["originalConmonWatch"], request["watch"])
            self.assertIn("conmon watch continuity unresolved", record["uncertainty"])

    def test_counter_read_failure_does_not_discard_held_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            marker.touch()
            old = observer.sample("after-inner-memory")["events"][0]["fileIdentity"]
            (group / "memory.events.local").write_text("partial")
            record = observer.sample("before-stop-request")
            self.assertEqual(record["events"][0]["fileIdentity"], old)
            self.assertEqual(record["counters"], {"availability": "unresolved"})
            self.assertIn("held counter read unresolved", record["uncertainty"])

    def test_autonomous_close_capture_survives_marker_and_parent_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            payload = b"completed before cleanup"
            marker.write_bytes(payload)
            inode = marker.stat().st_ino
            # No lifecycle sample before deletion: drain is the autonomous
            # observer path that must retain completed bytes before cleanup.
            observer.drain()
            marker.unlink()
            marker.parent.rmdir()
            record = observer.sample("before-stop-request")
            completed = record["markers"][0]["completedContents"]
            self.assertEqual(len(completed), 1)
            self.assertEqual(completed[0]["fileIdentity"]["ino"], inode)
            self.assertEqual(completed[0]["bytesRead"], len(payload))
            self.assertEqual(completed[0]["sha256"], hashlib.sha256(payload).hexdigest())
            close = next(event for event in record["events"] if event["mask"] & custody.IN_CLOSE_WRITE)
            self.assertEqual(close["completedContent"], completed[0])
            self.assertEqual(record["markers"][0]["availability"], "unresolved")
            self.assertTrue(record["uncertainty"])
            self.assertEqual(record["attribution"], "unresolved")

    def test_unclosed_rewrite_cannot_replace_prior_completed_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            original = b"original complete marker"
            marker.write_bytes(original)
            first = observer.sample("after-inner-memory")
            self.assertEqual(first["markers"][0]["availability"], "held")
            original_completion = dict(first["markers"][0]["completedContents"][0])
            with marker.open("wb") as writer:
                writer.write(b"prefix!")
                writer.flush()
                during = observer.sample("before-shutdown")
                current = during["markers"][0]
                self.assertEqual(current["availability"], "unresolved")
                self.assertNotIn("bytesRead", current)
                self.assertNotIn("sha256", current)
                self.assertEqual(current["completedContents"], [original_completion])
                self.assertEqual(original_completion["bytesRead"], len(original))
                self.assertIn("marker rewritten after completed observation", during["uncertainty"])
                writer.write(b"now closed")
            after = observer.sample("before-stop-request")
            self.assertEqual(after["markers"][0]["availability"], "held")
            completions = after["markers"][0]["completedContents"]
            self.assertEqual(completions[0], original_completion)
            self.assertEqual(len(completions), 2)
            self.assertEqual(completions[1]["sha256"], hashlib.sha256(b"prefix!now closed").hexdigest())
            self.assertGreater(completions[1]["observedWriteEpoch"], completions[0]["observedWriteEpoch"])
            self.assertIn("marker rewritten after completed observation", after["uncertainty"])

    def test_old_close_queued_before_later_open_rewrite_does_not_seal_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            marker.write_bytes(b"first writer closed")
            with marker.open("wb") as writer:
                writer.write(b"unclosed prefix")
                writer.flush()
                record = observer.sample("after-inner-memory")
                self.assertEqual(record["markers"][0]["availability"], "unresolved")
                self.assertEqual(record["markers"][0]["completedContents"], [])
                self.assertTrue(record["uncertainty"])
                self.assertTrue(all("completedContent" not in event for event in record["events"]))

    @staticmethod
    def _rewrite_after_queued_events(
        observer: custody.MarkerCustody, marker: Path, writers: list, raw: bytes
    ) -> list[tuple[int, int, int, bytes]]:
        parsed = custody.MarkerCustody._queued_events(observer, raw)
        if not writers:
            # The initial batch has been read and parsed; its old close has
            # not caused a content read. The modify enters the next batch.
            writer = marker.open("wb")
            writers.append(writer)
            writer.write(b"unclosed race prefix")
            writer.flush()
        return parsed

    def test_rewrite_after_initial_queue_read_cannot_seal_open_prefix(self) -> None:
        for prior_completion in (False, True):
            with self.subTest(prior_completion=prior_completion), tempfile.TemporaryDirectory() as directory:
                request, marker, group = self.fixture(Path(directory))
                observer = self.observer(request, group)
                retained = []
                if prior_completion:
                    marker.write_bytes(b"independently completed original")
                    retained = list(observer.sample("after-inner-memory")["markers"][0]["completedContents"])
                marker.write_bytes(b"old close awaiting observer")
                writers = []
                try:
                    with patch.object(
                        observer,
                        "_queued_events",
                        side_effect=partial(self._rewrite_after_queued_events, observer, marker, writers),
                    ):
                        record = observer.sample("before-shutdown")
                    self.assertEqual(len(writers), 1)
                    self.assertFalse(writers[0].closed)
                    current = record["markers"][0]
                    self.assertEqual(current["availability"], "unresolved")
                    self.assertEqual(current["completedContents"], retained)
                    self.assertNotIn("sha256", current)
                    self.assertNotIn("bytesRead", current)
                    self.assertIn("completed marker changed during post-read bracket", record["uncertainty"])
                    prefix_hash = hashlib.sha256(b"unclosed race prefix").hexdigest()
                    self.assertNotIn(prefix_hash, json.dumps(record))
                    self.assertEqual(record["attribution"], "unresolved")
                finally:
                    for writer in writers:
                        writer.close()

    def test_rewrite_during_content_read_keeps_prior_completion_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            marker.write_bytes(b"prior completed original")
            prior = list(observer.sample("after-inner-memory")["markers"][0]["completedContents"])
            marker.write_bytes(b"old close awaiting read")
            original_read = observer._read
            writers = []

            def read_then_rewrite(descriptor: int, maximum: int) -> bytes:
                raw = original_read(descriptor, maximum)
                if descriptor == observer.markers[0]["file"] and not writers:
                    writer = marker.open("wb")
                    writers.append(writer)
                    writer.write(b"during read prefix")
                    writer.flush()
                return raw

            try:
                with patch.object(observer, "_read", side_effect=read_then_rewrite):
                    record = observer.sample("before-shutdown")
                self.assertEqual(len(writers), 1)
                self.assertFalse(writers[0].closed)
                self.assertEqual(record["markers"][0]["availability"], "unresolved")
                self.assertEqual(record["markers"][0]["completedContents"], prior)
                self.assertNotIn(hashlib.sha256(b"during read prefix").hexdigest(), json.dumps(record))
                self.assertTrue(record["uncertainty"])
            finally:
                for writer in writers:
                    writer.close()

    def test_post_read_queue_failure_cannot_publish_proposed_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            marker.write_bytes(b"original sealed history")
            prior = list(observer.sample("after-inner-memory")["markers"][0]["completedContents"])
            marker.write_bytes(b"later closed candidate")
            queued = observer._pending_events()
            message = "post-read queue incomplete"
            with (
                patch.object(observer, "_pending_events", side_effect=[queued, ValueError(message)]),
                self.assertRaisesRegex(ValueError, "post-read queue incomplete"),
            ):
                observer.drain()
            self.assertEqual(observer.markers[0]["completedContents"], prior)
            self.assertFalse(observer.markers[0]["closedWrite"])
            self.assertNotIn(hashlib.sha256(b"later closed candidate").hexdigest(), json.dumps(observer.events))

    def test_read_budget_and_kernel_queue_overflow_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request, _marker, group = self.fixture(Path(directory))
            observer = self.observer(request, group)
            raw = custody.EVENT_HEADER.pack(-1, custody.IN_Q_OVERFLOW, 0, 0)
            with patch.object(custody.os, "read", return_value=raw), self.assertRaisesRegex(ValueError, "overflow"):
                observer.drain()
            observer.reads = custody.MAX_READS
            with self.assertRaisesRegex(ValueError, "budget exhausted"):
                observer.sample("after-inner-memory")


class CustodyProtocolTests(unittest.TestCase):
    def watch_fixture(self) -> dict:
        return {
            "availability": "observed",
            "file": "memory.events",
            "path": CURRENT,
            "inode": 20,
            "major": 0,
            "minor": 1,
            "fd": 7,
            "wd": 1,
            "rawKernelDevice": "1",
            "deviceEncoding": "Linux raw kernel dev_t; 20 minor bits",
            "directoryIdentity": {"dev": os.makedev(0, 1), "ino": 10},
        }

    def closed_observer(
        self, payload: bytes, *, exited: bool = False, watch: dict | None = None
    ) -> diagnostics.OomDiagnostics:
        ctx = MagicMock()
        ctx.timeout, ctx.observations = 1, []
        observer = diagnostics.OomDiagnostics(ctx, CID)
        observer.custody_watch = copy.deepcopy(self.watch_fixture() if watch is None else watch)
        unused_reader, input_writer = os.pipe()
        os.close(unused_reader)
        output_reader, output_writer = os.pipe()
        os.write(output_writer, payload)
        os.close(output_writer)
        process = MagicMock()
        process.stdin = os.fdopen(input_writer, "wb", buffering=0)
        process.stdout = os.fdopen(output_reader, "rb", buffering=0)
        process.poll.return_value = 0 if exited else None
        self.addCleanup(process.stdin.close)
        self.addCleanup(process.stdout.close)
        observer.custody = process
        return observer

    def terminal_fixture(self) -> dict:
        return {
            "schemaVersion": 1,
            "availability": "error",
            "attribution": "unresolved",
            "reason": "ValueError",
            "events": [
                {"candidate": 0, "mask": custody.IN_CREATE, "observedMonotonicNs": 123, "originalPidAlive": True}
            ],
            "uncertainty": ["conmon watch continuity unresolved"],
            "originalConmonWatch": self.watch_fixture(),
            "exitObservedMonotonicNs": None,
        }

    def complex_terminal_fixture(self) -> dict:
        case = MarkerCustodyTests()
        with tempfile.TemporaryDirectory() as directory:
            request, marker, group = case.fixture(Path(directory))
            original = request["watch"]
            request["watch"] = diagnostics._match_watch(
                [
                    {
                        "fd": original["fd"],
                        "wd": original["wd"],
                        "inode": original["inode"],
                        "major": original["major"],
                        "minor": original["minor"],
                        "rawKernelDevice": f"{(original['major'] << 20) | original['minor']:x}",
                    }
                ],
                [{key: original[key] for key in ("path", "inode", "major", "minor", "directoryIdentity")}],
            )
            observer = case.observer(request, group)
            try:
                marker.write_bytes(b"sealed terminal marker")
                observer.drain()
                observer.observe_watch({"availability": "unresolved"})
                return {
                    "schemaVersion": 1,
                    "availability": "error",
                    "attribution": "unresolved",
                    "reason": "ValueError",
                    "events": copy.deepcopy(observer.events),
                    "originalConmonWatch": copy.deepcopy(observer.watch),
                    "exitObservedMonotonicNs": observer.exited_at,
                    "uncertainty": list(observer.reasons),
                }
            finally:
                case.doCleanups()

    def test_real_producer_marker_watch_and_completed_hash_survive_closed_terminal_validation(self) -> None:
        terminal = self.complex_terminal_fixture()
        observer = self.closed_observer((json.dumps(terminal) + "\n").encode(), watch=terminal["originalConmonWatch"])
        observer._custody_sample("after-exit")
        result = observer.ctx.observations[-1]["snapshot"]
        self.assertEqual(result["availability"], "error")
        self.assertEqual(result["events"], terminal["events"])
        self.assertEqual(result["originalConmonWatch"], terminal["originalConmonWatch"])
        completed = next(event["completedContent"] for event in result["events"] if "completedContent" in event)
        self.assertEqual(completed["sha256"], hashlib.sha256(b"sealed terminal marker").hexdigest())
        self.assertEqual(completed["bytesRead"], len(b"sealed terminal marker"))
        self.assertEqual(result["uncertainty"], ["conmon watch continuity unresolved"])
        self.assertEqual(observer.custody_terminal, terminal)

    def test_terminal_optional_payloads_and_opaque_text_are_recursively_closed(self) -> None:
        terminal = self.complex_terminal_fixture()
        create = next(index for index, event in enumerate(terminal["events"]) if event["mask"] & custody.IN_CREATE)
        close = next(index for index, event in enumerate(terminal["events"]) if "completedContent" in event)
        opaque_text = "protected fixture text"
        changes = (
            (("originalConmonWatch",), {"rawMessage": opaque_text}),
            (("originalConmonWatch", "rawMessage"), opaque_text),
            (("originalConmonWatch", "directoryIdentity", "rawMessage"), opaque_text),
            (("originalConmonWatch", "path"), "/other-owned-scope"),
            (("originalConmonWatch", "fd"), True),
            (("originalConmonWatch", "rawKernelDevice"), "bad"),
            (("events", create, "fileIdentity", "rawMessage"), opaque_text),
            (("events", create, "fileIdentity", "uid"), opaque_text),
            (("events", create, "counters", "memory.events", "rawMessage"), opaque_text),
            (("events", create, "counters", "memory.events", "oom"), opaque_text),
            (("events", close, "completedContent"), {"rawMessage": opaque_text}),
            (("events", close, "completedContent", "fileIdentity", "dev"), opaque_text),
            (("events", close, "completedContent", "version", "rawMessage"), opaque_text),
            (("events", close, "completedContent", "readIntervalMonotonicNs", "rawMessage"), opaque_text),
            (("events", close, "completedContent", "sha256"), opaque_text),
            (("events", close, "completedContent", "limits"), opaque_text),
            (("events", close, "completedContent", "bytesRead"), diagnostics.MAX_FILE_BYTES + 1),
            (("events", close, "completedContent", "observedWriteEpoch"), diagnostics.MAX_GROUPS + 1),
            (("events", close, "mask"), -1),
            (("events", close, "mask"), True),
            (("reason",), "ProtectedFixtureText"),
            (("uncertainty",), [opaque_text]),
            (("uncertainty",), ["conmon watch continuity unresolved"] * 2),
        )
        for path, value in changes:
            changed = copy.deepcopy(terminal)
            target = changed
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = value
            with self.subTest(path=path):
                observer = self.closed_observer(
                    (json.dumps(changed) + "\n").encode(), watch=terminal["originalConmonWatch"]
                )
                observer._custody_sample("after-exit")
                result = observer.ctx.observations[-1]["snapshot"]
                self.assertEqual(result["availability"], "unavailable")
                self.assertIsNone(observer.custody_terminal)
                self.assertNotIn(opaque_text, json.dumps(observer.ctx.observations))
                self.assertNotIn("ProtectedFixtureText", json.dumps(observer.ctx.observations))

    def test_known_constructor_error_without_observer_fields_remains_available(self) -> None:
        terminal = {
            "schemaVersion": 1,
            "availability": "error",
            "attribution": "unresolved",
            "reason": "FileNotFoundError",
        }
        observer = self.closed_observer((json.dumps(terminal) + "\n").encode())
        observer._custody_sample("armed")
        self.assertEqual(observer.ctx.observations[-1]["snapshot"]["reason"], "FileNotFoundError")
        self.assertEqual(observer.custody_terminal, terminal)

    def test_buffered_terminal_error_survives_broken_pipe_or_already_exited_helper(self) -> None:
        for exited in (False, True):
            with self.subTest(exited=exited):
                terminal = self.terminal_fixture()
                observer = self.closed_observer((json.dumps(terminal) + "\n").encode(), exited=exited)
                observer._custody_sample("before-stop-request")
                record = observer.ctx.observations[-1]
                self.assertEqual(record["availability"], "error")
                self.assertEqual(record["snapshot"]["reason"], "ValueError")
                self.assertEqual(record["snapshot"]["events"], terminal["events"])
                self.assertEqual(record["snapshot"]["terminalReceipt"], "buffered-after-input-closed")
                record["snapshot"]["events"].clear()
                with patch.object(diagnostics.os, "read") as read, patch.object(diagnostics.os, "write") as write:
                    observer._custody_sample("after-exit")
                read.assert_not_called()
                write.assert_not_called()
                cached = observer.ctx.observations[-1]["snapshot"]
                self.assertEqual(cached["events"], terminal["events"])
                self.assertEqual(cached["terminalReceipt"], "previously-retained-terminal")
                self.assertEqual(cached["attribution"], "unresolved")
                observer.ctx.command.assert_not_called()

    def test_absent_partial_or_unknown_terminal_record_stays_unavailable(self) -> None:
        terminal = self.terminal_fixture()
        payloads = (
            b"",
            b"partial",
            b"{}\n",
            (json.dumps({**terminal, "schemaVersion": 2}) + "\n").encode(),
            (json.dumps({**terminal, "rawStderr": "protected fixture text"}) + "\n").encode(),
            (json.dumps({**terminal, "events": [{"rawMessage": "protected fixture text"}]}) + "\n").encode(),
            (json.dumps({**terminal, "uncertainty": [{"rawMessage": "protected fixture text"}]}) + "\n").encode(),
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                observer = self.closed_observer(payload)
                observer._custody_sample("after-exit")
                result = observer.ctx.observations[-1]["snapshot"]
                self.assertEqual(result["availability"], "unavailable")
                self.assertEqual(result["reason"], "terminal-record-unavailable-or-invalid")
                self.assertIsNone(observer.custody_terminal)
                self.assertNotIn("protected fixture text", json.dumps(observer.ctx.observations))

    def test_terminal_drain_never_renews_deadline_or_exceeds_response_bound(self) -> None:
        payload = (json.dumps(self.terminal_fixture()) + "\n").encode()
        observer = self.closed_observer(payload)
        with (
            patch.object(diagnostics.time, "monotonic", side_effect=[100, 100.1, 101.1]),
            patch.object(diagnostics.os, "read") as read,
        ):
            result = observer._custody_exchange({"phase": "after-exit"})
        read.assert_not_called()
        self.assertEqual(result["availability"], "unavailable")
        self.assertIsNone(observer.custody_terminal)
        observer = self.closed_observer(b"x", exited=True)
        with patch.object(diagnostics.os, "read", return_value=b"x" * (diagnostics.MAX_BYTES + 1)) as read:
            result = observer._custody_exchange({"phase": "after-exit"})
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.args[1], diagnostics.MAX_BYTES + 1)
        self.assertEqual(result["availability"], "unavailable")
        self.assertIsNone(observer.custody_terminal)

    def test_eof_partial_input_and_expired_input_are_bounded(self) -> None:
        for value in (b"", b"partial", None):
            with self.subTest(value=value):
                reader, writer = os.pipe()
                try:
                    if value is not None:
                        os.write(writer, value)
                    stream = MagicMock()
                    stream.fileno.return_value = reader
                    with patch.object(custody.sys, "stdin", stream):
                        if value is None:
                            with self.assertRaisesRegex(ValueError, "deadline expired"):
                                custody._line(time.monotonic() - 1)
                        else:
                            os.close(writer)
                            writer = None
                            if value:
                                with self.assertRaisesRegex(ValueError, "partial"):
                                    custody._line(time.monotonic() + 1)
                            else:
                                self.assertEqual(custody._line(time.monotonic() + 1), b"")
                finally:
                    os.close(reader)
                    if writer is not None:
                        os.close(writer)

    def test_server_eof_and_failure_close_original_custody_and_retain_events(self) -> None:
        for failure in (False, True):
            with self.subTest(failure=failure):
                observer, stream = MagicMock(), MagicMock()
                observer.deadline = time.monotonic() + 1
                observer.events = [{"mask": custody.IN_CREATE, "originalPidAlive": True}]
                observer.watch, observer.exited_at, observer.reasons = {}, None, []
                next_line = ValueError("partial custody input") if failure else b""
                with (
                    patch.object(custody, "MarkerCustody", return_value=observer),
                    patch.object(custody.sys, "stdin", stream),
                    patch.object(custody, "_line", side_effect=[b"{}\n", next_line]),
                    patch.object(custody.select, "select", return_value=([stream.fileno()], [], [])),
                    patch.object(custody, "_reply") as reply,
                ):
                    custody.main()
                observer.close.assert_called_once_with()
                if failure:
                    record = reply.call_args.args[0]
                    self.assertEqual(record["availability"], "error")
                    self.assertEqual(record["events"], observer.events)


if __name__ == "__main__":
    unittest.main()
