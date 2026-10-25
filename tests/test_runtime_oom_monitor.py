"""Synthetic monitor custody fixtures; no runtime, package queries or native OOM."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_docker_systemd as systemd
from scripts import runtime_oom_diagnostics as diagnostics
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


if __name__ == "__main__":
    unittest.main()
