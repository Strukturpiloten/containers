"""Authored controls for the separate ordinary-user Python import fixture."""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from scripts import python_runtime_fd_observation as observation
from scripts import runtime_docker_diagnostics as native_diagnostics

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = "/usr/lib/python3.14/lib-dynload/_ctypes.cpython-314-x86_64-linux-gnu.so"
LIBFFI = "/usr/lib/x86_64-linux-gnu/libffi.so.8.1.4"
GNU_BANNER = b"gnutimeout (GNU coreutils) 9.12\nprivate-discarded-version-footer\n"


def authored_stat(*, mode: int = stat.S_IFREG | 0o755, uid: int = 0, inode: int = 47) -> os.stat_result:
    """Provide authored file metadata without privileged filesystem operations."""
    return os.stat_result(
        (mode, inode, 2049, 1, uid, 0, 3, 1, 2, 3), {"st_mtime_ns": 2000000000, "st_ctime_ns": 3000000000}
    )


def file_record(path: str = "/usr/bin/python3.14") -> dict:
    """Construct a public-file record from authored facts."""
    return {"path": path, "identity": observation.identity(authored_stat()), "sha256": "a" * 64}


def child_record() -> dict:
    """Construct the complete expected wire shape independently of collection."""
    return {
        "runtime": {
            "implementation": "cpython",
            "version": [3, 14, 4],
            "build": "3.14.4 (fixture)",
            "platform": "linux",
            "machine": "x86_64",
        },
        "files": {"python": [file_record()], "ctypes": [file_record(EXTENSION)], "libffi": [file_record(LIBFFI)]},
        "before": {"state": "non-atomic", "closedDuringSnapshot": 1, "descriptors": []},
        "after": {
            "state": "non-atomic",
            "closedDuringSnapshot": 1,
            "descriptors": [
                {
                    "fd": 32768,
                    "identity": observation.identity(authored_stat()),
                    "matches": ["python", "ctypes", "libffi"],
                }
            ],
        },
    }


OUTER_GROUP_HELPER = textwrap.dedent("""\
    import ctypes,json,os,signal,subprocess,sys,time
    from contextlib import suppress
    assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
    started=time.monotonic()
    process=subprocess.Popen(['/usr/bin/gnutimeout','--signal=TERM','--kill-after=0.5s','2s',
                              sys.executable,'-I','-B','-S','-c',sys.argv[1]],
                             stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             close_fds=True)
    reaped=[]
    try:
        output,errors=process.communicate(timeout=5)
    finally:
        try:
            try:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:
                        try:
                            with suppress(ProcessLookupError):
                                os.kill(process.pid,signal.SIGKILL)
                        finally:
                            with suppress(ProcessLookupError):
                                os.killpg(process.pid,signal.SIGKILL)
            finally:
                process.wait(timeout=2)
        finally:
            process.stdout.close()
            process.stderr.close()
            end=time.monotonic()+2
            while True:
                try:
                    pid,status=os.waitpid(-1,os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    reaped.append((pid,status))
                else:
                    assert time.monotonic()<end
                    time.sleep(0.005)
    assert not errors and len(output)<100
    rows=[list(map(int,line.split())) for line in output.splitlines()]
    assert len(rows)==2 and all(len(row)==2 and row[1]==process.pid for row in rows)
    assert os.getpgrp()!=process.pid
    assert len(reaped)==2 and {pid for pid,status in reaped}=={row[0] for row in rows}
    assert all(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL for pid,status in reaped)
    print(json.dumps({'status':process.returncode,'reaped':len(reaped),'elapsed':time.monotonic()-started}))
    """)


class PythonFdObservationTests(unittest.TestCase):
    def test_pre_group_startup_timeout_kills_held_pid_retries_group_and_reaps(self) -> None:
        events = []
        for direct_missing, retry_missing in ((False, False), (False, True), (True, False), (True, True)):
            events.clear()
            process, libc = MagicMock(), MagicMock()
            process.pid, process.returncode = 31415, None
            failure = subprocess.TimeoutExpired("authored-fixed-provider", 5)
            process.communicate.side_effect = failure
            process.wait.side_effect = lambda **kw: events.append(("wait", kw["timeout"]))
            libc.prctl.return_value = 0

            def group(pid: int, number: int, *, retry_missing: bool = retry_missing) -> None:
                events.append(("group", pid, number))
                if len(events) == 1 or retry_missing:
                    raise ProcessLookupError

            def direct(pid: int, number: int, *, direct_missing: bool = direct_missing) -> None:
                events.append(("direct", pid, number))
                if direct_missing:
                    raise ProcessLookupError

            def reap(pid: int, flags: int) -> tuple[int, int]:
                events.append(("reap", pid, flags))
                if events.count(("reap", pid, flags)) == 1:
                    return 31416, signal.SIGKILL
                raise ChildProcessError

            with (
                self.subTest(direct_missing=direct_missing, retry_missing=retry_missing),
                patch("ctypes.CDLL", return_value=libc),
                patch.object(sys, "argv", ["helper", "fixture"]),
                patch.object(subprocess, "Popen", return_value=process) as launch,
                patch.object(os, "killpg", side_effect=group),
                patch.object(os, "kill", side_effect=direct),
                patch.object(os, "waitpid", side_effect=reap),
                self.assertRaises(subprocess.TimeoutExpired) as caught,
            ):
                exec(compile(OUTER_GROUP_HELPER, "authored-group-helper", "exec"), {})  # noqa: S102 - own fixture, all process/signal operations mocked.
            self.assertIs(caught.exception, failure)
            self.assertEqual(launch.call_args.args[0][0], "/usr/bin/gnutimeout")
            self.assertEqual(
                events,
                [
                    ("group", process.pid, signal.SIGKILL),
                    ("direct", process.pid, signal.SIGKILL),
                    ("group", process.pid, signal.SIGKILL),
                    ("wait", 2),
                    ("reap", -1, os.WNOHANG),
                    ("reap", -1, os.WNOHANG),
                ],
            )
            process.wait.assert_called_once_with(timeout=2)
            process.poll.assert_not_called()
            process.kill.assert_not_called()
            process.stdout.close.assert_called_once_with()
            process.stderr.close.assert_called_once_with()

    def test_outer_wrapper_covers_startup_and_kills_only_its_fixture_group(self) -> None:
        self.assertEqual(observation.GNU_TIMEOUT, "/usr/bin/gnutimeout")
        try:
            Path(observation.GNU_TIMEOUT).stat()
        except FileNotFoundError:
            self.skipTest("fixed /usr/bin/gnutimeout absent; OS watchdog behavior remains unobserved")
        provider = observation.gnu_provider(
            observation.capture(
                [observation.GNU_TIMEOUT, "--version"],
                time.monotonic() + 3,
            )
        )
        self.assertEqual(provider["provider"], "gnu-coreutils")
        # The separate helper is a process-local subreaper, so even group-SIGKILL
        # cannot leave the authored observer or its child for the host to reap.
        # The larger startup interval permits hosted scheduling before TERM;
        # the helper witnesses the held group and reaps before checking results.
        fixture = (
            "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print(os.getpid(),os.getpgrp(),flush=True); child=os.fork(); "
            "print(os.getpid(),os.getpgrp(),flush=True) if child==0 else None; time.sleep(10)"
        )
        result = subprocess.run(  # noqa: S603 - authored, isolated process-group cleanup fixture.
            [sys.executable, "-I", "-B", "-S", "-c", OUTER_GROUP_HELPER, fixture],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=True,
        )
        record = json.loads(result.stdout)
        self.assertEqual(record["status"], -signal.SIGKILL)
        self.assertEqual(record["reaped"], 2)
        self.assertLess(record["elapsed"], 5)

    def test_metadata_classification_never_reads_descriptor_targets_or_contents(self) -> None:
        records = [
            {"fd": 32768, "identity": observation.identity(authored_stat())},
            {"fd": 9, "identity": observation.identity(authored_stat(inode=48))},
        ]
        files = child_record()["files"]
        with (
            patch.object(observation.os, "read", side_effect=AssertionError),
            patch.object(observation.os, "readlink", side_effect=AssertionError),
        ):
            actual = observation.classify(records, files)
        self.assertEqual(actual[0]["matches"], ["python", "ctypes", "libffi"])
        self.assertEqual(actual[1]["matches"], [])
        self.assertEqual(set(actual[0]), {"fd", "identity", "matches"})

    def test_fd_enumeration_closes_iterator_before_fstat_and_includes_high_numbers(self) -> None:
        closed = []

        class Entries:
            def __enter__(self) -> list[SimpleNamespace]:
                return [SimpleNamespace(name=name) for name in ("0", "1", "2", "32768", "4")]

            def __exit__(self, *_: object) -> None:
                closed.append(True)

        def fstat(number: int) -> os.stat_result:
            self.assertTrue(closed)
            if number == observation.STDERR + 2:
                raise OSError(errno.EBADF, "private-error")
            return authored_stat()

        with (
            patch.object(observation.os, "scandir", return_value=Entries()),
            patch.object(observation.os, "fstat", side_effect=fstat),
        ):
            self.assertEqual(
                observation.snapshot(),
                {
                    "state": "non-atomic",
                    "closedDuringSnapshot": 1,
                    "descriptors": [{"fd": 32768, "identity": observation.identity(authored_stat())}],
                },
            )
        with patch.object(observation.os, "scandir") as scan:
            scan.return_value.__enter__.return_value = [SimpleNamespace(name=str(n)) for n in range(40)]
            with self.assertRaises(observation.UnavailableError):
                observation.snapshot()
        with patch.object(observation.os, "scandir") as scan:
            scan.return_value.__enter__.return_value = [SimpleNamespace(name="999999")]
            with self.assertRaises(observation.UnavailableError):
                observation.snapshot()

    def test_private_and_unknown_file_paths_are_rejected_before_open(self) -> None:
        paths = [
            "/private/libffi.so.8",
            "/home/private/_ctypes.so",
            "/usr/local/lib/libffi.so.8",
            "/usr/lib/x86_64-linux-gnu/libffi.so.8 (deleted)",
            "/usr/lib/../private/libffi.so.8",
        ]
        with patch.object(observation.os, "open", side_effect=AssertionError):
            for path in paths:
                with self.subTest(path=path), self.assertRaises(observation.UnavailableError):
                    observation.public_open(path, "libffi")

    def test_real_controlled_high_descriptor_is_observed_without_reading_it(self) -> None:
        descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        high = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 1024)
        try:
            with (
                patch.object(observation.os, "read", side_effect=AssertionError),
                patch.object(observation.os, "readlink", side_effect=AssertionError),
            ):
                sample = observation.snapshot()
            records = sample["descriptors"]
            self.assertEqual(sample["state"], "non-atomic")
            self.assertEqual(
                next(record["identity"] for record in records if record["fd"] == high),
                observation.identity(os.fstat(high)),
            )
        finally:
            os.close(high)
            os.close(descriptor)

    def test_snapshot_disappearing_descriptors_are_counted_without_identity_claim(self) -> None:
        with (
            patch.object(observation.os, "scandir") as scan,
            patch.object(observation.os, "fstat", side_effect=OSError(errno.EBADF, "private-error")),
        ):
            scan.return_value.__enter__.return_value = [SimpleNamespace(name=str(n)) for n in range(3, 6)]
            self.assertEqual(
                observation.snapshot(),
                {
                    "state": "non-atomic",
                    "closedDuringSnapshot": 3,
                    "descriptors": [],
                },
            )
            scan.return_value.__enter__.return_value = [SimpleNamespace(name=str(n)) for n in range(3, 37)]
            with self.assertRaises(observation.UnavailableError):
                observation.snapshot()

    def test_public_path_custody_refuses_writable_nonroot_and_excess_symlinks(self) -> None:
        directory = authored_stat(mode=stat.S_IFDIR | 0o755)
        bad = (
            authored_stat(mode=stat.S_IFDIR | 0o777),
            authored_stat(uid=1000),
            authored_stat(mode=stat.S_IFLNK | 0o777),
        )
        for value in bad:
            with (
                self.subTest(value=value),
                patch.object(observation.os, "open", return_value=10),
                patch.object(observation.os, "close") as close,
                patch.object(observation.os, "fstat", return_value=directory),
                patch.object(observation.os, "stat", return_value=value),
                patch.object(observation.os, "readlink", return_value="/usr/bin/python3"),
            ):
                with self.assertRaises(observation.UnavailableError):
                    observation.public_open(observation.PYTHON, "python")
                self.assertTrue(close.called)

    def test_root_owned_relative_system_symlink_has_closed_directory_custody(self) -> None:
        directory = authored_stat(mode=stat.S_IFDIR | 0o755)
        opened = {}

        def open_file(_path: str, flags: int, **_: object) -> int:
            descriptor = 10 + len(opened)
            opened[descriptor] = directory if flags & os.O_DIRECTORY else authored_stat()
            return descriptor

        def lookup(part: str, **_: object) -> os.stat_result:
            if part == "python3":
                return authored_stat(mode=stat.S_IFLNK | 0o777)
            return directory if part in {"usr", "bin"} else authored_stat()

        with (
            patch.object(observation.os, "open", side_effect=open_file),
            patch.object(observation.os, "fstat", side_effect=opened.__getitem__),
            patch.object(observation.os, "stat", side_effect=lookup),
            patch.object(observation.os, "readlink", return_value="python3.14"),
            patch.object(observation.os, "close") as close,
        ):
            descriptor, path = observation.public_open(observation.PYTHON, "python")
        self.assertEqual(path, "/usr/bin/python3.14")
        self.assertEqual({call.args[0] for call in close.call_args_list}, set(opened) - {descriptor})
        self.assertEqual(len(close.call_args_list), len(opened) - 1)

    def test_hash_uses_bounded_reads_stable_identity_and_closes_both_descriptors(self) -> None:
        with (
            patch.object(observation, "public_open", side_effect=[(10, observation.PYTHON), (11, observation.PYTHON)]),
            patch.object(observation.os, "fstat", return_value=authored_stat()),
            patch.object(observation.os, "read", side_effect=[b"abc", b""]) as read,
            patch.object(observation.os, "close") as close,
        ):
            record = observation.public_file(observation.PYTHON, "python")
        self.assertEqual(record["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertEqual([call.args[1] for call in read.call_args_list], [4, 1])
        self.assertEqual([call.args[0] for call in close.call_args_list], [11, 10])
        for value in (
            authored_stat(uid=1000),
            authored_stat(mode=stat.S_IFIFO | 0o644),
            authored_stat(mode=stat.S_IFREG | 0o777),
        ):
            with (
                self.subTest(value=value),
                patch.object(observation, "public_open", return_value=(10, observation.PYTHON)),
                patch.object(observation.os, "fstat", return_value=value),
                patch.object(observation.os, "close"),
                patch.object(observation.os, "read", side_effect=AssertionError),
                self.assertRaises(observation.UnavailableError),
            ):
                observation.public_file(observation.PYTHON, "python")
        with (
            patch.object(observation, "public_open", side_effect=[(10, observation.PYTHON), (11, observation.PYTHON)]),
            (
                patch.object(
                    observation.os, "fstat", side_effect=[authored_stat(), authored_stat(), authored_stat(inode=99)]
                )
            ),
            patch.object(observation.os, "read", side_effect=[b"abc", b""]),
            patch.object(observation.os, "close"),
            self.assertRaises(observation.UnavailableError),
        ):
            observation.public_file(observation.PYTHON, "python")

    def test_oversized_file_and_expired_hash_budget_fail_without_reading(self) -> None:
        oversized = SimpleNamespace(**{name: getattr(authored_stat(), name) for name in observation.ATTRIBUTES})
        oversized.st_size = observation.MAX_FILE + 1
        for value, end in ((oversized, float("inf")), (authored_stat(), time.monotonic() - 1)):
            with (
                self.subTest(value=value, end=end),
                patch.object(observation, "public_open", return_value=(10, observation.PYTHON)),
                patch.object(observation.os, "fstat", return_value=value),
                patch.object(observation.os, "close"),
                patch.object(observation.os, "read", side_effect=AssertionError),
                self.assertRaises(observation.UnavailableError),
            ):
                observation.public_file(observation.PYTHON, "python", end)

    def test_child_keeps_provenance_unavailable_on_private_or_unmapped_libffi(self) -> None:
        for raw in (b"private-address private /home/secret/libffi.so.8\n", b"00-01 r-xp 0 08:01 99 " + LIBFFI.encode()):
            with (
                self.subTest(raw=raw),
                patch.object(
                    observation, "snapshot", side_effect=[copy.deepcopy(child_record()["before"]) for _ in range(2)]
                ),
                patch.dict(sys.modules, {"_ctypes": SimpleNamespace(__file__=EXTENSION)}),
                patch.object(observation, "public_file", side_effect=lambda path, *_: file_record(path)),
                patch.object(observation.Path, "open", return_value=io.BytesIO(raw)),
            ):
                result = observation.child(time.monotonic() + 2)
            self.assertEqual(result["files"]["libffi"], [])
            body = json.dumps(result)
            self.assertNotIn("private-address", body)
            self.assertNotIn("/home/secret", body)

    def test_mapped_public_library_requires_matching_device_and_inode(self) -> None:
        raw = b"00-01 r-xp 0 08:01 47 " + LIBFFI.encode() + b"\n"
        with (
            patch.object(
                observation, "snapshot", side_effect=[copy.deepcopy(child_record()["before"]) for _ in range(2)]
            ),
            patch.dict(sys.modules, {"_ctypes": SimpleNamespace(__file__=EXTENSION)}),
            patch.object(observation, "public_file", side_effect=lambda path, *_: file_record(path)),
            patch.object(observation.Path, "open", return_value=io.BytesIO(raw)),
        ):
            result = observation.child(time.monotonic() + 2)
        self.assertEqual(result["files"]["libffi"], [file_record(LIBFFI)])
        self.assertNotIn("00-01", json.dumps(result))

    def test_closed_wire_rejects_unknown_fields_duplicates_private_paths_and_bounds(self) -> None:
        fixture = child_record()
        self.assertEqual(observation.decode(json.dumps(fixture).encode()), fixture)
        mutations = []
        for key, value in (("before", [{"fd": 3}] * 33), ("rawMaps", "private"), ("runtime", {"argv": "private"})):
            changed = copy.deepcopy(fixture)
            changed[key] = value
            mutations.append(changed)
        changed = copy.deepcopy(fixture)
        changed["files"]["python"][0]["path"] = "/home/private/python"
        mutations.append(changed)
        changed = copy.deepcopy(fixture)
        changed["after"]["descriptors"][0]["identity"]["inode"] = True
        mutations.append(changed)
        changed = copy.deepcopy(fixture)
        changed["after"]["descriptors"][0]["matches"] = ["private"]
        mutations.append(changed)
        changed = copy.deepcopy(fixture)
        changed["after"]["descriptors"][0]["matches"] = []
        mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(observation.UnavailableError):
                observation.decode(json.dumps(value).encode())
        for raw in (b"{", b'{"x":1,"x":2}', b"[]", b"NaN"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, observation.UnavailableError)):
                observation.decode(raw)

    def test_decoded_snapshot_race_counts_and_exact_shape_are_bounded(self) -> None:
        for key, bad in (
            ("closedDuringSnapshot", True),
            ("closedDuringSnapshot", -1),
            ("closedDuringSnapshot", 34),
            ("closedDuringSnapshot", 0.0),
            ("state", "atomic"),
            ("rawTarget", "private"),
        ):
            fixture = child_record()
            fixture["before"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(observation.UnavailableError):
                observation.decode(json.dumps(fixture).encode())
        fixture = child_record()
        fixture["after"]["closedDuringSnapshot"] = 33
        with self.assertRaises(observation.UnavailableError):
            observation.decode(json.dumps(fixture).encode())
        fixture = child_record()
        fixture["before"]["closedDuringSnapshot"] = 33
        self.assertEqual(observation.decode(json.dumps(fixture).encode()), fixture)
        fixture = child_record()
        fixture["after"]["descriptors"] = [
            {**fixture["after"]["descriptors"][0], "fd": number} for number in range(3, 36)
        ]
        with self.assertRaises(observation.UnavailableError):
            observation.decode(json.dumps(fixture).encode())

    def test_decoded_public_file_identity_rejects_unsafe_provenance(self) -> None:
        for key, bad in (
            ("uid", 1000),
            ("mode", stat.S_IFIFO | 0o644),
            ("mode", stat.S_IFREG | 0o777),
            ("mode", stat.S_IFREG | 0o4755),
            ("mode", stat.S_IFREG | 0o2755),
            ("size", 0),
            ("size", observation.MAX_FILE + 1),
        ):
            for kind in observation.PUBLIC:
                fixture = child_record()
                fixture["files"][kind][0]["identity"][key] = bad
                with self.subTest(kind=kind, key=key, bad=bad), self.assertRaises(observation.UnavailableError):
                    observation.decode(json.dumps(fixture).encode())

    def test_capture_bounds_stdout_stderr_and_time_and_reaps_direct_child(self) -> None:
        factory, processes = subprocess.Popen, []

        def launch(*args: object, **kwargs: object) -> subprocess.Popen:
            process = factory(*args, **kwargs)
            processes.append(process)
            self.assertEqual(kwargs["env"], {"LC_ALL": "C"})
            self.assertTrue(kwargs["close_fds"])
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            return process

        for program in (
            "import time; time.sleep(10)",
            "import os; os.write(1,b'x'*20000)",
            "import os; os.write(2,b'x'*20000)",
        ):
            with (
                self.subTest(program=program),
                patch.object(observation.subprocess, "Popen", side_effect=launch),
                self.assertRaises(observation.UnavailableError),
            ):
                observation.capture([sys.executable, "-I", "-B", "-S", "-c", program], time.monotonic() + 0.7)
            self.assertIsNotNone(processes[-1].returncode)
            self.assertTrue(processes[-1].stdout.closed)
            self.assertTrue(processes[-1].stderr.closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(processes[-1].pid, os.WNOHANG)

    def test_cleanup_uncertainty_closes_both_pipes_without_an_unbounded_wait(self) -> None:
        process = MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("fixed-child", 0)
        with self.assertRaises(observation.CleanupUncertainError):
            observation.stop(process, time.monotonic() - 1)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=0)
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()

    def test_cancellation_refuses_work_and_preserves_cleanup_uncertainty(self) -> None:
        output = SimpleNamespace(buffer=io.BytesIO())
        handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

        def cancelled(*_: object) -> bytes:
            observation.cancel(signal.SIGTERM, None)
            raise observation.CleanupUncertainError

        with (
            patch.object(observation, "_cancelled", new=False),
            patch.object(observation.os, "getuid", return_value=1000),
            patch.object(observation.os, "geteuid", return_value=1000),
            patch.object(observation, "public_file", return_value=file_record()),
            patch.object(observation, "capture", side_effect=cancelled),
            patch.object(observation.sys, "argv", ["fixture"]),
            patch.object(observation.sys, "stdout", output),
        ):
            self.assertEqual(observation.main(), 0)
            with self.assertRaises(observation.UnavailableError):
                observation.check(float("inf"))
        self.assertEqual(json.loads(output.buffer.getvalue())["cleanup"], "uncertain")
        self.assertEqual(handlers, {number: signal.getsignal(number) for number in handlers})

    def test_parent_uses_system_interpreter_and_one_absolute_budget(self) -> None:
        fixture = child_record()
        clock, captures = SimpleNamespace(now_ns=0), []

        def capture_child(_command: list[str], end: float) -> bytes:
            observation.check(end - observation.CLEANUP_RESERVE)
            clock.now_ns += 1000000000
            return captures.pop(0)

        def read_public(_path: str, _kind: str, end: float) -> dict:
            observation.check(end)
            clock.now_ns += 250000000
            return file_record()

        # The second authored clock reproduces the hosted conservative 1 ns
        # float-to-integer serialization, without relying on a float roundtrip.
        cases = (
            (128000000000, 136.0, 135.5, 135500000000, 0),
            (128618220789, 136.618220789, 136.118220789, 136118220788, 1),
        )
        for started_ns, expected_end, expected_work, expected_wire_ns, conservative_ns in cases:
            clock.now_ns = started_ns
            captures[:] = [GNU_BANNER, json.dumps(fixture).encode()]
            output = SimpleNamespace(buffer=io.BytesIO())
            with (
                self.subTest(started_ns=started_ns),
                patch.object(observation.time, "monotonic_ns", side_effect=lambda: clock.now_ns) as nano_clock,
                patch.object(observation.time, "monotonic", side_effect=lambda: clock.now_ns / 1000000000),
                patch.object(observation.os, "getuid", return_value=1000),
                patch.object(observation.os, "geteuid", return_value=1000),
                patch.object(observation, "public_file", side_effect=read_public) as read,
                patch.object(observation, "capture", side_effect=capture_child) as capture,
                patch.object(observation.sys, "argv", ["fixture"]),
                patch.object(observation.sys, "stdout", output),
            ):
                self.assertEqual(observation.main(), 0)
            nano_clock.assert_called_once_with()
            command, end = capture.call_args.args
            self.assertEqual(end, expected_end)
            self.assertEqual(capture.call_args_list[0].args, (["/usr/bin/gnutimeout", "--version"], expected_end))
            self.assertEqual(len(capture.call_args_list), 2)
            self.assertEqual(command[:4], ["/usr/bin/python3", "-I", "-B", "-S"])
            self.assertEqual(command[-1], str(expected_wire_ns))
            self.assertEqual(started_ns + 7500000000 - int(command[-1]), conservative_ns)
            self.assertEqual(expected_end - expected_work, observation.CLEANUP_RESERVE)
            self.assertEqual([call.args[2] for call in read.call_args_list], [expected_work, expected_work])
            self.assertEqual(clock.now_ns, started_ns + 2500000000)
            self.assertFalse(captures)
            result = json.loads(output.buffer.getvalue())
            self.assertEqual(result["state"], "observed")
            self.assertEqual(result["provenance"], "observed")
            self.assertEqual(result["packageProvenance"], "unavailable")
            self.assertEqual(
                result["timeoutProvider"],
                {
                    "state": "observed",
                    "provider": "gnu-coreutils",
                    "version": "9.12",
                    "pathKind": "prefixed",
                },
            )
            self.assertNotIn("private-discarded", output.buffer.getvalue().decode())

    def test_gnu_banner_acceptance_agrees_with_native_qualifier_without_importing_owner(self) -> None:
        cases = (
            GNU_BANNER,
            b"timeout (GNU coreutils) 9.7\nfooter",
            b"timeout (GNU coreutils) 9.7-unverified",
            b"timeout (uutils coreutils) 0.10.0",
            b"timeout (GNU coreutils) unknown",
            b"",
            b"private-error",
        )
        for raw in cases:
            context = SimpleNamespace(checks=[], command=lambda *_, raw=raw: raw.decode("ascii"))
            with (
                self.subTest(raw=raw),
                patch.object(native_diagnostics.shutil, "which", return_value=observation.GNU_TIMEOUT),
                patch.object(native_diagnostics.Path, "resolve", return_value=Path(observation.GNU_TIMEOUT)),
            ):
                try:
                    native = native_diagnostics.qualify_gnu_timeout(context)
                except ValueError:
                    with self.assertRaises(observation.UnavailableError):
                        observation.gnu_provider(raw)
                else:
                    self.assertEqual(observation.gnu_provider(raw)["version"], native[1])
                    self.assertEqual(native[2], "prefixed")
        with self.assertRaises(observation.UnavailableError):
            observation.gnu_provider(b"timeout (GNU coreutils) " + b"1." * 41 + b"1")
        self.assertNotIn("runtime_docker_diagnostics", (ROOT / "scripts/python_runtime_fd_observation.py").read_text())

    def test_unavailable_or_bad_fixed_gnu_provider_cannot_start_observation_child(self) -> None:
        for failure in (
            FileNotFoundError("private-file"),
            observation.UnavailableError(),
            b"private-error",
            b"timeout (uutils coreutils) 0.10.0",
            b"timeout (GNU coreutils) unknown",
        ):
            output = SimpleNamespace(buffer=io.BytesIO())
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(observation.os, "getuid", return_value=1000),
                patch.object(observation.os, "geteuid", return_value=1000),
                patch.object(observation.sys, "argv", ["fixture"]),
                patch.object(observation.sys, "stdout", output),
                patch.object(observation, "public_file", side_effect=AssertionError),
                patch.object(
                    observation,
                    "capture",
                    side_effect=failure if isinstance(failure, Exception) else None,
                    return_value=failure,
                ) as capture,
            ):
                self.assertEqual(observation.main(), 0)
            self.assertEqual(capture.call_args.args[0], ["/usr/bin/gnutimeout", "--version"])
            self.assertEqual(capture.call_count, 1)
            result = json.loads(output.buffer.getvalue())
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["timeoutProvider"], {"state": "unavailable"})
            self.assertNotIn("private", output.buffer.getvalue().decode())

    def test_context_has_only_valid_public_identifiers(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GITHUB_RUN_ID": "123",
                "GITHUB_SHA": "b" * 40,
                "GITHUB_REF": "refs/pull/492/merge",
                "GITHUB_REPOSITORY": "private/repo",
                "GITHUB_RUN_ATTEMPT": "private-error",
                "SECRET": "credential",
            },
            clear=True,
        ):
            result = observation.context()
        self.assertEqual(result["GITHUB_RUN_ID"], "123")
        self.assertEqual(result["GITHUB_SHA"], "b" * 40)
        self.assertIsNone(result["GITHUB_REPOSITORY"])
        self.assertIsNone(result["GITHUB_RUN_ATTEMPT"])
        self.assertNotIn("SECRET", result)

    def test_main_never_exports_raw_failure_or_replaces_qualification(self) -> None:
        output = SimpleNamespace(buffer=io.BytesIO())
        with (
            patch.object(observation.os, "getuid", return_value=1000),
            patch.object(observation.os, "geteuid", return_value=1000),
            patch.object(observation.sys, "argv", ["fixture"]),
            patch.object(observation.sys, "stdout", output),
            patch.object(observation, "public_file", side_effect=OSError("private-error /home/secret")),
            patch.object(observation, "capture", return_value=GNU_BANNER),
        ):
            self.assertEqual(observation.main(), 0)
        raw = output.buffer.getvalue()
        self.assertLessEqual(len(raw), observation.MAX_OUTPUT)
        result = json.loads(raw)
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["provenance"], "unavailable")
        self.assertEqual(result["qualification"], "none")
        self.assertFalse(result["policy_load_run"])
        self.assertFalse(result["container_run"])
        self.assertNotIn(b"private-error", raw)
        self.assertNotIn(b"/home/secret", raw)

    def test_main_rejects_malformed_and_oversized_child_output_without_echo(self) -> None:
        for raw in (b"private-child-error /home/secret", b"x" * (observation.MAX_OUTPUT + 1)):
            output = SimpleNamespace(buffer=io.BytesIO())
            with (
                self.subTest(raw=raw[:32]),
                patch.object(observation.os, "getuid", return_value=1000),
                patch.object(observation.os, "geteuid", return_value=1000),
                patch.object(observation.sys, "argv", ["fixture"]),
                patch.object(observation.sys, "stdout", output),
                patch.object(observation, "public_file", return_value=file_record()),
                patch.object(observation, "capture", side_effect=[GNU_BANNER, raw]),
            ):
                self.assertEqual(observation.main(), 0)
            result = output.buffer.getvalue()
            self.assertLessEqual(len(result), observation.MAX_OUTPUT)
            self.assertEqual(json.loads(result)["state"], "unavailable")
            self.assertNotIn(b"private-child-error", result)

    def test_workflow_is_optional_same_job_and_preserves_original_root_and_allowance(self) -> None:
        template = (ROOT / ".github/workflow-templates/ci.yml.j2").read_text()
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["userns-custody-unused"]
        self.assertEqual(job["timeout-minutes"], 5)
        self.assertIn("github.event.pull_request.number == 492", job["if"])
        self.assertIn("TheRealBecks/issue442-main-reconciled", job["if"])
        self.assertIn("github.repository == 'Strukturpiloten/containers'", job["if"])
        steps = job["steps"]
        step = next(s for s in steps if s["name"] == "Observe ordinary-user system Python import descriptors")
        self.assertTrue(step["continue-on-error"])
        self.assertEqual(step["timeout-minutes"], 1)
        self.assertIn("/usr/bin/gnutimeout --signal=TERM --kill-after=1s 9s /usr/bin/python3 -I -B -S", step["run"])
        self.assertNotIn("--foreground", step["run"])
        self.assertIn('> "${temporary}"', step["run"])
        self.assertIn('/usr/bin/mv -- "${temporary}" "${artifact}"', step["run"])
        self.assertEqual(steps.index(step), 3)
        upload = next(s for s in steps if s["name"] == "Retain separate nonqualifying Python import observation")
        self.assertEqual(upload["if"], "${{ always() }}")
        self.assertTrue(upload["continue-on-error"])
        self.assertEqual(upload["with"]["name"], "python-runtime-fd-observation")
        self.assertEqual(upload["uses"], steps[-2]["uses"])
        for start, end, digest in (
            (
                "Observe two real hosted unused ownership cycles",
                "Retain nonqualifying hosted unused custody observation",
                "2d0186cf5602e42e7febee289de2c40c38a0889ab6a42e4c79bae6d7bb64da83",
            ),
            (
                "Record original unused experiment allowance",
                "Check out owned PR merge candidate",
                "349a47e3139b289ca474dae937ab06fef6cb3822fa8857fbfe0fe1e09431891c",
            ),
        ):
            block = template.split(f"      - name: {start}\n", 1)[1].split(f"      - name: {end}\n", 1)[0]
            self.assertEqual(hashlib.sha256((f"      - name: {start}\n" + block).encode()).hexdigest(), digest)

    def test_workflow_publishes_only_completed_output_and_cleans_owned_temp(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        step = next(
            step
            for step in workflow["jobs"]["userns-custody-unused"]["steps"]
            if step["name"] == "Observe ordinary-user system Python import descriptors"
        )
        original = next(
            line.strip()[3:-6]
            for line in step["run"].splitlines()
            if line.strip().startswith("if /usr/bin/gnutimeout ")
        )
        cases = (
            ("/usr/bin/false", False),
            ('{ printf private-partial; /usr/bin/false; } > "${temporary}"', False),
            ('printf \'%s\\n\' \'{"fixture":"completed"}\' > "${temporary}"', True),
        )
        for command, completed in cases:
            run = step["run"].replace(original, command)
            with self.subTest(completed=completed, command=command), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(  # noqa: S603 - fixed Bash and authored completion/failure fixtures.
                    ["/bin/bash", "-c", run],
                    env={"RUNNER_TEMP": directory},
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, completed)
                artifact = Path(directory) / "python-runtime-fd-observation.json"
                record = json.loads(artifact.read_bytes())
                if completed:
                    self.assertEqual(record, {"fixture": "completed"})
                else:
                    self.assertEqual(record["state"], "unavailable")
                    self.assertEqual(record["timeoutProvider"], {"state": "unavailable"})
                    self.assertEqual(record["qualification"], "none")
                    self.assertFalse(record["policy_load_run"])
                    self.assertFalse(record["container_run"])
                    self.assertNotIn("private-partial", artifact.read_text())
                self.assertEqual(list(Path(directory).iterdir()), [artifact])
