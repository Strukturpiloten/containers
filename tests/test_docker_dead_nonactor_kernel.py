"""Owned Linux mechanism controls, not admitted-kernel qualification or PID-reuse proof.

No namespace, mount, sysctl, container or privileged-runtime setup is performed.
Depth-one contexts must refuse production positive coverage. Unsupported skips in
the generic unit gate do not qualify a native candidate. Numeric PID reuse remains
a separate control requiring an admitted isolated environment.

One child exists at a time; only the leader-exit case adds one sibling thread.
The harness owns four initial pipe ends, one process pidfd, and held proc/nsfs
references. All polls share a three-second deadline and a one-second reap reserve.
"""

from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import sys
import time
import unittest
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from scripts import docker_userns_active as active

if TYPE_CHECKING:
    from collections.abc import Iterator

WORK_NS = 3_000_000_000
CLEANUP_SECONDS = 1
POLL_SECONDS = 0.005
UNSUPPORTED = {errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES, errno.ENOTTY}
EXIT_SYSCALL = {"x86_64": 60, "aarch64": 93}
OWNED_HELPER = r"""
import ctypes
import os
import select
import sys
import threading
import time

control, ready, until, thread_exit = map(int, sys.argv[1:])
def finish():
    os.write(ready, b"R")
    remaining = max(0.0, (until - time.monotonic_ns()) / 1_000_000_000)
    available = select.select([control], [], [], remaining)[0]
    command = os.read(control, 1) if available else b""
    os._exit(0 if command == b"X" else 2)
if thread_exit:
    threading.Thread(target=finish).start()
    # CDLL releases the GIL. SYS_exit terminates only this leader thread;
    # the sibling owns the pipe barrier and eventual whole-process exit.
    ctypes.CDLL(None, use_errno=True).syscall(thread_exit, 0)
    os._exit(3)
finish()
"""


def remaining(until: int) -> float:
    """Use one absolute work boundary for every readiness/state poll."""
    value = (until - time.monotonic_ns()) / 1_000_000_000
    if value <= 0:
        raise TimeoutError
    return value


@contextmanager
def owned_child(until: int, *, thread_exit: int = 0) -> Iterator[SimpleNamespace]:
    """Own one exact unreaped child, flags-zero pidfd and four pipe ends on all paths."""
    descriptors = set()

    def close(descriptor: int) -> None:
        if descriptor in descriptors:
            descriptors.remove(descriptor)
            os.close(descriptor)

    with ExitStack() as handles:
        control_r, control_w = os.pipe2(os.O_CLOEXEC)
        for descriptor in (control_r, control_w):
            descriptors.add(descriptor)
            handles.callback(close, descriptor)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        for descriptor in (ready_r, ready_w):
            descriptors.add(descriptor)
            handles.callback(close, descriptor)
        process, pidfd = None, None
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed isolated interpreter/helper and owned pipe/deadline integers.
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    OWNED_HELPER,
                    str(control_r),
                    str(ready_w),
                    str(until),
                    str(thread_exit),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(control_r, ready_w),
                env={"LANG": "C", "LC_ALL": "C"},
            )
            close(control_r)
            close(ready_w)
            pidfd = os.pidfd_open(process.pid, 0)
            descriptors.add(pidfd)
            handles.callback(close, pidfd)
            if not select.select([ready_r], [], [], remaining(until))[0] or os.read(ready_r, 1) != b"R":
                raise AssertionError
            yield SimpleNamespace(process=process, pidfd=pidfd, release=control_w)
        finally:
            close(control_w)
            if process is not None and process.returncode is None:
                # Only this retained pidfd, or the exact still-unreaped child if
                # pidfd acquisition failed. No foreign/numeric rediscovery target.
                try:
                    if pidfd is None:
                        process.kill()
                    elif not select.select(
                        [pidfd], [], [], min(POLL_SECONDS, max(0, (until - time.monotonic_ns()) / 1_000_000_000))
                    )[0]:
                        with suppress(ProcessLookupError):
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                finally:
                    process.wait(
                        timeout=max(
                            0.001, (until + CLEANUP_SECONDS * 1_000_000_000 - time.monotonic_ns()) / 1_000_000_000
                        )
                    )


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux helper API required")
class OwnedCleanupRegression(unittest.TestCase):
    def test_signal_errors_still_wait_and_close_every_handle_after_setup_or_body_failure(self) -> None:
        for failure in ("pidfd-acquisition", "ready-barrier", "body"):
            events = []
            process = Mock(pid=123, returncode=None)
            denied = PermissionError(errno.EPERM, "injected owned-child signaling refusal")
            process.kill.side_effect = denied

            def waited(*, timeout: float, trace: list = events) -> int:
                trace.append(("wait", timeout))
                return 0

            process.wait.side_effect = waited
            readiness = [([], [], [])] if failure == "ready-barrier" else [([12], [], [])]
            readiness.append(([], [], []))
            with (
                self.subTest(failure=failure),
                patch.object(os, "pipe2", side_effect=[(10, 11), (12, 13)]),
                patch.object(os, "close", side_effect=lambda fd, trace=events: trace.append(("close", fd))),
                patch.object(os, "read", return_value=b"R"),
                patch.object(
                    os,
                    "pidfd_open",
                    side_effect=OSError(errno.EMFILE, "injected") if failure == "pidfd-acquisition" else None,
                    return_value=14,
                ),
                patch.object(subprocess, "Popen", return_value=process),
                patch.object(select, "select", side_effect=readiness),
                patch.object(signal, "pidfd_send_signal", side_effect=denied) as sent,
                patch.object(time, "monotonic_ns", return_value=3_000_000_000),
                self.assertRaises(PermissionError) as refused,
                owned_child(4_000_000_000),
            ):
                self.assertEqual(failure, "body")
                raise RuntimeError
            self.assertIs(refused.exception, denied)
            process.wait.assert_called_once_with(timeout=2.0)
            if failure == "pidfd-acquisition":
                process.kill.assert_called_once_with()
                sent.assert_not_called()
            else:
                sent.assert_called_once_with(14, signal.SIGKILL)
                process.kill.assert_not_called()
            closed = [value for operation, value in events if operation == "close"]
            self.assertEqual(
                sorted(closed), [10, 11, 12, 13] if failure == "pidfd-acquisition" else [10, 11, 12, 13, 14]
            )
            self.assertLess(events.index(("close", 11)), events.index(("wait", 2.0)))
            self.assertLess(events.index(("wait", 2.0)), events.index(("close", 12)))
            if failure != "pidfd-acquisition":
                self.assertLess(events.index(("wait", 2.0)), events.index(("close", 14)))


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux process pidfds required; unqualified"
)
class OwnedKernelControls(unittest.TestCase):
    def setUp(self) -> None:
        self.observations = {"nativeQualification": False, "numericPidReuse": "not exercised"}
        if os.uname().machine not in EXIT_SYSCALL:
            self.skipTest("production proc resolver architecture unsupported; unqualified")
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            self.skipTest("exclusive exact-child reap requires default SIGCHLD; unqualified")
        try:
            descriptor = os.pidfd_open(os.getpid(), 0)
        except OSError as error:
            if error.errno in UNSUPPORTED:
                self.skipTest("process pidfd syscall unavailable in this context; unqualified")
            raise
        os.close(descriptor)
        self.until = time.monotonic_ns() + WORK_NS

    def port(self, held: ExitStack, *, certificate_required: bool = False) -> active.RootPort:
        """Attempt the actual certificate; keep lower ABI observations explicitly unqualified."""
        port = active.RootPort.__new__(active.RootPort)
        port.cleanup, port.work_until = False, self.until
        port.record = {"retained": False}
        port.witness_counts = {"procBytes": 0, "pids": set()}
        try:
            view = active.ProcView(held, port.witness_proc_bytes, port.witness_pid)
            port._witness_proc = view
            observer = view.pid(view.self_pid())
            held.callback(os.close, observer)
            port._witness_observer = observer
            init = view.pid(1)
            held.callback(os.close, init)
            own_namespace = view.pid_namespace(held, observer)
            init_namespace = view.pid_namespace(held, init)
            if own_namespace != init_namespace:
                self.observations.update(procNamespaceCertified=False, realmMismatch=True)
                if certificate_required:
                    self.skipTest("self/init proc realm differs; production context unqualified")
                return self.uncertified_reader(held, port)
        except active.RefusedError:
            root_uid = Path("/proc").stat().st_uid
            self.observations.update(procNamespaceCertified=False, procRootUid=root_uid)
            if root_uid == 0:
                raise
            if certificate_required:
                self.skipTest("production certificate refuses non-root-owned proc view; unqualified")
            return self.uncertified_reader(held, port)
        except OSError as error:
            if error.errno in UNSUPPORTED:
                self.observations.update(procNamespaceCertified=False, certificateErrno=error.errno)
                if certificate_required:
                    self.skipTest("required proc/nsfs ABI unavailable in this context; unqualified")
                return self.uncertified_reader(held, port)
            raise
        self.observations["procNamespaceCertified"] = True
        return port

    def uncertified_reader(self, held: ExitStack, port: active.RootPort) -> active.RootPort:
        """Observe owned pidfd ABI only; this is no replacement for production certification."""
        root = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held.callback(os.close, root)
        active.filesystem_magic(root, 0x9FA0)
        self.assertEqual(os.readlink("self", dir_fd=root), str(os.getpid()))

        def owned_pid(pid: int) -> int:
            port.witness_pid(pid)
            descriptor = active.ProcView.open(root, str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                active.filesystem_magic(descriptor, 0x9FA0)
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor

        port._witness_proc = SimpleNamespace(open=active.ProcView.open, pid=owned_pid)
        port._witness_observer = owned_pid(os.getpid())
        held.callback(os.close, port._witness_observer)
        self.observations["uncertifiedOwnedAbiOnly"] = True
        return port

    @staticmethod
    def fields(raw: bytes) -> dict[bytes, list[bytes]]:
        """Read independent kernel field expectations without using a witness validator."""
        return {
            key: value.split()
            for line in raw.splitlines()
            for key, separator, value in [line.partition(b":")]
            if separator
        }

    def zombie(self, port: active.RootPort, directory: int) -> dict:
        """Await only the exact held child's Z state inside the original absolute boundary."""
        while True:
            raw = port.witness_read(directory, "stat")
            if raw[raw.rfind(b")") + 1 :].split()[0] == b"Z":
                return self.fields(port.witness_read(directory, "status"))
            select.select([], [], [], min(POLL_SECONDS, remaining(self.until)))

    def production_coverage(self, port: active.RootPort, task: dict, status: dict) -> None:
        """Require real depth-one refusal; never alter production's namespace-depth predicate."""
        self.assertEqual(status[b"Pid"], [str(task["pid"]).encode()])
        self.assertEqual(status[b"Tgid"], status[b"Pid"])
        self.assertEqual(status[b"PPid"], [str(os.getpid()).encode()])
        self.assertEqual(status[b"Uid"], [str(os.getuid()).encode()] * 4)
        self.assertEqual(status[b"State"], [b"Z", b"(zombie)"])
        depth = len(status[b"NSpid"])
        self.observations["nspidDepth"] = depth
        parent = {"pid": os.getpid(), "uid": os.getuid()}
        if depth < active.WITNESS_PID_DEPTH:
            with self.assertRaises(active.RefusedError):
                port.witness_dead_state(task, parent)
            self.assertEqual(port._witness_failure, "dead-nonactor")
            self.observations["positiveCoverage"] = "refused: depth one"
        elif self.observations.get("procNamespaceCertified") is True:
            first = port.witness_dead_state(task, parent)
            self.assertEqual(port.witness_dead_state(task, parent), first)
            self.observations["positiveCoverage"] = "actual nested-context proof executed"
        else:
            self.observations["positiveCoverage"] = "not attempted: proc certificate unavailable"

    def test_real_proc_resolver_nsfs_and_forbidden_magic_jump(self) -> None:
        with ExitStack() as held:
            port = self.port(held, certificate_required=True)
            self.assertEqual(port._witness_proc.self_pid(), os.getpid())
            with self.assertRaises(active.RefusedError):
                port._witness_proc.open(port._witness_observer, "../status", os.O_RDONLY)
            with self.assertRaises(OSError) as refused:
                port._witness_proc.open(port._witness_observer, "ns/pid", os.O_RDONLY)
            self.assertIn(refused.exception.errno, {errno.ELOOP, errno.EXDEV})
        self.observations["ordinaryMagicJumpRefused"] = True

    def test_retained_zombie_then_exact_reap_detaches_pidfd_and_refuses_production(self) -> None:
        with ExitStack() as held:
            port = self.port(held)
            with owned_child(self.until) as child:
                directory = port._witness_proc.pid(child.process.pid)
                held.callback(os.close, directory)
                os.write(child.release, b"X")
                self.assertTrue(select.select([child.pidfd], [], [], remaining(self.until))[0])
                status = self.zombie(port, directory)
                info = self.fields(port.witness_read(port._witness_observer, "fdinfo/" + str(child.pidfd)))
                if b"NSpid" not in info:
                    self.skipTest("pidfd fdinfo NSpid ABI missing; unqualified")
                self.assertEqual(info[b"Pid"], [str(child.process.pid).encode()])
                self.assertEqual(info[b"NSpid"], status[b"NSpid"])
                self.assertTrue(all(int(value) > 0 for value in info[b"NSpid"]))
                task = {"pid": child.process.pid, "directory": directory, "pidfd": child.pidfd}
                self.production_coverage(port, task, status)
                self.assertEqual(child.process.wait(timeout=remaining(self.until)), 0)
                detached = self.fields(port.witness_read(port._witness_observer, "fdinfo/" + str(child.pidfd)))
                self.assertEqual(detached[b"Pid"], [b"-1"])
                self.assertEqual(detached[b"NSpid"], [b"-1"])
                with self.assertRaises((OSError, active.RefusedError)):
                    port.witness_dead_state(task, {"pid": os.getpid(), "uid": os.getuid()})
        self.observations.update(retainedZombieReadable=True, retainedFdinfoPositive=True, reapedFdinfoDetached=True)

    def test_zombie_leader_with_live_sibling_is_not_process_pidfd_ready(self) -> None:
        with ExitStack() as held:
            port = self.port(held)
            with owned_child(self.until, thread_exit=EXIT_SYSCALL[os.uname().machine]) as child:
                directory = port._witness_proc.pid(child.process.pid)
                held.callback(os.close, directory)
                status = self.zombie(port, directory)
                self.assertFalse(select.select([child.pidfd], [], [], 0)[0])
                task = {"pid": child.process.pid, "directory": directory, "pidfd": child.pidfd}
                with self.assertRaises(active.RefusedError):
                    port.witness_dead_state(task, {"pid": os.getpid(), "uid": os.getuid()})
                os.write(child.release, b"X")
                self.assertTrue(select.select([child.pidfd], [], [], remaining(self.until))[0])
                self.production_coverage(port, task, status)
                self.assertEqual(child.process.wait(timeout=remaining(self.until)), 0)
        self.observations.update(zombieLeaderGroupReady=False, lastThreadExitGroupReady=True)
