"""Fixed privileged TEST entry, outside generic unittest discovery naming.

S certifies its exact child O from outside O's PID namespace. O alone creates a
private mount/proc view and controls its private allocator. D is descendant init
and the sole parent/reaper of A, its replacement R, and the leader/thread case.
No production actor, command service, fixture dependency or global write exists.
"""

# ruff: noqa: PLR0913, PLR0917, PLR2004
from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
import resource
import select
import signal
import socket
import stat
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import ModuleType

PID_NS = 0x20000000
MOUNT_NS = 0x00020000
USER_NS = 0x10000000
NSFS = 0x6E736673
EXIT_SYSCALL = {"x86_64": 60, "aarch64": 93}
CLEANUP_NS = 1_000_000_000
IPC_LIMIT = 4096
CONTROLS = (
    "certified-view",
    "retained-positive",
    "reaped-refusal",
    "numeric-reuse",
    "replacement-positive",
    "reserved-refusal",
    "leader-live-refusal",
    "last-thread-positive",
)
UNAVAILABLE = {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTTY, errno.ENOENT}


def require(value: object) -> None:
    """All uncertainty is a required-step failure, never a skip."""
    if not value:
        raise AssertionError


def remaining(until: int) -> float:
    """Share the original absolute boundary across every process and barrier."""
    value = (until - time.monotonic_ns()) / 1_000_000_000
    if value <= 0:
        raise TimeoutError
    return value


def send(channel: socket.socket, value: dict) -> None:
    """Send exactly one finite packet on a preallocated owned socketpair."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    require(len(raw) <= IPC_LIMIT and channel.send(raw) == len(raw))


def receive(channel: socket.socket, until: int) -> dict:
    """Reject truncation and unknown framing; callers check their closed step."""
    require(select.select([channel], [], [], remaining(until))[0])
    raw, _ancillary, flags, _address = channel.recvmsg(IPC_LIMIT)
    require(raw and not flags)
    value = json.loads(raw)
    require(type(value) is dict)
    return value


def exchange(channel: socket.socket, command: str, until: int) -> dict:
    """One fixed instruction, one acknowledged barrier, no retry."""
    send(channel, {"command": command})
    return receive(channel, until)


def namespace(api: ModuleType, descriptor: int, kind: int) -> tuple[int, int]:
    """Check the actual nsfs object and Linux namespace type."""
    api.filesystem_magic(descriptor, NSFS)
    require(fcntl.ioctl(descriptor, 0xB703) == kind)
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def parent_namespace(api: ModuleType, descriptor: int) -> tuple[int, int]:
    """Only callers outside a held descendant namespace may certify its parent."""
    parent = fcntl.ioctl(descriptor, 0xB702)
    try:
        return namespace(api, parent, PID_NS)
    finally:
        os.close(parent)


def parent_death(parent_pidfd: int) -> None:
    """Close the PR_SET_PDEATHSIG race with the inherited exact parent pidfd."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "parent-death setup refused")
    require(not select.select([parent_pidfd], [], [], 0)[0])


class ExactChild:
    """An unreaped fork return plus flags-zero pidfd; never numeric rediscovery."""

    def __init__(self, pid: int, until: int) -> None:
        """Retain the fork return before any fallible pidfd acquisition."""
        self.pid, self.until, self.pidfd, self.waited = pid, until, None, False

    def acquire(self) -> None:
        self.pidfd = os.pidfd_open(self.pid, 0)

    def wait(self, until: int) -> int:
        while True:
            # An expired allowance or broken readiness poll must not prevent an
            # already-reapable exact child from being collected. Late reap still
            # fails the original boundary after recording completed ownership.
            observed, status = os.waitpid(self.pid, os.WNOHANG)
            if observed:
                require(observed == self.pid)
                self.waited = True
                remaining(until)
                return status
            allowance = remaining(until)
            if self.pidfd is None:
                select.select([], [], [], min(0.001, allowance))
            else:
                require(select.select([self.pidfd], [], [], allowance)[0])

    def close(self) -> None:
        """Attempt exact wait and descriptor close even if signaling fails."""
        try:
            if not self.waited:
                try:
                    if self.pidfd is None:
                        os.kill(self.pid, signal.SIGKILL)
                    elif not select.select([self.pidfd], [], [], 0)[0]:
                        signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                finally:
                    self.wait(self.until + CLEANUP_NS)
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)


@contextmanager
def fork_owned(
    target: Callable,
    parent: socket.socket,
    child: socket.socket,
    parent_pidfd: int,
    until: int,
) -> Iterator[ExactChild]:
    """Record ownership before pidfd acquisition/release, with cleanup on setup faults."""
    try:
        pid = os.fork()
    except BaseException:
        try:
            parent.close()
        finally:
            child.close()
        raise
    if pid == 0:
        exit_code = 1
        try:
            parent.close()
            parent_death(parent_pidfd)
            target(child)
            exit_code = 0
        except BaseException:  # noqa: BLE001 - fork child must never reenter the supervisor's path.
            exit_code = 1
        finally:
            try:
                child.close()
            except BaseException:  # noqa: BLE001 - cleanup failure must also stay inside this fork child.
                exit_code = 1
            os._exit(exit_code)
    owned = ExactChild(pid, until)  # Record the unreaped return before even closing a socket.
    try:
        child.close()
        owned.acquire()
        yield owned
    finally:
        try:
            owned.close()
        finally:
            parent.close()


def fields(raw: bytes) -> dict[bytes, list[bytes]]:
    """Independent kernel field observations, not production parser expectations."""
    result = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b":")
        if separator:
            require(key not in result)
            result[key] = value.split()
    return result


def actor(channel: socket.socket, until: int, *, leader: bool) -> None:
    """One process; only the final case starts one controlled sibling thread."""
    leader_exit = threading.Event() if leader else None

    def sibling() -> None:
        translated = os.readlink("/proc/self")  # noqa: PTH115 - kernel-produced proc symlink, no path traversal.
        send(channel, {"observer": int(translated), "inner": os.getpid()})
        if leader:
            require(receive(channel, until) == {"command": "leader-exit"})
            send(channel, {"leader-exit": True})
            leader_exit.set()
        require(receive(channel, until) == {"command": "exit"})
        os._exit(0)

    if leader:
        threading.Thread(target=sibling).start()
        require(leader_exit.wait(remaining(until)))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall(EXIT_SYSCALL[os.uname().machine], 0)
        os._exit(2)
    sibling()


def descendant(channel: socket.socket, until: int) -> None:
    """D alone forks/reaps its exact child; idle acknowledgement is a fork barrier."""
    require(os.getpid() == 1)
    self_pidfd = os.pidfd_open(os.getpid(), 0)
    try:
        send(channel, {"init": 1})
        for case in ("original", "replacement", "leader"):
            require(receive(channel, until) == {"command": case})
            outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with fork_owned(
                lambda sock, leader=case == "leader": actor(sock, until, leader=leader),
                outer,
                inner,
                self_pidfd,
                until,
            ) as child:
                report = receive(outer, until)
                require(set(report) == {"observer", "inner"} and report["inner"] == child.pid)
                send(channel, report)
                if case == "leader":
                    require(receive(channel, until) == {"command": "leader-exit"})
                    require(exchange(outer, "leader-exit", until) == {"leader-exit": True})
                    send(channel, {"leader-exit": True})
                require(receive(channel, until) == {"command": "exit"})
                send(outer, {"command": "exit"})
                send(channel, {"released": True})
                require(receive(channel, until) == {"command": "reap"})
                require(child.wait(until) == 0)
            send(channel, {"reaped": True, "idle": True})
        require(receive(channel, until) == {"command": "finish"})
        send(channel, {"finished": True})
    finally:
        os.close(self_pidfd)


def mount_private_proc() -> None:
    """Only O calls this after verifying its distinct mount namespace."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    if libc.mount(None, b"/", None, (1 << 18) | (1 << 14), None):  # MS_PRIVATE | MS_REC
        raise OSError(ctypes.get_errno(), "private propagation refused")
    verify_private_mounts()
    if libc.mount(b"proc", b"/proc", b"proc", 2 | 4 | 8, None):  # NOSUID | NODEV | NOEXEC
        raise OSError(ctypes.get_errno(), "private proc refused")
    verify_private_mounts()


def verify_private_mounts() -> None:
    """Reject any shared/master propagation or an unbounded mountinfo view."""
    descriptor = os.open("/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while len(data) <= 262144:
            chunk = os.read(descriptor, 262145 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        raw = bytes(data)
        require(raw and len(raw) <= 262144 and raw.endswith(b"\n"))
        for line in raw.splitlines():
            before, separator, _after = line.partition(b" - ")
            parts = before.split()
            require(separator and len(parts) >= 6)
            require(not any(part.startswith((b"shared:", b"master:", b"propagate_from:")) for part in parts[6:]))
    finally:
        os.close(descriptor)


def port_view(api: ModuleType, held: ExitStack, until: int, expected: tuple) -> object:
    """Minimal real RootPort with the unchanged production ledger and predicates."""
    port = api.RootPort.__new__(api.RootPort)
    port.cleanup, port.work_until = False, until
    port.record = {"retained": False}
    port.witness_counts = {"procBytes": 0, "pids": set()}
    port._witness_proc = api.ProcView(held, port.witness_proc_bytes, port.witness_pid)
    view = port._witness_proc
    port._witness_observer = view.pid(view.self_pid())
    held.callback(os.close, port._witness_observer)
    init = view.pid(1)
    held.callback(os.close, init)
    require(view.pid_namespace(held, port._witness_observer) == view.pid_namespace(held, init) == expected)
    port._witness_owner_pidfd = os.pidfd_open(os.getpid(), 0)
    held.callback(os.close, port._witness_owner_pidfd)
    return port


def refused(api: ModuleType, call: Callable) -> None:
    """Require a production refusal, keeping errors as separate fixture failures."""
    try:
        call()
    except api.RefusedError:
        return
    raise AssertionError


def status_z(port: object, task: dict, until: int) -> dict:
    """Observe the held leader's actual zombie state under the original deadline."""
    while True:
        status = fields(port.witness_read(task["directory"], "status"))
        if status[b"State"] == [b"Z", b"(zombie)"]:
            return status
        select.select([], [], [], min(0.001, remaining(until)))


def task_for(port: object, held: ExitStack, report: dict, parent: dict) -> dict:
    """Open a genuine held task and corroborate the kernel-derived translated PID."""
    require(set(report) == {"observer", "inner"})
    require(all(type(report[key]) is int and report[key] > 1 for key in report))
    pid = report["observer"]
    require(pid not in {os.getpid(), parent["pid"]})
    directory = port._witness_proc.pid(pid)
    held.callback(os.close, directory)
    pidfd = os.pidfd_open(pid, 0)
    held.callback(os.close, pidfd)
    status = fields(port.witness_read(directory, "status"))
    require(status[b"Pid"] == status[b"Tgid"] == [str(pid).encode()])
    require(status[b"PPid"] == [str(parent["pid"]).encode()])
    require(status[b"Uid"] == [b"0"] * 4)
    require(status[b"NSpid"] == [str(pid).encode(), str(report["inner"]).encode()])
    return {"pid": pid, "directory": directory, "pidfd": pidfd}


def positive(port: object, held: ExitStack, task: dict, parent: dict, until: int) -> list:
    """Independent depth/readiness observations followed by every production proof."""
    status = status_z(port, task, until)
    require(select.select([task["pidfd"]], [], [], remaining(until))[0])
    info = fields(port.witness_read(port._witness_observer, "fdinfo/" + str(task["pidfd"])))
    require(info[b"Pid"] == status[b"Pid"] and info[b"NSpid"] == status[b"NSpid"])
    require(len(info[b"NSpid"]) == 2 and all(int(part) > 0 for part in info[b"NSpid"]))
    raw_stat = port.witness_read(task["directory"], "stat")
    head, separator, tail = raw_stat.rpartition(b") ")
    columns = tail.split()
    require(separator and head.split(b" ", 1)[0] == str(task["pid"]).encode())
    require(len(columns) > 19 and columns[0] == b"Z" and columns[1] == str(parent["pid"]).encode())
    require(columns[19].isdigit() and int(columns[19]) > 0)
    state = port.witness_dead_state(task, parent)
    require(state["startTicks"] == int(columns[19]))
    dead = port.witness_dead(held, {task["pid"]}, parent, {"roles": {}})
    require(len(dead) == 1 and dead[0]["before"] == state)
    port.witness_dead_readback(ExitStack(), dead, parent)
    return dead


def detached(port: object, task: dict) -> None:
    """Require the admitted ABI's detached sentinel on the original held pidfd."""
    info = fields(port.witness_read(port._witness_observer, "fdinfo/" + str(task["pidfd"])))
    require(info[b"Pid"] == info[b"NSpid"] == [b"-1"])


def hold_sibling(port: object, held: ExitStack, task: dict) -> dict:
    """Hold the sibling before leader exit can make its task directory unavailable."""
    view = port._witness_proc
    directory = view.open(task["directory"], "task", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held.callback(os.close, directory)
    names = os.listdir(directory)  # noqa: PTH208 - list the held proc descriptor, never a pathname.
    require(len(names) == 2 and str(task["pid"]) in names)
    sibling = next(name for name in names if name != str(task["pid"]))
    require(sibling.isascii() and sibling.isdecimal() and 0 < int(sibling) <= 9_999_999_999)
    port.witness_pid(int(sibling))
    descriptor = view.open(directory, sibling, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held.callback(os.close, descriptor)
    return {"directory": descriptor, "pid": int(sibling)}


def leader_sibling(port: object, task: dict, sibling: dict) -> None:
    """Observe the surviving sibling through its original held proc object."""
    status = fields(port.witness_read(sibling["directory"], "status"))
    require(status[b"State"][0] in {b"S", b"R"})
    require(status[b"Pid"] == [str(sibling["pid"]).encode()] and status[b"Tgid"] == [str(task["pid"]).encode()])
    require(status[b"Uid"] == [b"0"] * 4 and len(status[b"NSpid"]) == 2)


def stale_refusal(api: ModuleType, port: object, task: dict, dead: list, parent: dict) -> None:
    """Held old proc lookup may error at the kernel; the production call must refuse."""
    for call in (
        lambda: port.witness_dead_state(task, parent),
        lambda: port.witness_dead_readback(ExitStack(), dead, parent),
    ):
        try:
            call()
        except api.RefusedError, ProcessLookupError, FileNotFoundError:
            continue
        raise AssertionError


def allocator_reset(api: ModuleType, port: object, held: ExitStack, certificate: dict) -> None:
    """Write once to the fixed allocator leaf of O's genuine certified private proc."""
    # All checks occur before opening the writable leaf. No fork/thread allocation
    # happens in O; D is at the post-wait barrier and cannot fork without a command.
    require(certificate["handshake"] is True and certificate["idle"] is True)
    require(certificate["mount"] != certificate["originalMount"])
    require(certificate["namespace"] != certificate["originalNamespace"])
    require(os.getpid() == 1)
    current = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
    try:
        require(namespace(api, current, MOUNT_NS) == certificate["mount"])
    finally:
        os.close(current)
    verify_private_mounts()
    view = port._witness_proc
    init = view.pid(1)
    held.callback(os.close, init)
    expected = (*certificate["namespace"], PID_NS)
    require(view.self_pid() == 1)
    require(view.pid_namespace(held, init) == view.pid_namespace(held, port._witness_observer) == expected)
    d_status = fields(port.witness_read(certificate["descendantDirectory"], "status"))
    require(d_status[b"State"][0] in {b"S", b"R"} and d_status[b"Threads"] == [b"1"])
    require(d_status[b"Pid"] == d_status[b"Tgid"] == [str(certificate["descendantPid"]).encode()])
    require(d_status[b"PPid"] == [b"1"])
    require(d_status[b"NSpid"] == [str(certificate["descendantPid"]).encode(), b"1"])
    require(d_status[b"Uid"] == [b"0"] * 4)
    require(not select.select([certificate["descendantPidfd"]], [], [], 0)[0])
    old, locator = certificate["old"], certificate["old"]["pid"]
    require(type(locator) is int and 1 < locator <= api.PROC_PID_MAX and locator != certificate["descendantPid"])
    detached(port, old)
    try:
        fresh = view.pid(locator)
    except FileNotFoundError:
        pass
    else:
        os.close(fresh)
        raise AssertionError
    descriptor = view.open(view.root, "sys/kernel/ns_last_pid", os.O_WRONLY | os.O_NOFOLLOW)
    try:
        api.filesystem_magic(descriptor, 0x9FA0)
        value = str(locator - 1).encode("ascii")
        require(os.write(descriptor, value) == len(value))
    finally:
        os.close(descriptor)
    descriptor = view.open(view.root, "sys/kernel/ns_last_pid", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        api.filesystem_magic(descriptor, 0x9FA0)
        require(os.read(descriptor, 32).strip() == value)
    finally:
        os.close(descriptor)


def controls(  # noqa: PLR0915 - fixed ordered ownership/reap/reuse barriers stay visible together.
    api: ModuleType,
    held: ExitStack,
    port: object,
    channel: socket.socket,
    child: ExactChild,
    certificate: dict,
    until: int,
    outcomes: dict,
) -> None:
    """Run all independent observations and original production predicates in order."""
    view = port._witness_proc
    directory = view.pid(child.pid)
    held.callback(os.close, directory)
    ns_directory = view.open(directory, "ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held.callback(os.close, ns_directory)
    child_ns = os.open("pid", os.O_RDONLY | os.O_CLOEXEC, dir_fd=ns_directory)
    held.callback(os.close, child_ns)
    require(namespace(api, child_ns, PID_NS) != certificate["namespace"])
    require(parent_namespace(api, child_ns) == certificate["namespace"])
    require(receive(channel, until) == {"init": 1})
    parent = {"pid": child.pid, "uid": 0}
    report = exchange(channel, "original", until)
    old = task_for(port, held, report, parent)
    reserved = {"roles": {"original": {"pid": old["pid"]}}}
    require(exchange(channel, "exit", until) == {"released": True})
    dead = positive(port, held, old, parent, until)
    outcomes["retained-positive"] = "passed"
    require(exchange(channel, "reap", until) == {"reaped": True, "idle": True})
    detached(port, old)
    stale_refusal(api, port, old, dead, parent)
    outcomes["reaped-refusal"] = "passed"
    certificate.update(
        idle=True, descendantPid=child.pid, descendantDirectory=directory, descendantPidfd=child.pidfd, old=old
    )
    allocator_reset(api, port, held, certificate)
    replacement = exchange(channel, "replacement", until)
    require(replacement["observer"] == old["pid"] and replacement["inner"] != report["inner"])
    new = task_for(port, held, replacement, parent)
    require(fields(port.witness_read(new["directory"], "status"))[b"State"][0] in {b"S", b"R"})
    require(not select.select([new["pidfd"]], [], [], 0)[0])
    require(
        (os.fstat(new["directory"]).st_dev, os.fstat(new["directory"]).st_ino)
        != (os.fstat(old["directory"]).st_dev, os.fstat(old["directory"]).st_ino)
    )
    require(exchange(channel, "exit", until) == {"released": True})
    positive(port, held, new, parent, until)
    outcomes["replacement-positive"] = "passed"
    detached(port, old)
    stale_refusal(api, port, old, dead, parent)
    outcomes["numeric-reuse"] = "passed"
    refused(api, lambda: port.witness_dead(held, {old["pid"]}, parent, reserved))
    require(port._witness_failure == "dead-nonactor")
    outcomes["reserved-refusal"] = "passed"
    require(exchange(channel, "reap", until) == {"reaped": True, "idle": True})
    leader = task_for(port, held, exchange(channel, "leader", until), parent)
    sibling = hold_sibling(port, held, leader)
    require(exchange(channel, "leader-exit", until) == {"leader-exit": True})
    status = status_z(port, leader, until)
    require(status[b"Threads"] == [b"2"])
    leader_sibling(port, leader, sibling)
    require(not select.select([leader["pidfd"]], [], [], 0)[0])
    refused(api, lambda: port.witness_dead_state(leader, parent))
    outcomes["leader-live-refusal"] = "passed"
    require(exchange(channel, "exit", until) == {"released": True})
    positive(port, held, leader, parent, until)
    outcomes["last-thread-positive"] = "passed"
    require(exchange(channel, "reap", until) == {"reaped": True, "idle": True})
    require(exchange(channel, "finish", until) == {"finished": True})
    require(child.wait(until) == 0)


def observer(api: ModuleType, channel: socket.socket, original: dict, until: int) -> None:
    """Perform isolated operations only after S's external namespace certificate."""
    outcomes = dict.fromkeys(CONTROLS, "not-run")
    result = {"controls": outcomes, "status": "failed", "cleanup": False, "complete": False}
    try:
        with ExitStack() as held:
            ack = receive(channel, until)
            require(set(ack) == {"namespace"} and len(ack["namespace"]) == 2)
            own = os.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)
            held.callback(os.close, own)
            current = namespace(api, own, PID_NS)
            require(os.getpid() == 1 and current == tuple(ack["namespace"]) and current != original["pid"])
            os.unshare(MOUNT_NS)
            mount = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
            held.callback(os.close, mount)
            mount_identity = namespace(api, mount, MOUNT_NS)
            require(mount_identity != original["mnt"])
            mount_private_proc()
            port = port_view(api, held, until, (*current, PID_NS))
            try:
                unexpected = port._witness_proc.open(port._witness_observer, "ns/pid", os.O_RDONLY)
            except OSError as error:
                require(error.errno in {errno.EXDEV, errno.ELOOP})
            else:
                os.close(unexpected)
                raise AssertionError
            outcomes["certified-view"] = "passed"
            certificate = {
                "handshake": True,
                "namespace": current,
                "originalNamespace": original["pid"],
                "mount": mount_identity,
                "originalMount": original["mnt"],
            }
            self_pidfd = os.pidfd_open(os.getpid(), 0)
            held.callback(os.close, self_pidfd)
            os.unshare(PID_NS)
            outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with fork_owned(lambda sock: descendant(sock, until), outer, inner, self_pidfd, until) as child:
                controls(api, held, port, outer, child, certificate, until, outcomes)
            remaining(until)
        result.update(status="passed", cleanup=True, complete=True)
    except OSError as error:
        result["status"] = "unavailable" if error.errno in UNAVAILABLE else "failed"
    except BaseException:  # noqa: BLE001 - report only closed outcomes, never raw exceptions.
        result["status"] = "failed"
    # S waits for this namespace init even after a negative result. Its exact wait
    # is the final teardown barrier; a partial result cannot qualify the caller.
    send(channel, result)


def supervise(api: ModuleType, until: int) -> dict:
    """Certify O from its ancestor and wait for exact namespace-init teardown."""
    with ExitStack() as held:
        original = {}
        for name, kind in (("pid", PID_NS), ("mnt", MOUNT_NS), ("user", USER_NS)):
            descriptor = os.open("/proc/self/ns/" + name, os.O_RDONLY | os.O_CLOEXEC)
            held.callback(os.close, descriptor)
            original[name] = namespace(api, descriptor, kind)
        root = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held.callback(os.close, root)
        api.filesystem_magic(root, 0x9FA0)
        info = os.fstat(root)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0)
        require(os.readlink("self", dir_fd=root) == str(os.getpid()))
        self_pidfd = os.pidfd_open(os.getpid(), 0)
        held.callback(os.close, self_pidfd)
        os.unshare(PID_NS)
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with fork_owned(lambda sock: observer(api, sock, original, until), outer, inner, self_pidfd, until) as child:
            directory = api.ProcView.open(root, str(child.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held.callback(os.close, directory)
            ns_directory = api.ProcView.open(directory, "ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held.callback(os.close, ns_directory)
            child_ns = os.open("pid", os.O_RDONLY | os.O_CLOEXEC, dir_fd=ns_directory)
            held.callback(os.close, child_ns)
            identity = namespace(api, child_ns, PID_NS)
            require(identity != original["pid"] and parent_namespace(api, child_ns) == original["pid"])
            send(outer, {"namespace": identity})
            result = receive(outer, until)
            require(child.wait(until) == 0)
        # S never changed active PID/user/mount identity or mounted over its proc.
        for name, kind in (("pid", PID_NS), ("mnt", MOUNT_NS), ("user", USER_NS)):
            current = os.open("/proc/self/ns/" + name, os.O_RDONLY | os.O_CLOEXEC)
            try:
                require(namespace(api, current, kind) == original[name])
            finally:
                os.close(current)
        require(set(result) == {"controls", "status", "complete", "cleanup"})
        remaining(until)
        return result


def main() -> int:
    """Only the launcher supplies fixed source/stage/run arguments; emit closed data."""
    association = json.loads(sys.argv[2])
    until = int(sys.argv[3])
    machine = os.uname().machine
    result = {
        "schemaVersion": 1,
        "association": association,
        "kernel": os.uname().release,
        "architecture": {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, "unsupported"),
        "controls": dict.fromkeys(CONTROLS, "not-run"),
        "status": "failed",
        "complete": False,
        "cleanup": False,
    }
    try:
        require(os.getuid() == os.geteuid() == 0 and machine in EXIT_SYSCALL)
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        require(0 < until - time.monotonic_ns() <= 3_000_000_000)
        maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        require(3 <= maximum <= 1_048_576)
        os.closerange(3, maximum)
        # -I -B -S excludes cwd/site/user imports. The sole extra path is the
        # already authenticated immutable stage, never the mutable checkout.
        sys.path.insert(0, sys.argv[1])
        from scripts import docker_userns_active as api  # noqa: PLC0415

        result.update(supervise(api, until))
    except OSError as error:
        result["status"] = "unavailable" if error.errno in UNAVAILABLE else "failed"
    except BaseException:  # noqa: BLE001 - closed required-step failure, never traceback/source output.
        result["status"] = "failed"
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["status"] == "passed" and result["complete"] is True and result["cleanup"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
