"""Unused root-custody child boundary; no bootstrap, parser or supervisor adapter."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from contextlib import AbstractContextManager

MAX_SOURCE = 65536
MAX_INTERPRETER = 16 * 1024 * 1024
MAX_POLICY = 1024
_SEAL_VALUES = tuple(
    getattr(fcntl, name, None) for name in ("F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
)
SEALS = sum(_SEAL_VALUES) if all(type(value) is int for value in _SEAL_VALUES) else None
MODULES = ("canonical_policy", "native_outer_diagnostic_capture")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
CODE = r"""
import ctypes, errno, fcntl, hashlib, importlib.abc, importlib.util, json, os, re, resource, signal, sys
interpreter, receipt, first, second, name, uid, gid, seconds = sys.argv[1:]
uid, gid = int(uid), int(gid)
if uid <= 0 or gid <= 0 or os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
    raise SystemExit(1)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
    raise SystemExit(1)
with open("/proc/self/status", "rb") as stream:
    status = stream.read(8193)
if len(status) > 8192:
    raise SystemExit(1)
for key in (b"CapEff", b"CapPrm", b"CapInh", b"CapAmb", b"NoNewPrivs"):
    values = [row.split(b":", 1)[1].strip() for row in status.splitlines() if row.startswith(key + b":")]
    if len(values) != 1 or not re.fullmatch(rb"[0-9a-fA-F]{1,16}", values[0]):
        raise SystemExit(1)
    if int(values[0], 16) != (1 if key == b"NoNewPrivs" else 0):
        raise SystemExit(1)
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(int(seconds))
os.close(int(interpreter))
records = {}
for module, encoded in zip(("canonical_policy", "native_outer_diagnostic_capture"), (first, second), strict=True):
    descriptor, size, digest = encoded.split(":")
    descriptor, size = int(descriptor), int(size)
    if fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise SystemExit(1)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
        raise SystemExit(1)
    before = os.fstat(descriptor)
    raw = os.pread(descriptor, size + 1, 0)
    after = os.fstat(descriptor)
    stable = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode,
                           item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (stable(before) != stable(after) or before.st_uid != 0
            or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest):
        raise SystemExit(1)
    records[module] = raw
proof = {"schema": 1, "uid": uid, "gid": gid, "groups": [], "nnp": 1, "capabilities": "zero"}
raw = json.dumps(proof, sort_keys=True).encode("ascii")
if os.write(int(receipt), raw) != len(raw):
    raise SystemExit(1)
os.close(int(receipt))
allowed = {0, 1, 2, int(first.split(":")[0]), int(second.split(":")[0])}
for entry in os.listdir("/proc/self/fd"):
    descriptor = int(entry)
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise SystemExit(1)
        continue
    if descriptor not in allowed:
        raise SystemExit(1)
class SourceLoader(importlib.abc.MetaPathFinder, importlib.abc.SourceLoader):
    def find_spec(self, fullname, path=None, target=None):
        return importlib.util.spec_from_loader(fullname, self) if fullname in records else None
    def get_filename(self, fullname):
        if fullname not in records:
            raise ImportError
        return "/__containers_verified__/" + fullname + ".py"
    def get_data(self, path):
        names = {self.get_filename(module): module for module in records}
        if path not in names:
            raise OSError
        return records[names[path]]
loader = SourceLoader()
sys.meta_path.insert(0, loader)
spec = loader.find_spec("canonical_policy")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
loader.exec_module(module)
value = module.profile_bytes(name)
if type(value) is not bytes or len(value) > 1024:
    raise SystemExit(1)
sys.stdout.buffer.write(value)
"""


class Clock(Protocol):
    """Provide the parent's original integer monotonic clock."""

    def now_ns(self) -> int:
        """Return monotonic nanoseconds."""
        ...


class Lifetime(StrEnum):
    """Keep actual child lifetime independent of the primary operation result."""

    NEVER_STARTED = "never-started"
    DEAD = "proven-dead"
    UNKNOWN = "unknown"


class ChildError(Exception):
    """Report only a closed child failure and whether group death was proven."""

    def __init__(self, *, dead: bool | None = None, lifetime: Lifetime | None = None) -> None:
        """Retain lifetime uncertainty independently of raw child output."""
        super().__init__("child-refused")
        self.lifetime = lifetime or (
            Lifetime.NEVER_STARTED if dead is None else Lifetime.DEAD if dead else Lifetime.UNKNOWN
        )
        self.dead = self.lifetime is Lifetime.DEAD
        self.pending = self.lifetime is Lifetime.UNKNOWN


WORK_FAILURE_LIMIT = 512
WORK_FAILURE_FIELDS = ("context", "site", "failure")
_WORK_CATEGORIES = frozenset(
    ("REFUSED", "OS_ERROR", "TIMEOUT", "DECODE", "VALUE_ERROR", "LOOKUP_ERROR", "TYPE_ERROR", "OTHER")
)
_WORK_REFUSAL = frozenset(("REFUSED",))
WORK_FAILURES = {
    ("CHILD_PARENT", "B_BUILD_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_BUILD_G03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_BUILD_STATUS_REFUSAL"): _WORK_REFUSAL,
    ("CHILD_PARENT", "B_BYTES_AT_EXTEND"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_BYTES_AT_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_EXTEND"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_G03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W04"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W05"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W06"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W07"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W08"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_CAPTURE_W09"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_EXECUTE_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_EXECUTE_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_EXECUTE_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_EXECUTE_W03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_G03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_G04"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_INTERPRETER_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_G03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_G04"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PREFLIGHT_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PRIVILEGE_RECEIPT_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PRIVILEGE_RECEIPT_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PRIVILEGE_RECEIPT_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G04"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G06"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_G07"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_STATUS_REFUSAL"): _WORK_REFUSAL,
    ("CHILD_PARENT", "B_PROBE_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_PROBE_W03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_DUP"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_G01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_G02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W01"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W02"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W03"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W04"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W05"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_SEAL_W06"): _WORK_CATEGORIES,
    ("CHILD_PARENT", "B_UNIQUE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_BUDGET_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_BUDGET_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CALLER_G01"): _WORK_REFUSAL,
    ("CUSTODY", "C_CLOCK_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CLOCK_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_COHORT_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_COHORT_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_COHORT_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W07"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W08"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W09"): _WORK_CATEGORIES,
    ("CUSTODY", "C_CREATE_W10"): _WORK_CATEGORIES,
    ("CUSTODY", "C_DIRECTORY_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_EXACT_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_FILE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_FILE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_GROUP_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_INITIAL_G01"): _WORK_REFUSAL,
    ("CUSTODY", "C_INTEGER_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_JOURNAL_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_JOURNAL_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_JOURNAL_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G07"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G08"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_G09"): _WORK_CATEGORIES,
    ("CUSTODY", "C_MANIFEST_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_NEXT_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G01"): _WORK_REFUSAL,
    ("CUSTODY", "C_OBSERVATION_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G07"): _WORK_CATEGORIES,
    ("CUSTODY", "C_OBSERVATION_G08"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PHASE_G06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_POPULATE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_POPULATE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_POPULATE_G03"): _WORK_REFUSAL,
    ("CUSTODY", "C_POPULATE_G05"): _WORK_REFUSAL,
    ("CUSTODY", "C_POPULATE_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_POPULATE_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PREPARE_UNUSED_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PREPARE_UNUSED_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PREPARE_UNUSED_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PREPARE_UNUSED_G04"): _WORK_REFUSAL,
    ("CUSTODY", "C_PREPARE_UNUSED_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_PROCESS_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_ROOT_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_RUN_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_RUN_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_RUN_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_SELF_START_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_SELF_START_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_SELF_START_OPEN"): _WORK_CATEGORIES,
    ("CUSTODY", "C_SELF_START_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_START_G01"): _WORK_REFUSAL,
    ("CUSTODY", "C_STORE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_LOAD_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_LOAD_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_LOAD_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_LOAD_G04"): _WORK_REFUSAL,
    ("CUSTODY", "C_STORE_LOAD_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_LOAD_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_READ_W03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_STATE_REPLACE"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_SAVE_W06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W06"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W07"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_W08"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_DUP"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_W01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_W02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_W03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_W04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_STORE_WRITE_W05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_TOKEN_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_UNIQUE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G01"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G02"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G03"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G04"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G05"): _WORK_CATEGORIES,
    ("CUSTODY", "C_VALIDATE_G06"): _WORK_CATEGORIES,
    ("HOSTED", "H_CLOCK_BOOT_ID_G01"): _WORK_REFUSAL,
    ("HOSTED", "H_CLOCK_NOW_NS_W01"): _WORK_CATEGORIES,
    ("HOSTED", "H_GROUP_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_GROUP_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_GROUP_LSTAT"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G03"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G04"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G05"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G06"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_OBSERVE_G08"): _WORK_REFUSAL,
    ("HOSTED", "H_HOSTPORT_OBSERVE_W01"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_REOBSERVE_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_HOSTPORT_REOBSERVE_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G03"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G04"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G05"): _WORK_CATEGORIES,
    ("HOSTED", "H_PROCESS_G06"): _WORK_REFUSAL,
    ("HOSTED", "H_READ_ROOT_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G03"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G04"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G05"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G06"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_G07"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_W01"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_W02"): _WORK_CATEGORIES,
    ("HOSTED", "H_READ_ROOT_W03"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_COMPONENT_LSTAT"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G01"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G02"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G03"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G04"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G05"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G06"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_G07"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_READLINK"): _WORK_CATEGORIES,
    ("HOSTED", "H_SAFE_PATH_ROOT_LSTAT"): _WORK_CATEGORIES,
}


def work_failure(value: object) -> dict[str, object] | None:
    """Normalize one closed optional detail without accepting authored or unknown data."""
    if type(value) is not dict or set(value) != {"schema", "context", "site", "failure"}:
        return None
    if type(value["schema"]) is not int or value["schema"] != 1:
        return None
    if any(type(value[key]) is not str for key in ("context", "site", "failure")):
        return None
    if value["failure"] not in WORK_FAILURES.get((value["context"], value["site"]), ()):
        return None
    result = {"schema": 1, "context": value["context"], "site": value["site"], "failure": value["failure"]}
    if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > WORK_FAILURE_LIMIT:
        return None
    return result


class WorkObserver:
    """Keep only immutable closed first-work evidence for one explicit preparation scope."""

    __slots__ = ("_active", "_fault", "_invalid", "_mute_depth", "_sealed", "_work_depth", "_work_site")

    def __init__(self) -> None:
        """Start inactive, without references to privileged inputs."""
        self._active = self._sealed = self._invalid = False
        self._fault: tuple[str, str, str] | None = None
        self._work_depth = self._mute_depth = 0
        self._work_site: tuple[str, str] | None = None

    def record(self, context: str, site: str, failure: str) -> None:
        """Accept an active closed candidate; conflicting candidates invalidate detail."""
        if not self._active or self._sealed or self._mute_depth or not self._work_depth or self._invalid:
            return
        candidate = (context, site, failure)
        if (context, site) != self._work_site:
            self._invalid, self._fault = True, None
            return
        if work_failure({"schema": 1, "context": context, "site": site, "failure": failure}) is None or (
            self._fault is not None and self._fault != candidate
        ):
            self._invalid, self._fault = True, None
        else:
            self._fault = candidate

    def snapshot(self) -> dict[str, object] | None:
        """Expose sealed safe values without exceptions, captures or cleanup authority."""
        if not self._sealed or self._active or self._invalid or self._fault is None:
            return None
        context, site, failure = self._fault
        return work_failure({"schema": 1, "context": context, "site": site, "failure": failure})

    @contextmanager
    def observing(self) -> Iterator[None]:
        """Activate once, then seal before later phases or invocation cleanup."""
        if self._active or self._sealed:
            self._invalid, self._fault = True, None
            yield
            return
        self._active = True
        try:
            yield
        finally:
            sealed = False
            with suppress(Exception):
                self.seal()
                sealed = True
            if not sealed:
                self._invalid, self._fault, self._active = True, None, False

    def seal(self) -> None:
        """Seal only closed evidence; the caller suppresses diagnostic sealing failure."""
        self._active, self._sealed = False, True

    @contextmanager
    def muted(self) -> Iterator[None]:
        """Exclude retention and its shared helper calls from work attribution."""
        self._mute_depth += 1
        try:
            yield
        finally:
            self._mute_depth -= 1

    def _attempt(self, context: str, site: str, failure: str) -> None:
        if self._fault is not None or self._invalid:
            return
        recorded = False
        with suppress(Exception):
            self.record(context, site, failure)
            recorded = True
        if not recorded:
            self._invalid, self._fault = True, None

    @contextmanager
    def work(self, context: str, site: str | None, refusals: tuple[type[Exception], ...]) -> Iterator[None]:
        """Latch only this original work operation before its enclosing release runs."""
        if site is None or not self._active or self._sealed or self._mute_depth or self._invalid:
            yield
            return
        if type(context) is not str or type(site) is not str or (context, site) not in WORK_FAILURES:
            self._invalid, self._fault = True, None
            yield
            return
        previous = self._work_site
        self._work_site = (context, site)
        self._work_depth += 1
        try:
            yield
        except Exception as error:
            if self._fault is None and not self._invalid:
                recorded = False
                with suppress(Exception):
                    self._attempt(context, site, _failure(error, refusals))
                    recorded = True
                if not recorded:
                    self._invalid, self._fault = True, None
            raise
        finally:
            self._work_depth -= 1
            self._work_site = previous

    def refused(self, context: str, site: str | None) -> None:
        """Record an actual false guard without reading or re-evaluating its operands."""
        if site is None or not self._active or self._sealed or self._mute_depth or self._invalid:
            return
        if type(context) is not str or type(site) is not str or (context, site) not in WORK_FAILURES:
            self._invalid, self._fault = True, None
            return
        previous = self._work_site
        self._work_site = (context, site)
        self._work_depth += 1
        try:
            self._attempt(context, site, "REFUSED")
        finally:
            self._work_depth -= 1
            self._work_site = previous


def new_observer() -> WorkObserver | None:
    """Disable observation silently if its local collector cannot be constructed."""
    result = None
    with suppress(Exception):
        result = WorkObserver()
    return result


def observer_args(observer: WorkObserver | None) -> dict[str, WorkObserver]:
    """Keep omitted observers' shared call signatures unchanged."""
    return {"observer": observer} if type(observer) is WorkObserver else {}


@contextmanager
def observing(observer: WorkObserver | None) -> Iterator[None]:
    """Scope only explicitly supplied observers, preserving default callers."""
    if type(observer) is WorkObserver:
        with observer.observing():
            yield
    else:
        yield


@contextmanager
def muted(observer: WorkObserver | None) -> Iterator[None]:
    """Mute only the supplied invocation's cleanup, without ambient state."""
    if type(observer) is WorkObserver:
        with observer.muted():
            yield
    else:
        yield


def _failure(error: Exception, refusals: tuple[type[Exception], ...]) -> str:
    for category, kinds in (
        ("REFUSED", refusals),
        ("TIMEOUT", (subprocess.TimeoutExpired,)),
        ("OS_ERROR", (OSError,)),
        ("DECODE", (UnicodeError,)),
        ("VALUE_ERROR", (ValueError,)),
        ("LOOKUP_ERROR", (LookupError,)),
        ("TYPE_ERROR", (TypeError,)),
    ):
        if isinstance(error, kinds):
            return category
    return "OTHER"


@contextmanager
def work(
    observer: WorkObserver | None, context: str, site: str | None, refusals: tuple[type[Exception], ...]
) -> Iterator[None]:
    """Observe only a named original work site, leaving default consumers unchanged."""
    if type(observer) is WorkObserver:
        with observer.work(context, site, refusals):
            yield
    else:
        yield


def refused(observer: WorkObserver | None, context: str, site: str | None) -> None:
    """Offer only an actual false predicate or the approved known-dead status refusal."""
    if type(observer) is WorkObserver:
        observer.refused(context, site)


def _work(observer: WorkObserver | None, site: str | None) -> AbstractContextManager[None]:
    return work(observer, "CHILD_PARENT", site, (ChildError,))


def _observe[T](
    observer: WorkObserver | None, site: str, operation: Callable[..., T], /, *args: object, **kwargs: object
) -> T:
    with _work(observer, site):
        return operation(*args, **kwargs)


def _pairs(observer: WorkObserver | None) -> Callable[..., dict[str, object]]:
    return _unique if observer is None else partial(_unique, observer=observer)


@dataclass(frozen=True)
class Interpreter:
    """Require explicit reviewed system-interpreter authority; never use sys.executable."""

    descriptor: int
    sha256: str


@dataclass(frozen=True)
class Source:
    """A sealed read-only descriptor for exactly one canonical module."""

    module: str
    descriptor: int
    size: int
    sha256: str


@dataclass(frozen=True)
class Build:
    """Bind dropped credentials and both original child/cleanup deadlines."""

    name: str
    uid: int
    gid: int
    deadline_ns: int
    cleanup_deadline_ns: int


@dataclass(frozen=True)
class Outcome:
    """Complete output plus independently verified process-group death."""

    policy: bytes
    dead: bool


def _need(
    value: object, *, dead: bool | None = None, observer: WorkObserver | None = None, work_site: str | None = None
) -> None:
    if not value:
        refused(observer, "CHILD_PARENT", work_site)
        raise ChildError(dead=dead)


def bytes_at(descriptor: int, limit: int, *, observer: WorkObserver | None = None) -> bytes:
    """Read finite descriptor bytes without changing its shared offset."""
    content = bytearray()
    while len(content) <= limit:
        raw = _observe(
            observer, "B_BYTES_AT_W01", os.pread, descriptor, min(65536, limit + 1 - len(content)), len(content)
        )
        if not raw:
            return bytes(content)
        _observe(observer, "B_BYTES_AT_EXTEND", content.extend, raw)
    raise ChildError(dead=False)


def seal(module: str, data: bytes, *, observer: WorkObserver | None = None) -> Source:
    """Create immutable read-only source FDs without exposing root directories."""
    with _work(observer, "B_SEAL_G01"):
        _need(
            os.geteuid() == 0
            and module in MODULES
            and 0 < len(data) <= MAX_SOURCE
            and SEALS is not None
            and hasattr(fcntl, "F_ADD_SEALS")
            and hasattr(fcntl, "F_GET_SEALS")
            and hasattr(os, "memfd_create")
            and hasattr(os, "MFD_ALLOW_SEALING")
        )
    descriptor = _observe(
        observer, "B_SEAL_W01", os.memfd_create, "containers-userns-source", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    read_only = None
    try:
        with os.fdopen(_observe(observer, "B_SEAL_DUP", os.dup, descriptor), "wb") as stream:
            _observe(observer, "B_SEAL_W02", stream.write, data)
            _observe(observer, "B_SEAL_W03", stream.flush)
        _observe(observer, "B_SEAL_W04", os.fchmod, descriptor, 0o400)
        _observe(observer, "B_SEAL_W05", fcntl.fcntl, descriptor, fcntl.F_ADD_SEALS, SEALS)
        read_only = _observe(observer, "B_SEAL_W06", os.open, f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
        with _work(observer, "B_SEAL_G02"):
            _need(fcntl.fcntl(read_only, fcntl.F_GET_SEALS) & SEALS == SEALS)
        return Source(module, read_only, len(data), hashlib.sha256(data).hexdigest())
    except BaseException:
        if read_only is not None:
            os.close(read_only)
        raise
    finally:
        os.close(descriptor)


def file_mark(info: os.stat_result) -> tuple[int, ...]:
    """Compare descriptor identity without access timestamps changed by reads."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _interpreter(value: Interpreter, *, observer: WorkObserver | None = None) -> tuple[tuple[int, ...], bytes]:
    info = _observe(observer, "B_INTERPRETER_W01", os.fstat, value.descriptor)
    with _work(observer, "B_INTERPRETER_G01"):
        _need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and info.st_mode & 0o111
            and not info.st_mode & 0o7022
            and fcntl.fcntl(value.descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        )
    try:
        capabilities = os.getxattr(value.descriptor, "security.capability")
    except OSError as error:
        with _work(observer, "B_INTERPRETER_G02"):
            _need(error.errno == errno.ENODATA)
    else:
        with _work(observer, "B_INTERPRETER_G03"):
            _need(not capabilities)
    raw = _observe(
        observer, "B_INTERPRETER_W02", bytes_at, value.descriptor, MAX_INTERPRETER, **observer_args(observer)
    )
    with _work(observer, "B_INTERPRETER_G04"):
        _need(
            raw.startswith(b"\x7fELF")
            and hashlib.sha256(raw).hexdigest() == value.sha256
            and file_mark(os.fstat(value.descriptor)) == file_mark(info)
        )
    return file_mark(info), raw


def _capture(
    process: subprocess.Popen[bytes], receipt: int, lease: Build, clock: Clock, *, observer: WorkObserver | None = None
) -> tuple[bytes, bytes]:
    output, proof = bytearray(), bytearray()
    with _observe(observer, "B_CAPTURE_W01", selectors.DefaultSelector) as selector:
        _observe(
            observer, "B_CAPTURE_W02", selector.register, process.stdout, selectors.EVENT_READ, (output, MAX_POLICY)
        )
        _observe(observer, "B_CAPTURE_W03", selector.register, receipt, selectors.EVENT_READ, (proof, MAX_POLICY))
        while selector.get_map():
            with _work(observer, "B_CAPTURE_G01"):
                _need(clock.now_ns() < lease.deadline_ns)
            for key, _ in _observe(observer, "B_CAPTURE_W04", selector.select, 0.01):
                content, limit = key.data
                raw = _observe(observer, "B_CAPTURE_W05", os.read, key.fd, min(1024, limit + 1 - len(content)))
                _observe(observer, "B_CAPTURE_EXTEND", content.extend, raw)
                with _work(observer, "B_CAPTURE_G02"):
                    _need(len(content) <= limit)
                if not raw:
                    _observe(observer, "B_CAPTURE_W06", selector.unregister, key.fileobj)
    while (
        _observe(observer, "B_CAPTURE_W07", os.waitid, os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        is None
    ):
        with _work(observer, "B_CAPTURE_G03"):
            _need(clock.now_ns() < lease.deadline_ns)
        # The child also owns an independent, nonrenewed wall alarm.
        with _observe(observer, "B_CAPTURE_W08", selectors.DefaultSelector) as selector:
            _observe(observer, "B_CAPTURE_W09", selector.select, 0.001)
    return bytes(output), bytes(proof)


def _stop(process: subprocess.Popen[bytes], lease: Build, clock: Clock) -> tuple[int | None, bool]:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    remaining = min(500_000_000, lease.cleanup_deadline_ns - clock.now_ns())
    try:
        status = process.wait(timeout=remaining / 1_000_000_000) if remaining > 0 else process.poll()
    except subprocess.TimeoutExpired:
        return None, False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return status, status is not None
    return status, False


def _preflight(
    interpreter: Interpreter,
    sources: tuple[Source, ...],
    lease: Build,
    clock: Clock,
    *,
    observer: WorkObserver | None = None,
) -> tuple[tuple[tuple[int, ...], bytes], int]:
    with _work(observer, "B_PREFLIGHT_G01"):
        _need(
            os.geteuid() == 0
            and SEALS is not None
            and hasattr(fcntl, "F_GET_SEALS")
            and type(lease.uid) is int
            and 0 < lease.uid < 2**31
            and type(lease.gid) is int
            and 0 < lease.gid < 2**31
            and tuple(item.module for item in sources) == MODULES
            and re.fullmatch(
                r"dockerlens-127-upstream-rootless-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}", lease.name
            )
        )
    seconds = min(5, (lease.deadline_ns - _observe(observer, "B_PREFLIGHT_W01", clock.now_ns)) // 1_000_000_000)
    with _work(observer, "B_PREFLIGHT_G02"):
        _need(seconds >= 1 and lease.deadline_ns < lease.cleanup_deadline_ns)
    before = _interpreter(interpreter, **observer_args(observer))
    for item in sources:
        with _work(observer, "B_PREFLIGHT_G03"):
            _need(
                fcntl.fcntl(item.descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                and fcntl.fcntl(item.descriptor, fcntl.F_GET_SEALS) & SEALS == SEALS
                and os.fstat(item.descriptor).st_uid == 0
                and hashlib.sha256(bytes_at(item.descriptor, item.size, **observer_args(observer))).hexdigest()
                == item.sha256
            )
    # Hashing must not consume time and then start a child on the earlier allowance.
    seconds = min(5, (lease.deadline_ns - _observe(observer, "B_PREFLIGHT_W02", clock.now_ns)) // 1_000_000_000)
    with _work(observer, "B_PREFLIGHT_G04"):
        _need(seconds >= 1)
    return before, seconds


@dataclass(frozen=True)
class _ExecuteArgs:
    interpreter: Interpreter
    sources: tuple[Source, ...]
    lease: Build
    clock: Clock
    seconds: int


def _execute(
    interpreter: Interpreter, sources: tuple[Source, ...], lease: Build, clock: Clock, seconds: int
) -> tuple[bytes, bytes, int | None, Lifetime]:
    return _execute_observed(_ExecuteArgs(interpreter, sources, lease, clock, seconds))


def _execute_observed(
    arguments: _ExecuteArgs, observer: WorkObserver | None = None
) -> tuple[bytes, bytes, int | None, Lifetime]:
    interpreter, sources, lease, clock, seconds = (
        arguments.interpreter,
        arguments.sources,
        arguments.lease,
        arguments.clock,
        arguments.seconds,
    )
    try:
        read, write = _observe(observer, "B_EXECUTE_W01", os.pipe2, os.O_CLOEXEC | os.O_NONBLOCK)
    except Exception as error:
        raise ChildError(lifetime=Lifetime.NEVER_STARTED) from error
    process, dead, status = None, False, None
    primary = None
    attempted = False
    try:
        seconds = min(seconds, (lease.deadline_ns - _observe(observer, "B_EXECUTE_W02", clock.now_ns)) // 1_000_000_000)
        with _work(observer, "B_EXECUTE_G01"):
            _need(seconds >= 1)
        arguments = [
            str(interpreter.descriptor),
            str(write),
            *(f"{item.descriptor}:{item.size}:{item.sha256}" for item in sources),
            lease.name,
            str(lease.uid),
            str(lease.gid),
            str(seconds),
        ]
        attempted = True
        process = _observe(
            observer,
            "B_EXECUTE_W03",
            subprocess.Popen,
            [f"/proc/self/fd/{interpreter.descriptor}", "-I", "-B", "-S", "-c", CODE, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,
            user=lease.uid,
            group=lease.gid,
            extra_groups=(),
            pass_fds=(interpreter.descriptor, write, *(item.descriptor for item in sources)),
        )
        os.close(write)
        write = -1
        output, proof = _capture(process, read, lease, clock, **observer_args(observer))
    except (ChildError, OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        primary = error
    finally:
        primary = _close_pipes((write, read), primary)
        if process is not None:
            try:
                status, dead = _stop(process, lease, clock)
            except (ChildError, OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                primary = primary or error
            finally:
                if process.stdout is not None:
                    try:
                        process.stdout.close()
                    except OSError as error:
                        primary = primary or error
    lifetime = Lifetime.DEAD if dead else Lifetime.UNKNOWN if attempted else Lifetime.NEVER_STARTED
    if primary is not None:
        raise ChildError(lifetime=lifetime) from primary
    return output, proof, status, lifetime


def _close_pipes(descriptors: tuple[int, int], primary: Exception | None) -> Exception | None:
    for descriptor in descriptors:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError as error:
                primary = primary or error
    return primary


def build(
    interpreter: Interpreter,
    sources: tuple[Source, ...],
    lease: Build,
    clock: Clock,
    *,
    observer: WorkObserver | None = None,
) -> Outcome:
    """Preserve failure while reporting never-started, proven-dead or unknown lifetime."""
    try:
        before, seconds = _preflight(interpreter, sources, lease, clock, **observer_args(observer))
    except Exception as error:
        raise ChildError(lifetime=Lifetime.NEVER_STARTED) from error
    output, proof, status, lifetime = (
        _execute(interpreter, sources, lease, clock, seconds)
        if observer is None
        else _execute_observed(_ExecuteArgs(interpreter, sources, lease, clock, seconds), observer)
    )
    try:
        try:
            _need(
                lifetime is Lifetime.DEAD and status == 0 and clock.now_ns() < lease.deadline_ns,
                dead=lifetime is Lifetime.DEAD,
            )
        except ChildError:
            if lifetime is Lifetime.DEAD and type(status) is int and status != 0:
                refused(observer, "CHILD_PARENT", "B_BUILD_STATUS_REFUSAL")
            raise
        _privilege_receipt(proof, lease, **observer_args(observer))
        with _work(observer, "B_BUILD_G02"):
            _need(_interpreter(interpreter, **observer_args(observer)) == before, dead=lifetime is Lifetime.DEAD)
        with _work(observer, "B_BUILD_G03"):
            _need(clock.now_ns() < lease.deadline_ns, dead=lifetime is Lifetime.DEAD)
        return Outcome(output, dead=True)

    except Exception as error:
        raise ChildError(lifetime=lifetime) from error


def _privilege_receipt(proof: bytes, lease: Build, *, observer: WorkObserver | None = None) -> None:
    """Require a duplicate-free closed receipt with integer IDs/schema/NNP, never bool or float."""
    actual = _observe(observer, "B_PRIVILEGE_RECEIPT_W01", json.loads, proof, object_pairs_hook=_pairs(observer))
    with _work(observer, "B_PRIVILEGE_RECEIPT_G01"):
        _need(type(actual) is dict and all(type(actual.get(key)) is int for key in ("schema", "uid", "gid", "nnp")))
    with _work(observer, "B_PRIVILEGE_RECEIPT_G02"):
        _need(
            actual == {"schema": 1, "uid": lease.uid, "gid": lease.gid, "groups": [], "nnp": 1, "capabilities": "zero"}
        )


def _unique(pairs: list[tuple[str, object]], *, observer: WorkObserver | None = None) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        with _work(observer, "B_UNIQUE_G01"):
            _need(key not in result)
        result[key] = value
    return result


# Reuse the same pre-import credential/NNP checks, but expose only two fixed probes.
PROBE_CODE = (
    CODE[: CODE.index("os.close(int(interpreter))")].replace(
        "interpreter, receipt, first, second, name, uid, gid, seconds = sys.argv[1:]",
        "interpreter, receipt, target, kind, uid, gid, seconds = sys.argv[1:]",
    )
    + r"""
os.close(int(interpreter))
proof = {"schema": 1, "uid": uid, "gid": gid, "groups": [], "nnp": 1, "capabilities": "zero"}
raw = json.dumps(proof, sort_keys=True).encode("ascii")
if os.write(int(receipt), raw) != len(raw):
    raise SystemExit(1)
os.close(int(receipt))
target = int(target)
if kind == "parser-version":
    if os.execve not in os.supports_fd:
        raise SystemExit(1)
    os.set_inheritable(target, False)
    os.execve(target, ["apparmor_parser", "--config-file=/dev/null", "--skip-cache", "--jobs=0", "--version"],
              {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
elif kind == "write-denial":
    try:
        descriptor = os.open("/proc/self/fd/" + str(target), os.O_WRONLY)
    except PermissionError:
        sys.stdout.buffer.write(b"write-denied\n")
    else:
        os.close(descriptor)
        raise SystemExit(1)
else:
    raise SystemExit(1)
"""
)


@dataclass(frozen=True)
class _ProbeArgs:
    interpreter: Interpreter
    target: int
    kind: str
    lease: Build
    clock: Clock

    def observe(self, observer: WorkObserver | None = None) -> Outcome:
        """Use the shared private probe body with an explicit local observer."""
        return _probe_observed(self, observer)


def probe_input(interpreter: Interpreter, target: int, kind: str, lease: Build, clock: Clock) -> _ProbeArgs:
    """Group the hosted adapter's existing probe inputs without changing its capabilities."""
    return _ProbeArgs(interpreter, target, kind, lease, clock)


def probe(interpreter: Interpreter, target: int, kind: str, lease: Build, clock: Clock) -> Outcome:
    """Keep legacy version-only and synthetic permission probes unobserved by default."""
    return _probe_observed(_ProbeArgs(interpreter, target, kind, lease, clock))


def _probe_observed(arguments: _ProbeArgs, observer: WorkObserver | None = None) -> Outcome:
    interpreter, target, kind, lease, clock = (
        arguments.interpreter,
        arguments.target,
        arguments.kind,
        arguments.lease,
        arguments.clock,
    )
    """Run a fixed version-only or synthetic permission probe after complete ID drop."""
    with _work(observer, "B_PROBE_G01"):
        _need(
            kind in {"parser-version", "write-denial"}
            and type(lease.uid) is int
            and type(lease.gid) is int
            and lease.uid > 0
            and lease.gid > 0
            and os.geteuid() == 0
            and clock.now_ns() < lease.deadline_ns < lease.cleanup_deadline_ns
        )
    before = _interpreter(interpreter, **observer_args(observer))
    target_mark = file_mark(_observe(observer, "B_PROBE_W01", os.fstat, target))
    with _work(observer, "B_PROBE_G02"):
        _need(os.fstat(target).st_uid == 0 and not os.fstat(target).st_mode & 0o7022)
    if kind == "parser-version":
        with _work(observer, "B_PROBE_G03"):
            _need(bytes_at(target, MAX_INTERPRETER, **observer_args(observer)).startswith(b"\x7fELF"))
    read, write = _observe(observer, "B_PROBE_W02", os.pipe2, os.O_CLOEXEC | os.O_NONBLOCK)
    process, attempted, dead = None, False, False
    try:
        seconds = min(5, (lease.deadline_ns - clock.now_ns()) // 1_000_000_000)
        with _work(observer, "B_PROBE_G04"):
            _need(os.geteuid() == 0 and seconds >= 1 and lease.deadline_ns < lease.cleanup_deadline_ns)
        attempted = True
        process = _observe(
            observer,
            "B_PROBE_W03",
            subprocess.Popen,
            [
                f"/proc/self/fd/{interpreter.descriptor}",
                "-I",
                "-B",
                "-S",
                "-c",
                PROBE_CODE,
                str(interpreter.descriptor),
                str(write),
                str(target),
                kind,
                str(lease.uid),
                str(lease.gid),
                str(seconds),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,
            user=lease.uid,
            group=lease.gid,
            extra_groups=(),
            pass_fds=(interpreter.descriptor, write, target),
        )
        os.close(write)
        write = -1
        output, proof = _capture(process, read, lease, clock, **observer_args(observer))
        status, dead = _stop(process, lease, clock)
        try:
            _need(status == 0 and dead and clock.now_ns() < lease.deadline_ns, dead=dead)
        except ChildError:
            if dead is True and type(status) is int and status != 0:
                refused(observer, "CHILD_PARENT", "B_PROBE_STATUS_REFUSAL")
            raise
        _privilege_receipt(proof, lease, **observer_args(observer))
        with _work(observer, "B_PROBE_G06"):
            _need(
                _interpreter(interpreter, **observer_args(observer)) == before
                and file_mark(os.fstat(target)) == target_mark,
                dead=dead,
            )
        with _work(observer, "B_PROBE_G07"):
            _need(clock.now_ns() < lease.deadline_ns, dead=dead)
        return Outcome(output, dead=True)
    except Exception as error:
        if process is not None and not dead:
            with suppress(Exception):
                _, dead = _stop(process, lease, clock)
        raise ChildError(
            lifetime=Lifetime.DEAD if dead else Lifetime.UNKNOWN if attempted else Lifetime.NEVER_STARTED
        ) from error
    finally:
        _close_pipes((write, read), None)
        if process is not None and process.stdout is not None:
            process.stdout.close()
