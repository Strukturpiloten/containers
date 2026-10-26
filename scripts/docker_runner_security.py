"""Capture bounded read-only CI host diagnostics, without native admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

PARSER = Path("/usr/sbin/apparmor_parser")
ENABLED = Path("/sys/module/apparmor/parameters/enabled")
RESTRICT = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
USERNS = Path("/proc/sys/user/max_user_namespaces")
STATUS = Path("/proc/self/status")
PROFILE = Path("/proc/self/attr/apparmor/current")
MAX_FILE = 8192
MAX_OUTPUT = 4096
MAX_JSON = 8192
MAX_BINARY = 16 * 1024 * 1024
MAX_VERSION = 80
REASONS = frozenset(
    {"unavailable", "malformed", "oversized", "unsafe-tool", "timeout", "failed", "changed", "cancelled"}
)
_cancelled = False


class _ObservationError(Exception):
    """Carry only closed diagnostic reasons, never raw tool or host text."""


def _refuse(reason: str) -> None:
    raise _ObservationError(reason)


def _unknown(reason: str) -> dict[str, Any]:
    return {"state": "unknown", "reason": reason if reason in REASONS else "unavailable"}


def _observed(value: object) -> dict[str, Any]:
    return {"state": "observed", "value": value}


def _check(deadline: float) -> None:
    if _cancelled:
        _refuse("cancelled")
    if time.monotonic() >= deadline:
        _refuse("timeout")


def _read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        value = os.read(descriptor, MAX_FILE + 1)
        if len(value) > MAX_FILE:
            _refuse("oversized")
        return value.strip()
    finally:
        os.close(descriptor)


def _number(path: Path, maximum: int) -> dict[str, Any]:
    try:
        raw = _read(path)
        if not re.fullmatch(rb"[0-9]{1,20}", raw) or int(raw) > maximum:
            return _unknown("malformed")
        return _observed(int(raw))
    except OSError:
        return _unknown("unavailable")
    except _ObservationError as error:
        return _unknown(str(error))


def _process() -> dict[str, Any]:
    result = {
        "subject": "collector-process-not-guest",
        "seccomp": _unknown("unavailable"),
        "noNewPrivs": _unknown("unavailable"),
        "profileKind": _unknown("unavailable"),
    }
    try:
        lines = _read(STATUS).splitlines()
        for label, key, maximum in ((b"Seccomp", "seccomp", 2), (b"NoNewPrivs", "noNewPrivs", 1)):
            values = [line.split(b":", 1)[1].strip() for line in lines if line.startswith(label + b":")]
            result[key] = (
                _observed(int(values[0]))
                if len(values) == 1 and re.fullmatch(rb"[0-9]", values[0]) and int(values[0]) <= maximum
                else _unknown("malformed")
            )
    except OSError, _ObservationError:
        pass
    try:
        value = _read(PROFILE)
        if value == b"unconfined":
            result["profileKind"] = _observed("unconfined")
        elif b"\0" not in value and value.endswith((b" (enforce)", b" (complain)")):
            result["profileKind"] = _observed("confined")
        else:
            result["profileKind"] = _unknown("malformed")
    except OSError, _ObservationError:
        pass
    return result


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _trusted_parser(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and bool(info.st_mode & 0o111)
        and not info.st_mode & 0o7022
        and 0 < info.st_size <= MAX_BINARY
    )


def _capture(process: subprocess.Popen[bytes], deadline: float) -> tuple[bytes, int]:
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            _check(deadline)
            for key, _ in selector.select(0.05):
                raw = os.read(key.fd, min(1024, MAX_OUTPUT + 1 - len(output)))
                if not raw:
                    selector.unregister(key.fileobj)
                output.extend(raw)
                if len(output) > MAX_OUTPUT:
                    _refuse("oversized")
        while True:
            _check(deadline)
            try:
                return bytes(output), process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue


def _stop(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.returncode is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=0.5)
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _version(deadline: float) -> str:
    process = None
    try:
        _check(deadline)
        process = subprocess.Popen(  # noqa: S603 - fixed verified system parser, version-only, clean environment.
            [str(PARSER), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"LC_ALL": "C"},
            start_new_session=True,
        )
        output, status = _capture(process, deadline)
        if status != 0:
            _refuse("failed")
        matches = re.findall(
            rb"(?m)^AppArmor parser version ([0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9.+~_-]{0,32})\r?$", output
        )
        if len(matches) != 1 or len(matches[0]) > MAX_VERSION:
            _refuse("malformed")
        return matches[0].decode("ascii")
    finally:
        if process is not None:
            _stop(process)


def _unchanged(descriptor: int, before: os.stat_result) -> None:
    if _identity(before) != _identity(os.fstat(descriptor)) or _identity(before) != _identity(
        PARSER.stat(follow_symlinks=False)
    ):
        _refuse("changed")


def _parser(deadline: float) -> dict[str, Any]:
    result = {**_unknown("unavailable"), "version": None, "executable": None}
    descriptor = None
    try:
        if os.geteuid() == 0:
            _refuse("unsafe-tool")
        descriptor = os.open(PARSER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if not _trusted_parser(before):
            _refuse("unsafe-tool")
        digest, size = hashlib.sha256(), 0
        while size <= before.st_size:
            _check(deadline)
            raw = os.read(descriptor, min(65536, before.st_size + 1 - size))
            if not raw:
                break
            if size == 0 and not raw.startswith(b"\x7fELF"):
                _refuse("unsafe-tool")
            size += len(raw)
            digest.update(raw)
        if size != before.st_size:
            _refuse("changed")
        _unchanged(descriptor, before)
        version = _version(min(deadline, time.monotonic() + 1.0))
        _unchanged(descriptor, before)
        return {
            "state": "observed",
            "reason": None,
            "version": version,
            "executable": {
                "sha256": digest.hexdigest(),
                "size": size,
                "device": before.st_dev,
                "inode": before.st_ino,
                "mode": before.st_mode,
                "links": before.st_nlink,
            },
        }
    except _ObservationError as error:
        result["reason"] = str(error) if str(error) in REASONS else "unavailable"
    except OSError, subprocess.SubprocessError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


def collect() -> dict[str, Any]:
    """Observe this validate-job host only; never qualify native behavior."""
    deadline = time.monotonic() + 4.0
    try:
        enabled = {b"Y": _observed(value=True), b"N": _observed(value=False)}.get(_read(ENABLED), _unknown("malformed"))
    except OSError, _ObservationError:
        enabled = _unknown("unavailable")
    kernel = os.uname()
    release = kernel.release if re.fullmatch(r"[A-Za-z0-9_.+-]{1,96}", kernel.release) else None
    return {
        "schemaVersion": 1,
        "scope": "ci-validate-host-only",
        "qualification": "none",
        "kernel": {
            "release": release,
            "machine": kernel.machine if kernel.machine in {"x86_64", "aarch64"} else "other",
        },
        "apparmor": {
            "enabled": enabled,
            "restrictUnprivilegedUserns": _number(RESTRICT, 1),
            "parser": _parser(deadline),
        },
        "userNamespaces": {"maximum": _number(USERNS, 2**63 - 1)},
        "collectorProcess": _process(),
    }


def main() -> int:
    """Write only the closed JSON artifact; errors never print host values."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

    def cancel(_number: int, _frame: object) -> None:
        global _cancelled  # noqa: PLW0603 - one CLI-scoped cancellation flag.
        _cancelled = True

    try:
        for number in previous:
            signal.signal(number, cancel)
        body = (json.dumps(collect(), sort_keys=True) + "\n").encode()
        if len(body) > MAX_JSON:
            return 1
        with args.output.open("xb") as output:
            output.write(body)
        return int(_cancelled)
    except OSError, ValueError:
        sys.stderr.write("runner security observation unavailable\n")
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
