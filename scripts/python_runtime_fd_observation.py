"""Observe an ordinary-user system-Python fixture; never grant runtime authority."""

from __future__ import annotations

import errno
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

PYTHON = "/usr/bin/python3"
GNU_TIMEOUT = "/usr/bin/gnutimeout"
MAX_OUTPUT = 16384
MAX_FILE = 32 * 1024 * 1024
MAX_FDS = 32
MAX_LINKS = 8
MAX_MAPS = 262144
MAX_LIBRARIES = 4
MAX_VERSION = 999
MAX_PROVIDER_VERSION = 80
MAX_FD_NUMBER = 99999
STDERR = 2
VERSION_PARTS = 3
MAP_FIELDS = 6
CLEANUP_RESERVE = 0.5
CLEANUP_ERRORS = (OSError, subprocess.TimeoutExpired)
_cancelled = False
IDENTITY = ("device", "inode", "mode", "uid", "gid", "size", "links", "mtimeNs", "ctimeNs")
ATTRIBUTES = ["st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns"]
PUBLIC = {
    "python": r"/usr/bin/python3(?:\.[0-9]{1,2})?",
    "ctypes": r"/usr/lib(?:64)?/python3\.[0-9]{1,2}/lib-dynload/_ctypes[\w.-]{0,96}\.so",
    "libffi": r"/(?:usr/)?lib(?:64)?/(?:[a-z0-9_-]{1,40}-linux-gnu/)?libffi\.so(?:\.[0-9]{1,3}){1,3}",
}


class UnavailableError(Exception):
    """Refuse without carrying private input or exception text."""


class CleanupUncertainError(UnavailableError):
    """The owned child or pipe cleanup could not be verified."""


def cancel(_number: int, _frame: object) -> None:
    """Remember cancellation without interrupting owned-child cleanup."""
    global _cancelled  # noqa: PLW0603 - process-local sticky cancellation flag.
    _cancelled = True


def require(condition: bool) -> None:  # noqa: FBT001 - this helper consumes a predicate, not an option.
    """Refuse a predicate without preserving its inputs."""
    if not condition:
        raise UnavailableError


def check(deadline: float) -> None:
    """Use only the original monotonic budget, including sticky cancellation."""
    require(not _cancelled and time.monotonic() < deadline)


def identity(value: os.stat_result) -> dict[str, int]:
    """Retain fstat metadata only, without descriptor targets or contents."""
    return dict(zip(IDENTITY, (getattr(value, attr) for attr in ATTRIBUTES), strict=True))


def public_path(path: str, kind: str) -> bool:
    """Accept only the exact public system-file namespace for this role."""
    return type(path) is str and re.fullmatch(PUBLIC[kind], path, flags=re.ASCII) is not None


def public_identity(value: dict[str, int]) -> bool:
    """Apply identical known-public-file custody rules in collection and decoding."""
    return (
        value["uid"] == 0
        and stat.S_ISREG(value["mode"])
        and not value["mode"] & 0o6022
        and 0 < value["size"] <= MAX_FILE
    )


def public_open(path: str, kind: str) -> tuple[int, str]:
    """Resolve at most eight symlinks through held, nonwritable root directories."""
    require(public_path(path, kind))
    remaining, resolved, links = path.split("/")[1:], [], 0
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root = os.fstat(directory)
        require(root.st_uid == 0 and not root.st_mode & 0o022)
        while remaining:
            part = remaining.pop(0)
            value = os.stat(part, dir_fd=directory, follow_symlinks=False)
            require(value.st_uid == 0)
            if stat.S_ISLNK(value.st_mode):
                links += 1
                target = os.readlink(part, dir_fd=directory)
                candidate = "/" + "/".join([*resolved, target, *remaining])
                if target.startswith("/"):
                    candidate = target + ("/" + "/".join(remaining) if remaining else "")
                require(links <= MAX_LINKS and public_path(candidate, kind))
                os.close(directory)
                directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                remaining, resolved = candidate.split("/")[1:], []
                continue
            require(not value.st_mode & 0o022)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            descriptor = os.open(part, flags | (os.O_DIRECTORY if remaining else 0), dir_fd=directory)
            try:
                require(identity(value) == identity(os.fstat(descriptor)))
            except BaseException:
                os.close(descriptor)
                raise
            if not remaining:
                return descriptor, "/" + "/".join([*resolved, part])
            os.close(directory)
            directory = descriptor
            resolved.append(part)
    finally:
        os.close(directory)
    raise UnavailableError


def public_file(path: str, kind: str, deadline: float = float("inf")) -> dict[str, Any]:
    """Hash only a stable, bounded, root-owned regular public file."""
    check(deadline)
    descriptor, resolved = public_open(path, kind)
    try:
        before = os.fstat(descriptor)
        require(public_identity(identity(before)))
        digest, count = hashlib.sha256(), 0
        while count <= before.st_size:
            check(deadline)
            raw = os.read(descriptor, min(65536, before.st_size + 1 - count))
            if not raw:
                break
            digest.update(raw)
            count += len(raw)
        verify_fd, again = public_open(path, kind)
        try:
            require(
                count == before.st_size
                and resolved == again
                and (identity(before) == identity(os.fstat(descriptor)) == identity(os.fstat(verify_fd)))
            )
        finally:
            os.close(verify_fd)
        require(not _cancelled and time.monotonic() < deadline)
        return {"path": resolved, "identity": identity(before), "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def snapshot() -> dict[str, Any]:
    """Inspect metadata for at most 32 nonstdio descriptors; read no targets."""
    names = []
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > MAX_FDS + 4 or not re.fullmatch(r"[0-9]{1,5}", entry.name):
                raise UnavailableError
    result, closed = [], 0
    for number in sorted(int(name) for name in names if int(name) > STDERR):
        try:
            result.append({"fd": number, "identity": identity(os.fstat(number))})
        except OSError as error:
            if error.errno != errno.EBADF:
                raise UnavailableError from None
            closed += 1
    if len(result) > MAX_FDS:
        raise UnavailableError
    require(len(result) + closed <= MAX_FDS + 1)
    return {"state": "non-atomic", "closedDuringSnapshot": closed, "descriptors": result}


def classify(descriptors: list[dict[str, Any]], files: dict[str, Any]) -> list[dict[str, Any]]:
    """Match object device/inode identity only; this does not identify an OFD or cause."""
    for record in descriptors:
        record["matches"] = [
            name
            for name, values in files.items()
            if any(
                all(record["identity"][key] == value["identity"][key] for key in ("device", "inode"))
                for value in values
            )
        ]
    return descriptors


def child(deadline: float) -> dict[str, Any]:
    """Observe this fixture around one import, separately from the root launcher."""
    check(deadline)
    before = snapshot()
    import _ctypes  # noqa: PLC0415 - the observation intentionally brackets this import.

    after = snapshot()
    files: dict[str, Any] = {"python": [], "ctypes": [], "libffi": []}
    for kind, path in (("python", PYTHON), ("ctypes", _ctypes.__file__)):
        with suppress(OSError, UnavailableError):
            files[kind].append(public_file(path, kind, deadline))
    # Raw mappings/addresses stay local; only strict known public libffi paths survive.
    with suppress(OSError, ValueError, UnavailableError):
        with Path("/proc/self/maps").open("rb") as stream:
            raw = stream.read(MAX_MAPS + 1)
        if len(raw) > MAX_MAPS:
            raise UnavailableError
        mappings = [line.split(maxsplit=5) for line in raw.splitlines() if b"libffi.so" in line]
        paths = {line[-1].decode("ascii") for line in mappings}
        if not 0 < len(paths) <= MAX_LIBRARIES or any(not public_path(path, "libffi") for path in paths):
            raise UnavailableError
        libraries = [public_file(path, "libffi", deadline) for path in sorted(paths)]
        for library in libraries:
            mapped = [line for line in mappings if line[-1].decode("ascii") == library["path"]]
            if not mapped or any(
                len(line) != MAP_FIELDS
                or (int(line[4]), *(int(part, 16) for part in line[3].split(b":")))
                != (
                    library["identity"]["inode"],
                    os.major(library["identity"]["device"]),
                    os.minor(library["identity"]["device"]),
                )
                for line in mapped
            ):
                raise UnavailableError
        files["libffi"] = libraries
    check(deadline)
    for phase in (before, after):
        classify(phase["descriptors"], files)
    return {
        "runtime": {
            "implementation": sys.implementation.name,
            "version": list(sys.version_info[:3]),
            "build": sys.version,
            "platform": sys.platform,
            "machine": os.uname().machine,
        },
        "files": files,
        "before": before,
        "after": after,
    }


def decode(raw: bytes) -> dict[str, Any]:  # noqa: C901 - explicit closed wire schema, no generic validator.
    """Accept exactly the closed child schema, never arbitrary child strings."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise UnavailableError
        return result

    def integer(value: object) -> bool:
        return type(value) is int and 0 <= value < 2**64

    def metadata(value: object) -> bool:
        return type(value) is dict and set(value) == set(IDENTITY) and all(integer(v) for v in value.values())

    require(len(raw) <= MAX_OUTPUT)
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {"runtime", "files", "before", "after"}:
        raise UnavailableError
    runtime, files = value["runtime"], value["files"]
    if type(runtime) is not dict or set(runtime) != {"implementation", "version", "build", "platform", "machine"}:
        raise UnavailableError
    if any(
        type(runtime[k]) is not str or not re.fullmatch(r"[\w .,+()\[\]:/\n-]{1,200}", runtime[k], re.ASCII)
        for k in ("implementation", "build", "platform", "machine")
    ):
        raise UnavailableError
    if (
        type(runtime["version"]) is not list
        or len(runtime["version"]) != VERSION_PARTS
        or not all(type(n) is int and 0 <= n <= MAX_VERSION for n in runtime["version"])
    ):
        raise UnavailableError
    if type(files) is not dict or set(files) != set(PUBLIC):
        raise UnavailableError
    for kind, records in files.items():
        if type(records) is not list or len(records) > (MAX_LIBRARIES if kind == "libffi" else 1):
            raise UnavailableError
        for record in records:
            if (
                type(record) is not dict
                or set(record) != {"path", "identity", "sha256"}
                or not (
                    public_path(record["path"], kind)
                    and metadata(record["identity"])
                    and public_identity(record["identity"])
                    and type(record["sha256"]) is str
                    and re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                )
            ):
                raise UnavailableError
    for phase in ("before", "after"):
        sample = value[phase]
        require(type(sample) is dict and set(sample) == {"state", "closedDuringSnapshot", "descriptors"})
        require(sample["state"] == "non-atomic" and integer(sample["closedDuringSnapshot"]))
        records = sample["descriptors"]
        require(type(records) is list and len(records) <= MAX_FDS)
        require(len(records) + sample["closedDuringSnapshot"] <= MAX_FDS + 1)
        for record in records:
            if (
                type(record) is not dict
                or set(record) != {"fd", "identity", "matches"}
                or not (
                    type(record["fd"]) is int
                    and STDERR < record["fd"] <= MAX_FD_NUMBER
                    and metadata(record["identity"])
                    and type(record["matches"]) is list
                    and len(record["matches"]) <= len(PUBLIC)
                    and all(type(match) is str and match in PUBLIC for match in record["matches"])
                )
            ):
                raise UnavailableError
        expected = [record["matches"] for record in records]
        require(len({record["fd"] for record in records}) == len(records))
        require(expected == [record["matches"] for record in classify(records, files)])
    return value


def stop(process: subprocess.Popen[bytes], deadline: float) -> None:
    """Attempt exact direct-child cleanup within the original reserved interval."""
    cleanup = True
    try:
        if process.poll() is None:
            with suppress(ProcessLookupError):
                process.kill()
        process.wait(timeout=max(0, deadline - time.monotonic()))
    except CLEANUP_ERRORS:
        cleanup = False
    finally:
        for pipe in (process.stdout, process.stderr):
            try:
                pipe.close()
            except OSError:
                cleanup = False
    if not cleanup:
        raise CleanupUncertainError


def capture(command: list[str], deadline: float) -> bytes:
    """Bound both output streams while alive; always kill/reap and close the child."""
    process = subprocess.Popen(  # noqa: S603 - fixed isolated system Python; no user-selected commands.
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C"},
        close_fds=True,
    )
    output, total = bytearray(), 0
    try:
        work_end = deadline - CLEANUP_RESERVE
        check(work_end)  # Popen itself is not an interruptible operation.
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                check(work_end)
                for key, _ in selector.select(min(0.05, max(0, work_end - time.monotonic()))):
                    raw = os.read(key.fileobj.fileno(), 4096)
                    total += len(raw)
                    if total > MAX_OUTPUT:
                        raise UnavailableError
                    if key.fileobj is process.stdout:
                        output.extend(raw)
                    if not raw:
                        selector.unregister(key.fileobj)
            if process.wait(timeout=max(0, work_end - time.monotonic())) != 0:
                raise UnavailableError
        return bytes(output)
    finally:
        stop(process, deadline)


def context() -> dict[str, str | None]:
    """Keep only validated public run/source identifiers; these are not attestations."""
    patterns = {
        "GITHUB_RUN_ID": r"[0-9]{1,20}",
        "GITHUB_RUN_ATTEMPT": r"[0-9]{1,4}",
        "GITHUB_SHA": r"[0-9a-f]{40}",
        "GITHUB_WORKFLOW_SHA": r"[0-9a-f]{40}",
        "GITHUB_REPOSITORY": r"Strukturpiloten/containers",
        "GITHUB_REF": r"refs/pull/492/merge",
    }
    return {
        key: value if re.fullmatch(pattern, value := os.environ.get(key, "")) else None
        for key, pattern in patterns.items()
    }


def gnu_provider(raw: bytes) -> dict[str, str]:
    """Qualify only the fixed prefixed OS provider; discard its complete raw output."""
    banner = raw.splitlines()[0] if raw else b""
    found = re.fullmatch(rb"(?:gnu)?timeout \(GNU coreutils\) ([0-9]+(?:\.[0-9]+)+)", banner)
    require(found is not None and len(found[1]) <= MAX_PROVIDER_VERSION)
    return {
        "state": "observed",
        "provider": "gnu-coreutils",
        "version": found[1].decode("ascii"),
        "pathKind": "prefixed",
    }


def main() -> int:
    """Emit one capped, nonqualifying observation with no raw failure information."""
    deadline_ns = time.monotonic_ns() + 8000000000
    deadline = deadline_ns / 1000000000
    base: dict[str, Any] = {
        "schema": 1,
        "qualification": "none",
        "policy_load_run": False,
        "container_run": False,
        "scope": "ordinary-user-isolated-import-fixture",
        "context": context(),
        "state": "unavailable",
        "provenance": "unavailable",
        "packageProvenance": "unavailable",
        "timeoutProvider": {"state": "unavailable"},
    }
    result = base.copy()
    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        require(os.getuid() != 0 and os.geteuid() != 0)
        if len(sys.argv) == VERSION_PARTS and sys.argv[1] == "--child":
            require(re.fullmatch(r"[0-9]{1,20}", sys.argv[2]) is not None)
            require(int(sys.argv[2]) <= deadline_ns)
            result = child(int(sys.argv[2]) / 1000000000)
        else:
            require(not sys.argv[1:])
            work_end = deadline - CLEANUP_RESERVE
            base["timeoutProvider"] = gnu_provider(capture([GNU_TIMEOUT, "--version"], deadline))
            result["timeoutProvider"] = base["timeoutProvider"]
            before = public_file(PYTHON, "python", work_end)
            command = [
                PYTHON,
                "-I",
                "-B",
                "-S",
                str(Path(__file__).resolve()),
                "--child",
                str(int(work_end * 1000000000)),
            ]
            observed = decode(capture(command, deadline))
            require(before == public_file(PYTHON, "python", work_end) and observed["files"]["python"] == [before])
            result.update(
                state="observed",
                observation=observed,
                provenance="observed" if all(observed["files"].values()) else "unavailable",
            )
        raw = json.dumps(result, sort_keys=True, ensure_ascii=True).encode("ascii") + b"\n"
        require(len(raw) <= MAX_OUTPUT)
    except CleanupUncertainError:
        base["cleanup"] = "uncertain"
        raw = json.dumps(base).encode("ascii") + b"\n"
    except Exception:  # noqa: BLE001 - failures never retain arbitrary child/error/host data.
        raw = json.dumps(base).encode("ascii") + b"\n"
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    if _cancelled:
        raw = json.dumps(base).encode("ascii") + b"\n"
    try:
        sys.stdout.buffer.write(raw)
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
