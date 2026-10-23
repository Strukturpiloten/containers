"""Non-acceptance, private-read diagnostics for an early rootless Docker failure.

Raw inspect/journal data never enters RuntimeContext.command or its public log
recorder. Only closed fields and task-window record counts leave this module.
"""

# Closed read-only argv and access to the invocation's held ownership are intentional.
# ruff: noqa: EM101, PLR2004, S603

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.runtime_docker_backend import DockerBackend
    from scripts.runtime_tests import RuntimeContext

DIAGNOSTIC_SECONDS = 5
BYTE_LIMIT = 64 * 1024
JOURNAL_RECORD_LIMIT = 64
PROTOCOL_LIMIT = 96 * 1024
SECURITY_OPTIONS = {
    "apparmor=unconfined": "apparmor-unconfined",
    "seccomp=unconfined": "seccomp-unconfined",
    "label=disable": "selinux-label-disabled",
    "no-new-privileges": "no-new-privileges",
    "no-new-privileges=true": "no-new-privileges",
}
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"owner":{{json (index .Config.Labels "io.strukturpiloten.runtime")}},'
    '"cgroup":{{json .HostConfig.CgroupParent}},"privileged":{{json .HostConfig.Privileged}},'
    '"apparmor":{{json .AppArmorProfile}},"securityOptions":{{json .HostConfig.SecurityOpt}},'
    '"state":{{json .State.Status}},"exitCode":{{json .State.ExitCode}},'
    '"oomKilled":{{json .State.OOMKilled}},"pid":{{json .State.Pid}}}'
)


class _UnavailableError(Exception):
    """Carry only a closed diagnostic-availability reason, never raw output."""


def _valid_timeout_provider(admitted: object) -> bool:
    return (
        isinstance(admitted, tuple)
        and len(admitted) == 3
        and all(isinstance(value, str) for value in admitted)
        and Path(admitted[0]).is_absolute()
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", admitted[1]) is not None
        and admitted[2] in {"prefixed", "unprefixed"}
    )


def qualify_gnu_timeout(ctx: RuntimeContext) -> tuple[str, str, str]:
    """Admit one private GNU path through the invocation's existing command owner."""
    admitted = vars(ctx).get("_gnu_timeout_provider")
    if admitted is not None:
        if not _valid_timeout_provider(admitted):
            reason = "GNU timeout provider admission is invalid"
            raise ValueError(reason)
        return admitted
    candidate = shutil.which("gnutimeout")
    kind = "prefixed"
    if candidate is None:
        candidate, kind = shutil.which("timeout"), "unprefixed"
    if candidate is None:
        reason = "GNU timeout prerequisite is unavailable"
        raise ValueError(reason)
    try:
        executable = str(Path(candidate).resolve(strict=True))
    except OSError, RuntimeError:
        reason = "GNU timeout prerequisite path is unavailable"
        raise ValueError(reason) from None
    first_record = len(ctx.checks)
    try:
        output = ctx.command("qualify GNU timeout provider", [executable, "--version"])
    except Exception:  # noqa: BLE001 - prerequisite errors never publish an arbitrary provider's output/path.
        reason = "GNU timeout prerequisite command failed"
        raise ValueError(reason) from None
    finally:
        # Even a failing provider's recorded error may contain private path/output.
        del ctx.checks[first_record:]
        ctx.checks.append({"name": "GNU timeout provider admission", "status": "failed"})
    banner = output.splitlines()[0] if isinstance(output, str) and output else ""
    observed = re.fullmatch(r"(?:gnu)?timeout \(GNU coreutils\) ([0-9]+(?:\.[0-9]+)+)", banner)
    if observed is None:
        reason = "GNU timeout provider identity is unverified"
        raise ValueError(reason)
    provider = (executable, observed[1], kind)
    ctx._gnu_timeout_provider = provider  # noqa: SLF001 - invocation-private custody, never public evidence.
    ctx.checks[-1].update(
        {
            "name": "GNU timeout provider admission",
            "status": "passed",
            "provider": "gnu-coreutils",
            "version": observed[1],
            "pathKind": kind,
        }
    )
    return provider


def redact_timeout_provider(ctx: RuntimeContext, value: str) -> str:
    """Redact only the admitted watchdog path from a public text copy."""
    provider = vars(ctx).get("_gnu_timeout_provider")
    if provider is None:
        provider = getattr(vars(ctx).get("backend"), "_gnu_timeout_provider", None)
    if not _valid_timeout_provider(provider):
        return value
    executable = provider[0]
    spellings = {executable, shlex.quote(executable)}
    for spelling in (
        repr(executable),
        ascii(executable),
        json.dumps(executable),
        json.dumps(executable, ensure_ascii=False),
    ):
        spellings.update((spelling, spelling[1:-1]))
    for spelling in sorted(spellings, key=len, reverse=True):
        value = value.replace(spelling, "[gnu-timeout]")
    return value


def _read_stdout(
    process: subprocess.Popen[bytes], deadline: float, limit: int = BYTE_LIMIT, interrupted: list[bool] | None = None
) -> bytes:
    output = bytearray()
    if process.stdout is None:
        raise _UnavailableError("query-unavailable")
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _UnavailableError("timeout")
            try:
                if not selector.select(remaining):
                    raise _UnavailableError("timeout")
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
            except KeyboardInterrupt:
                if interrupted is None:
                    raise
                interrupted[0] = True
                continue
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > limit:
                raise _UnavailableError("byte-limit")


def _wait_wrapper(process: subprocess.Popen[bytes], deadline: float, interrupted: list[bool]) -> int:
    while True:
        try:
            return process.wait(timeout=max(0, deadline - time.monotonic()))
        except KeyboardInterrupt:
            interrupted[0] = True
        except subprocess.TimeoutExpired as error:
            raise _UnavailableError("cleanup-unverified") from error


def _drain_query(process: subprocess.Popen[bytes], deadline: float) -> None:
    # start_new_session binds PGID to the held, unreaped direct child's PID.
    # Signal BEFORE wait/poll: keeping that child unreaped prevents PID reuse.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    interrupted = [False]
    _wait_wrapper(process, deadline, interrupted)
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            raise _UnavailableError("cleanup-unverified")
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def _observe_exit(process: subprocess.Popen[bytes], deadline: float) -> None:
    # EOF can precede the inner guard reaping its successful query. Observe
    # natural guard exit WITHOUT releasing its PID/PGID ownership binding.
    while time.monotonic() < deadline:
        observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None:
            if observed.si_pid != process.pid:
                raise _UnavailableError("cleanup-unverified")
            return
        time.sleep(min(0.005, max(0, deadline - time.monotonic())))
    raise _UnavailableError("timeout")


def _read_query(process: subprocess.Popen[bytes], deadline: float) -> bytes:
    if os.getpgid(process.pid) != process.pid:
        raise _UnavailableError("cleanup-unverified")
    output = _read_stdout(process, deadline, BYTE_LIMIT)
    _observe_exit(process, deadline)
    return output


def _spawn_query(
    arguments: list[str], work_deadline: float, remaining: float, timeout_executable: str | None
) -> subprocess.Popen[bytes]:
    if remaining <= 0.05:
        raise _UnavailableError("budget-exhausted")
    if timeout_executable is None or not Path(timeout_executable).is_absolute():
        raise _UnavailableError("query-unavailable")
    work = work_deadline - time.monotonic() - min(0.05, remaining / 16)
    if work <= 0:
        raise _UnavailableError("budget-exhausted")
    # This guard is INSIDE the query's new session and survives owner death.
    # Killing/reaping the outer sudo/timeout owner cannot disarm this guard.
    return subprocess.Popen(
        [timeout_executable, "--signal=KILL", f"{work}s", *arguments],
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def _query_capture(arguments: list[str], deadline: float, timeout_executable: str | None = None) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    # Prepay cleanup and protocol transmission inside the one original budget.
    work_deadline = deadline - min(2.0, remaining * 0.6)
    try:
        process = _spawn_query(arguments, work_deadline, remaining, timeout_executable)
    except _UnavailableError as error:
        return {"status": str(error), "teardownVerified": True}
    raw = b""
    status = "query-unavailable"
    try:
        raw = _read_query(process, work_deadline)
        status = "available"
    except _UnavailableError as error:
        status = str(error)
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception:  # noqa: BLE001 - no raw query/parser failures leave the root-side owner.
        status = "query-unavailable"
    finally:
        try:
            _drain_query(process, deadline - min(0.25, remaining / 8))
        except Exception, KeyboardInterrupt:  # noqa: BLE001 - only an affirmative drain permits a teardown ACK.
            status = "cleanup-unverified"
        if process.stdout is not None:
            process.stdout.close()
    if status == "cleanup-unverified":
        return {"status": status, "teardownVerified": False}
    if process.returncode != 0 and status == "available":
        status = "query-unavailable"
    result: dict[str, Any] = {"status": status, "teardownVerified": True}
    if status == "available":
        result["data"] = base64.b64encode(raw).decode("ascii")
    return result


def _worker_arguments(directory: Path, request: list[str]) -> list[str]:
    if request[0] == "inspect" and len(request) == 2 and re.fullmatch(r"[0-9a-f]{64}", request[1]):
        docker = shutil.which("docker")
        if docker is None:
            raise _UnavailableError("query-unavailable")
        environment = ["env"]
        for variable in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_API_VERSION",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            environment.extend(("-u", variable))
        return [
            *environment,
            docker,
            "--config",
            str(directory / "cli"),
            "--host",
            "unix://" + str(directory / "docker.sock"),
            "--tls=false",
            "inspect",
            "--format",
            INSPECT_FORMAT,
            request[1],
        ]
    if (
        request[0] == "journal"
        and len(request) == 3
        and all(re.fullmatch(r"[0-9]+\.[0-9]{6}", value) for value in request[1:])
    ):
        journalctl = shutil.which("journalctl")
        if journalctl is None:
            raise _UnavailableError("query-unavailable")
        return [
            journalctl,
            "--quiet",
            "--no-pager",
            "--boot=0",
            "--dmesg",
            "--since=@" + request[1],
            "--until=@" + request[2],
            "--output=json",
            "--output-fields=MESSAGE",
            "--lines=65",
            "--grep=rootlesskit",
        ]
    raise _UnavailableError("invalid-fields")


def _verified_protocol(output: bytes, returncode: int) -> dict[str, Any]:
    protocol = json.loads(output)
    if returncode != 0 or not isinstance(protocol, dict) or protocol.get("teardownVerified") is not True:
        raise _UnavailableError("cleanup-unverified")
    allowed = {
        "available",
        "budget-exhausted",
        "query-unavailable",
        "byte-limit",
        "timeout",
        "interrupted",
        "invalid-fields",
    }
    if protocol.get("status") not in allowed:
        raise _UnavailableError("cleanup-unverified")
    return protocol


def _capture(backend: DockerBackend, request: list[str], deadline: float) -> bytes:
    """Accept data only after the fixed root-side owner acknowledges query drain."""
    if backend.diagnostic_reader_pending:
        raise _UnavailableError("cleanup-unverified")
    remaining = backend.command_timeout(deadline - time.monotonic())
    command = backend.privileged(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--capture",
            "--directory",
            str(backend.directory),
            "--deadline-ns",
            str(int(deadline * 1_000_000_000)),
            "--timeout-executable",
            backend.timeout_executable(),
            *request,
        ],
        remaining,
    )
    backend.diagnostic_reader_pending = True
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        # Popen reaps an exec-failed child before raising; no query owner ran.
        backend.diagnostic_reader_pending = False
        raise
    interrupted = [False]
    try:
        try:
            try:
                output = _read_stdout(process, deadline, PROTOCOL_LIMIT, interrupted)
            except (Exception, KeyboardInterrupt) as error:
                raise _UnavailableError("cleanup-unverified") from error
        finally:
            # Never kill sudo/the watchdog: the root owner must reap its query.
            returncode = _wait_wrapper(process, deadline, interrupted)
        protocol = _verified_protocol(output, returncode)
        backend.diagnostic_reader_pending = False
        if interrupted[0]:
            raise KeyboardInterrupt
        if protocol.get("status") != "available":
            raise _UnavailableError(protocol["status"])
        raw = base64.b64decode(protocol["data"], validate=True)
        if len(raw) > BYTE_LIMIT or time.monotonic() >= deadline:
            raise _UnavailableError("timeout")
        backend.check_deadline()
        return raw  # noqa: TRY300 - the finally block must close the private protocol pipe.
    except (ValueError, KeyError, TypeError) as error:
        raise _UnavailableError("cleanup-unverified") from error
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _inspect_projection(raw: bytes, backend: DockerBackend, container: str) -> dict[str, Any]:
    observed = json.loads(raw)
    if not isinstance(observed, dict) or any(
        observed.get(key) != expected
        for key, expected in {"id": container, "owner": backend.owner, "cgroup": backend.slice}.items()
    ):
        raise _UnavailableError("ownership-unverified")
    if any(type(observed.get(key)) is not bool for key in ("privileged", "oomKilled")):
        raise _UnavailableError("invalid-fields")
    if observed.get("state") not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}:
        raise _UnavailableError("invalid-fields")
    if type(observed.get("exitCode")) is not int or not 0 <= observed["exitCode"] <= 255:
        raise _UnavailableError("invalid-fields")
    if type(observed.get("pid")) is not int or not 0 <= observed["pid"] <= 2**31 - 1:
        raise _UnavailableError("invalid-fields")
    apparmor = observed.get("apparmor")
    options = observed.get("securityOptions")
    if options is None:
        options = []
    if (
        "securityOptions" not in observed
        or not isinstance(apparmor, str)
        or not isinstance(options, list)
        or len(options) > 32
        or any(not isinstance(option, str) for option in options)
    ):
        raise _UnavailableError("invalid-fields")
    return {
        "privileged": observed["privileged"],
        "apparmorProfile": {"": "empty", "unconfined": "unconfined", "docker-default": "docker-default"}.get(
            apparmor, "other"
        ),
        "securityOptions": sorted({SECURITY_OPTIONS[option] for option in options if option in SECURITY_OPTIONS}),
        "unknownSecurityOptionCount": sum(option not in SECURITY_OPTIONS for option in options),
        "state": observed["state"],
        "exitCode": observed["exitCode"],
        "oomKilled": observed["oomKilled"],
        "hostPidAvailable": observed["pid"] > 0,
    }


def _journal_projection(raw: bytes) -> dict[str, Any]:
    lines = raw.splitlines()
    if len(lines) > JOURNAL_RECORD_LIMIT:
        raise _UnavailableError("record-limit")
    count = 0
    for line in lines:
        entry = json.loads(line)
        if not isinstance(entry, dict) or not isinstance(entry.get("MESSAGE"), str):
            raise _UnavailableError("invalid-fields")
        fields = shlex.split(entry["MESSAGE"])
        if {"apparmor=DENIED", "operation=userns_create", "comm=rootlesskit"} <= set(fields):
            count += 1
    return {
        "availability": "available",
        "attribution": "host-task-window-only",
        "rootlesskitUsernsDenialRecords": count,
    }


def _journal(backend: DockerBackend, deadline: float, started: float, finished: float) -> dict[str, Any]:
    try:
        if not all(math.isfinite(value) for value in (started, finished)) or not 0 <= finished - started <= 1800:
            return {"availability": "invalid-window", "attribution": "host-task-window-only"}
        journalctl = shutil.which("journalctl")
        if journalctl is None:
            return {"availability": "query-unavailable", "attribution": "host-task-window-only"}
        raw = _capture(backend, ["journal", f"{started:.6f}", f"{finished:.6f}"], deadline)
        return _journal_projection(raw)
    except _UnavailableError as error:
        reason = str(error)
    except KeyboardInterrupt:
        reason = "interrupted"
    except Exception:  # noqa: BLE001 - raw command/parser errors must never escape into public evidence.
        reason = "query-unavailable"
    return {"availability": reason, "attribution": "host-task-window-only"}


def _collect(ctx: RuntimeContext, backend: DockerBackend, container: str, started: float) -> dict[str, Any]:
    finished = time.time()
    if (
        not backend.ready
        or backend.cleaning_up
        or backend.deadline is None
        or re.fullmatch(r"[0-9a-f]{64}", container) is None
        or container not in ctx.containers
    ):
        raise _UnavailableError("ownership-unverified")
    deadline = min(time.monotonic() + DIAGNOSTIC_SECONDS, backend.deadline - 60)
    if deadline - time.monotonic() <= 0.01:
        raise _UnavailableError("budget-exhausted")
    raw = _capture(backend, ["inspect", container], deadline)
    projection = _inspect_projection(raw, backend, container)
    if time.monotonic() >= deadline:
        raise _UnavailableError("timeout")
    journal = _journal(backend, deadline, started, finished)
    if time.monotonic() >= deadline:
        raise _UnavailableError("timeout")
    backend.check_deadline()
    return {"availability": "collected", "container": projection, "kernelJournal": journal}


def diagnose_rootless_failure(ctx: RuntimeContext, container: str, started: float) -> None:
    """Append only non-acceptance diagnostics, without replacing the launch error."""
    from scripts.runtime_docker_backend import DockerBackend  # noqa: PLC0415 - root capture CLI is stdlib-only under -I.

    backend = getattr(ctx, "backend", None)
    if not isinstance(backend, DockerBackend):
        return
    record: dict[str, Any] = {
        "name": "early rootless Docker launch failure diagnostics",
        "status": "failed",
        "diagnosticOnly": True,
        "acceptanceEvidence": False,
    }
    try:
        record.update(_collect(ctx, backend, container, started))
    except _UnavailableError as error:
        record["availability"] = str(error)
    except KeyboardInterrupt:
        record["availability"] = "interrupted"
    except Exception:  # noqa: BLE001 - retain the original launch error, with no raw exception serialization.
        record["availability"] = "query-unavailable"
    ctx.checks.append(record)


def main() -> None:
    """Run only the two fixed root-side read queries, with a drain acknowledgement."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, action="store_true")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--deadline-ns", required=True, type=int)
    parser.add_argument("--timeout-executable", required=True, type=Path)
    parser.add_argument("request", nargs="+")
    args = parser.parse_args()
    interrupted = [False]

    def note_interruption(_signum: int, _frame: object) -> None:
        # Do not interrupt root-side group termination/reaping. Its work/select
        # deadlines are already prepaid; the outer root watchdog stays intact.
        interrupted[0] = True

    signal.signal(signal.SIGTERM, note_interruption)
    signal.signal(signal.SIGINT, note_interruption)
    try:
        deadline = args.deadline_ns / 1_000_000_000
        if (
            os.geteuid() != 0
            or not args.directory.is_absolute()
            or not args.timeout_executable.is_absolute()
            or not 0 < deadline - time.monotonic() <= 5
        ):
            result = {"status": "query-unavailable", "teardownVerified": False}
        else:
            result = _query_capture(
                _worker_arguments(args.directory, args.request), deadline, str(args.timeout_executable)
            )
        if interrupted[0] and result.get("teardownVerified") is True:
            result = {"status": "interrupted", "teardownVerified": True}
    except Exception:  # noqa: BLE001 - fixed acknowledgement only; never serialize private failures.
        result = {"status": "query-unavailable", "teardownVerified": False}
    try:
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
    except OSError:
        pass  # The owned query has already been reaped even if its caller disappeared.


if __name__ == "__main__":
    main()
