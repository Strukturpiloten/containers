"""Resource admission and readback for isolated nested Docker runtime probes."""

# Fixed argv and task-owned paths are intentional; explicit evidence errors are useful here.
# ruff: noqa: EM101, EM102, S603, SLF001, TRY003, TRY301

from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import TYPE_CHECKING, Self

from scripts.runtime_docker_diagnostics import qualify_gnu_timeout, redact_timeout_provider
from scripts.runtime_errors import ProbeError

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

    from scripts.runtime_tests import RuntimeContext

CPU_LIMIT = 2
MEMORY_LIMIT_BYTES = 4 * 1024**3
PIDS_LIMIT = 512
STORE_LIMIT_BYTES = 12 * 1024**3
STORE_POLL_SECONDS = 2.0
STORE_SAMPLE_TIMEOUT_SECONDS = 5


def outer_container_limits() -> tuple[str, ...]:
    """Bound the whole inner daemon and its nested workloads with one outer cgroup."""
    return (
        "--cpus",
        str(CPU_LIMIT),
        "--memory",
        str(MEMORY_LIMIT_BYTES),
        "--pids-limit",
        str(PIDS_LIMIT),
        "--cgroupns",
        "private",
    )


def verify_outer_container_limits(ctx: RuntimeContext, container: str, *, timeout: float | None = None) -> None:
    """Read effective cgroup v2 limits inside the outer container; fail closed."""
    options = {} if timeout is None else {"timeout": timeout}
    raw = ctx.exec(
        "read outer Docker cgroup limits",
        container,
        "sh",
        "-euc",
        "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max",
        **options,
    )
    requested = {"cpus": CPU_LIMIT, "memoryBytes": MEMORY_LIMIT_BYTES, "pids": PIDS_LIMIT}
    try:
        cpu, memory, pids = raw.splitlines()
        quota_text, period_text = cpu.split()
        quota, period = int(quota_text), int(period_text)
        memory_bytes, pid_count = int(memory), int(pids)
        if not (0 < quota <= CPU_LIMIT * period and period > 0):
            raise ValueError("CPU quota exceeds the requested limit")
        if not (0 < memory_bytes <= MEMORY_LIMIT_BYTES):
            raise ValueError("memory limit exceeds the requested limit")
        if not (0 < pid_count <= PIDS_LIMIT):
            raise ValueError("PID limit exceeds the requested limit")
    except ValueError as error:
        ctx.checks.append(
            {
                "name": "outer Docker resource limits",
                "status": "failed",
                "requested": requested,
                "readback": raw,
                "error": str(error),
            }
        )
        raise ProbeError(f"outer Docker cgroup limits were not enforced: {error}") from error
    ctx.checks.append(
        {
            "name": "outer Docker resource limits",
            "status": "passed",
            "requested": requested,
            "readback": {"cpuQuota": quota, "cpuPeriod": period, "memoryBytes": memory_bytes, "pids": pid_count},
        }
    )


class IsolatedStoreDiskBudget:
    """Observe a task-owned Podman store; this is admission, not a hard quota."""

    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        limit_bytes: int = STORE_LIMIT_BYTES,
        poll_seconds: float = STORE_POLL_SECONDS,
        source_archive: Path | None = None,
    ) -> None:
        """Keep all measurements scoped to this invocation's isolated store."""
        self.ctx = ctx
        self.limit_bytes = limit_bytes
        self.poll_seconds = poll_seconds
        self.source_archive = source_archive
        self.source_identity: tuple[int, int, int, int, int] | None = None
        if source_archive is not None and (
            not source_archive.is_absolute()
            or not source_archive.is_file()
            or source_archive.is_symlink()
            or source_archive.is_relative_to(ctx.directory)
        ):
            raise ProbeError("disk budget source must be one exact regular archive outside the owned store")
        self.peak_bytes = 0
        self.samples = 0
        self.transient_retries = 0
        self._error: str | None = None
        self._gnu_timeout_provider: tuple[str, str, str] | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll, name="isolated-docker-disk-budget", daemon=True)

    def bind_source_archive(self, identity: tuple[int, int, int, int, int]) -> None:
        """Pin accounting to the same frozen archive inode consumed by both phases."""
        if self.source_identity is not None and self.source_identity != identity:
            raise ProbeError("disk budget source identity cannot be rebound")
        self.source_identity = identity
        self._verify_source_archive()

    def _verify_source_archive(self) -> None:
        if self.source_archive is not None and self.source_identity is not None:
            try:
                value = self.source_archive.stat(follow_symlinks=False)
            except OSError as error:
                raise ProbeError("disk budget lost custody of the pinned source archive path") from error
            actual = value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
            if actual != self.source_identity or self.source_archive.is_symlink():
                raise ProbeError("disk budget source path no longer accounts for the pinned archive inode")

    def _du_once(self) -> tuple[int, str, str]:
        self._verify_source_archive()
        if self._gnu_timeout_provider is None:
            try:
                self._gnu_timeout_provider = qualify_gnu_timeout(self.ctx)
            except ValueError:
                raise ProbeError("GNU timeout prerequisite admission failed") from None
        command = [
            *self.ctx._sudo,
            self._gnu_timeout_provider[0],
            "--signal=KILL",
            f"{STORE_SAMPLE_TIMEOUT_SECONDS}s",
            "du",
            "--summarize",
            "--one-file-system",
            "--block-size=1",
            "--",
            str(self.ctx.directory),
            *((str(self.source_archive),) if self.source_archive is not None else ()),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                env={**os.environ, "LC_ALL": "C"},
            )
        except OSError as error:
            detail = redact_timeout_provider(self.ctx, str(error))
            raise ProbeError(f"isolated Docker store disk measurement failed: {detail}") from None
        try:
            stdout, stderr = process.communicate(timeout=STORE_SAMPLE_TIMEOUT_SECONDS + 3)
        except subprocess.TimeoutExpired:
            raise ProbeError(
                f"isolated Docker store disk measurement timed out after {STORE_SAMPLE_TIMEOUT_SECONDS}s"
            ) from None
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except PermissionError:
                    try:
                        subprocess.run(
                            [*self.ctx._sudo, "kill", "-KILL", "--", f"-{process.pid}"],
                            capture_output=True,
                            check=False,
                            timeout=3,
                        )
                    except (OSError, subprocess.TimeoutExpired) as error:
                        detail = redact_timeout_provider(self.ctx, str(error))
                        raise ProbeError(f"could not stop isolated disk sampler process group: {detail}") from None
                except ProcessLookupError:
                    pass
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    raise ProbeError("could not reap isolated disk sampler process group") from None
        self._verify_source_archive()
        return process.returncode, stdout, stderr

    def _measure(self) -> None:
        for attempt in range(2):
            status, stdout, stderr = self._du_once()
            if status == 0:
                break
            diagnostics = [line for line in stderr.splitlines() if line.strip()]
            if attempt == 0 and diagnostics and all("No such file or directory" in line for line in diagnostics):
                self.transient_retries += 1
                continue
            detail = redact_timeout_provider(self.ctx, stderr.strip())
            raise ProbeError(f"isolated Docker store disk measurement failed (exit {status}): {detail}")
        try:
            if self.source_archive is None:
                size = int(stdout.split(maxsplit=1)[0])
            else:
                expected = {str(self.ctx.directory), str(self.source_archive)}
                measured = {}
                for line in stdout.splitlines():
                    count, path = line.split("\t", 1)
                    if path not in expected or path in measured or not count.isdecimal():
                        raise ValueError("unexpected or duplicate archive/store byte count")
                    measured[path] = int(count)
                if measured.keys() != expected:
                    raise ValueError("missing archive/store byte count")
                size = sum(measured.values())
        except IndexError, ValueError:
            raise ProbeError("isolated Docker store disk measurement returned no byte count") from None
        self.samples += 1
        self.peak_bytes = max(self.peak_bytes, size)

    def _poll(self) -> None:
        while not self._stop.wait(self.poll_seconds):
            try:
                self._measure()
            except Exception as error:  # noqa: BLE001 - report unexpected sampler failures in runtime evidence.
                self._error = redact_timeout_provider(self.ctx, f"{type(error).__name__}: {error}")
                return
            if self.peak_bytes > self.limit_bytes:
                return

    def _record(self) -> None:
        exceeded = self.peak_bytes > self.limit_bytes
        self.ctx.checks.append(
            {
                "name": "isolated Docker store disk budget",
                "status": "failed" if exceeded or self._error else "passed",
                "limitBytes": self.limit_bytes,
                "peakBytes": self.peak_bytes,
                "overshootBytes": max(0, self.peak_bytes - self.limit_bytes),
                "pollIntervalSeconds": self.poll_seconds,
                "sampleTimeoutSeconds": STORE_SAMPLE_TIMEOUT_SECONDS,
                "samples": self.samples,
                "transientRetries": self.transient_retries,
                "error": redact_timeout_provider(self.ctx, self._error) if self._error is not None else None,
                **(
                    {"sourceArchive": redact_timeout_provider(self.ctx, str(self.source_archive))}
                    if self.source_archive is not None
                    else {}
                ),
            }
        )

    def _failure(self) -> ProbeError | None:
        if self._error:
            return ProbeError(redact_timeout_provider(self.ctx, self._error))
        if self.peak_bytes > self.limit_bytes:
            return ProbeError(
                f"isolated Docker store exceeded {self.limit_bytes} byte budget "
                f"(observed {self.peak_bytes}); preserving store for cleanup evidence"
            )
        return None

    def checkpoint(self) -> None:
        """Stop new nested work after any failed disk observation."""
        self._verify_source_archive()
        failure = self._failure()
        if failure is not None:
            raise failure

    def __enter__(self) -> Self:
        """Reject an oversized store before any nested Docker work begins."""
        try:
            self._measure()  # Admission before saving the offline fixture or starting the daemon.
        except ProbeError as error:
            self._error = redact_timeout_provider(self.ctx, str(error))
            self._record()
            raise
        failure = self._failure()
        if failure is not None:
            self._record()
            raise failure
        self._thread.start()
        return self

    def __exit__(
        self, error_type: type[BaseException] | None, _error: BaseException | None, _traceback: TracebackType | None
    ) -> None:
        """Record the peak and fail if the budget was exceeded or unreadable."""
        self._stop.set()
        self._thread.join()
        try:
            self._measure()
        except ProbeError as error:
            self._error = redact_timeout_provider(self.ctx, str(error))
        self._record()
        failure = self._failure()
        if failure is not None and error_type is None:
            raise failure
