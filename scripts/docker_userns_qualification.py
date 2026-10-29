"""Closed Containers scoped-profile qualification; observations grant no mutation authority.

The validation-only runner collector is deliberately not an admission receipt.
This module reuses its bounded fixed-path reader, with a separate fail-closed
native contract and the caller's original monotonic deadline.
"""

from __future__ import annotations

import errno
import hashlib
import json
import re
import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, Protocol

from scripts import docker_runner_security as reader

if TYPE_CHECKING:
    from collections.abc import Callable

LEGACY_CLONE = Path("/proc/sys/kernel/unprivileged_userns_clone")
MAX_NAMESPACES = 2**63 - 1
CONSUMER = "containers-ubuntu26-userns-active"


class QualificationError(Exception):
    """Expose a closed refusal, never a raw host value or OS exception."""

    def __init__(self, reason: str) -> None:
        """Keep refusal output within the reviewed finite vocabulary."""
        allowed = {
            "deadline",
            "cancelled",
            "host-unavailable",
            "host-malformed",
            "host-refused",
            "host-drift",
            "context",
            "admission",
            "owner",
            "state",
            "load",
            "subject",
            "absence",
            "unload",
            "retained",
        }
        super().__init__(reason if reason in allowed else "host-refused")


@dataclass(frozen=True)
class HostControls:
    """Only the four fixed scalar facts; absence never means a disabled restriction."""

    enabled: bool
    restricted_userns: int
    maximum_userns: int
    legacy_clone: int | None


def _refuse(reason: str) -> NoReturn:
    raise QualificationError(reason) from None


def _remaining(deadline_ns: int, cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        _refuse("cancelled")
    if type(deadline_ns) is not int or deadline_ns <= time.monotonic_ns():
        _refuse("deadline")


def _fixed_read(path: Path) -> bytes:
    # Reuse only the reviewed no-follow/nonblocking/cap-plus-one read primitive.
    return reader._read(path)  # noqa: SLF001 - validation-only collector semantics are not reused.


def _scalar(raw: bytes) -> int:
    if not re.fullmatch(rb"0|[1-9][0-9]{0,19}", raw) or int(raw) > MAX_NAMESPACES:
        _refuse("host-malformed")
    return int(raw)


def validation_profile(value: object) -> str:
    """Canonicalize only the workflow's known ASCII choices; preserve raw evidence separately."""
    if type(value) is not str or not value.isascii() or value.lower() not in {"", "full", "docker-rootless-diagnostic"}:
        _refuse("context")
    return value.lower() or "full"


def observe_controls(deadline_ns: int, *, cancelled: Callable[[], bool] | None = None) -> HostControls:
    """Admit only fixed host controls under the existing absolute native deadline.

    The legacy clone control may be absent only on an explicit ENOENT. All
    other missing, malformed, disabled or unknown observations refuse work.
    No environment variable, pathname or caller-selected scalar is accepted.
    """
    values: list[bytes | None] = []
    for path in (reader.ENABLED, reader.RESTRICT, reader.USERNS, LEGACY_CLONE):
        _remaining(deadline_ns, cancelled)
        try:
            values.append(_fixed_read(path))
        except OSError as error:
            if path == LEGACY_CLONE and error.errno == errno.ENOENT:
                values.append(None)
            else:
                _refuse("host-unavailable")
        except reader._ObservationError:  # noqa: SLF001 - collapse private bounded-reader refusals.
            _refuse("host-unavailable")
    _remaining(deadline_ns, cancelled)
    enabled, restricted, maximum, clone = values
    if enabled != b"Y" or restricted != b"1":
        _refuse("host-refused")
    if maximum is None:
        _refuse("host-unavailable")
    count = _scalar(maximum)
    if count == 0 or clone not in (None, b"1"):
        _refuse("host-refused")
    return HostControls(
        enabled=True, restricted_userns=1, maximum_userns=count, legacy_clone=None if clone is None else 1
    )


def guard_controls(
    expected: HostControls, deadline_ns: int, *, cancelled: Callable[[], bool] | None = None
) -> HostControls:
    """Refuse drift at a later boundary; two samples are not historical process proof."""
    actual = observe_controls(deadline_ns, cancelled=cancelled)
    if type(expected) is not HostControls or actual != expected:
        _refuse("host-drift")
    return actual


@dataclass(frozen=True)
class NativeBinding:
    """One immutable native phase, image and private runtime; never a publication authority."""

    candidate: str
    run: str
    attempt: str
    job: str
    architecture: str
    phase: str
    image: str
    archive_sha256: str
    manifest_digest: str
    config_digest: str
    owner: str
    runtime_slice: str
    slice_identity: str
    deadline_ns: int

    def validate(self) -> None:
        """Require the candidate's closed shape before interpreting any root request."""
        hashes = (
            self.archive_sha256,
            self.manifest_digest.removeprefix("sha256:"),
            self.config_digest.removeprefix("sha256:"),
        )
        if (
            not re.fullmatch(r"[0-9a-f]{40}", self.candidate)
            or not self.manifest_digest.startswith("sha256:")
            or not self.config_digest.startswith("sha256:")
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
            or any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (self.run, self.attempt))
            or self.job != "smoke-build"
            or self.architecture not in {"amd64", "arm64"}
            or self.phase not in {"clean-control", "enforcement"}
            or self.image != "docker-29-conformance-rootless"
            or not re.fullmatch(r"[0-9a-f]{32}", self.owner)
            or self.runtime_slice != "strukturpiloten" + self.owner + ".slice"
            or not re.fullmatch(r"[0-9]+:[1-9][0-9]*", self.slice_identity)
            or type(self.deadline_ns) is not int
        ):
            _refuse("context")

    def digest(self) -> str:
        """Bind every field into root receipts and the finalizer's original lease."""
        self.validate()
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class State(StrEnum):
    """Intent precedes each mutation; uncertainty is terminal for normal progression."""

    PREPARED = "prepared"
    ARM_INTENT = "arm-intent"
    ARMED = "armed"
    LOAD_INTENT = "load-intent"
    LOADED = "loaded"
    CREATE_INTENT = "create-intent"
    ATTACHED = "attached"
    REMOVE_INTENT = "remove-intent"
    REMOVED = "removed"
    UNLOAD_INTENT = "unload-intent"
    CLOSED = "closed"
    RETAINED = "retained"


class ActivePort(Protocol):
    """Fixed root operations only; the concrete adapter owns source and OS admission."""

    def admit(self, binding: NativeBinding) -> None:
        """Freshly check the new active predicate; ARM must refuse mutation."""
        ...

    def clean_owner(self, binding: NativeBinding) -> None:
        """Prove a fresh same-source/VM unused owner normal close, without loading policy."""
        ...

    def arm(self, binding: NativeBinding) -> None:
        """Affirm independent finalizer identity/readiness outside the bound runtime slice."""
        ...

    def guard(self, binding: NativeBinding) -> None:
        """Recheck source, host namespace, cohort, finalizer and original deadline."""
        ...

    def persist(self, state: State, container: str | None) -> None:
        """Durably commit one locked bounded state before its corresponding mutation."""
        ...

    def load(self) -> None:
        """Load only the root-held exact canonical owned profile and prove its presence."""
        ...

    def bind_subject(self, container: str, binding: NativeBinding) -> None:
        """Bind exact CID/labels/image/incarnation/held task/cgroup/effective owned profile."""
        ...

    def remove_subject(self, container: str | None) -> None:
        """Remove only the bound guest, then prove safe absence while its daemon remains live."""
        ...

    def unload(self) -> None:
        """Remove only the exact owned profile and prove its absence in the same namespace."""
        ...

    def dispose(self) -> None:
        """Prove finalizer termination before disposing exact known custody leaves."""
        ...

    def retain(self) -> None:
        """Latch uncertainty without granting cleanup or deleting custody."""
        ...


class ProfileLease:
    """One closed lifecycle, shared by hermetic controls and the concrete root adapter."""

    def __init__(self, binding: NativeBinding, port: ActivePort) -> None:
        """Construct without root operations or mutation authority."""
        self.binding, self.port = binding, port
        self.state = State.PREPARED
        self.container: str | None = None

    def _persist(self, state: State) -> None:
        self.port.persist(state, self.container)
        self.state = state

    def _retained(self) -> None:
        self.state = State.RETAINED
        with suppress(Exception, KeyboardInterrupt):
            self.port.retain()

    def prepare(self) -> None:
        """Independently admit and arm before committing the first load intent."""
        try:
            self.binding.validate()
            if self.state is not State.PREPARED:
                _refuse("state")
            self.port.admit(self.binding)
            self.port.clean_owner(self.binding)
            self._persist(State.ARM_INTENT)
            self.port.arm(self.binding)
            self._persist(State.ARMED)
            self.port.guard(self.binding)
            self._persist(State.LOAD_INTENT)
            self.port.load()
            self.port.guard(self.binding)
            self._persist(State.LOADED)
        except BaseException:
            self._retained()
            raise

    def create_intent(self) -> None:
        """Grant one exact guest attempt, after durable intent and repeated admission."""
        try:
            if self.state is not State.LOADED:
                _refuse("state")
            self.port.guard(self.binding)
            self._persist(State.CREATE_INTENT)
        except BaseException:
            self._retained()
            raise

    def bind(self, container: str) -> None:
        """Never adopt a container until its complete held-task readback is verified."""
        try:
            if self.state is not State.CREATE_INTENT or re.fullmatch(r"[0-9a-f]{64}", container) is None:
                _refuse("state")
            self.port.guard(self.binding)
            self.port.bind_subject(container, self.binding)
            self.container = container
            self._persist(State.ATTACHED)
        except BaseException:
            self._retained()
            raise

    def close(self) -> None:
        """Prove guest absence, then unload, then dispose; no uncertain path may skip ahead."""
        try:
            if self.state not in {State.LOADED, State.ATTACHED}:
                _refuse("state")
            self.port.guard(self.binding)
            self._persist(State.REMOVE_INTENT)
            self.port.remove_subject(self.container)
            self._persist(State.REMOVED)
            self.port.guard(self.binding)
            self._persist(State.UNLOAD_INTENT)
            self.port.unload()
            self._persist(State.CLOSED)
            self.port.dispose()
        except BaseException:
            self._retained()
            raise
