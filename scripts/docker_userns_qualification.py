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
PREREQUISITE_SCHEMA = 2
ADMISSION_SCHEMA = 3
ADMISSION_REVISION = "containers527-maintained-bounded-v1"
MAINTAINED_PROFILES = ("full", "docker-rootless-qualification")
EXPERIMENTAL_PURPOSE = "experimental-candidate"
MAINTAINED_PURPOSE = "maintained-prerequisite"
WORKFLOW = "Strukturpiloten/containers/.github/workflows/ci.yml"
WORKFLOW_CONTEXT_KEYS = frozenset(
    (
        "candidate",
        "workflow",
        "checkout",
        "repository",
        "event",
        "ref",
        "workflowRef",
        "job",
        "run",
        "attempt",
        "architecture",
        "image",
        "imageOS",
        "imageVersion",
        "imageVersionKind",
        "validationProfile",
        "validationProfileRequested",
        "purpose",
        "admissionRevision",
        "admissionSha256",
    )
)
SCOPED_RECEIPT_KEYS = frozenset(
    (
        "schemaVersion",
        "consumer",
        "qualification",
        "binding",
        "bindingSha256",
        "lease",
        "profileName",
        "state",
        "sourceManifestSha256",
        "imageVersion",
        "imageVersionKind",
        "validationProfile",
        "validationProfileRequested",
        "parserExecutionNamespace",
        "cleanOwnerVerified",
        "ownerReady",
        "ownerTerminationVerified",
        "custodyDisposed",
        "preflight",
        "namespace",
        "guestAbsenceVerified",
        "taskAbsenceVerified",
        "scopeAbsenceVerified",
        "profileAbsenceVerified",
        "profileObservation",
        "retained",
        "readerPending",
        "childPending",
        "purpose",
        "admissionRevision",
        "admissionSha256",
        "workflowContext",
        "bootstrapSha256",
    )
)


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
    if (
        type(value) is not str
        or not value.isascii()
        or value.lower() not in {"", *MAINTAINED_PROFILES, "docker-rootless-diagnostic"}
    ):
        _refuse("context")
    return value.lower() or "full"


def selected_manual_ref(value: object) -> str:
    """Keep the actual dispatch branch/tag ref; never normalize an arbitrary locator."""
    if (
        type(value) is not str
        or re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,179}", value) is None
        or any(part in {"", ".", ".."} or part.endswith((".", ".lock")) for part in value.split("/"))
        or ".." in value
    ):
        _refuse("context")
    return value


def event_scope(event: object) -> tuple[str, str]:
    """Derive the finite purpose/ref from the fixed workflow-dispatch payload."""
    if type(event) is not dict or type(event.get("inputs", {})) is not dict:
        _refuse("context")
    inputs = event.get("inputs", {})
    canonical = validation_profile(inputs.get("validation_profile", "full"))
    focused = inputs.get("focused_runtime", "witness-diagnostic")
    if type(focused) is not str or focused not in {"witness-diagnostic", "mandatory-accounting"}:
        _refuse("context")
    if canonical in MAINTAINED_PROFILES:
        if (
            "inputs" not in event
            or focused != "witness-diagnostic"
            or type(event.get("repository")) is not dict
            or event["repository"].get("full_name") != "Strukturpiloten/containers"
            or event.get("workflow") != ".github/workflows/ci.yml"
        ):
            _refuse("context")
        return MAINTAINED_PURPOSE, selected_manual_ref(event.get("ref"))
    if (
        event.get("ref", "refs/heads/TheRealBecks/issue527") != "refs/heads/TheRealBecks/issue527"
        or (
            "repository" in event
            and (
                type(event["repository"]) is not dict
                or event["repository"].get("full_name") != "Strukturpiloten/containers"
            )
        )
        or event.get("workflow", ".github/workflows/ci.yml") != ".github/workflows/ci.yml"
    ):
        _refuse("context")
    return EXPERIMENTAL_PURPOSE, "refs/heads/TheRealBecks/issue527"


def context_digest(value: dict[str, str]) -> str:
    """Bind the complete staged workflow context, including purpose/admission/ref."""
    if (
        type(value) is not dict
        or set(value) != WORKFLOW_CONTEXT_KEYS
        or any(type(item) is not str for item in value.values())
    ):
        _refuse("context")
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def admission_document(raw: bytes) -> dict:
    """Read the closed reviewed attempt policy; it never declares native success."""

    def unique(pairs: list[tuple[str, object]]) -> dict:
        value = {}
        for key, item in pairs:
            if key in value:
                _refuse("admission")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if (
        type(value) is not dict
        or set(value)
        != {
            "schemaVersion",
            "consumer",
            "purpose",
            "qualification",
            "sourceManifestSha256",
            "context",
            "cohorts",
            "architectures",
            "policyNamespace",
            "parserExecutionNamespace",
            "review",
            "revision",
            "maintainedContext",
            "maintainedArchitectures",
        }
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != ADMISSION_SCHEMA
        or value["consumer"] != CONSUMER
        or value["purpose"] != "scoped-prerequisite-attempt"
        or value["qualification"] != "none"
        or value["revision"] != ADMISSION_REVISION
        or value["architectures"] != {"amd64": "experimental-load-candidate", "arm64": "compile-only-refuse-load"}
        or value["maintainedArchitectures"] != {"amd64": "maintained-prerequisite", "arm64": "maintained-prerequisite"}
    ):
        _refuse("admission")
    context_keys = {
        "repository",
        "workflow",
        "event",
        "ref",
        "validationProfile",
        "job",
        "image",
        "imageOS",
        "imageVersion",
    }
    for name in ("context", "maintainedContext"):
        expected_keys = (
            context_keys if name == "context" else (context_keys - {"validationProfile"}) | {"validationProfiles"}
        )
        if (
            type(value[name]) is not dict
            or set(value[name]) != expected_keys
            or any(type(item) is not str for key, item in value[name].items() if key != "validationProfiles")
        ):
            _refuse("admission")
    if (
        value["context"]["ref"] != "refs/heads/TheRealBecks/issue527"
        or value["context"]["validationProfile"] != "docker-rootless-diagnostic"
        or value["maintainedContext"]["ref"] != "event-selected-manual-ref"
        or value["maintainedContext"]["validationProfiles"] != list(MAINTAINED_PROFILES)
    ):
        _refuse("admission")
    _validate_cohorts(value["cohorts"])
    return value


def _validate_cohorts(cohorts: object) -> None:
    """Require complete distinct finite per-architecture predicates before an attempt."""
    if type(cohorts) is not dict or set(cohorts) != {"amd64", "arm64"}:
        _refuse("admission")
    fields = {
        "osID",
        "osVersion",
        "machine",
        "kernel",
        "parserVersion",
        "parserSha256",
        "abiSha256",
        "namespaceMaskSha256",
        "policyVersion9Sha256",
        "interpreter",
        "interpreterSha256",
        "pythonVersion",
    }
    for architecture, cohort in cohorts.items():
        if (
            type(cohort) is not dict
            or set(cohort) != fields
            or cohort["osID"] != "ubuntu"
            or cohort["osVersion"] != "26.04"
            or cohort["machine"] != {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
            or cohort["kernel"] != "7.0.0-1017-azure"
            or cohort["parserVersion"] != "5.0.2"
            or cohort["interpreter"] != "/usr/bin/python3.14"
            or cohort["pythonVersion"] != [3, 14, 4, "final", 0]
            or any(
                type(item) is not type(expected)
                for item, expected in zip(cohort["pythonVersion"], [3, 14, 4, "final", 0], strict=True)
            )
            or any(
                type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for key, value in cohort.items()
                if key.endswith("Sha256")
            )
        ):
            _refuse("admission")
    if any(cohorts["amd64"][key] == cohorts["arm64"][key] for key in ("parserSha256", "interpreterSha256")):
        _refuse("admission")


def active_cohort(admission: dict, context: dict) -> dict:
    """Select only maintained native architectures or the existing experimental AMD64 route."""
    architecture = context["architecture"]
    if (
        architecture not in {"amd64", "arm64"}
        or context["purpose"] not in {EXPERIMENTAL_PURPOSE, MAINTAINED_PURPOSE}
        or (architecture == "arm64" and context["purpose"] != MAINTAINED_PURPOSE)
    ):
        _refuse("admission")
    return admission["cohorts"][architecture]


def validate_workflow_context(context: dict[str, str], admission: dict, admission_sha256: str) -> None:
    """Validate archived purpose intrinsically; no consumer environment supplies authority."""
    context_digest(context)
    purpose = context["purpose"]
    expected = admission["maintainedContext"] if purpose == MAINTAINED_PURPOSE else admission["context"]
    canonical = validation_profile(context["validationProfileRequested"])
    if (
        purpose not in {EXPERIMENTAL_PURPOSE, MAINTAINED_PURPOSE}
        or context["admissionRevision"] != admission["revision"]
        or context["admissionRevision"] != ADMISSION_REVISION
        or context["admissionSha256"] != admission_sha256
        or re.fullmatch(r"[0-9a-f]{64}", admission_sha256) is None
        or context["candidate"] != context["workflow"]
        or context["candidate"] != context["checkout"]
        or re.fullmatch(r"[0-9a-f]{40}", context["candidate"]) is None
        or any(re.fullmatch(r"[1-9][0-9]{0,19}", context[key]) is None for key in ("run", "attempt"))
        or context["repository"] != expected["repository"]
        or context["repository"] != "Strukturpiloten/containers"
        or context["event"] != expected["event"]
        or context["event"] != "workflow_dispatch"
        or expected["workflow"] != ".github/workflows/ci.yml"
        or context["workflowRef"] != WORKFLOW + "@" + selected_manual_ref(context["ref"])
        or context["job"] != expected["job"]
        or context["job"] != "smoke-build"
        or context["image"] != expected["image"]
        or context["image"] != "docker-29-conformance-rootless"
        or expected["imageOS"] != "ubuntu26"
        or context["architecture"] not in {"amd64", "arm64"}
        or context["imageOS"] != {"amd64": "ubuntu26", "arm64": "ubuntu26-arm64"}.get(context["architecture"])
        or context["imageVersionKind"] != "workflow-reported-provenance-not-vm-attestation"
        or re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", context["imageVersion"]) is None
        or canonical != context["validationProfile"]
        or (purpose == EXPERIMENTAL_PURPOSE and canonical != expected["validationProfile"])
    ):
        _refuse("context")

    if purpose == MAINTAINED_PURPOSE:
        if (
            canonical not in MAINTAINED_PROFILES
            or canonical not in expected["validationProfiles"]
            or expected["ref"] != "event-selected-manual-ref"
            or admission["maintainedArchitectures"].get(context["architecture"]) != MAINTAINED_PURPOSE
        ):
            _refuse("admission")
    elif (
        canonical != "docker-rootless-diagnostic"
        or context["ref"] != expected["ref"]
        or context["ref"] != "refs/heads/TheRealBecks/issue527"
    ):
        _refuse("context")


def validate_stage_disposal(value: object, scoped: dict) -> None:
    """Bind completion of the existing stage disposal to this exact root bootstrap."""
    if (
        type(value) is not dict
        or set(value)
        != {
            "schemaVersion",
            "consumer",
            "stageDisposed",
            "purpose",
            "admissionRevision",
            "admissionSha256",
            "bootstrapSha256",
            "workflowContextSha256",
        }
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != PREREQUISITE_SCHEMA
        or value["consumer"] != CONSUMER
        or value["stageDisposed"] is not True
        or value["purpose"] != scoped["purpose"]
        or value["admissionRevision"] != scoped["admissionRevision"]
        or value["admissionSha256"] != scoped["admissionSha256"]
        or value["bootstrapSha256"] != scoped["bootstrapSha256"]
        or re.fullmatch(r"[0-9a-f]{64}", value["bootstrapSha256"]) is None
        or value["workflowContextSha256"] != context_digest(scoped["workflowContext"])
    ):
        _refuse("absence")


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
    purpose: str
    admission_sha256: str
    workflow_context_sha256: str

    def validate(self) -> None:
        """Require the candidate's closed shape before interpreting any root request."""
        if any(type(value) is not str for key, value in asdict(self).items() if key != "deadline_ns"):
            _refuse("context")
        hashes = (
            self.archive_sha256,
            self.manifest_digest.removeprefix("sha256:"),
            self.config_digest.removeprefix("sha256:"),
            self.admission_sha256,
            self.workflow_context_sha256,
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
            or self.purpose not in {EXPERIMENTAL_PURPOSE, MAINTAINED_PURPOSE}
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
