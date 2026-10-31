"""Finite nonqualifying direct-rootless diagnostic identity and pair contract.

This module performs no acquisition, runtime operation or policy admission.
Executable versions come from payload declarations and actual observations,
never a second software-pin table here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

PROFILE = "docker-direct-rootless-diagnostic"
PURPOSE = "direct-startup-diagnostic"
VARIANT = "direct-uid1000-profiled-b"
CONTROL_VARIANT = "direct-uid1000-unprofiled-a"
REF = "refs/heads/TheRealBecks/issue442-direct-startup-20261031"
BRANCH = REF.removeprefix("refs/heads/")
CONSUMER = "containers-direct-rootless-startup-diagnostic"
SCHEMA = 1
ROWS = (("docker-20.10-rootless", "amd64"), ("docker-26-rootless", "arm64"))
CONTEXT_FIELDS = ("diagnosticVariant", "launcher", "expectedUid", "diagnosticArm")
PAIR_SECONDS = 900
CLEANUP_SECONDS = 60
ARM_WORK_SECONDS = 300
HOST_SECONDS = 4
HOST_BYTES = 8192
FAILURE_SECONDS = 5
JOURNAL_RECORDS = 64
JOURNAL_BYTES = 65536
GUEST_BYTES = 2048
MAX_NATIVE_EXIT = 255
RECORD_BYTES = 4096
PAIR_RECORD_BYTES = 2 * RECORD_BYTES + GUEST_BYTES
NAMESPACE_CONTROLS = (
    ("U", ("/usr/bin/unshare", "--user", "--", "/usr/bin/true")),
    ("M", ("/usr/bin/unshare", "--mount", "--propagation", "unchanged", "--", "/usr/bin/true")),
    ("UM", ("/usr/bin/unshare", "--user", "--mount", "--propagation", "unchanged", "--", "/usr/bin/true")),
)
# Current held-PID1 readers cannot authenticate these short-lived post-exec
# utility actors. This is an unavailable optional route, never permission to
# infer equivalence from the parent or to try an alternate command/provider.
CONTROL_AVAILABILITY = "unavailable-post-exec-actor-equivalence"
EXPECTED_A = "rootlesskit-child-start-eperm"
STARTUP_KINDS = frozenset((EXPECTED_A, "ready", "other-failure", "unknown"))
OWNERSHIP_FIELDS = ("ownerSha256", "storeSha256", "sliceSha256", "networkSha256", "guestSha256", "volumesSha256")


MAX_GROUPS = 64
MIN_NAMESPACE_DEPTH = 2
MAX_NAMESPACE_DEPTH = 32
ACTOR_KEYS = (
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "Seccomp_filters",
    "uid_mapSha256",
    "gid_mapSha256",
    "namespaceDepth",
    "guestPid",
    "namespaces",
)


class DirectDiagnosticError(ValueError):
    """Refuse a malformed diagnostic without including protected input."""

    def __init__(self) -> None:
        """Use one fixed failure message without protected data."""
        super().__init__("direct startup diagnostic contract refused")


def require(condition: object) -> None:
    """Keep all local failure text closed and private-value-free."""
    if not condition:
        raise DirectDiagnosticError


def exact_keys(value: object, keys: tuple[str, ...]) -> dict[str, Any]:
    """Accept a plain closed object, without Boolean/numeric coercion."""
    require(type(value) is dict and set(value) == set(keys))
    return value


def canonical(value: object) -> bytes:
    """Serialize a bounded closed summary, not a native command transcript."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def finite_tuple(image: object, architecture: object) -> None:
    """Admit only the two actual image/architecture representatives."""
    require(type(image) is str and type(architecture) is str and (image, architecture) in ROWS)


@dataclass(frozen=True)
class DirectDiagnosticBinding:
    """A separate profiled-B UID1000 type; never a widened maintained29 binding."""

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
    variant: str
    launcher: str
    expected_uid: str
    arm: str

    def validate(self) -> None:
        """Authenticate the finite direct discriminator independently of native29."""
        self._validate("B", "direct-profiled", VARIANT)

    def _validate(self, arm: str, phase: str, variant: str) -> None:
        require(all(type(value) is str for key, value in asdict(self).items() if key != "deadline_ns"))
        finite_tuple(self.image, self.architecture)
        require(
            self.purpose == PURPOSE
            and self.variant == variant
            and self.launcher == "direct"
            and self.expected_uid == "1000"
            and self.arm == arm
            and self.phase == phase
            and self.job == "smoke-build"
            and re.fullmatch(r"[0-9a-f]{40}", self.candidate) is not None
            and self.candidate != "0" * 40
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (self.run, self.attempt))
            and re.fullmatch(r"[0-9a-f]{32}", self.owner) is not None
            and self.runtime_slice == "strukturpiloten" + self.owner + ".slice"
            and re.fullmatch(r"[0-9]+:[1-9][0-9]*", self.slice_identity) is not None
            and type(self.deadline_ns) is int
            and self.deadline_ns > 0
        )
        require(
            self.manifest_digest.startswith("sha256:")
            and self.config_digest.startswith("sha256:")
            and all(
                re.fullmatch(r"[0-9a-f]{64}", value) is not None
                for value in (
                    self.archive_sha256,
                    self.manifest_digest.removeprefix("sha256:"),
                    self.config_digest.removeprefix("sha256:"),
                    self.admission_sha256,
                    self.workflow_context_sha256,
                )
            )
        )

    def digest(self) -> str:
        """Bind UID/arm/launcher/image alongside the original phase custody fields."""
        self.validate()
        return hashlib.sha256(canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class DirectControlBinding(DirectDiagnosticBinding):
    """Identify A's read-only gate; this type cannot enter the policy factory."""

    def validate(self) -> None:
        """Authenticate only the genuine unprofiled control identity."""
        self._validate("A", "direct-control", CONTROL_VARIANT)


@dataclass(frozen=True)
class PairDeadline:
    """One inherited pair deadline; constructors cannot renew a phase budget."""

    started_ns: int
    deadline_ns: int

    def validate(self, now_ns: int) -> None:
        """Refuse missing, expired or enlarged absolute allowances."""
        require(all(type(value) is int for value in (self.started_ns, self.deadline_ns, now_ns)))
        require(0 < self.started_ns <= now_ns < self.deadline_ns)
        require(0 < self.deadline_ns - self.started_ns <= PAIR_SECONDS * 1_000_000_000)

    def arm_deadline(self, now_ns: int) -> int:
        """Require the predeclared whole arm, including its cleanup, before prep."""
        self.validate(now_ns)
        needed = (ARM_WORK_SECONDS + CLEANUP_SECONDS) * 1_000_000_000
        require(now_ns + needed <= self.deadline_ns)
        return now_ns + needed

    def remaining(self, now_ns: int, requested_seconds: int, *, cleanup: bool = False) -> float:
        """Clamp a command to the same original clock and cleanup reserve."""
        self.validate(now_ns)
        require(type(requested_seconds) is int and requested_seconds > 0 and type(cleanup) is bool)
        reserve = 0 if cleanup else CLEANUP_SECONDS * 1_000_000_000
        available = (self.deadline_ns - now_ns - reserve) / 1_000_000_000
        require(available > 0)
        return min(float(requested_seconds), available)


def admission_context() -> dict[str, Any]:
    """Return only the reviewed finite manual profile, never a caller policy."""
    return {
        "repository": "Strukturpiloten/containers",
        "workflow": ".github/workflows/ci.yml",
        "event": "workflow_dispatch",
        "ref": REF,
        "job": "smoke-build",
        "validationProfile": PROFILE,
        "purpose": PURPOSE,
        "qualification": "none",
        "rows": [{"image": image, "architecture": architecture} for image, architecture in ROWS],
        "diagnosticVariant": VARIANT,
        "launcher": "direct",
        "expectedUid": "1000",
        "diagnosticArm": "B",
    }


def optional_controls() -> dict[str, Any]:
    """Expose the reviewed U/M/UM contract without running unbound utility actors."""
    return {
        "availability": CONTROL_AVAILABILITY,
        "controls": [name for name, _argv in NAMESPACE_CONTROLS],
        "attempted": 0,
    }


def validate_actor(value: object) -> dict:
    """Accept only the fixed privacy-preserving actor summary, never process text."""
    actor = exact_keys(value, ACTOR_KEYS)
    for key in ("Uid", "Gid"):
        require(
            type(actor[key]) is list and actor[key] == ["1000"] * 4 and all(type(item) is str for item in actor[key])
        )
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(type(actor[key]) is list and len(actor[key]) == 1)
        require(type(actor[key][0]) is str and re.fullmatch(r"[0-9a-f]{16}", actor[key][0]) is not None)
    for key in ("Groups", "NoNewPrivs", "Seccomp", "Seccomp_filters"):
        require(type(actor[key]) is list and len(actor[key]) <= MAX_GROUPS)
        require(all(type(item) is str and re.fullmatch(r"[0-9]{1,10}", item) is not None for item in actor[key]))
        require(key == "Groups" or len(actor[key]) == 1)
    for key in ("uid_mapSha256", "gid_mapSha256"):
        require(type(actor[key]) is str and re.fullmatch(r"[0-9a-f]{64}", actor[key]) is not None)
    require(type(actor["guestPid"]) is int and actor["guestPid"] == 1)
    require(
        type(actor["namespaceDepth"]) is int and MIN_NAMESPACE_DEPTH <= actor["namespaceDepth"] <= MAX_NAMESPACE_DEPTH
    )
    namespaces = exact_keys(actor["namespaces"], ("user", "mnt", "pid"))
    for kind, item in namespaces.items():
        exact_keys(item, ("sha256", "relationship"))
        require(type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None)
        require(item["relationship"] == ("same-host" if kind == "user" else "owned-distinct"))
    require(len(canonical(actor)) <= GUEST_BYTES)
    return actor


def validate_executables(value: object) -> dict:
    """Accept only actual bounded hashes/versions, never a second pin table."""
    tools = exact_keys(value, ("launcherSha256", "rootlesskitSha256", "rootlesskitVersion", "engineVersion"))
    for key in ("launcherSha256", "rootlesskitSha256"):
        require(type(tools[key]) is str and re.fullmatch(r"[0-9a-f]{64}", tools[key]) is not None)
    for key in ("rootlesskitVersion", "engineVersion"):
        require(type(tools[key]) is str and re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}", tools[key]) is not None)
    return tools


def validate_guest(value: object) -> dict:
    """Close each two-KiB actual guest observation before public emission."""
    guest = exact_keys(value, ("actor", "executables", "postExecVerified"))
    validate_actor(guest["actor"])
    validate_executables(guest["executables"])
    require(type(guest["postExecVerified"]) is bool and len(canonical(guest)) <= GUEST_BYTES)
    return guest


def validate_arm(value: object) -> dict[str, Any]:
    """Require complete typed observations; expected A failure stays negative."""
    arm = exact_keys(
        value,
        (
            "arm",
            "image",
            "architecture",
            "qualification",
            "startup",
            "nativeExitCode",
            "cleanupVerified",
            "factsComplete",
            "nonPolicyFactsSha256",
            "sourceIdentitySha256",
            "ownership",
            "kernelAttribution",
            "namespaceControls",
            "profileBound",
            "guest",
        ),
    )
    finite_tuple(arm["image"], arm["architecture"])
    require(type(arm["arm"]) is str and arm["arm"] in {"A", "B"})
    require(type(arm["qualification"]) is str and arm["qualification"] == "none")
    require(type(arm["startup"]) is str and arm["startup"] in STARTUP_KINDS)
    require(
        arm["nativeExitCode"] is None
        or (type(arm["nativeExitCode"]) is int and 0 <= arm["nativeExitCode"] <= MAX_NATIVE_EXIT)
    )
    if arm["startup"] == "ready":
        require(arm["nativeExitCode"] is None)
    for key in ("cleanupVerified", "factsComplete", "profileBound"):
        require(type(arm[key]) is bool)
    for key in ("nonPolicyFactsSha256", "sourceIdentitySha256"):
        require(type(arm[key]) is str and re.fullmatch(r"[0-9a-f]{64}", arm[key]) is not None)
    ownership = exact_keys(arm["ownership"], OWNERSHIP_FIELDS)
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in ownership.values()))
    require(
        type(arm["kernelAttribution"]) is str
        and arm["kernelAttribution"] in {"exact-owned-userns-denial", "unavailable", "none-observed", "inconclusive"}
    )
    controls = exact_keys(arm["namespaceControls"], ("availability", "controls", "attempted"))
    require(type(controls["attempted"]) is int and controls["attempted"] == 0)
    require(type(controls["controls"]) is list and all(type(value) is str for value in controls["controls"]))
    require(type(controls["availability"]) is str and controls == optional_controls())
    require(arm["profileBound"] is (arm["arm"] == "B"))
    guest = validate_guest(arm["guest"])
    require(guest["postExecVerified"] is (arm["startup"] == "ready"))
    require(len(canonical(arm)) <= RECORD_BYTES)
    return arm


def compare_pair(first: object, second: object) -> str:
    """Classify only a cleaned, comparable pair; never infer an absent syscall."""
    a, b = validate_arm(first), validate_arm(second)
    require(a["arm"] == "A" and b["arm"] == "B")
    require((a["image"], a["architecture"]) == (b["image"], b["architecture"]))
    require(a["cleanupVerified"] is True and b["cleanupVerified"] is True)
    require(a["factsComplete"] is True and b["factsComplete"] is True)
    require(a["sourceIdentitySha256"] == b["sourceIdentitySha256"])
    require(all(a["ownership"][key] != b["ownership"][key] for key in OWNERSHIP_FIELDS))
    require(a["startup"] == EXPECTED_A and type(a["nativeExitCode"]) is int and a["nativeExitCode"] > 0)
    if a["nonPolicyFactsSha256"] != b["nonPolicyFactsSha256"]:
        return "inconclusive"
    if b["startup"] == "ready" and b["nativeExitCode"] is None:
        return "profile-dependent-startup"
    if b["startup"] == EXPECTED_A and type(b["nativeExitCode"]) is int and b["nativeExitCode"] > 0:
        return "profile-not-demonstrated-remedy"
    return "inconclusive"
