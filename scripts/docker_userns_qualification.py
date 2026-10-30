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
PREREQUISITE_SCHEMA = 3
ADMISSION_SCHEMA = 4
ADMISSION_REVISION = "containers527-maintained-callers-v1"
MAINTAINED_PROFILES = ("full", "docker-rootless-qualification")
EXPERIMENTAL_PURPOSE = "experimental-candidate"
MAINTAINED_PURPOSE = "maintained-prerequisite"
WORKFLOW = "Strukturpiloten/containers/.github/workflows/ci.yml"
REPOSITORY = "Strukturpiloten/containers"
CI_WORKFLOW = ".github/workflows/ci.yml"
PUBLICATION_WORKFLOW = ".github/workflows/publish-images.yml"
MAX_CALLER_FIELD = 512
CRON_FIELDS = 5
NATIVE_JOBS = frozenset(("smoke-build", "build"))
CALLER_FACT_KEYS = (
    "caller",
    "workflowPath",
    "eventAction",
    "pullRequestNumber",
    "eventHeadSha",
    "eventBaseSha",
    "eventHeadRef",
    "eventBaseRef",
    "headRepository",
    "baseRepository",
    "defaultBranch",
    "eventSchedule",
    "publicationScope",
    "publicationTarget",
)
MAINTAINED_CALLERS = {
    "ci-pr": {
        "workflow": ".github/workflows/ci.yml",
        "event": "pull_request",
        "job": "smoke-build",
        "refPolicy": "pr-merge",
        "selector": "automatic-full",
    },
    "ci-merge-group": {
        "workflow": ".github/workflows/ci.yml",
        "event": "merge_group",
        "job": "smoke-build",
        "refPolicy": "queue-head",
        "selector": "automatic-full",
    },
    "ci-manual": {
        "workflow": ".github/workflows/ci.yml",
        "event": "workflow_dispatch",
        "job": "smoke-build",
        "refPolicy": "event-selected-manual-ref",
        "selector": "manual-ci",
    },
    "publication-push": {
        "workflow": ".github/workflows/publish-images.yml",
        "event": "push",
        "job": "build",
        "refPolicy": "main-push",
        "selector": "publication-default",
    },
    "publication-schedule": {
        "workflow": ".github/workflows/publish-images.yml",
        "event": "schedule",
        "job": "build",
        "refPolicy": "main-schedule",
        "selector": "publication-default",
    },
    "publication-manual": {
        "workflow": ".github/workflows/publish-images.yml",
        "event": "workflow_dispatch",
        "job": "build",
        "refPolicy": "event-selected-manual-ref",
        "selector": "publication-default",
    },
}
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
        *CALLER_FACT_KEYS,
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


def caller_identity(identity: dict[str, str]) -> str:
    """Check only the finite runner-provided caller tuple before reading event data."""
    if (
        type(identity) is not dict
        or set(identity) != {"repository", "event", "ref", "workflowRef", "job", "candidate"}
        or any(type(value) is not str or len(value) > MAX_CALLER_FIELD for value in identity.values())
        or identity["repository"] != REPOSITORY
    ):
        _refuse("context")
    event_ref(identity["ref"])
    prefix, separator, suffix = identity["workflowRef"].partition("@")
    if not separator or suffix != identity["ref"] or not prefix.startswith(REPOSITORY + "/"):
        _refuse("context")
    workflow = prefix.removeprefix(REPOSITORY + "/")
    if not any(
        (workflow, identity["event"], identity["job"]) == (policy["workflow"], policy["event"], policy["job"])
        for policy in MAINTAINED_CALLERS.values()
    ):
        _refuse("context")
    return workflow


def event_ref(value: object) -> str:
    """Accept a finite PR merge ref or the existing validated branch/tag refs."""
    if type(value) is str and re.fullmatch(r"refs/pull/[1-9][0-9]{0,19}/merge", value):
        return value
    return selected_manual_ref(value)


def _event_oid(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None or value == "0" * 40:
        _refuse("context")
    return value


def _event_repository(value: object) -> None:
    if type(value) is not dict or value.get("full_name") != REPOSITORY:
        _refuse("context")


def _head_ref(value: object) -> str:
    result = selected_manual_ref(value)
    if not result.startswith("refs/heads/"):
        _refuse("context")
    return result


def _branch_ref(value: object) -> str:
    if type(value) is not str:
        _refuse("context")
    return _head_ref("refs/heads/" + value)


def _pr_caller(event: dict, identity: dict, facts: dict) -> None:
    request = event.get("pull_request")
    number = event.get("number")
    if (
        event.get("action") not in ("opened", "synchronize", "reopened")
        or type(request) is not dict
        or type(number) is not int
        or not 0 < number < 10**20
        or type(request.get("number")) is not int
        or request["number"] != number
        or identity["ref"] != f"refs/pull/{number}/merge"
    ):
        _refuse("context")
    for role in ("head", "base"):
        part = request.get(role)
        if type(part) is not dict:
            _refuse("context")
        _event_repository(part.get("repo"))
        facts["event" + role.title() + "Sha"] = _event_oid(part.get("sha"))
        facts["event" + role.title() + "Ref"] = _branch_ref(part.get("ref"))
        facts[role + "Repository"] = REPOSITORY
    if request.get("merge_commit_sha") is not None:
        _event_oid(request["merge_commit_sha"])
    if identity["candidate"] in {facts["eventHeadSha"], facts["eventBaseSha"]}:
        _refuse("context")
    facts.update(caller="ci-pr", eventAction=event["action"], pullRequestNumber=str(number))


def _queue_caller(event: dict, identity: dict, facts: dict) -> None:
    group = event.get("merge_group")
    if event.get("action") != "checks_requested" or type(group) is not dict:
        _refuse("context")
    head = _head_ref(group.get("head_ref"))
    base = _head_ref(group.get("base_ref"))
    head_sha, base_sha = _event_oid(group.get("head_sha")), _event_oid(group.get("base_sha"))
    if (
        not head.startswith("refs/heads/gh-readonly-queue/")
        or head != identity["ref"]
        or head_sha != identity["candidate"]
        or base_sha == head_sha
        or base == head
    ):
        _refuse("context")
    facts.update(
        caller="ci-merge-group",
        eventAction="checks_requested",
        eventHeadRef=head,
        eventBaseRef=base,
        eventHeadSha=head_sha,
        eventBaseSha=base_sha,
    )


def _publication_caller(event: dict, identity: dict, facts: dict) -> None:
    if event["repository"].get("default_branch") != "main":
        _refuse("context")
    facts.update(defaultBranch="main", publicationScope="all")
    kind = identity["event"]
    if kind == "push":
        if (
            event.get("deleted") is not False
            or event.get("ref") != "refs/heads/main"
            or identity["ref"] != "refs/heads/main"
        ):
            _refuse("context")
        after = _event_oid(event.get("after"))
        if after != identity["candidate"]:
            _refuse("context")
        facts.update(caller="publication-push", eventHeadSha=after)
    elif kind == "schedule":
        schedule = event.get("schedule")
        if (
            identity["ref"] != "refs/heads/main"
            or event.get("ref", identity["ref"]) != identity["ref"]
            or type(schedule) is not str
            or re.fullmatch(r"[A-Za-z0-9*/ ,\-]{1,96}", schedule) is None
            or len(schedule.split()) != CRON_FIELDS
        ):
            _refuse("context")
        facts.update(caller="publication-schedule", eventSchedule=schedule)
    else:
        _publication_dispatch(event, identity, facts)


def _publication_dispatch(event: dict, identity: dict, facts: dict) -> None:
    inputs = event.get("inputs", {})
    if (
        event.get("workflow") != PUBLICATION_WORKFLOW
        or selected_manual_ref(event.get("ref")) != identity["ref"]
        or type(inputs) is not dict
        or set(inputs) - {"scope", "target"}
    ):
        _refuse("context")
    scope, target = inputs.get("scope", "all"), inputs.get("target", "")
    if (
        type(scope) is not str
        or scope not in {"all", "image", "family"}
        or type(target) is not str
        or (scope == "all" and target != "")
        or (scope != "all" and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", target) is None)
    ):
        _refuse("context")
    facts.update(caller="publication-manual", publicationScope=scope, publicationTarget=target)


def caller_context(event: object, identity: dict[str, str]) -> dict[str, str]:
    """Derive purpose and source/caller facts; a routing Boolean grants no authority."""
    workflow = caller_identity(identity)
    _event_oid(identity["candidate"])
    if type(event) is not dict or ("workflow" in event and event["workflow"] != workflow):
        _refuse("context")
    facts = dict.fromkeys(CALLER_FACT_KEYS, "")
    facts["workflowPath"] = workflow
    purpose, profile, requested = MAINTAINED_PURPOSE, "full", ""
    if workflow == CI_WORKFLOW and identity["event"] == "workflow_dispatch":
        purpose, ref = event_scope(event)
        if ref != identity["ref"]:
            _refuse("context")
        requested = event.get("inputs", {}).get("validation_profile", "full")
        profile = validation_profile(requested)
        facts["caller"] = "ci-manual"
    else:
        _event_repository(event.get("repository"))
        if workflow == PUBLICATION_WORKFLOW:
            _publication_caller(event, identity, facts)
        elif identity["event"] == "pull_request":
            _pr_caller(event, identity, facts)
        else:
            _queue_caller(event, identity, facts)
    return {
        **facts,
        **{key: identity[key] for key in ("repository", "event", "ref", "workflowRef", "job")},
        "purpose": purpose,
        "validationProfile": profile,
        "validationProfileRequested": requested,
    }


def validate_pr_commit(commit: bytes, context: dict[str, str]) -> None:
    """Bind only PR candidates to ordered event base/head parents before tree reads."""
    if context["caller"] != "ci-pr":
        return
    header, delimiter, _message = commit.partition(b"\n\n")
    lines = header.split(b"\n")
    expected = [b"parent " + context[key].encode("ascii") for key in ("eventBaseSha", "eventHeadSha")]
    prefix_length = len(expected) + 1
    if (
        not delimiter
        or len(lines) < prefix_length
        or re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]) is None
        or lines[1:prefix_length] != expected
        or any(line.startswith(b"parent") for line in lines[prefix_length:])
    ):
        _refuse("context")


def _archived_event(context: dict[str, str]) -> dict:
    """Reconstruct only normalized root-bound facts for intrinsic archived validation."""
    event = {"repository": {"full_name": context["repository"]}, "workflow": context["workflowPath"]}
    caller = context["caller"]
    if caller == "ci-manual":
        event.update(ref=context["ref"], inputs={"validation_profile": context["validationProfileRequested"]})
    elif caller == "ci-pr":
        number = context["pullRequestNumber"]
        if re.fullmatch(r"[1-9][0-9]{0,19}", number) is None:
            _refuse("context")
        request = {"number": int(number)}
        for role in ("head", "base"):
            request[role] = {
                "repo": {"full_name": context[role + "Repository"]},
                "sha": context["event" + role.title() + "Sha"],
                "ref": context["event" + role.title() + "Ref"].removeprefix("refs/heads/"),
            }
        event.update(action=context["eventAction"], number=int(number), pull_request=request)
    elif caller == "ci-merge-group":
        event.update(
            action=context["eventAction"],
            merge_group={
                "head_sha": context["eventHeadSha"],
                "base_sha": context["eventBaseSha"],
                "head_ref": context["eventHeadRef"],
                "base_ref": context["eventBaseRef"],
            },
        )
    elif caller in {"publication-push", "publication-schedule", "publication-manual"}:
        event["repository"]["default_branch"] = context["defaultBranch"]
        if caller == "publication-push":
            event.update(ref=context["ref"], after=context["eventHeadSha"], deleted=False)
        elif caller == "publication-schedule":
            event["schedule"] = context["eventSchedule"]
        else:
            event.update(
                ref=context["ref"],
                inputs={"scope": context["publicationScope"], "target": context["publicationTarget"]},
            )
    else:
        _refuse("context")
    return event


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
            "maintainedCallers",
        }
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != ADMISSION_SCHEMA
        or value["consumer"] != CONSUMER
        or value["purpose"] != "scoped-prerequisite-attempt"
        or value["qualification"] != "none"
        or value["revision"] != ADMISSION_REVISION
        or value["architectures"] != {"amd64": "experimental-load-candidate", "arm64": "compile-only-refuse-load"}
        or value["maintainedArchitectures"] != {"amd64": "maintained-prerequisite", "arm64": "maintained-prerequisite"}
        or value["maintainedCallers"] != MAINTAINED_CALLERS
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
            context_keys
            if name == "context"
            else {"repository", "image", "imageOS", "imageVersion", "validationProfiles"}
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
    """Validate root-bound caller facts intrinsically, without current consumer environment."""
    context_digest(context)
    purpose = context["purpose"]
    if purpose not in {EXPERIMENTAL_PURPOSE, MAINTAINED_PURPOSE}:
        _refuse("context")
    expected = admission["maintainedContext"] if purpose == MAINTAINED_PURPOSE else admission["context"]
    identity = {key: context[key] for key in ("repository", "event", "ref", "workflowRef", "job", "candidate")}
    derived = caller_context(_archived_event(context), identity)
    if (
        any(context[key] != value for key, value in derived.items())
        or context["admissionRevision"] != admission["revision"]
        or context["admissionRevision"] != ADMISSION_REVISION
        or context["admissionSha256"] != admission_sha256
        or re.fullmatch(r"[0-9a-f]{64}", admission_sha256) is None
        or context["candidate"] != context["workflow"]
        or context["candidate"] != context["checkout"]
        or any(re.fullmatch(r"[1-9][0-9]{0,19}", context[key]) is None for key in ("run", "attempt"))
        or context["repository"] != expected["repository"]
        or context["repository"] != REPOSITORY
        or context["image"] != expected["image"]
        or context["image"] != "docker-29-conformance-rootless"
        or expected["imageOS"] != "ubuntu26"
        or context["architecture"] not in {"amd64", "arm64"}
        or context["imageOS"] != {"amd64": "ubuntu26", "arm64": "ubuntu26-arm64"}[context["architecture"]]
        or context["imageVersionKind"] != "workflow-reported-provenance-not-vm-attestation"
        or re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", context["imageVersion"]) is None
    ):
        _refuse("context")
    if purpose == MAINTAINED_PURPOSE:
        policy = admission["maintainedCallers"].get(context["caller"])
        if (
            policy is None
            or context["validationProfile"] not in expected["validationProfiles"]
            or admission["maintainedArchitectures"].get(context["architecture"]) != MAINTAINED_PURPOSE
            or (context["workflowPath"], context["event"], context["job"])
            != (policy["workflow"], policy["event"], policy["job"])
        ):
            _refuse("admission")
    elif (
        context["caller"] != "ci-manual"
        or context["workflowPath"] != expected["workflow"]
        or context["event"] != expected["event"]
        or context["job"] != expected["job"]
        or context["ref"] != expected["ref"]
        or context["validationProfile"] != expected["validationProfile"]
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
            or self.job not in NATIVE_JOBS
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
