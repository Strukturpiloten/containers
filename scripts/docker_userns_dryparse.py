"""Nonqualifying, hosted-PR-only AppArmor 5.0.2 compilation; never load policy."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts import docker_userns_policy_source as source

ROOT = Path(__file__).resolve().parents[1]
EVENT = Path("/home/runner/work/_temp/_github_workflow/event.json")
PARSER = Path("/usr/sbin/apparmor_parser")
ABI = Path("/etc/apparmor.d/abi/4.0")
STATUS = Path("/proc/self/status")
FACTS = {
    "apparmorEnabled": Path("/sys/module/apparmor/parameters/enabled"),
    "restrictUnprivilegedUserns": Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
    "namespaceMask": Path("/sys/kernel/security/apparmor/features/namespaces/mask"),
    "policyVersion9": Path("/sys/kernel/security/apparmor/features/policy/versions/v9"),
}
COMMON = (
    "--config-file=/dev/null",
    "--skip-cache",
    "--jobs=0",
    "--Werror=rule-not-enforced",
    "--Werror=rule-downgraded",
    "--Werror=abi",
    "--warn=all",
    "--Werror",
    "--base=/etc/apparmor.d",
    "--Include=/etc/apparmor.d",
)
COMPILE = (*COMMON, "--skip-kernel-load")
PARSER_EXEC = """\
if os.execve not in os.supports_fd:
    raise SystemExit(1)
descriptor = int(sys.argv[2])
os.set_inheritable(descriptor, False)
os.execve(descriptor, sys.argv[3:], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
"""
GIT_MERGE = """\
os.execve("/usr/bin/git", ["/usr/bin/git", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
    "--git-dir=" + sys.argv[2], "cat-file", "commit", sys.argv[3]],
    {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
     "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"})
"""
MAX_BINARY = 16 * 1024 * 1024
MAX_ARTIFACT = 128 * 1024
MAX_EVENT = 256 * 1024
MAX_TOOL_OUTPUT = 4096
MAX_MERGE_OBJECT = 8192
PULL_REQUEST = 492
CAPABILITIES = ("CapEff", "CapPrm", "CapInh", "CapAmb")
EXPECTED_CONTEXT = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
    "ImageOS": "ubuntu26",
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "Strukturpiloten/containers",
    "GITHUB_REF": "refs/pull/492/merge",
    "GITHUB_JOB": "userns-dryparse",
    "GITHUB_WORKFLOW_REF": "Strukturpiloten/containers/.github/workflows/ci.yml@refs/pull/492/merge",
    "GITHUB_EVENT_PATH": str(EVENT),
    "RUNNER_TEMP": str(EVENT.parent.parent),
}


def _status() -> dict[str, int]:
    raw = source.snapshot(STATUS, source.MAX_SOURCE, os.geteuid()).data
    result = {}
    for key in (*CAPABILITIES, "CapBnd", "NoNewPrivs", "Seccomp"):
        values = [line.split(b":", 1)[1].strip() for line in raw.splitlines() if line.startswith(key.encode() + b":")]
        source.need(len(values) == 1 and re.fullmatch(rb"[0-9a-fA-F]{1,16}", values[0]), "process-facts")
        result[key] = int(values[0], 16 if key.startswith("Cap") else 10)
    source.need(all(result[key] == 0 for key in CAPABILITIES), "process-capabilities")
    source.need(result["NoNewPrivs"] in (0, 1) and result["Seccomp"] in (0, 1, 2), "process-facts")
    return result


def _merge_parents(merge: str, base: str, head: str) -> None:
    output, status = source.bounded_child(
        GIT_MERGE,
        [str(ROOT / ".git"), merge],
        b"",
        time.monotonic() + 2.0,
        MAX_MERGE_OBJECT,
    )
    headers, separator, _message = output.partition(b"\n\n")
    lines = headers.splitlines()
    source.need(
        status == 0 and separator and lines and re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]), "checkout-candidate"
    )
    parents = [line.removeprefix(b"parent ") for line in lines if line.startswith(b"parent ")]
    source.need(parents == [base.encode("ascii"), head.encode("ascii")], "checkout-candidate")


def _context(environment: dict[str, str]) -> dict[str, Any]:
    source.need(os.geteuid() != 0, "root-refused")
    source.need(all(environment.get(key) == value for key, value in EXPECTED_CONTEXT.items()), "unsupported-context")
    source.need(re.fullmatch(r"[0-9.]{1,64}", environment.get("ImageVersion", "")), "runner-image")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        source.need(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")), "run-identity")
    source.need(source.COMMIT.fullmatch(environment.get("GITHUB_SHA", "")), "workflow-candidate")
    event = json.loads(source.snapshot(EVENT, MAX_EVENT, os.geteuid()).data, object_pairs_hook=source.unique_object)
    source.need(type(event) is dict and type(event.get("pull_request")) is dict, "event-schema")
    pull = event["pull_request"]
    source.need(event.get("number") == PULL_REQUEST and pull.get("number") == PULL_REQUEST, "event-pr")
    head, base = pull.get("head"), pull.get("base")
    source.need(type(head) is dict and type(base) is dict, "event-schema")
    for item in (head, base):
        source.need(
            type(item.get("repo")) is dict and item["repo"].get("full_name") == EXPECTED_CONTEXT["GITHUB_REPOSITORY"],
            "event-repository",
        )
    source.need(
        head.get("ref") == "TheRealBecks/issue442-main-reconciled"
        and type(head.get("sha")) is str
        and source.COMMIT.fullmatch(head["sha"]),
        "event-head",
    )
    source.need(type(base.get("sha")) is str and source.COMMIT.fullmatch(base["sha"]), "event-head")
    source.need(stat.S_ISDIR((ROOT / ".git").lstat().st_mode), "checkout-layout")
    checkout = source.snapshot(ROOT / ".git/HEAD", source.MAX_POLICY, os.geteuid())
    source.need(
        checkout.data.strip() == environment["GITHUB_SHA"].encode("ascii"),
        "checkout-candidate",
    )
    _merge_parents(environment["GITHUB_SHA"], base["sha"], head["sha"])
    source.recheck(checkout)
    kernel = os.uname()
    source.need(kernel.machine == "x86_64" and re.fullmatch(r"[A-Za-z0-9_.+-]{1,96}", kernel.release), "kernel-context")
    distribution = _root_file(Path("/usr/lib/os-release"), source.MAX_SOURCE).data
    source.need(
        b"ID=ubuntu" in distribution.splitlines() and b'VERSION_ID="26.04"' in distribution.splitlines(), "distribution"
    )
    return {
        "candidate": environment["GITHUB_SHA"],
        "workflowCandidate": environment["GITHUB_SHA"],
        "pullRequestHead": head["sha"],
        "pullRequestBase": base["sha"],
        "checkoutIdentity": "github-pr-merge",
        "workflowRun": environment["GITHUB_RUN_ID"],
        "attempt": environment["GITHUB_RUN_ATTEMPT"],
        "pullRequest": PULL_REQUEST,
        "kernel": {"release": kernel.release, "machine": kernel.machine},
        "runner": {"imageOS": "ubuntu26", "imageVersion": environment["ImageVersion"]},
        "collectorProcess": {"subject": "compile-job-process-not-guest", **_status()},
    }


def _root_parents(path: Path) -> None:
    current = Path("/")
    for part in path.parts[1:-1]:
        current /= part
        info = current.lstat()
        source.need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "unsafe-system-path")


def _root_file(path: Path, limit: int, *, executable: bool = False) -> source.HeldFile:
    _root_parents(path)
    return source.snapshot(path, limit, 0, executable=executable)


def _null() -> tuple[int, ...]:
    path = Path("/dev/null")
    _root_parents(path)
    info = path.lstat()
    source.need(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and info.st_rdev == os.makedev(1, 3), "config-null")
    return (*source.identity(info), info.st_rdev)


def _features() -> tuple[dict[str, Any], tuple[source.HeldFile, ...]]:
    held = {key: _root_file(path, 4096) for key, path in FACTS.items()}
    source.need(
        held["apparmorEnabled"].data == b"Y\n" and held["restrictUnprivilegedUserns"].data == b"1\n",
        "kernel-policy-context",
    )
    namespace = held["namespaceMask"].data
    source.need(
        re.fullmatch(rb"[a-z_ \n]{1,4096}", namespace)
        and b"userns_create" in namespace.split()
        and held["policyVersion9"].data == b"yes\n",
        "kernel-features",
    )
    return (
        {
            "apparmorEnabled": True,
            "restrictUnprivilegedUserns": 1,
            "namespaceMask": namespace.decode("ascii").split(),
            "policyVersion9": True,
            "files": {key: item.public() for key, item in held.items()},
        },
        tuple(held.values()),
    )


@dataclass(frozen=True)
class _Cohort:
    """Bind one open parser descriptor to the original ABI, features and config."""

    parser: source.HeldExecutable
    files: tuple[source.HeldFile, ...]
    config: tuple[int, ...]


def _stable(cohort: _Cohort) -> None:
    source.need(_null() == cohort.config, "config-changed")
    _root_parents(PARSER)
    cohort.parser.check()
    for item in cohort.files:
        source.need(_root_file(item.path, max(1, len(item.data))) == item, "cohort-changed")
    _status()


def _query(
    arguments: tuple[str, ...],
    data: bytes,
    deadline: float,
    cohort: _Cohort,
) -> tuple[bytes, int]:
    _stable(cohort)
    output, status = source.bounded_child(
        PARSER_EXEC,
        source.ExecutableCall(cohort.parser, (str(PARSER), *arguments)),
        data,
        deadline,
        MAX_TOOL_OUTPUT,
    )
    _stable(cohort)
    source.check(deadline)
    return output, status


def experiment(environment: dict[str, str], result: dict[str, Any]) -> None:
    """Compile only on this explicitly admitted PR host; no load-stage transition exists."""
    deadline = time.monotonic() + 30.0
    result["stage"] = "context"
    result["context"] = _context(environment)
    result["stage"] = "source-manifest"
    value = source.manifest()
    result["stage"] = "features"
    features, feature_files = _features()
    result["features"] = features
    result["stage"] = "parser"
    _root_parents(PARSER)
    with source.hold_executable(PARSER, MAX_BINARY, 0) as parser:
        result["parser"] = {"expectedVersion": value["parser"]["expectedVersion"], "executable": parser.file.public()}
        result["stage"] = "abi"
        abi = _root_file(ABI, source.MAX_SOURCE)
        result["abi4"] = {**abi.public(), "contentBase64": base64.b64encode(abi.data).decode("ascii")}
        result["stage"] = "config"
        cohort = _Cohort(parser, (abi, *feature_files), _null())
        _compile(environment, result, value, cohort, deadline)
    source.check(deadline)
    result["stage"] = "complete"
    result["outcome"] = "compiled-nonqualifying"


def _compile(
    environment: dict[str, str],
    result: dict[str, Any],
    value: dict[str, Any],
    cohort: _Cohort,
    deadline: float,
) -> None:
    result["stage"] = "parser-version"
    output, status = _query(
        ("--config-file=/dev/null", "--skip-cache", "--jobs=0", "--version"),
        b"",
        min(deadline, time.monotonic() + 2.0),
        cohort,
    )
    version = re.fullmatch(rb"AppArmor parser version (5\.0\.2)\n[^\x00]{0,4000}", output)
    source.need(status == 0 and version is not None, "parser-version")
    result["parser"]["observedVersion"] = version[1].decode("ascii")
    run, attempt = environment["GITHUB_RUN_ID"], environment["GITHUB_RUN_ATTEMPT"]
    name = f"dockerlens-127-upstream-rootless-{run}-{attempt}-{secrets.token_hex(16)}"
    with tempfile.TemporaryDirectory(prefix="containers-userns-dryparse-") as directory:
        result["stage"] = "source-custody"
        held = source.custody(Path(directory), value, min(deadline, time.monotonic() + 12.0))
        result["stage"] = "builder"
        policy = source.build(held, name, min(deadline, time.monotonic() + 3.0))
        result["source"] = {
            "repository": value["source"]["repository"],
            "ref": value["source"]["ref"],
            "commit": value["source"]["commit"],
            "license": value["source"]["license"],
            "files": value["source"]["files"],
        }
        result["policy"] = {
            "identifier": name,
            "namespaceAuthority": "identifier-only-not-dockerlens-consumer",
            "sha256": hashlib.sha256(policy).hexdigest(),
            "size": len(policy),
            "abi": "4.0",
        }
        result["compile"] = {"completion": "unknown", "outputBytes": None, "outputSha256": None}
        result["stage"] = "compile"
        output, status = _query(COMPILE, policy, min(deadline, time.monotonic() + 5.0), cohort)
        held.check()
    result["compile"] = {
        "completion": "observed",
        "exitStatus": status,
        "outputBytes": len(output),
        "outputSha256": hashlib.sha256(output).hexdigest(),
        "child": json.loads(source.CHILD_RECEIPT),
    }
    source.need(status == 0 and not output, "compile-refused")
    source.check(deadline)


def _cancel(_number: int, _frame: object) -> None:
    source.CANCELLED = True


def main() -> int:
    """Emit bounded, sanitized diagnostics; refusal is never positive admission."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "consumer": source.CONSUMER,
        "qualification": "none",
        "scope": "hostcompile-only",
        "outcome": "refused",
        "plannedFixture": "docker-20.10-rootless",
        "image_build_run": False,
        "bootstrap_run": False,
        "policy_load_run": False,
    }
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    previous_cancelled = source.CANCELLED
    source.CANCELLED = False
    try:
        for number in previous:
            signal.signal(number, _cancel)
        try:
            experiment(dict(os.environ), result)
            source.need(not source.CANCELLED, "cancelled")
        except source.RefusedError as error:
            result.update(outcome="refused", reason=str(error))
        except OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, urllib.error.URLError:
            result.update(outcome="refused", reason="unavailable")
        if source.CANCELLED:
            result.update(outcome="refused", reason="cancelled")
        body = (json.dumps(result, sort_keys=True) + "\n").encode("ascii")
        source.need(len(body) <= MAX_ARTIFACT, "artifact-bound")
        with args.output.open("xb") as output:
            output.write(body)
        return int(source.CANCELLED or result["outcome"] != "compiled-nonqualifying")
    except OSError, source.RefusedError:
        sys.stderr.write("compile-only diagnostic artifact unavailable\n")
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        source.CANCELLED = previous_cancelled


if __name__ == "__main__":
    raise SystemExit(main())
