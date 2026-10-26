"""Offline hostile Git proofs against the sole canonical root-bootstrap verifier."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import docker_userns_bootstrap_bundle as bundle

ROOT = Path(__file__).resolve().parents[1]


FULL_PROGRAM_BYTES = 17111
FULL_PROGRAM_SHA256 = "3aa48b3adef2d2e2e2f8824701053dba649f34a530fa4c50b6e3e35c9556f164"


def canonical_program() -> str:
    """Read the single canonical literal env carrier, including its terminal try/except."""
    text = (ROOT / ".github/workflow-templates/ci.yml.j2").read_text()
    begin = text.index("            # BEGIN FIXED USERNS ROOT BOOTSTRAP")
    end = text.index("        run: |\n", begin)
    return "".join(line.removeprefix("            ") for line in text[begin:end].splitlines(keepends=True))


def hosted_step() -> dict[str, object]:
    """Read the generated step as GitHub receives it, without executing any workflow code."""
    import yaml  # noqa: PLC0415 - existing locked dependency.

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    return next(
        step
        for step in workflow["jobs"]["userns-custody-unused"]["steps"]
        if step["name"] == "Observe two real hosted unused ownership cycles"
    )


def canonical_bootstrap() -> dict[str, object]:
    """Compile definitions from the canonical carrier; never execute terminal root_main."""
    program = canonical_program()
    code = program[: program.index("# END FIXED USERNS ROOT BOOTSTRAP")]
    scope = {}
    exec(compile(code, "<canonical-root-bootstrap>", "exec"), scope)  # noqa: S102 - repository's exact inert functions.
    return scope


def git_id(kind: str, data: bytes) -> str:
    """Independently frame Git's content-addressed object identity."""
    return hashlib.sha1(
        kind.encode() + b" " + str(len(data)).encode() + b"\0" + data,
        usedforsecurity=False,
    ).hexdigest()


class Proof:
    def __init__(self, *, mode: bytes = b"100644", traversal: bool = False) -> None:
        """Build a connected synthetic Git DAG without invoking Git or network."""
        self.objects = {}
        self.head, self.base = "b" * 40, "c" * 40
        self.context = {
            "candidate": "",
            "head": self.head,
            "base": self.base,
            "run": "1",
            "attempt": "1",
            "imageOS": "ubuntu26",
            "imageVersion": "20261023.163.3",
        }
        self.files = {path: (ROOT / path).read_bytes() for path in bundle.FILES}
        self.sources = {
            "scripts/native-runner-apparmor.py": b"inert builder",
            "scripts/native_outer_diagnostic_capture.py": b"inert capture",
            "LICENSE": b"inert license",
        }
        manifest = json.loads(self.files[bundle.MANIFEST])
        manifest["source"]["files"] = [
            {"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for path, raw in self.sources.items()
        ]
        self.files[bundle.MANIFEST] = json.dumps(manifest).encode()
        nested = {}
        for path, data in self.files.items():
            directory, name = path.split("/")
            nested.setdefault(directory, {})[name] = data
        root_entries = []
        for directory, files in sorted(nested.items()):
            entries = []
            for name, data in sorted(files.items()):
                actual_mode = mode if name == "docker_userns_hosted.py" else b"100644"
                actual_name = "../escape" if traversal and name == "docker_userns_hosted.py" else name
                entries.append(
                    actual_mode + b" " + actual_name.encode() + b"\0" + bytes.fromhex(self.add("blob", data))
                )
            root_entries.append(
                b"40000 " + directory.encode() + b"\0" + bytes.fromhex(self.add("tree", b"".join(entries)))
            )
        tree = self.add("tree", b"".join(root_entries))
        self.candidate = self.add(
            "commit",
            f"tree {tree}\nparent {self.base}\nparent {self.head}\n"
            "author Test <test@example.invalid> 1 +0000\n"
            "committer Test <test@example.invalid> 1 +0000\n\nunused fixture\n".encode(),
        )
        self.context["candidate"] = self.candidate
        self.context.update(
            {
                "workflow": self.candidate,
                "checkout": self.candidate,
                "repository": "Strukturpiloten/containers",
                "job": "userns-custody-unused",
                "checkoutIdentity": "github-pr-merge",
                "deadlineNs": 240000000000,
            }
        )

    def add(self, kind: str, raw: bytes) -> str:
        identifier = git_id(kind, raw)
        self.objects[identifier] = {"oid": identifier, "kind": kind, "data": base64.b64encode(raw).decode()}
        return identifier

    def value(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "context": self.context,
            "objects": list(self.objects.values()),
            "sources": [{"path": path, "data": base64.b64encode(raw).decode()} for path, raw in self.sources.items()],
        }


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = canonical_bootstrap()
        self.verify = self.scope["verify_bundle"]
        self.proof = Proof()

    def check(self, value: dict[str, object] | None = None) -> object:
        return self.verify(
            json.dumps(value or self.proof.value()).encode(), self.proof.candidate, self.proof.head, self.proof.base
        )

    def test_connected_merge_tree_blob_proof_returns_exact_selected_closure(self) -> None:
        context, files, sources = self.check()
        self.assertEqual(context, self.proof.context)
        self.assertEqual(files, self.proof.files)
        self.assertEqual(sources, self.proof.sources)
        self.assertEqual(tuple(self.scope["CLOSED_FILES"]), bundle.FILES)

    def test_unprivileged_collector_produces_the_same_connected_proof(self) -> None:
        lookup = {oid: (item["kind"], base64.b64decode(item["data"])) for oid, item in self.proof.objects.items()}
        with patch.object(bundle, "git_object", side_effect=lambda _kind, oid: lookup[oid][1]):
            collected = bundle.proof(self.proof.candidate)
        value = self.proof.value()
        value["objects"] = collected
        self.check(value)

    def test_rehashed_substitute_blob_cannot_change_selected_commit_authority(self) -> None:
        value = self.proof.value()
        target = next(
            item
            for item in value["objects"]
            if item["kind"] == "blob"
            and base64.b64decode(item["data"]) == self.proof.files["scripts/docker_userns_hosted.py"]
        )
        target["data"] = base64.b64encode(b"print('forged root code')").decode()
        target["oid"] = git_id("blob", b"print('forged root code')")
        with self.assertRaises(ValueError):
            self.check(value)

    def test_duplicate_unconnected_wrong_kind_and_wrong_size_objects_refuse(self) -> None:
        original = self.proof.value()
        cases = []
        duplicate = copy.deepcopy(original)
        duplicate["objects"].append(duplicate["objects"][0])
        cases.append(duplicate)
        extra = copy.deepcopy(original)
        raw = b"unconnected"
        extra["objects"].append({"oid": git_id("blob", raw), "kind": "blob", "data": base64.b64encode(raw).decode()})
        cases.append(extra)
        wrong_kind = copy.deepcopy(original)
        wrong_kind["objects"][0]["kind"] = "tree"
        cases.append(wrong_kind)
        too_big = copy.deepcopy(original)
        too_big["objects"][0]["data"] = base64.b64encode(b"x" * 262145).decode()
        cases.append(too_big)
        for value in cases:
            with self.subTest(case=len(value["objects"])), self.assertRaises(ValueError):
                self.check(value)

    def test_selected_candidate_and_ordered_event_parents_are_authoritative(self) -> None:
        for candidate, head, base in (
            ("a" * 40, self.proof.head, self.proof.base),
            (self.proof.candidate, self.proof.base, self.proof.head),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.verify(json.dumps(self.proof.value()).encode(), candidate, head, base)

    def test_symlink_submodule_executable_and_traversal_closure_refuse(self) -> None:
        for mode in (b"120000", b"160000", b"100755", b"040000"):
            proof = Proof(mode=mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.verify(json.dumps(proof.value()).encode(), proof.candidate, proof.head, proof.base)
        proof = Proof(traversal=True)
        with self.assertRaises(ValueError):
            self.verify(json.dumps(proof.value()).encode(), proof.candidate, proof.head, proof.base)

    def test_duplicate_json_extra_fields_and_changed_sdk_source_refuse(self) -> None:
        raw = json.dumps(self.proof.value()).encode()
        with self.assertRaises(ValueError):
            self.verify(raw[:-1] + b',"schemaVersion":1}', self.proof.candidate, self.proof.head, self.proof.base)
        value = self.proof.value()
        value["authorizationHashes"] = []
        with self.assertRaises(ValueError):
            self.check(value)
        value = self.proof.value()
        value["sources"][0]["data"] = base64.b64encode(b"wrong source").decode()
        with self.assertRaises(ValueError):
            self.check(value)

    def test_input_symlink_and_hardlink_refuse_without_reading_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input"
            target.write_bytes(b"inert")
            linked = Path(directory) / "linked"
            linked.symlink_to(target)
            with self.assertRaises(OSError):
                self.scope["read_input"](linked, os.getuid(), 100, time.monotonic_ns() + 1_000_000_000)
            linked.unlink()
            linked.hardlink_to(target)
            with self.assertRaises(ValueError):
                self.scope["read_input"](target, os.getuid(), 100, time.monotonic_ns() + 1_000_000_000)

    def test_handoff_open_is_nonblocking_and_rejects_special_type_before_read(self) -> None:
        info = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_nlink=1, st_uid=os.getuid(), st_size=0)
        with (
            patch.object(os, "open", return_value=12345) as opened,
            patch.object(os, "fstat", return_value=info),
            patch.object(os, "read") as read,
            patch.object(os, "close") as closed,
            self.assertRaises(ValueError),
        ):
            self.scope["read_input"]("inert-input", os.getuid(), 100, time.monotonic_ns() + 1_000_000_000)
        self.assertTrue(opened.call_args.args[1] & os.O_NONBLOCK)
        self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        read.assert_not_called()
        closed.assert_called_once_with(12345)

    def test_actual_nonroot_fifo_refusal_is_bounded_without_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "handoff"
            os.mkfifo(fifo, 0o600)
            script = (
                "import os,sys,time;from pathlib import Path;"
                "text=Path(sys.argv[1]).read_text();"
                "a=text.index('            # BEGIN FIXED USERNS ROOT BOOTSTRAP');"
                "b=text.index('            # END FIXED USERNS ROOT BOOTSTRAP',a);scope={};"
                "code=chr(10).join(line.removeprefix('            ') for line in text[a:b].splitlines());"
                "exec(compile(code,'<fixed-bootstrap>','exec'),scope);"
                "\ntry: scope['read_input'](sys.argv[2],os.getuid(),100,time.monotonic_ns()+1000000000)"
                "\nexcept ValueError: print('refused')"
                "\nelse: raise SystemExit(1)"
            )
            result = subprocess.run(  # noqa: S603 - inert nonroot FIFO control, fixed script and deadline.
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    script,
                    str(ROOT / ".github/workflow-templates/ci.yml.j2"),
                    str(fifo),
                ],
                capture_output=True,
                timeout=2,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"refused\n")

    def test_expired_input_is_refused_before_open_and_late_read_cannot_return_success(self) -> None:
        with patch.object(os, "open") as opened, self.assertRaises(ValueError):
            self.scope["read_input"]("inert", os.getuid(), 100, time.monotonic_ns())
        opened.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "regular"
            path.write_bytes(b"inert")
            deadline = time.monotonic_ns() + 1_000_000_000
            original = os.read

            def late(descriptor: int, size: int) -> bytes:
                result = original(descriptor, size)
                self.scope["time"].monotonic_ns = lambda: deadline
                return result

            with (
                patch.object(os, "read", side_effect=late),
                patch.object(time, "monotonic_ns", return_value=deadline - 1),
                self.assertRaises(ValueError),
            ):
                self.scope["read_input"](path, os.getuid(), 100, deadline)

    def test_root_interpreter_trust_checks_intermediate_symlink_components(self) -> None:
        link = stat.S_IFLNK | 0o777
        directory = stat.S_IFDIR | 0o755

        def metadata(path: Path) -> SimpleNamespace:
            if str(path) == "/usr/bin/python3":
                return SimpleNamespace(st_uid=0, st_mode=link)
            if str(path) == "/untrusted":
                return SimpleNamespace(st_uid=1000, st_mode=directory)
            return SimpleNamespace(st_uid=0, st_mode=directory)

        with (
            patch.object(Path, "lstat", autospec=True, side_effect=metadata),
            patch.object(os, "readlink", return_value="/untrusted/../usr/bin/python3.14"),
            self.assertRaises(ValueError),
        ):
            self.scope["trusted_path"]("/usr/bin/python3")
        with (
            patch.object(Path, "lstat", autospec=True, side_effect=metadata),
            patch.object(os, "readlink", return_value="python3"),
            self.assertRaises(ValueError),
        ):
            self.scope["trusted_path"]("/usr/bin/python3")

    def test_root_imports_are_stdlib_or_the_verified_closed_package(self) -> None:
        allowed = {Path(path).stem for path in bundle.FILES if path.startswith("scripts/")}
        for path in bundle.FILES:
            if not path.endswith(".py"):
                continue
            tree = ast.parse((ROOT / path).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        self.assertIn(item.name.split(".")[0], sys.stdlib_module_names, (path, item.name))
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module == "scripts":
                        self.assertTrue(all(item.name in allowed for item in node.names), path)
                    else:
                        self.assertIn(node.module.split(".")[0], sys.stdlib_module_names, (path, node.module))

    def test_reused_pins_have_one_existing_owner_and_manual_admission_is_not_auto_rewritten(self) -> None:
        config = json.loads((ROOT / ".github/renovate.json").read_text())
        managers = [
            item
            for item in config["customManagers"]
            if any("docker-userns-policy-source" in value for value in item["managerFilePatterns"])
        ]
        self.assertEqual(len(managers), 2)
        self.assertEqual({item["datasourceTemplate"] for item in managers}, {"github-digest", "gitlab-tags"})
        self.assertTrue(all("unused-admission" not in json.dumps(item["managerFilePatterns"]) for item in managers))
        rule = next(
            item
            for item in config["packageRules"]
            if ".github/docker-userns-policy-source.json" in item.get("matchFileNames", [])
        )
        self.assertTrue(rule["dependencyDashboardApproval"])
        self.assertFalse(rule["automerge"])
        self.assertIn("manually re-admit", rule["description"])

    def test_literal_env_carrier_preserves_full_executed_program_and_source_boundaries(self) -> None:
        step = hosted_step()
        program, run = step["env"]["FIXED_ROOT_BOOTSTRAP"], step["run"]
        self.assertEqual(program, canonical_program())
        self.assertEqual(len(program.encode()), FULL_PROGRAM_BYTES)
        self.assertEqual(hashlib.sha256(program.encode()).hexdigest(), FULL_PROGRAM_SHA256)
        self.assertNotIn("${{", program)
        self.assertNotIn("\0", program)
        self.assertNotIn("BEGIN FIXED USERNS ROOT BOOTSTRAP", run)
        self.assertNotIn("<<", run)
        self.assertIn("FIXED_ROOT_BOOTSTRAP: |", (ROOT / ".github/workflow-templates/ci.yml.j2").read_text())
        tree = ast.parse(program)
        self.assertTrue(any(isinstance(node, ast.Try) for node in tree.body))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == "__file__" for node in ast.walk(tree)))
        self.assertFalse(
            any(
                isinstance(node, ast.Attribute)
                and node.attr == "stdin"
                and isinstance(node.value, ast.Name)
                and node.value.id == "sys"
                for node in ast.walk(tree)
            )
        )
        self.assertLess(len(run.encode()), 8192)
        self.assertLess(run.index("${FIXED_ROOT_BOOTSTRAP:-}"), run.index("readonly FIXED_ROOT_BOOTSTRAP"))
        self.assertLess(run.index("readonly FIXED_ROOT_BOOTSTRAP"), run.index("uv run"))
        self.assertIn('capture_unused_artifact < /dev/null > "${artifact}"', run)
        self.assertEqual(run.count("sudo --"), 1)

    def inert_step(
        self, directory: Path, *, status: int = 0, program: str | None = None, mutation: bool = False
    ) -> tuple[subprocess.CompletedProcess[bytes], Path, Path, Path, Path]:
        """Run short Bash with builtin-only workspace/privilege shims and hostile parent stdin."""
        artifact = directory / "docker-userns-custody-unused.json"
        argv_file, after, workspace = directory / "argv", directory / "after", directory / "workspace"
        shim = r"""set -euo pipefail
uv() {
  printf called > "${PROBE_WORKSPACE}"
  if [[ "${PROBE_MUTATE}" == 1 ]]; then
    FIXED_ROOT_BOOTSTRAP=changed
  fi
}
id() {
  case "$1" in
    -u) printf '%s\n' "${PROBE_UID}" ;;
    -g) printf '%s\n' "${PROBE_GID}" ;;
    *) return 94 ;;
  esac
}
sudo() {
  [[ -e "${artifact}" && -O "${artifact}" ]] || return 92
  if IFS= read -r probe_line; then return 93; fi
  printf '%s\0' "$@" > "${PROBE_ARGV}"
  printf 'fixed-root-output\n'
  printf 'shim-stderr\n' >&2
  return "${PROBE_STATUS}"
}
"""
        script = shim + hosted_step()["run"] + 'printf continued > "${PROBE_AFTER}"\n'
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "RUNNER_TEMP": str(directory),
            "PYTHON_VERSION": "3.14",
            "SELECTED_MERGE": "a" * 40,
            "GITHUB_EVENT_PATH": "event with spaces",
            "GITHUB_RUN_ID": "17",
            "GITHUB_RUN_ATTEMPT": "2",
            "ImageVersion": "20261023.163.3",
            "WORKFLOW_CANDIDATE": "b" * 40,
            "PROBE_UID": str(os.getuid()),
            "PROBE_GID": str(os.getgid()),
            "PROBE_STATUS": str(status),
            "PROBE_MUTATE": "1" if mutation else "0",
            "PROBE_ARGV": str(argv_file),
            "PROBE_AFTER": str(after),
            "PROBE_WORKSPACE": str(workspace),
        }
        if program is not None:
            environment["FIXED_ROOT_BOOTSTRAP"] = program
        result = subprocess.run(  # noqa: S603 - inert Bash functions never dispatch sudo, uv or Python.
            ["/bin/bash", "-c", script],
            env=environment,
            input=b"unexpected-parent-stdin\n",
            capture_output=True,
            timeout=2,
            check=False,
        )
        return result, artifact, argv_file, after, workspace

    def test_caller_capture_passes_one_quoted_program_exact_args_and_stdin_eof(self) -> None:
        program = canonical_program()
        for status in (0, 37):
            with tempfile.TemporaryDirectory(prefix="containers-bootstrap space ") as directory:
                target = Path(directory)
                result, artifact, argv_file, after, workspace = self.inert_step(target, status=status, program=program)
                expected = [
                    "--",
                    "/usr/bin/env",
                    "-i",
                    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG=C",
                    "LC_ALL=C",
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    program,
                    str(target / "docker-userns-custody-bundle.json"),
                    "a" * 40,
                    "event with spaces",
                    str(os.getuid()),
                    str(os.getgid()),
                    "17",
                    "2",
                    "20261023.163.3",
                    "b" * 40,
                ]
                with self.subTest(status=status):
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(artifact.stat().st_uid, os.getuid())
                    self.assertEqual(artifact.read_bytes(), b"fixed-root-output\n")
                    self.assertEqual(argv_file.read_bytes().split(b"\0")[:-1], [value.encode() for value in expected])
                    self.assertEqual(after.exists(), status == 0)
                    self.assertTrue(workspace.exists())
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"shim-stderr\n")

    def test_missing_or_empty_program_refuses_before_workspace_or_privileged_command(self) -> None:
        for program in (None, ""):
            with tempfile.TemporaryDirectory() as directory:
                result, artifact, argv_file, after, workspace = self.inert_step(Path(directory), program=program)
                with self.subTest(program=program):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"Fixed root bootstrap is required", result.stderr)
                    self.assertFalse(artifact.exists())
                    self.assertFalse(workspace.exists())
                    self.assertFalse(argv_file.exists())
                    self.assertFalse(after.exists())

    def test_workspace_cannot_reassign_readonly_program_before_root_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, _artifact, argv_file, after, workspace = self.inert_step(
                Path(directory), program=canonical_program(), mutation=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"readonly variable", result.stderr)
            self.assertTrue(workspace.exists())
            self.assertFalse(argv_file.exists())
            self.assertFalse(after.exists())

    def test_job_is_merge_only_without_secret_credentials_or_privileged_uv(self) -> None:
        import yaml  # noqa: PLC0415 - use the project's existing locked test dependency.

        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["userns-custody-unused"]
        self.assertEqual(job["timeout-minutes"], 5)
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("secrets", json.dumps(job))
        checkout = next(step for step in job["steps"] if step["name"] == "Check out owned PR merge candidate")
        self.assertNotIn("ref", checkout["with"])
        self.assertFalse(checkout["with"]["persist-credentials"])
        run = next(
            step["run"] for step in job["steps"] if step["name"] == "Observe two real hosted unused ownership cycles"
        )
        self.assertIn("/usr/bin/env -i", run)
        self.assertIn("/usr/bin/python3 -I -B -S -", run)
        program = hosted_step()["env"]["FIXED_ROOT_BOOTSTRAP"]
        before_verified_exec = program[: program.index("result = capture_observer")]
        self.assertNotIn('subprocess.run(["git"', before_verified_exec)
        self.assertIn("verify_bundle(read_input", before_verified_exec)
        self.assertEqual(program.count("BEGIN FIXED USERNS ROOT BOOTSTRAP"), 1)
        ast.parse(program)


if __name__ == "__main__":
    unittest.main()
