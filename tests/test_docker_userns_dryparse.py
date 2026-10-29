"""Stage 1 can report compilation only, never policy loading or runtime acceptance."""

from __future__ import annotations

import copy
import errno
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from scripts import docker_userns_dryparse as dry
from scripts import docker_userns_policy_source as source

HEAD = "a" * 40
MERGE = "b" * 40
BASE = "d" * 40
MERGE_OBJECT = (
    f"tree {'e' * 40}\nparent {BASE}\nparent {HEAD}\n"
    "author private-author <private@example.invalid> 0 +0000\n\nprivate message\n"
).encode("ascii")
NONCE = "c" * 32
NAME = "dockerlens-127-upstream-rootless-123-2-" + NONCE
POLICY = f"abi <abi/4.0>,\nprofile {NAME} flags=(unconfined) {{\n  userns,\n}}\n".encode("ascii")
CONTEXT = {
    **dry.EXPECTED_CONTEXT,
    "GITHUB_SHA": MERGE,
    "GITHUB_RUN_ID": "123",
    "GITHUB_RUN_ATTEMPT": "2",
    "ImageVersion": "20261020.1.0",
}
EVENT = {
    "number": 492,
    "pull_request": {
        "number": 492,
        "head": {
            "ref": "TheRealBecks/issue442-main-reconciled",
            "sha": HEAD,
            "repo": {"full_name": "Strukturpiloten/containers"},
        },
        "base": {"sha": BASE, "repo": {"full_name": "Strukturpiloten/containers"}},
    },
}


def held(path: Path, data: bytes) -> source.HeldFile:
    """Private synthetic custody; no kernel or system-tool file is read."""
    return source.HeldFile(path, data, (1, 2, 0, 0, stat.S_IFREG | 0o644, 1, len(data), 3, 4))


class ContextTests(unittest.TestCase):
    def test_head_or_unrelated_actual_checkout_refuses_before_git_or_parser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            for actual in (HEAD, "f" * 40, "refs/heads/main"):

                def snapshot(
                    path: Path, _limit: int, _owner: int, _actual: str = actual, **_options: object
                ) -> source.HeldFile:
                    return held(path, json.dumps(EVENT).encode() if path == dry.EVENT else _actual.encode())

                with (
                    self.subTest(actual=actual),
                    patch.object(dry, "ROOT", root),
                    patch.object(source.os, "geteuid", return_value=1000),
                    patch.object(source, "snapshot", side_effect=snapshot),
                    patch.object(source, "bounded_child") as child,
                    self.assertRaisesRegex(source.RefusedError, "checkout-candidate"),
                ):
                    dry._context(CONTEXT)
                child.assert_not_called()

    def test_checkout_drift_after_merge_proof_refuses_before_host_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            values = iter((MERGE, HEAD))

            def snapshot(path: Path, _limit: int, _owner: int, **_options: object) -> source.HeldFile:
                return held(path, json.dumps(EVENT).encode() if path == dry.EVENT else next(values).encode())

            with (
                patch.object(dry, "ROOT", root),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source, "snapshot", side_effect=snapshot),
                patch.object(source, "bounded_child", return_value=(MERGE_OBJECT, 0)),
                patch.object(dry.os, "uname") as kernel,
                self.assertRaisesRegex(source.RefusedError, "file-changed"),
            ):
                dry._context(CONTEXT)
            kernel.assert_not_called()

    def test_merge_parent_proof_rejects_false_pairs_and_git_failures(self) -> None:
        for output, status in (
            (MERGE_OBJECT, 1),
            (b"", 0),
            (MERGE_OBJECT.replace(HEAD.encode(), ("f" * 40).encode()), 0),
            (
                MERGE_OBJECT.replace(BASE.encode(), HEAD.encode()).replace(
                    b"parent " + HEAD.encode() + b"\nparent " + HEAD.encode(),
                    b"parent " + HEAD.encode() + b"\nparent " + BASE.encode(),
                ),
                0,
            ),
            (MERGE_OBJECT.replace(b"parent " + HEAD.encode() + b"\n", b""), 0),
            (f"tree {'e' * 40}\n\nparent {BASE}\nparent {HEAD}\n".encode(), 0),
        ):
            with (
                self.subTest(output=output, status=status),
                patch.object(source, "bounded_child", return_value=(output, status)),
                self.assertRaisesRegex(source.RefusedError, "checkout-candidate"),
            ):
                dry._merge_parents(MERGE, BASE, HEAD)
        with patch.object(source, "bounded_child", return_value=(MERGE_OBJECT, 0)):
            dry._merge_parents(MERGE, BASE, HEAD)
        child_os = MagicMock()
        exec(  # noqa: S102 - fixed readonly Git stub; execution is mocked.
            dry.GIT_MERGE,
            {
                "os": child_os,
                "sys": SimpleNamespace(argv=["wrapper", "receipt", "/owned/.git", MERGE]),
            },
        )
        argv = child_os.execve.call_args.args[1]
        environment = child_os.execve.call_args.args[2]
        self.assertEqual(
            argv,
            [
                "/usr/bin/git",
                "--no-pager",
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--git-dir=/owned/.git",
                "cat-file",
                "commit",
                MERGE,
            ],
        )
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")

    def test_actual_merge_checkout_and_source_checked_head_are_bound_as_distinct_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()

            def snapshot(path: Path, _limit: int, _owner: int, **_options: object) -> source.HeldFile:
                return held(path, json.dumps(EVENT).encode() if path == dry.EVENT else MERGE.encode())

            with (
                patch.object(dry, "ROOT", root),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source, "snapshot", side_effect=snapshot),
                patch.object(source, "bounded_child", return_value=(MERGE_OBJECT, 0)) as child,
                patch.object(
                    dry,
                    "_root_file",
                    return_value=held(Path("/usr/lib/os-release"), b'ID=ubuntu\nVERSION_ID="26.04"\n'),
                ),
                patch.object(dry, "_status", return_value={"CapEff": 0}),
                patch.object(
                    dry.os,
                    "uname",
                    return_value=SimpleNamespace(machine="x86_64", release="7.0.0-test", nodename="private-host"),
                ),
            ):
                result = dry._context(CONTEXT)
        self.assertEqual(result["candidate"], MERGE)
        self.assertEqual(result["workflowCandidate"], MERGE)
        self.assertEqual(result["pullRequestHead"], HEAD)
        self.assertEqual(result["pullRequestBase"], BASE)
        self.assertEqual(result["checkoutIdentity"], "github-pr-merge")
        self.assertEqual(child.call_args.args[:3], (dry.GIT_MERGE, [str(root / ".git"), MERGE], b""))
        self.assertEqual(result["collectorProcess"]["subject"], "compile-job-process-not-guest")
        self.assertNotIn("private-host", json.dumps(result))
        self.assertNotIn("private-author", json.dumps(result))

    def test_wrong_consumer_context_architecture_event_or_root_never_starts_child(self) -> None:
        with (
            patch.object(source.os, "geteuid", return_value=0),
            self.assertRaisesRegex(source.RefusedError, "root-refused"),
        ):
            dry._context(CONTEXT)
        for key in dry.EXPECTED_CONTEXT:
            with (
                self.subTest(key=key),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source, "bounded_child") as child,
                self.assertRaisesRegex(source.RefusedError, "unsupported-context"),
            ):
                dry._context({**CONTEXT, key: "wrong"})
            child.assert_not_called()

    def test_wrong_pr_fork_ref_candidate_and_duplicate_event_keys_refuse(self) -> None:
        variants = []
        for key, replacement in (("number", 493), ("number", "492")):
            value = copy.deepcopy(EVENT)
            value[key] = replacement
            variants.append(json.dumps(value).encode())
        for key, replacement in (("ref", "unreviewed"), ("sha", MERGE), ("repo", {"full_name": "other/containers"})):
            value = copy.deepcopy(EVENT)
            value["pull_request"]["head"][key] = replacement
            variants.append(json.dumps(value).encode())
        variants.append(b'{"number":492,"number":492}')
        for raw in variants:
            with (
                self.subTest(raw=raw),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source, "snapshot", return_value=held(dry.EVENT, raw)),
                self.assertRaises(source.RefusedError),
            ):
                dry._context(CONTEXT)

    def test_active_capabilities_or_ambiguous_process_status_refuse(self) -> None:
        fields = b"CapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\nCapBnd:\tffffffff\nNoNewPrivs:\t0\nSeccomp:\t2\n"
        with patch.object(source, "snapshot", return_value=held(dry.STATUS, fields)):
            self.assertEqual(dry._status()["CapEff"], 0)
            self.assertGreater(dry._status()["CapBnd"], 0)
        for raw in (
            fields.replace(b"CapEff:\t0", b"CapEff:\t1"),
            fields + b"CapEff:\t0\n",
            fields.replace(b"CapAmb:\t0", b"CapAmb:\t1"),
        ):
            with (
                patch.object(source, "snapshot", return_value=held(dry.STATUS, raw)),
                self.assertRaises(source.RefusedError),
            ):
                dry._status()


class ParserTests(unittest.TestCase):
    def test_replacing_parser_name_after_hold_cannot_redirect_execution_and_still_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parser"
            original, replacement = b"\x7fELForiginal-inert", b"\x7fELFreplacement-inert"
            path.write_bytes(original)
            path.chmod(0o700)
            calls = []

            def simulated_exec(descriptor: int, argv: list[str], environment: dict[str, str]) -> None:
                self.assertIs(type(descriptor), int)
                calls.append((descriptor, argv, environment))
                self.assertEqual(os.pread(descriptor, source.MAX_SOURCE, 0), original)
                self.assertEqual(path.read_bytes(), replacement)

            child_os = SimpleNamespace(execve=simulated_exec, supports_fd={simulated_exec}, set_inheritable=MagicMock())

            def child(_code: str, arguments: source.ExecutableCall, data: bytes, *_rest: object) -> tuple[bytes, int]:
                self.assertEqual(data, POLICY)
                substitute = Path(directory) / "replacement"
                substitute.write_bytes(replacement)
                substitute.chmod(0o700)
                path.rename(Path(directory) / "retained-original")
                substitute.replace(path)
                context = {
                    "os": child_os,
                    "sys": SimpleNamespace(
                        argv=["wrapper", "receipt", str(arguments.executable.descriptor), *arguments.argv]
                    ),
                }
                exec(dry.PARSER_EXEC, context)  # noqa: S102 - fixed FD-exec stub with parser/kernel calls mocked.
                return b"", 0

            with (
                patch.object(source.os, "getxattr", side_effect=OSError(errno.ENODATA, "private")),
                patch.object(dry, "_root_parents"),
                patch.object(dry, "_null", return_value=(1,)),
                patch.object(dry, "_status", return_value={}),
                patch.object(source, "bounded_child", side_effect=child),
                self.assertRaises(source.RefusedError),
                source.hold_executable(path, source.MAX_SOURCE, os.geteuid()) as parser,
            ):
                descriptor = parser.descriptor
                dry._query(dry.COMPILE, POLICY, time.monotonic() + 1, dry._Cohort(parser, (), (1,)))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], descriptor)
            self.assertEqual(calls[0][1], [str(dry.PARSER), *dry.COMPILE])
            self.assertEqual(child_os.set_inheritable.call_args.args, (descriptor, False))
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_child_fd_exec_unavailable_or_rejected_has_no_pathname_retry(self) -> None:
        for supported in (False, True):
            child_os = MagicMock()
            child_os.execve.side_effect = NotImplementedError
            child_os.supports_fd = {child_os.execve} if supported else set()
            with self.subTest(supported=supported), self.assertRaises(NotImplementedError if supported else SystemExit):
                exec(  # noqa: S102 - fixed stub; no real exec or kernel operation.
                    dry.PARSER_EXEC,
                    {
                        "os": child_os,
                        "sys": SimpleNamespace(argv=["wrapper", "receipt", "17", str(dry.PARSER), "--version"]),
                    },
                )
            if supported:
                child_os.execve.assert_called_once_with(17, [str(dry.PARSER), "--version"], source.ENVIRONMENT)
                self.assertEqual(child_os.set_inheritable.call_args.args, (17, False))
            else:
                child_os.execve.assert_not_called()
                child_os.set_inheritable.assert_not_called()

    def test_exact_strict_compile_contract_has_no_loading_cache_or_feature_override(self) -> None:
        self.assertEqual(
            dry.COMPILE,
            (
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
                "--skip-kernel-load",
            ),
        )
        self.assertNotIn("--jobs=1", dry.COMPILE)
        self.assertTrue({"--warn=all", "--Werror", "--Werror=abi", "--Werror=rule-downgraded"} <= set(dry.COMPILE))
        for forbidden in ("--add", "--replace", "--remove", "--override-policy-abi", "--features-file"):
            self.assertNotIn(forbidden, dry.COMPILE)

    def test_kernel_features_are_fresh_exact_and_missing_or_unknown_features_refuse(self) -> None:
        data = {
            "apparmorEnabled": b"Y\n",
            "restrictUnprivilegedUserns": b"1\n",
            "namespaceMask": b"userns_create\n",
            "policyVersion9": b"yes\n",
        }

        def snapshot(path: Path, _limit: int) -> source.HeldFile:
            key = next(key for key, item in dry.FACTS.items() if item == path)
            return held(path, data[key])

        with patch.object(dry, "_root_file", side_effect=snapshot):
            facts, files = dry._features()
            self.assertEqual(facts["namespaceMask"], ["userns_create"])
            self.assertEqual({item.path for item in files}, set(dry.FACTS.values()))
            for key, replacement in (
                ("namespaceMask", b""),
                ("policyVersion9", b"no\n"),
                ("apparmorEnabled", b"N\n"),
                ("restrictUnprivilegedUserns", b"0\n"),
            ):
                original = data[key]
                data[key] = replacement
                with self.subTest(key=key), self.assertRaises(source.RefusedError):
                    dry._features()
                data[key] = original

    def test_system_path_symlinks_writable_ancestors_and_wrong_null_refuse(self) -> None:
        unsafe = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        with (
            patch.object(Path, "lstat", return_value=unsafe),
            self.assertRaisesRegex(source.RefusedError, "unsafe-system-path"),
        ):
            dry._root_parents(dry.ABI)
        unsafe = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)
        with patch.object(Path, "lstat", return_value=unsafe), self.assertRaises(source.RefusedError):
            dry._root_parents(dry.PARSER)
        with (
            patch.object(dry, "_root_parents"),
            patch.object(Path, "lstat", return_value=unsafe),
            self.assertRaisesRegex(source.RefusedError, "config-null"),
        ):
            dry._null()

    def test_query_holds_parser_abi_features_and_configuration_around_exact_stdin(self) -> None:
        files = (held(dry.ABI, b"abi fixture"),)
        parser = MagicMock()
        cohort = dry._Cohort(parser, files, (1,))
        with (
            patch.object(dry, "_stable") as stable,
            patch.object(source, "bounded_child", return_value=(b"", 0)) as child,
        ):
            self.assertEqual(dry._query(dry.COMPILE, POLICY, time.monotonic() + 1, cohort), (b"", 0))
        self.assertEqual(stable.call_count, 2)
        self.assertEqual(
            child.call_args.args[0:3],
            (
                dry.PARSER_EXEC,
                source.ExecutableCall(parser, (str(dry.PARSER), *dry.COMPILE)),
                POLICY,
            ),
        )
        with (
            patch.object(dry, "_stable", side_effect=[None, source.RefusedError("cohort-changed")]),
            patch.object(source, "bounded_child", return_value=(b"", 0)),
            self.assertRaisesRegex(source.RefusedError, "cohort-changed"),
        ):
            dry._query(dry.COMPILE, POLICY, time.monotonic() + 1, cohort)
        with (
            patch.object(dry, "_stable"),
            patch.object(source, "bounded_child", return_value=(b"", 0)),
            patch.object(source.time, "monotonic", return_value=2.0),
            self.assertRaisesRegex(source.RefusedError, "deadline"),
        ):
            dry._query(dry.COMPILE, POLICY, 1.0, cohort)

    def _experiment(
        self, queries: list[tuple[bytes, int]], result: dict[str, object], *, final_error: Exception | None = None
    ) -> MagicMock:
        parser = MagicMock(file=held(dry.PARSER, b"\x7fELFinert"))
        with (
            patch.object(dry, "_context", return_value={"candidate": HEAD}),
            patch.object(dry, "_features", return_value=({"namespaceMask": ["userns_create"]}, ())),
            patch.object(dry, "_root_parents"),
            patch.object(source, "hold_executable") as hold,
            patch.object(
                dry,
                "_root_file",
                side_effect=lambda path, *_args, **_kwargs: held(
                    path, b"\x7fELF" if path == dry.PARSER else b"exact abi"
                ),
            ),
            patch.object(dry, "_null", return_value=(1,)),
            patch.object(source, "custody", return_value=MagicMock()),
            patch.object(source, "build", return_value=POLICY) as builder,
            patch.object(dry.secrets, "token_hex", return_value=NONCE),
            patch.object(dry, "_query", side_effect=queries) as query,
        ):
            hold.return_value.__enter__.return_value = parser
            hold.return_value.__exit__.side_effect = final_error
            dry.experiment(CONTEXT, result)
        hold.assert_called_once_with(dry.PARSER, dry.MAX_BINARY, 0)
        self.assertIs(query.call_args_list[0].args[-1].parser, parser)
        self.assertIs(query.call_args_list[-1].args[-1].parser, parser)
        self.assertEqual(builder.call_args.args[1], NAME)
        return query

    def test_final_descriptor_revalidation_failure_cannot_leave_positive_completion(self) -> None:
        result = {}
        with self.assertRaisesRegex(source.RefusedError, "file-changed"):
            self._experiment(
                [(b"AppArmor parser version 5.0.2\n", 0), (b"", 0)],
                result,
                final_error=source.RefusedError("file-changed"),
            )
        self.assertNotIn("outcome", result)

    def test_compile_success_is_nonqualifying_and_keeps_exact_canonical_bytes(self) -> None:
        result = {"qualification": "none", "scope": "hostcompile-only"}
        query = self._experiment([(b"AppArmor parser version 5.0.2\n", 0), (b"", 0)], result)
        self.assertEqual(result["outcome"], "compiled-nonqualifying")
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(query.call_args_list[1].args[:2], (dry.COMPILE, POLICY))
        self.assertEqual(result["policy"]["sha256"], hashlib.sha256(POLICY).hexdigest())
        self.assertEqual(result["compile"]["child"]["noNewPrivs"], 1)
        self.assertFalse(result["compile"]["child"]["boundingSetRequiredZero"])
        self.assertNotIn("DOCKERLENS_NATIVE_APPARMOR_PROFILE", json.dumps(result))

    def test_parser_version_warning_downgrade_unsupported_flag_and_exit_failures_refuse(self) -> None:
        for output, status in ((b"warning: downgraded private/path", 0), (b"unknown option", 1), (b"", 1)):
            result = {}
            with self.subTest(output=output), self.assertRaisesRegex(source.RefusedError, "compile-refused"):
                self._experiment([(b"AppArmor parser version 5.0.2\n", 0), (output, status)], result)
            self.assertNotIn("outcome", result)
            self.assertEqual(result["compile"]["outputBytes"], len(output))
            self.assertNotIn(output.decode() if output else "private/path", json.dumps(result))
        for banner in (b"AppArmor parser version 4.0.1\n", b"AppArmor parser version 5.0.3\n", b"private output"):
            with self.subTest(banner=banner), self.assertRaisesRegex(source.RefusedError, "parser-version"):
                self._experiment([(banner, 0)], {})

    def test_cli_refusal_and_failures_emit_only_closed_nonqualifying_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            with (
                patch.object(dry.sys, "argv", ["dryparse", "--output", str(path)]),
                patch.object(dry.signal, "signal"),
                patch.object(dry, "experiment", side_effect=OSError("/private/host-sentinel")),
                patch.object(dry.sys, "stderr", new_callable=io.StringIO) as errors,
            ):
                self.assertEqual(dry.main(), 1)
                result = json.loads(path.read_bytes())
                self.assertEqual(result["qualification"], "none")
                self.assertEqual(result["outcome"], "refused")
                for flag in ("image_build_run", "bootstrap_run", "policy_load_run"):
                    self.assertFalse(result[flag])
                self.assertNotIn("host-sentinel", path.read_text())
                self.assertEqual(errors.getvalue(), "")
                self.assertEqual(dry.main(), 1)
                self.assertEqual(errors.getvalue(), "compile-only diagnostic artifact unavailable\n")


class IntegrationTests(unittest.TestCase):
    def test_ci_compiles_only_owned_pr_without_entering_ordinary_qualification(self) -> None:
        workflow = yaml.safe_load((dry.ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        job = jobs["userns-dryparse"]
        self.assertEqual(job["needs"], "validate")
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertIn("github.event.pull_request.number == 492", job["if"])
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", job["if"])
        self.assertIn("TheRealBecks/issue442-main-reconciled", job["if"])
        self.assertEqual(job["runs-on"], "ubuntu-26.04")
        checkout = job["steps"][0]
        self.assertNotIn("ref", checkout.get("with", {}))
        self.assertFalse(checkout["with"]["persist-credentials"])
        self.assertEqual(jobs["required-ci"]["needs"], ["validate", "plan", "smoke-build", "payloads"])
        self.assertEqual(jobs["required-ci"]["if"], "$" + "{{ always() }}")
        for baseline in ("plan", "payloads", "smoke-build", "required-ci"):
            self.assertNotIn("userns-dryparse", json.dumps(jobs[baseline]))
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        compile_step = next(step for step in job["steps"] if "scripts.docker_userns_dryparse" in step.get("run", ""))
        self.assertNotIn("CONTAINERS_DRY_PARSE_CANDIDATE_SHA", compile_step.get("env", {}))
        self.assertIn("scripts.docker_userns_dryparse", commands)
        for forbidden in ("sudo", "docker run", "build-arch-image", "--add", "--remove"):
            self.assertNotIn(forbidden, commands)
        self.assertTrue(all("continue-on-error" not in step for step in job["steps"]))

    def test_active_pins_have_unique_manifest_only_owners_and_mandatory_human_review(self) -> None:
        config = json.loads((dry.ROOT / ".github/renovate.json").read_text())
        text = source.MANIFEST.read_text()
        managers = [
            item
            for item in config["customManagers"]
            if item.get("datasourceTemplate") in {"github-digest", "gitlab-tags"}
        ]
        self.assertEqual(len(managers), 2)
        results = {}
        for manager in managers:
            pattern = manager["matchStrings"][0].replace("(?<", "(?P<")
            matches = list(re.finditer(pattern, text))
            self.assertEqual(len(matches), 1)
            results[manager["datasourceTemplate"]] = matches[0].groupdict()
            paths = manager["managerFilePatterns"]
            self.assertEqual(len(paths), 1)
            path_pattern = paths[0][1:-1]
            self.assertIsNotNone(re.fullmatch(path_pattern, ".github/docker-userns-policy-source.json"))
            for historical in (".artifacts/old-source.json", "docs/old-source.json", ".github/old-source.json"):
                self.assertIsNone(re.fullmatch(path_pattern, historical))
        self.assertEqual(
            results["github-digest"],
            {
                "currentValue": "TheRealBecks/issue127",
                "currentDigest": "26bf21298c839893177c96fc2036b64e2911344f",
            },
        )
        self.assertEqual(results["gitlab-tags"], {"currentValue": "5.0.2"})
        parser = next(item for item in managers if item["datasourceTemplate"] == "gitlab-tags")
        self.assertEqual(parser["registryUrlTemplate"], "https://gitlab.com")
        self.assertEqual(parser["packageNameTemplate"], "apparmor/apparmor")
        rule = next(
            item
            for item in config["packageRules"]
            if item.get("matchFileNames") == [".github/docker-userns-policy-source.json"]
        )
        self.assertTrue(rule["dependencyDashboardApproval"])
        self.assertFalse(rule["automerge"])
        self.assertEqual(set(rule["matchPackageNames"]), {"Strukturpiloten/docker-lens", "apparmor/apparmor"})


if __name__ == "__main__":
    unittest.main()
