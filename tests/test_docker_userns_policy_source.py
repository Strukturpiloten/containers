"""The pure policy source boundary must refuse substitution without executing producers."""

from __future__ import annotations

import copy
import errno
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import docker_userns_policy_source as source

NAME = "dockerlens-127-upstream-rootless-123-2-" + "a" * 32
POLICY = f"abi <abi/4.0>,\nprofile {NAME} flags=(unconfined) {{\n  userns,\n}}\n".encode("ascii")


def fixture() -> tuple[dict[str, object], dict[str, bytes]]:
    """Construct inert fixtures; none is importable or executable producer code."""
    value = json.loads(source.MANIFEST.read_bytes())
    data = {name: f"inert owned fixture: {name}\n".encode() for name in source.FILES}
    value["source"]["files"] = [
        {"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in data.items()
    ]
    return value, data


class SourceTests(unittest.TestCase):
    def test_bound_descriptor_hash_detects_in_place_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inert-elf"
            path.write_bytes(b"\x7fELForiginal")
            path.chmod(0o700)
            with (
                patch.object(source.os, "getxattr", side_effect=OSError(errno.ENODATA, "private")),
                self.assertRaisesRegex(source.RefusedError, "file-changed|oversized"),
                source.hold_executable(path, source.MAX_SOURCE, os.geteuid()) as executable,
            ):
                path.write_bytes(b"\x7fELFmodified")
                executable.check()

    def test_only_bound_executable_and_receipt_are_inherited_and_parent_keeps_its_fd(self) -> None:
        executable = MagicMock(descriptor=12345)
        process = MagicMock(pid=54321)
        process.wait.return_value = 0
        real_close = os.close
        call = source.ExecutableCall(executable, ("/fixed/parser", "--version"))
        with (
            patch.object(source.os, "geteuid", return_value=1000),
            patch.object(source.subprocess, "Popen", return_value=process) as start,
            patch.object(source.os, "set_blocking"),
            patch.object(source.os, "write", return_value=0),
            patch.object(source, "_capture", return_value=(b"", source.CHILD_RECEIPT)),
            patch.object(source.os, "waitid", return_value=SimpleNamespace(si_pid=process.pid)),
            patch.object(source.os, "killpg", side_effect=[None, ProcessLookupError]),
            patch.object(source.os, "close", wraps=real_close) as close,
        ):
            self.assertEqual(source.bounded_child("", call, b"", time.monotonic() + 1, 1024), (b"", 0))
        argv = start.call_args.args[0]
        self.assertEqual(start.call_args.kwargs["pass_fds"], (int(argv[5]), executable.descriptor))
        self.assertTrue(start.call_args.kwargs["close_fds"])
        self.assertEqual(argv[6:], [str(executable.descriptor), "/fixed/parser", "--version"])
        self.assertEqual(executable.check.call_count, 2)
        self.assertNotIn((executable.descriptor,), [item.args for item in close.call_args_list])

    def test_held_elf_descriptor_stays_open_rechecks_bytes_and_closes_on_all_exits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inert-elf"
            original = b"\x7fELFnever-execute-this-fixture"
            path.write_bytes(original)
            path.chmod(0o700)
            with patch.object(source.os, "getxattr", side_effect=OSError(errno.ENODATA, "private")):
                with source.hold_executable(path, source.MAX_SOURCE, os.geteuid()) as executable:
                    descriptor = executable.descriptor
                    self.assertEqual(os.pread(descriptor, source.MAX_SOURCE, 0), original)
                    self.assertFalse(os.get_inheritable(descriptor))
                    os.lseek(descriptor, 0, os.SEEK_END)
                    executable.check()
                    self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), len(original))
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                with (
                    self.assertRaisesRegex(source.RefusedError, "cancelled"),
                    source.hold_executable(path, source.MAX_SOURCE, os.geteuid()) as executable,
                ):
                    descriptor = executable.descriptor
                    source.refuse("cancelled")
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_unsupported_descriptor_execution_refuses_before_open_without_filename_fallback(self) -> None:
        with (
            patch.object(source.os, "supports_fd", new=set()),
            patch.object(source.os, "open") as opening,
            self.assertRaisesRegex(source.RefusedError, "fd-exec-unsupported"),
            source.hold_executable(Path("/fixed/parser"), source.MAX_SOURCE, 0),
        ):
            self.fail("unsupported FD execution must never enter custody")
        opening.assert_not_called()

    def test_signal_cancellation_is_sticky_but_does_not_interrupt_spawn_or_cleanup(self) -> None:
        with patch.object(source, "CANCELLED", new=True), self.assertRaisesRegex(source.RefusedError, "cancelled"):
            source.check(time.monotonic() + 1)
        process = MagicMock(pid=54321)
        process.wait.return_value = 0
        with (
            patch.object(source, "CANCELLED", new=True),
            patch.object(source.os, "killpg", side_effect=[None, ProcessLookupError]),
        ):
            self.assertEqual(source._cleanup(process), 0)

    def test_child_privilege_guard_refuses_kernel_failures_and_active_capabilities_offline(self) -> None:
        clean = b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"
        for calls, status, uid, success in (
            ([0, 1], clean, 1000, True),
            ([-1], clean, 1000, False),
            ([0, 0], clean, 1000, False),
            ([0, 1], clean.replace(b"CapAmb: 0", b"CapAmb: 1"), 1000, False),
            ([0, 1], clean.replace(b"NoNewPrivs: 1", b"NoNewPrivs: 0"), 1000, False),
            ([0, 1], clean, 0, False),
        ):
            libc, ctypes, child_os, resource, signal = (MagicMock() for _ in range(5))
            ctypes.CDLL.return_value = libc
            libc.prctl.side_effect = calls
            child_os.geteuid.return_value = uid
            child_os.write.side_effect = lambda _descriptor, data: len(data)
            with (
                self.subTest(calls=calls, status=status, uid=uid),
                patch.dict(sys.modules, {"ctypes": ctypes, "os": child_os, "resource": resource, "signal": signal}),
                patch.object(sys, "argv", ["wrapper", "17"]),
                patch("builtins.open", return_value=io.BytesIO(status)),
            ):
                if success:
                    exec(source.CHILD_SETUP, {})  # noqa: S102 - fixed reviewed wrapper, all kernel interfaces mocked.
                    child_os.write.assert_called_once_with(17, source.CHILD_RECEIPT)
                    child_os.close.assert_called_once_with(17)
                    self.assertEqual(libc.prctl.argtypes, [ctypes.c_int, *([ctypes.c_ulong] * 4)])
                else:
                    with self.assertRaises(SystemExit):
                        exec(source.CHILD_SETUP, {})  # noqa: S102 - exercise fixed guard refusals without kernel calls.
                    child_os.write.assert_not_called()

    def test_capture_enforces_actual_pipe_output_bound_without_launching_a_process(self) -> None:
        read, write = os.pipe()
        proof_read, proof_write = os.pipe()
        try:
            os.write(write, b"x" * (source.MAX_POLICY + 1))
            os.write(proof_write, source.CHILD_RECEIPT)
            os.close(write)
            os.close(proof_write)
            with os.fdopen(read, "rb") as stdout, self.assertRaisesRegex(source.RefusedError, "child-output"):
                source._capture(SimpleNamespace(stdout=stdout), proof_read, time.monotonic() + 1, source.MAX_POLICY)
        finally:
            os.close(proof_read)

    def test_active_manifest_binds_exact_closure_license_and_reviewed_parser(self) -> None:
        value = source.manifest()
        self.assertEqual(value["consumer"], source.CONSUMER)
        self.assertEqual(value["source"]["commit"], "26bf21298c839893177c96fc2036b64e2911344f")
        self.assertEqual(value["source"]["ref"], "TheRealBecks/issue127")
        self.assertEqual({item["path"] for item in value["source"]["files"]}, source.FILES)
        self.assertEqual(value["source"]["license"], "MPL-2.0")
        self.assertTrue(value["source"]["managed"])
        self.assertEqual(value["parser"]["expectedVersion"], "5.0.2")

    def test_manifest_substitutions_duplicate_keys_and_unreviewed_versions_refuse(self) -> None:
        original = source.manifest()
        changes = [
            ("consumer", "dockerlens-native"),
            ("qualification", "accepted"),
            ("schemaVersion", True),
        ]
        variants = []
        for key, replacement in changes:
            value = copy.deepcopy(original)
            value[key] = replacement
            variants.append(value)
        for key, replacement in (("repository", "other/project"), ("ref", "main"), ("commit", "x" * 40)):
            value = copy.deepcopy(original)
            value["source"][key] = replacement
            variants.append(value)
        value = copy.deepcopy(original)
        value["source"]["files"][0]["path"] = "../untrusted.py"
        variants.append(value)
        value = copy.deepcopy(original)
        value["source"]["files"][0] = value["source"]["files"][1]
        variants.append(value)
        value = copy.deepcopy(original)
        value["parser"]["expectedVersion"] = "5.0.3"
        variants.append(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for value in variants:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(source.RefusedError):
                        source.manifest(path)
            path.write_text('{"schemaVersion":1,"schemaVersion":1}')
            with self.assertRaisesRegex(source.RefusedError, "duplicate-json-key"):
                source.manifest(path)

    def test_snapshot_rejects_symlinks_aliases_permissions_and_file_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned"
            path.write_bytes(b"\x7fELFinert")
            path.chmod(0o700)
            with patch.object(source.os, "getxattr", side_effect=OSError(errno.ENODATA, "private")):
                held = source.snapshot(path, source.MAX_SOURCE, os.geteuid(), executable=True)
                self.assertNotIn("uid", held.public())
            with (
                patch.object(source.os, "getxattr", return_value=b"capabilities"),
                self.assertRaises(source.RefusedError),
            ):
                source.snapshot(path, source.MAX_SOURCE, os.geteuid(), executable=True)
            path.chmod(0o777)
            with self.assertRaises(source.RefusedError):
                source.snapshot(path, source.MAX_SOURCE, os.geteuid())
            path.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                source.snapshot(link, source.MAX_SOURCE, os.geteuid())
            link.unlink()
            os.link(path, link)
            with self.assertRaises(source.RefusedError):
                source.snapshot(path, source.MAX_SOURCE, os.geteuid())

    def test_private_custody_checks_every_hash_and_both_directory_identities(self) -> None:
        value, data = fixture()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(source, "fetch", side_effect=lambda _commit, name, _size, _deadline: data[name]),
        ):
            held = source.custody(Path(directory), value, time.monotonic() + 1)
            held.check()
            self.assertEqual({item.path.relative_to(directory).as_posix() for item in held.files}, source.FILES)
            path = Path(directory) / "scripts/native_outer_diagnostic_capture.py"
            path.chmod(0o600)
            path.write_bytes(b"substituted")
            with self.assertRaisesRegex(source.RefusedError, "file-changed|oversized"):
                held.check()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(source, "fetch", return_value=b"wrong"),
            self.assertRaisesRegex(source.RefusedError, "source-integrity"),
        ):
            source.custody(Path(directory), value, time.monotonic() + 1)

    def test_import_directory_substitution_and_extra_modules_refuse(self) -> None:
        value, data = fixture()
        for substitution in ("extra", "symlink"):
            with (
                self.subTest(substitution=substitution),
                tempfile.TemporaryDirectory() as directory,
                patch.object(source, "fetch", side_effect=lambda _commit, name, _size, _deadline: data[name]),
            ):
                root = Path(directory)
                held = source.custody(root, value, time.monotonic() + 1)
                if substitution == "extra":
                    (root / "scripts/unexpected.py").write_bytes(b"inert")
                else:
                    (root / "scripts").rename(root / "moved")
                    (root / "scripts").symlink_to(root / "moved", target_is_directory=True)
                with self.assertRaises(source.RefusedError):
                    held.check()

    def test_fetch_has_only_immutable_public_https_without_proxy_or_redirect(self) -> None:
        commit = "a" * 40
        url = f"https://raw.githubusercontent.com/Strukturpiloten/docker-lens/{commit}/LICENSE"
        response = MagicMock(status=200)
        response.geturl.return_value = url
        response.read1.side_effect = [b"abc", b""]
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(source.urllib.request, "build_opener", return_value=opener) as factory:
            self.assertEqual(source._download(commit, "LICENSE", 3, time.monotonic() + 1), b"abc")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, url)
        self.assertFalse(request.has_header("Authorization"))
        self.assertEqual(factory.call_args.args[0].proxies, {})
        self.assertIsNone(source._NoRedirect().redirect_request(None))
        for name in ("../secret", "/etc/passwd", "scripts/not-allowed.py"):
            with self.subTest(name=name), self.assertRaisesRegex(source.RefusedError, "source-request"):
                source._download(commit, name, 3, time.monotonic() + 1)
        response.geturl.return_value = "https://elsewhere.invalid/LICENSE"
        with (
            patch.object(source.urllib.request, "build_opener", return_value=opener),
            self.assertRaisesRegex(source.RefusedError, "source-response"),
        ):
            source._download(commit, "LICENSE", 3, time.monotonic() + 1)
        with patch.object(source, "bounded_child", return_value=(b"abc", 0)) as child:
            self.assertEqual(source.fetch(commit, "LICENSE", 3, time.monotonic() + 1), b"abc")
        self.assertEqual(child.call_args.args[0], source.DOWNLOAD)
        self.assertEqual(child.call_args.args[1][1:4], [commit, "LICENSE", "3"])
        self.assertEqual(child.call_args.args[2], b"")

    def test_only_pure_builder_is_invoked_with_unmodified_bytes_and_private_rechecks(self) -> None:
        held = MagicMock(directory=Path("/owned/private"))
        with (
            patch.object(source.os, "geteuid", return_value=1000),
            patch.object(source, "bounded_child", return_value=(POLICY, 0)) as child,
        ):
            self.assertEqual(source.build(held, NAME, time.monotonic() + 1), POLICY)
        self.assertEqual(held.check.call_count, 2)
        self.assertEqual(child.call_args.args[:3], (source.BUILDER, ["/owned/private/scripts", NAME], b""))
        self.assertIn("module.profile_bytes", source.BUILDER)
        for forbidden in ("RunnerProfile", "consumer_mode", "main(", "--add", "--remove"):
            self.assertNotIn(forbidden, source.BUILDER)
        with patch.object(source.os, "geteuid", return_value=0), self.assertRaises(source.RefusedError):
            source.build(held, NAME, time.monotonic() + 1)
        with patch.object(source.os, "geteuid", return_value=1000), self.assertRaises(source.RefusedError):
            source.build(held, NAME.replace("dockerlens-127", "containers"), time.monotonic() + 1)

    def test_builder_failure_or_post_import_substitution_is_never_positive(self) -> None:
        for raw, status in ((b"private traceback", 1), (POLICY, 1), (b"abi <abi/5.0>,\n", 0)):
            held = MagicMock(directory=Path("/owned/private"))
            with (
                self.subTest(status=status),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source, "bounded_child", return_value=(raw, status)),
                self.assertRaises(source.RefusedError),
            ):
                source.build(held, NAME, time.monotonic() + 1)
        held.check.side_effect = [None, source.RefusedError("file-changed")]
        with (
            patch.object(source.os, "geteuid", return_value=1000),
            patch.object(source, "bounded_child", return_value=(POLICY, 0)),
            self.assertRaisesRegex(source.RefusedError, "file-changed"),
        ):
            source.build(held, NAME, time.monotonic() + 1)

    def test_child_receipt_is_separate_and_cleanup_owns_only_its_process_group(self) -> None:
        process = MagicMock(pid=54321)
        process.wait.return_value = 0
        with (
            patch.object(source.os, "geteuid", return_value=1000),
            patch.object(source.subprocess, "Popen", return_value=process) as start,
            patch.object(source.os, "set_blocking"),
            patch.object(source.os, "write", return_value=0),
            patch.object(source, "_capture", return_value=(POLICY, source.CHILD_RECEIPT)),
            patch.object(source.os, "waitid", return_value=SimpleNamespace(si_pid=process.pid)),
            patch.object(source.os, "killpg", side_effect=[None, ProcessLookupError]) as kill,
        ):
            self.assertEqual(
                source.bounded_child(source.BUILDER, ["private", NAME], b"", time.monotonic() + 1, 1024), (POLICY, 0)
            )
        argv = start.call_args.args[0]
        self.assertEqual(argv[1:4], ["-I", "-B", "-c"])
        self.assertEqual(argv[4], source.CHILD_SETUP + source.BUILDER)
        self.assertEqual(start.call_args.kwargs["pass_fds"], (int(argv[5]),))
        self.assertEqual(start.call_args.kwargs["env"], source.ENVIRONMENT)
        self.assertTrue(start.call_args.kwargs["start_new_session"])
        self.assertEqual(kill.call_args_list[0].args, (process.pid, source.signal.SIGKILL))
        self.assertEqual(kill.call_args_list[1].args, (process.pid, 0))
        self.assertIn(
            "ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong", source.CHILD_SETUP
        )
        self.assertIn("libc.prctl(38, 1, 0, 0, 0)", source.CHILD_SETUP)
        self.assertIn("libc.prctl(39, 0, 0, 0, 0)", source.CHILD_SETUP)
        self.assertIn("os.close(int(sys.argv[1]))", source.CHILD_SETUP)
        self.assertIn("signal.alarm(8)", source.CHILD_SETUP)

    def test_bad_receipt_timeout_cancellation_and_uncertain_cleanup_refuse(self) -> None:
        with (
            patch.object(source.os, "geteuid", return_value=1000),
            patch.object(source.subprocess, "Popen", return_value=MagicMock(pid=54321)),
            patch.object(source.os, "set_blocking"),
            patch.object(source.os, "write", return_value=0),
            patch.object(source, "_capture", return_value=(b"", b"untrusted receipt")),
            patch.object(source.os, "waitid", return_value=SimpleNamespace(si_pid=54321)),
            patch.object(source, "_cleanup", return_value=0) as cleanup,
            self.assertRaisesRegex(source.RefusedError, "child-privilege-receipt"),
        ):
            source.bounded_child(source.BUILDER, [], b"", time.monotonic() + 1, 1024)
        cleanup.assert_called_once()
        for reason in ("deadline", "cancelled", "child-output"):
            process = MagicMock(pid=54321)
            with (
                self.subTest(reason=reason),
                patch.object(source.os, "geteuid", return_value=1000),
                patch.object(source.subprocess, "Popen", return_value=process),
                patch.object(source.os, "set_blocking"),
                patch.object(source.os, "write", return_value=0),
                patch.object(source, "_capture", side_effect=source.RefusedError(reason)),
                patch.object(source.os, "killpg", side_effect=[None, ProcessLookupError]) as kill,
                self.assertRaisesRegex(source.RefusedError, reason),
            ):
                source.bounded_child(source.BUILDER, [], b"", time.monotonic() + 1, 1024)
            kill.assert_any_call(process.pid, source.signal.SIGKILL)
            process.wait.assert_called_once_with(timeout=0.5)
        with patch.object(source.os, "killpg"), self.assertRaisesRegex(source.RefusedError, "child-cleanup-unverified"):
            source._cleanup(MagicMock(pid=54321))


if __name__ == "__main__":
    unittest.main()
