"""Independent offline archive-barrier expectations; no container runtime is executed."""

from __future__ import annotations

import ast
import base64
import ctypes
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import runtime_docker_systemd
from scripts.runtime_docker_backend import DockerBackend
from scripts.runtime_docker_systemd import (
    LEAF_WITNESS_BRIDGE_COMMAND,
    LEAF_WITNESS_START,
    RESOURCE_START_FILE,
    _leaf_archive_after,
    _leaf_archive_api,
    _leaf_archive_end,
    _leaf_archive_http,
    _leaf_archive_request,
    _leaf_archive_tar,
    _LeafArchiveError,
    _LeafWitnessArchive,
)
from scripts.runtime_errors import ProbeError
from scripts.runtime_resource_budgets import IsolatedStoreDiskBudget
from scripts.runtime_tests import RuntimeContext

CID = "a" * 64
GUEST = "b" * 64
IMAGE = "sha256:" + "c" * 64

# Immutable public version/image facts retained from native run 40989306028,
# not operational pins, private runtime IDs, or proof of its missing exception.
RECORDED_SERVER = {"Version": "29.9.2", "ApiVersion": "1.56", "MinAPIVersion": "1.40"}
RECORDED_CONFIG = "sha256:83a47ae795f62e40e87b7d2e227ef788858d068235703b23c45ba0edb93a0ba3"

# An authored certless Unix command contract, not a Python port of Docker's
# flag/default/TLS implementation. No socket, certificate read, or runtime call.
CERTLESS_UNIX_CLI = r"""
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FIXTURE_ARGV"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")
if any(item == "--tlsverify" or item.startswith("--tlsverify=") for item in args):
    print("certless Unix fixture refuses an explicit TLS verification flag", file=sys.stderr)
    raise SystemExit(64)
if args[:3] != ["--host", "unix:///run/user/1000/docker.sock", "--tls=false"]:
    raise SystemExit(65)
if args[3:] == ["version", "--format", "{{json .Server}}"]:
    print(os.environ["FIXTURE_SERVER"])
elif args[3:] == ["image", "inspect", "--format", "{{.Id}}", os.environ["FIXTURE_IMAGE"]]:
    print(os.environ["FIXTURE_CONFIG"])
else:
    raise SystemExit(66)
"""


class BeforeFixtureCreateError(RuntimeError):
    """The inert process boundary stopped before creating any resource."""


class CertlessUnixDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.argv_log = self.root / "argv.jsonl"
        self.cli = self.root / "docker"
        self.cli.write_text("#!" + sys.executable + "\n" + CERTLESS_UNIX_CLI, encoding="utf-8")
        self.cli.chmod(0o700)
        self.ctx = RuntimeContext(
            image="docker-29-conformance-rootless",
            architecture="amd64",
            timeout=45,
            use_sudo=False,
            outer_engine="docker",
        )
        self.addCleanup(shutil.rmtree, self.ctx.directory)
        self.ctx.containers.append(GUEST)
        self.ctx.runtime_deadline = time.monotonic() + 300
        self.ctx.backend.deadline = time.monotonic() + 360
        # Explicit inert provider identity. The real prefix/rebudget/deadline
        # methods run; no provider admission or privileged tool is executed.
        self.ctx.backend._gnu_timeout_provider = ("/fixture/gnu-timeout", "9.7", "fixture")
        self.ctx.exec_guard = runtime_docker_systemd.guarded_command()
        self.budget = IsolatedStoreDiskBudget(self.ctx)
        self.session = _LeafWitnessArchive(self.ctx, self.budget, (GUEST, "rootless"), None, {})
        self.process_run = subprocess.run
        self.commands: list[list[str]] = []
        self.inner_commands: list[list[str]] = []
        self.cancel_next = False

    def process(self, command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        """Replace only the external process with an owned inert CLI/shell."""
        self.commands.append(command)
        self.assertEqual(command[:2], ["/fixture/gnu-timeout", "--signal=TERM"])
        self.assertTrue(command[2].startswith("--kill-after="))
        self.assertGreater(float(command[3][:-1]), 0)
        self.assertLess(float(command[3][:-1]), options["timeout"])
        self.assertGreater(options["timeout"], 0)
        self.assertLessEqual(options["timeout"], self.ctx.timeout)
        self.assertTrue(options["text"] is True)
        self.assertTrue(options["check"] is False)
        outer = command.index("/fixture/outer-docker")
        self.assertEqual(command[4], "env")
        self.assertEqual(
            command[5:outer],
            [
                token
                for name in (
                    "DOCKER_HOST",
                    "DOCKER_CONTEXT",
                    "DOCKER_CONFIG",
                    "DOCKER_API_VERSION",
                    "DOCKER_TLS",
                    "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH",
                )
                for token in ("-u", name)
            ],
        )
        self.assertEqual(
            command[outer + 1 : outer + 8],
            [
                "--config",
                str(self.ctx.backend.cli_config),
                "--host",
                "unix://" + str(self.ctx.backend.socket),
                "--tls=false",
                "exec",
                GUEST,
            ],
        )
        guest = command[outer + 8 :]
        self.assertEqual(guest[: len(self.ctx.exec_guard)], list(self.ctx.exec_guard))
        inner = guest[len(self.ctx.exec_guard) :]
        self.inner_commands.append(inner)
        if self.cancel_next:
            raise KeyboardInterrupt
        if inner[:5] == ["docker", "--host", "unix:///run/user/1000/docker.sock", "--tls=false", "create"]:
            raise BeforeFixtureCreateError
        if inner[:3] == ["sh", "-euc", 'test ! -e "$1"; test ! -L "$1"']:
            return subprocess.CompletedProcess(command, 0, "", "")
        environment = {
            "PATH": str(self.root),
            "FIXTURE_ARGV": str(self.argv_log),
            "FIXTURE_SERVER": json.dumps(RECORDED_SERVER),
            "FIXTURE_CONFIG": RECORDED_CONFIG,
            "FIXTURE_IMAGE": self.ctx.image_ref,
        }
        if inner[:1] == ["docker"]:
            executable = [str(self.cli), *inner[1:]]
        else:
            self.assertEqual(inner[:2], ["sh", "-euc"])
            shell = shutil.which("dash")
            self.assertIsNotNone(shell)
            executable = [shell, *inner[1:]]
        return self.process_run(
            executable,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=options["timeout"],
        )

    def test_real_archive_chain_reads_recorded_api_and_config_before_create(self) -> None:
        original = (self.ctx.runtime_deadline, self.ctx.backend.deadline, self.session.end)
        with (
            patch.object(DockerBackend, "_tool", return_value="/fixture/outer-docker"),
            patch("scripts.runtime_tests.subprocess.run", side_effect=self.process),
            self.assertRaises(BeforeFixtureCreateError),
        ):
            self.session.create()
        self.assertEqual(self.session.image, RECORDED_CONFIG)
        self.assertEqual(self.session.record["archive"]["operation"], "create")
        self.assertFalse(self.session.record["archive"]["preflight"])
        calls = [json.loads(line) for line in self.argv_log.read_text().splitlines()]
        self.assertEqual(
            [item[3:] for item in calls],
            [
                ["version", "--format", "{{json .Server}}"],
                ["image", "inspect", "--format", "{{.Id}}", self.ctx.image_ref],
            ],
        )
        self.assertEqual(len(self.commands), 4)
        self.assertEqual(original, (self.ctx.runtime_deadline, self.ctx.backend.deadline, self.session.end))
        self.assertEqual(self.ctx.backend.units, {})
        self.assertFalse(list(self.root.glob("*.pem")))

    def test_real_chain_refuses_tlsverify_counterfactual_before_create(self) -> None:
        with (
            patch.object(DockerBackend, "_tool", return_value="/fixture/outer-docker"),
            patch("scripts.runtime_tests.subprocess.run", side_effect=self.process),
            self.assertRaisesRegex(ProbeError, "certless Unix fixture refuses"),
        ):
            self.session.command("certless flag counterfactual", "--tlsverify=false", "version")
        self.assertEqual(len(self.commands), 1)
        self.assertFalse(self.session.custody)
        self.assertIsNone(self.session.workload)

    def test_all_six_authored_cli_routes_keep_explicit_certless_unix_contract(self) -> None:
        source = Path(runtime_docker_systemd.__file__).read_text()
        tree = ast.parse(source)
        self.assertEqual(
            sum(
                node.value.count("--tls=false")
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            ),
            6,
        )
        arguments = {
            "_leaf_witness_bind": ["/owned.scope", "21", CID, "unix:///run/user/1000/docker.sock"],
            "_leaf_witness_cleanup": ["unix:///run/user/1000/docker.sock", "nonce", RECORDED_CONFIG, "rootless"],
            "_leaf_witness_failure_command": [CID, "unix:///run/user/1000/docker.sock"],
            "_leaf_witness_observe": ["/owned.scope", "21", CID, "unix:///run/user/1000/docker.sock"],
        }
        self.assertEqual(
            set(arguments),
            {
                "_leaf_witness_bind",
                "_leaf_witness_cleanup",
                "_leaf_witness_failure_command",
                "_leaf_witness_observe",
            },
        )
        with (
            patch.object(DockerBackend, "_tool", return_value="/fixture/outer-docker"),
            patch("scripts.runtime_tests.subprocess.run", side_effect=self.process),
        ):
            self.assertEqual(
                json.loads(
                    self.session.command(
                        "direct certless archive route",
                        "version",
                        "--format",
                        "{{json .Server}}",
                    )
                ),
                RECORDED_SERVER,
            )
            for owner, argv in arguments.items():
                function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == owner)
                literals = [
                    node.value
                    for node in ast.walk(function)
                    if isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and "command docker --host" in node.value
                ]
                self.assertEqual(len(literals), 1, owner)
                # Execute the actual authored wrapper and positional expansion,
                # not a second copy or a fake cgroup/native implementation.
                prefix = literals[0].split("};", 1)[0] + "}; "
                result = self.ctx.exec(
                    "certless shell route " + owner,
                    GUEST,
                    "sh",
                    "-euc",
                    prefix + 'docker version --format "{{json .Server}}"',
                    "--",
                    *argv,
                )
                self.assertEqual(json.loads(result), RECORDED_SERVER)
        # The sixth route is the complete bridge, exercised by BridgeShellTests
        # below; its independent CLI fixture validates actual expanded argv.
        self.assertIn('docker --host "$2" --tls=false system dial-stdio', LEAF_WITNESS_BRIDGE_COMMAND)
        self.assertEqual(len(self.commands), 5)

    def test_original_deadline_reserve_budget_and_cancellation_precede_create(self) -> None:
        with (
            patch.object(DockerBackend, "_tool", return_value="/fixture/outer-docker"),
            patch("scripts.runtime_tests.subprocess.run", side_effect=self.process),
        ):
            self.budget.peak_bytes = self.budget.limit_bytes + 1
            with self.assertRaisesRegex(ProbeError, "disk budget|store exceeded"):
                self.session.command("over-budget archive", "version")
            self.budget.peak_bytes = 0
            original = self.ctx.backend.deadline
            self.ctx.backend.deadline = time.monotonic() + 59
            with self.assertRaises(_LeafArchiveError):
                self.session.command("reserved cleanup archive", "version")
            self.ctx.backend.deadline = original
            self.assertEqual(self.commands, [])
            self.cancel_next = True
            with self.assertRaises(KeyboardInterrupt):
                self.session.command("cancelled archive", "version")
        self.assertFalse(self.session.custody)
        self.assertIsNone(self.session.workload)
        self.assertFalse(self.session.record["archive"]["preflight"])


def _reply(status: int = 200, *, headers: bytes = b"", body: bytes = b"") -> bytes:
    return f"HTTP/1.1 {status} Result\r\n".encode() + headers + b"\r\n" + body + b"\nBFW1 OK complete\n"


def _stat_header(**changes: object) -> dict[str, str]:
    value = {
        "name": "boxferry-leaf-witness-start.after",
        "size": 0,
        "mode": 0o600,
        "mtime": "2026-10-30T00:00:00Z",
        "linkTarget": "",
    }
    value.update(changes)
    return {"x-docker-container-path-stat": base64.b64encode(json.dumps(value).encode()).decode()}


class ArchiveProtocolTests(unittest.TestCase):
    def session(self) -> _LeafWitnessArchive:
        ctx = MagicMock(timeout=45, runtime_deadline=time.monotonic() + 100, containers=[GUEST])
        ctx.backend.command_timeout.side_effect = lambda value: value
        ctx.image_ref = "localhost/actual:private"
        session = _LeafWitnessArchive(ctx, MagicMock(), (GUEST, "rootless"), MagicMock(), {})
        session.image, session.workload = IMAGE, CID
        return session

    def inspected(self, session: _LeafWitnessArchive, *, running: bool = False) -> dict:
        return {
            "Id": CID,
            "Name": "/docker-native-limit-memory-witness",
            "Image": IMAGE,
            "Config": {
                "Labels": {
                    "org.strukturpiloten.witness": session.nonce,
                    "org.strukturpiloten.witness-mode": "rootless",
                },
                "Cmd": ["docker-resource-probe", "memory-witness", "--wait-for-start", LEAF_WITNESS_START],
            },
            "State": {"Running": running, "Status": "running" if running else "created"},
            "HostConfig": {"ReadonlyRootfs": False, "Tmpfs": {}},
            "Mounts": [],
        }

    def stopped_source_wire(self, session: _LeafWitnessArchive) -> str:
        """Return an authored Engine/CLI 29.9.2 shape, not a native capture."""
        # Engine 0367cbeb / CLI a82e5289 serialize the empty optional Tmpfs
        # map with omitempty, but emit ReadonlyRootfs=false and Linux Mounts=[].
        # Synthetic identities bind this fixture to the current test session.
        return (
            (
                '{"Id":"@cid@","Name":"/docker-native-limit-memory-witness","Image":"@image@",'
                '"Config":{"Labels":{"org.strukturpiloten.witness":"@nonce@",'
                '"org.strukturpiloten.witness-mode":"rootless"},'
                '"Cmd":["docker-resource-probe","memory-witness","--wait-for-start",'
                '"/boxferry-leaf-witness-start"]},"State":{"Running":false,"Status":"created"},'
                '"HostConfig":{"ReadonlyRootfs":false},"Mounts":[]}'
            )
            .replace("@cid@", CID)
            .replace("@image@", IMAGE)
            .replace("@nonce@", session.nonce)
        )

    def test_source_versioned_wire_accepts_only_absent_empty_tmpfs_normalization(self) -> None:
        session = self.session()
        omitted = self.stopped_source_wire(session)
        explicit = omitted.replace('"ReadonlyRootfs":false', '"ReadonlyRootfs":false,"Tmpfs":{}')
        for wire in (omitted, explicit):
            with self.subTest(wire=wire), patch.object(session, "command", return_value=wire):
                session.inspect(running=False)
        self.assertNotIn("Tmpfs", json.loads(omitted)["HostConfig"])
        self.assertEqual(json.loads(omitted)["Mounts"], [])

    def test_optional_tmpfs_keeps_existing_null_and_noncovering_mount_policy(self) -> None:
        session = self.session()
        for tmpfs, mounts in (
            (None, []),
            ({}, None),
            (None, None),
            ({"/safe-other": "rw", "/boxferry-leaf-witness-start-neighbor": "rw"}, [{"Destination": "/unrelated"}]),
        ):
            value = json.loads(self.stopped_source_wire(session))
            value["HostConfig"]["Tmpfs"], value["Mounts"] = tmpfs, mounts
            with (
                self.subTest(tmpfs=tmpfs, mounts=mounts),
                patch.object(session, "command", return_value=json.dumps(value)),
            ):
                session.inspect(running=False)

    def test_source_wire_requires_explicit_readonly_mounts_and_owned_identity(self) -> None:
        session = self.session()
        variants = []
        for readonly in (True, None, 0, "false"):
            value = json.loads(self.stopped_source_wire(session))
            value["HostConfig"]["ReadonlyRootfs"] = readonly
            variants.append(value)
        for parent, key in ((None, "HostConfig"), ("HostConfig", "ReadonlyRootfs"), (None, "Mounts")):
            value = json.loads(self.stopped_source_wire(session))
            del (value[parent] if parent else value)[key]
            variants.append(value)
        for host in (None, [], "", False):
            value = json.loads(self.stopped_source_wire(session))
            value["HostConfig"] = host
            variants.append(value)
        for field, replacement in (("Id", "d" * 64), ("Image", "sha256:" + "e" * 64), ("Name", "/foreign")):
            value = json.loads(self.stopped_source_wire(session))
            value[field] = replacement
            variants.append(value)
        value = json.loads(self.stopped_source_wire(session))
        value["Config"]["Labels"]["org.strukturpiloten.witness"] = "foreign-nonce"
        variants.append(value)
        value = json.loads(self.stopped_source_wire(session))
        value["Config"]["Cmd"] = ["sh"]
        variants.append(value)
        value = json.loads(self.stopped_source_wire(session))
        del value["Mounts"]
        value["HostConfig"]["Mounts"] = []
        variants.append(value)
        value = json.loads(self.stopped_source_wire(session))
        value["State"] = {"Running": False, "Status": "exited"}
        variants.append(value)
        for value in variants:
            with (
                self.subTest(value=value),
                patch.object(session, "command", return_value=json.dumps(value)),
                self.assertRaises(_LeafArchiveError),
            ):
                session.inspect(running=False)

    def test_source_wire_rejects_present_wrong_types_and_both_covering_mount_sources(self) -> None:
        session = self.session()
        variants = []
        for field in ("Tmpfs", "Mounts"):
            for malformed in ([], "", 0, False) if field == "Tmpfs" else ({}, "", 0, False):
                value = json.loads(self.stopped_source_wire(session))
                (value["HostConfig"] if field == "Tmpfs" else value)[field] = malformed
                variants.append(value)
        for destination in (
            "/",
            "/boxferry-leaf-witness-start",
            "/boxferry-leaf-witness-start.after",
            "/boxferry-leaf-witness-start.finish",
            "/boxferry-leaf-witness-start/",
            "/../bad",
            "/./bad",
            "//bad",
            "relative",
        ):
            for field in ("Tmpfs", "Mounts"):
                value = json.loads(self.stopped_source_wire(session))
                if field == "Tmpfs":
                    value["HostConfig"]["Tmpfs"] = {destination: "rw"}
                else:
                    value["Mounts"] = [{"Destination": destination}]
                variants.append(value)
        for value in variants:
            with (
                self.subTest(value=value),
                patch.object(session, "command", return_value=json.dumps(value)),
                self.assertRaises(_LeafArchiveError),
            ):
                session.inspect(running=False)

    def test_tar_is_one_canonical_empty_root_regular_member_without_extensions(self) -> None:
        for marker in (LEAF_WITNESS_START, LEAF_WITNESS_START + ".finish"):
            body = _leaf_archive_tar(marker)
            self.assertEqual(len(body), 1536)
            self.assertEqual(body[512:], bytes(1024))
            self.assertEqual(body[257:263], b"ustar\x00")
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
                members = archive.getmembers()
                self.assertEqual(len(members), 1)
                item = members[0]
                self.assertEqual(
                    (item.name, item.size, item.mode, item.uid, item.gid, item.mtime), (marker[1:], 0, 0o600, 0, 0, 0)
                )
                self.assertTrue(item.isreg())
                self.assertEqual(item.pax_headers, {})
                self.assertEqual((item.uname, item.gname, item.linkname), ("", "", ""))
        for marker in (RESOURCE_START_FILE, "../other", LEAF_WITNESS_START + ".after"):
            with self.assertRaises(_LeafArchiveError):
                _leaf_archive_tar(marker)

    def test_request_has_exact_binary_length_and_no_expect_or_compression(self) -> None:
        body = _leaf_archive_tar(LEAF_WITNESS_START)
        request = _leaf_archive_request("PUT", "/v1.40/containers/" + CID + "/archive?path=%2F", body)
        header, actual = request.split(b"\r\n\r\n", 1)
        self.assertEqual(actual, body)
        self.assertIn(b"Content-Length: 1536\r\n", header + b"\r\n")
        self.assertLess(len(request), 4096)
        self.assertNotIn(b"Expect:", request)
        self.assertNotIn(b"Transfer-Encoding:", request)
        with self.assertRaises(_LeafArchiveError):
            _leaf_archive_request("HEAD", "/bad\r\ninjection")

    def test_http_requires_complete_frame_and_real_completion_receipt(self) -> None:
        status, _, body = _leaf_archive_http(_reply(404, headers=b"Content-Length: 991\r\n"), "HEAD")
        self.assertEqual((status, body), (404, b""))
        self.assertEqual(_leaf_archive_http(_reply(headers=b"Content-Length: 0\r\n"), "PUT")[0], 200)
        invalid = (
            _reply().replace(b"OK complete", b"FAIL cli"),
            _reply()[:-1],
            _reply() + b"extra",
            _reply(headers=b"Content-Length: 0\r\nContent-Length: 0\r\n"),
            _reply(headers=b"Transfer-Encoding: chunked\r\n"),
            _reply(headers=b"Content-Encoding: gzip\r\n"),
            _reply(headers=b"Bad\x00: value\r\n"),
            _reply(headers=b" folded\r\n"),
            _reply(headers=b"Content-Length: 2\r\n", body=b"x"),
            _reply(body=b"unexpected HEAD body"),
            _reply().replace(b"\r\n", b"\n"),
            b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n\nBFW1 OK complete\n",
            b"x" * 32769,
        )
        for raw in invalid:
            with self.subTest(raw=raw[:60]), self.assertRaises(_LeafArchiveError):
                _leaf_archive_http(raw, "HEAD")
        with self.assertRaises(_LeafArchiveError):
            _leaf_archive_http(_reply(headers=b"Content-Length: 3\r\n", body=b"x"), "PUT")

    def test_head_ack_uses_go_regular_mode_not_posix_s_ifreg(self) -> None:
        _leaf_archive_after(_stat_header())
        for change in (
            {"name": "other"},
            {"size": True},
            {"size": 1},
            {"mode": True},
            {"mode": -1},
            {"mode": 2**32},
            {"mode": 0o100600},
            {"mode": 0x08000000 | 0o777},
            {"mode": 0x80000000 | 0o700},
            {"mode": 0x02000000},
            {"mode": 0x01000000},
            {"linkTarget": "/elsewhere"},
        ):
            with self.subTest(change=change), self.assertRaises(_LeafArchiveError):
                _leaf_archive_after(_stat_header(**change))
        for encoded in ("not base64", base64.b64encode(b'{"name":"x","name":"y"}').decode(), "x" * 1025):
            with self.assertRaises(_LeafArchiveError):
                _leaf_archive_after({"x-docker-container-path-stat": encoded})

    def test_after_timestamp_requires_real_rfc3339_calendar_without_freshness_claim(self) -> None:
        for timestamp in ("2024-02-29T23:59:59.123456789Z", "0001-01-01T00:00:00Z", "2026-10-30T12:00:00+01:30"):
            _leaf_archive_after(_stat_header(mtime=timestamp))
        for timestamp in (
            "T",
            "2026-02-29T12:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-30T24:00:00Z",
            "2026-10-30T12:00:00+24:00",
            "2026-10-30T12:00:00+00:60",
            "2026-10-30T12:00:00.1234567890Z",
            "2026-10-30",
            True,
            None,
            0,
        ):
            with self.subTest(timestamp=timestamp), self.assertRaises(_LeafArchiveError):
                _leaf_archive_after(_stat_header(mtime=timestamp))

    def test_api_range_is_numeric_and_actual_not_truthy(self) -> None:
        self.assertGreater(_leaf_archive_api("1.40"), _leaf_archive_api("1.9"))
        for value in (None, True, 1.4, "", "1", "1.40x", "0.1"):
            with self.subTest(value=value), self.assertRaises(_LeafArchiveError):
                _leaf_archive_api(value)

    def test_identity_readonly_mount_and_command_refusals(self) -> None:
        session = self.session()
        good = self.inspected(session)
        with patch.object(session, "command", return_value=json.dumps(good)):
            session.inspect(running=False)
        variants = []
        for field, value in (("Id", "d" * 64), ("Image", "wrong"), ("Name", "/wrong")):
            variants.append({**good, field: value})
        variants.extend(
            [
                {**good, "HostConfig": {"ReadonlyRootfs": True, "Tmpfs": {}}},
                {**good, "HostConfig": {"ReadonlyRootfs": 0, "Tmpfs": {}}},
                {**good, "HostConfig": {"Tmpfs": {}}},
                {**good, "HostConfig": {"ReadonlyRootfs": False, "Tmpfs": {"/": ""}}},
            ]
        )
        destinations = (
            "/",
            LEAF_WITNESS_START,
            LEAF_WITNESS_START + ".after",
            LEAF_WITNESS_START + ".finish",
            "/../bad",
        )
        variants.extend({**good, "Mounts": [{"Destination": destination}]} for destination in destinations)
        variants.append({**good, "Config": {**good["Config"], "Labels": {}}})
        variants.append({**good, "State": {"Running": False, "Status": "exited"}})
        for value in variants:
            with (
                self.subTest(value=value),
                patch.object(session, "command", return_value=json.dumps(value)),
                self.assertRaises(_LeafArchiveError),
            ):
                session.inspect(running=False)

    def prepare_create(self, session: _LeafWitnessArchive, *, slow: bool = False) -> list[str]:
        calls = []

        def command(name: str, *_args: str) -> str:
            calls.append(name)
            if "API range" in name:
                return '{"ApiVersion":"1.56","MinAPIVersion":"1.40"}'
            if "pin actual" in name:
                return IMAGE
            return CID

        session.command = MagicMock(side_effect=command)
        session.inspect = MagicMock()
        session.rpc = MagicMock(return_value=(404, {}))
        if slow:
            session.end = time.monotonic() + 9
            session.phase_end = session.end
        return calls

    def test_create_preflight_then_start_and_no_actor_when_session_room_is_short(self) -> None:
        session = self.session()
        calls = self.prepare_create(session)
        self.assertEqual(session.create(), CID)
        self.assertEqual(session.rpc.call_count, 3)
        self.assertTrue(session.record["archive"]["preflight"])
        self.assertLess(
            calls.index("create diagnostic-only leaf memory witness"),
            calls.index("start diagnostic-only leaf memory witness"),
        )
        session = self.session()
        calls = self.prepare_create(session, slow=True)
        with self.assertRaises(_LeafArchiveError):
            session.create()
        self.assertNotIn("start diagnostic-only leaf memory witness", calls)
        self.assertTrue(session.custody)

    def test_any_preexisting_entry_including_dangling_link_prevents_start(self) -> None:
        for marker_index in range(3):
            session = self.session()
            calls = self.prepare_create(session)
            session.rpc.side_effect = [(404, {})] * marker_index + [(200, _stat_header(mode=0x08000000))]
            with self.assertRaises(_LeafArchiveError):
                session.create()
            self.assertNotIn("start diagnostic-only leaf memory witness", calls)

    def test_missing_container_after_404_is_not_marker_absence(self) -> None:
        session = self.session()
        calls = self.prepare_create(session)
        session.inspect.side_effect = [None, _LeafArchiveError("identity")]
        with self.assertRaises(_LeafArchiveError):
            session.create()
        self.assertNotIn("start diagnostic-only leaf memory witness", calls)
        self.assertFalse(session.record["archive"]["preflight"])

    def test_uncertain_put_is_never_retried_and_does_not_claim_release(self) -> None:
        session = self.session()
        session.rpc = MagicMock(side_effect=_LeafArchiveError("transport"))
        with self.assertRaises(_LeafArchiveError):
            session.await_after()
        self.assertEqual(session.rpc.call_count, 1)
        self.assertEqual(session.record["archive"]["release"], "unavailable")

    def test_one_protocol_deadline_and_ping_poll_overhead_share_allowance(self) -> None:
        clock = [100.0]
        ctx = MagicMock(timeout=20, runtime_deadline=200)
        ctx.backend.command_timeout.side_effect = lambda value: min(value, 15)
        with patch("scripts.runtime_docker_systemd.time.monotonic", side_effect=lambda: clock[0]):
            end = _leaf_archive_end(ctx)
        self.assertEqual(end, 115)
        session = self.session()
        session.end, session.phase_end = 120, 120
        session.ctx.runtime_deadline = 200
        session.inspect = MagicMock()

        def rpc(*_args: object) -> tuple[int, dict]:
            clock[0] += 5  # Includes actual CLI initialization, not just socket work.
            return 200, {}

        session.rpc = MagicMock(side_effect=rpc)
        with (
            patch("scripts.runtime_docker_systemd.time.monotonic", side_effect=lambda: clock[0]),
            self.assertRaises(_LeafArchiveError),
        ):
            session.await_after()
        self.assertEqual(session.end, 120)
        self.assertEqual(session.rpc.call_count, 2)
        self.assertNotEqual(session.record.get("awaitResult"), "after-observed")

    def test_rpc_keeps_outer_guard_stdout_role_and_explicit_inner_endpoint(self) -> None:
        session = self.session()
        session.ctx.exec_guard = ("owned-placement-guard",)
        session.ctx.read_witness_response.return_value = _reply(404)
        self.assertEqual(session.rpc("HEAD", LEAF_WITNESS_START)[0], 404)
        call = session.ctx.podman.call_args
        self.assertEqual(call.args[1:4], ("exec", GUEST, "owned-placement-guard"))
        self.assertIn("/bin/dash", call.args)
        self.assertEqual(call.args[-2], "unix:///run/user/1000/docker.sock")
        self.assertIs(call.kwargs["stdout"], session.response)
        self.assertNotIn("stdin", call.kwargs)
        self.assertNotIn("--tty", call.args)
        encoded = call.args[-3]
        request = base64.b64decode(encoded, validate=True)
        self.assertIn(CID.encode(), request)
        self.assertNotIn("/proc/", request.decode())
        self.assertNotIn(CID, json.dumps(session.record))
        session.ctx.containers = []
        session.ctx.podman.reset_mock()
        with self.assertRaises(_LeafArchiveError):
            session.rpc("HEAD", LEAF_WITNESS_START)
        session.ctx.podman.assert_not_called()

    def test_late_http_parsing_refuses_before_publishing_status_or_ack(self) -> None:
        session = self.session()
        clock = [time.monotonic()]
        session.end = clock[0] + 1
        session.phase_end = session.end
        session.ctx.read_witness_response.return_value = _reply(404)

        def late(_raw: bytes, _method: str) -> tuple[int, dict, bytes]:
            clock[0] += 2
            return 404, {}, b""

        with (
            patch("scripts.runtime_docker_systemd.time.monotonic", side_effect=lambda: clock[0]),
            patch("scripts.runtime_docker_systemd._leaf_archive_http", side_effect=late),
            self.assertRaises(_LeafArchiveError),
        ):
            session.rpc("HEAD", LEAF_WITNESS_START)
        self.assertNotIn("httpStatus", session.record["archive"])

    def test_actual_api_range_refuses_create_and_uncertain_start_is_once_only(self) -> None:
        for version in (
            '{"ApiVersion":"1.39","MinAPIVersion":"1.20"}',
            '{"ApiVersion":"1.56","MinAPIVersion":"1.41"}',
            '{"ApiVersion":"1.56","MinAPIVersion":true}',
        ):
            session = self.session()
            session.command = MagicMock(return_value=version)
            with self.assertRaises(_LeafArchiveError):
                session.create()
            self.assertFalse(session.custody)
            self.assertEqual(session.command.call_count, 1)
        session = self.session()
        self.prepare_create(session)
        original = session.command.side_effect

        def uncertain(name: str, *args: str) -> str:
            return "" if name.startswith("start diagnostic") else original(name, *args)

        session.command.side_effect = uncertain
        with self.assertRaises(_LeafArchiveError):
            session.create()
        starts = [call for call in session.command.call_args_list if call.args[0].startswith("start diagnostic")]
        self.assertEqual(len(starts), 1)
        self.assertTrue(session.custody)
        self.assertEqual(session.workload, CID)


class BridgeShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.previous_subreaper = ctypes.c_int()
        if not hasattr(cls.libc, "prctl") or cls.libc.prctl(37, ctypes.byref(cls.previous_subreaper), 0, 0, 0) != 0:
            message = "Linux child custody unavailable"
            raise unittest.SkipTest(message)
        if cls.libc.prctl(36, 1, 0, 0, 0) != 0:
            message = "cannot retain task-owned orphan children"
            raise unittest.SkipTest(message)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.libc.prctl(36, cls.previous_subreaper.value, 0, 0, 0) != 0:
            message = "failed to restore test process child custody"
            raise AssertionError(message)

    def owned_shell(self, command: list[str], environment: dict[str, str]) -> tuple[bytes, bytes, int]:
        # Retain the leader as a zombie until signalling its exact session/group;
        # its reserved PID cannot be reused. Reap only this group's adopted children.
        with (
            tempfile.TemporaryFile() as output,
            subprocess.Popen(  # noqa: S603 — one task-owned test session.
                command,
                env=environment,
                stdout=output,
                stderr=subprocess.PIPE,
                start_new_session=True,
            ) as process,
        ):
            try:
                end = time.monotonic() + 5
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    self.assertLess(time.monotonic(), end, "owned bridge failed to terminate")
                    time.sleep(0.01)
            finally:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                _, error = process.communicate(timeout=2)
                end = time.monotonic() + 2
                while True:
                    try:
                        child, _ = os.waitpid(-process.pid, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if child == 0:
                        self.assertLess(time.monotonic(), end, "task-owned child did not reap")
                        time.sleep(0.01)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)
            output.seek(0)
            return output.read(32770), error, process.returncode

    def run_bridge(self, mode: str = "ok", *, script: str = LEAF_WITNESS_BRIDGE_COMMAND) -> tuple[bytes, bool]:
        shell = shutil.which("dash") or shutil.which("sh")
        self.assertIsNotNone(shell)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            called = root / "called"
            tools = {name: shutil.which(name) for name in ("mktemp", "stat", "base64", "rm", "rmdir", "head", "cat")}
            self.assertTrue(all(tools.values()))
            busybox = root / "busybox"
            busybox.write_text(
                "#!"
                + sys.executable
                + "\nimport os,sys\n"
                + "tools="
                + repr(tools)
                + "\nargs=sys.argv[1:]\n"
                + "if args[0]=='mktemp': args[-1]=os.environ['TEST_ROOT']+'/scratch.XXXXXX'\n"
                + "os.execv(tools[args[0]],args)\n"
            )
            busybox.chmod(0o700)
            docker = root / "docker"
            docker.write_text(
                "#!"
                + sys.executable
                + "\nimport os,sys,resource,signal\n"
                + "mode=os.environ['TEST_MODE']\n"
                + "assert sys.argv[1:]==['--host','unix:///private.sock','--tls=false','system','dial-stdio']\n"
                + "open(os.environ['TEST_CALLED'],'wb').write(b'x')\n"
                + "soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)\n"
                + "assert 0<soft<=1024 and soft==hard\n"
                + "assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\n"
                + "data=sys.stdin.buffer.read(4096);assert data.startswith(b'HEAD ')\n"
                + "if mode=='signal': os.kill(os.getpid(),signal.SIGTERM)\n"
                + "if mode=='producer-death':\n"
                + " os.write(1,b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n\\nBFW1 OK complete\\n');"
                + " parent=os.getppid()\n"
                + " for _ in range(4):\n"
                + "  assert parent!=os.getpgrp() and os.getpgid(parent)==os.getpgrp()\n"
                + "  try: target=os.readlink('/proc/'+str(parent)+'/fd/7')\n"
                + "  except FileNotFoundError: target=''\n"
                + "  if target.endswith('/proof'): break\n"
                + "  parent=int(open('/proc/'+str(parent)+'/stat').read().rsplit(')',1)[1].split()[1])\n"
                + " else: raise AssertionError('owned producer not found')\n"
                + " os.kill(parent,signal.SIGKILL);sys.exit(0)\n"
                + "if mode=='stderr-http': os.write(2,b'HTTP/1.1 200 OK\\r\\n\\r\\n')\n"
                + "if mode=='stderr-flood':\n"
                + " try: os.write(2,b'x'*4096)\n except OSError: pass\n"
                + "if mode in ('missing','symlink','replace'):\n"
                + " path=os.readlink('/proc/self/fd/4');os.unlink(path)\n"
                + " if mode=='symlink': os.symlink('/dev/null',path)\n"
                + " if mode=='replace': open(path,'wb').close()\n"
                + "os.write(1,b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n')\n"
                + "sys.exit(1 if mode=='lost-status' else 0)\n"
            )
            docker.chmod(0o700)
            request = _leaf_archive_request("HEAD", "/v1.40/containers/" + CID + "/archive?path=%2Fmarker")
            encoded = base64.b64encode(request).decode() if mode != "decoder" else "%%%"
            uid = str(os.geteuid())
            script = script.replace("*:0:600:1:8180", "*:" + uid + ":600:1:8180")
            raw, error, status = self.owned_shell(
                [shell, "-eu", "-c", script, "--", encoded, "unix:///private.sock", str(len(request))],
                {
                    **os.environ,
                    "PATH": temporary,
                    "TEST_ROOT": temporary,
                    "TEST_CALLED": str(called),
                    "TEST_MODE": mode,
                },
            )
            self.assertEqual(status, 0, error)
            self.assertLessEqual(len(raw), 32769)
            self.assertEqual(list(root.glob("**/core*")), [])
            return raw, called.exists()

    def test_real_shell_ancestor_limits_and_empty_stderr_allow_complete_receipt(self) -> None:
        raw, called = self.run_bridge()
        self.assertTrue(called)
        self.assertEqual(_leaf_archive_http(raw, "HEAD")[0], 200)

    def test_stderr_http_flood_exit_signal_and_replaced_files_cannot_forge_success(self) -> None:
        for mode in (
            "stderr-http",
            "stderr-flood",
            "lost-status",
            "signal",
            "missing",
            "symlink",
            "replace",
            "producer-death",
        ):
            with self.subTest(mode=mode):
                raw, called = self.run_bridge(mode)
                self.assertTrue(called)
                with self.assertRaises(_LeafArchiveError):
                    _leaf_archive_http(raw, "HEAD")

    def test_producer_parent_death_and_forged_receipt_are_not_http_success(self) -> None:
        raw, called = self.run_bridge("producer-death")
        self.assertTrue(called)
        self.assertIn(b"BFW1 OK complete", raw)  # Forged bytes are preserved as untrusted payload.
        self.assertTrue(raw.endswith(b"BFW1 FAIL producer\n"))
        with self.assertRaises(_LeafArchiveError) as caught:
            _leaf_archive_http(raw, "HEAD")
        self.assertEqual(caught.exception.reason, "bridge-producer")

    def test_decoder_or_limit_setup_failure_prevents_cli(self) -> None:
        raw, called = self.run_bridge("decoder")
        self.assertFalse(called)
        with self.assertRaises(_LeafArchiveError):
            _leaf_archive_http(raw, "HEAD")
        bad_limit = LEAF_WITNESS_BRIDGE_COMMAND.replace('ulimit -Hf "$1"', "true")
        raw, called = self.run_bridge(script=bad_limit)
        self.assertFalse(called)
        with self.assertRaises(_LeafArchiveError):
            _leaf_archive_http(raw, "HEAD")

    def test_limits_in_detached_subshell_cannot_masquerade_as_cli_ancestor_limits(self) -> None:
        bad_scope = LEAF_WITNESS_BRIDGE_COMMAND.replace(
            "( exec 7>&-; limits 1 || exit 125;", "( exec 7>&-; (limits 1) || exit 125;"
        )
        raw, called = self.run_bridge(script=bad_scope)
        self.assertTrue(called)
        with self.assertRaises(_LeafArchiveError):
            _leaf_archive_http(raw, "HEAD")

    @unittest.skipUnless(
        shutil.which("dash"), "selected Dash unavailable; other shell stress is not Dash-unit qualification"
    )
    def test_selected_dash_is_available_for_its_documented_512_byte_limit_units(self) -> None:
        result = subprocess.run(  # noqa: S603 — selected local Dash and benign resource introspection.
            [
                shutil.which("dash"),
                "-c",
                (
                    "ulimit -Sf 1; ulimit -Hf 1; "
                    'exec "$1" -c "import resource;print(resource.getrlimit(resource.RLIMIT_FSIZE))"'
                ),
                "--",
                sys.executable,
            ],
            capture_output=True,
            check=True,
            timeout=2,
        )
        self.assertEqual(result.stdout.strip(), b"(512, 512)")


if __name__ == "__main__":
    unittest.main()
