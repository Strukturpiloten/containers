"""Offline contract tests with fake root/host/supervisor facts and owned inert files."""

from __future__ import annotations

import ast
import hashlib
import importlib.abc
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

if TYPE_CHECKING:
    from collections.abc import Iterator

from scripts import docker_userns_custody as custody
from scripts import docker_userns_custody_child as child

REPO = Path(__file__).resolve().parents[1]
BOOT = "11111111-1111-1111-1111-111111111111"
OTHER_BOOT = "22222222-2222-2222-2222-222222222222"


def digest(data: bytes) -> str:
    """Hash inert fixture bytes."""
    return hashlib.sha256(data).hexdigest()


def policy(name: str) -> bytes:
    """Independent expected bytes emitted only by the test's fake builder."""
    return f"abi <abi/4.0>,\nprofile {name} flags=(unconfined) {{\n  userns,\n}}\n".encode("ascii")


def identity(inode: int, mode: int = 0o644) -> custody.FileIdentity:
    """Create explicit fake fresh root filesystem facts."""
    return custody.FileIdentity(1, inode, 0, stat.S_IFREG | mode, 1, 0, 4, 5)


class Clock:
    def __init__(self) -> None:
        """Keep test time/boot mutable without changing a host clock."""
        self.time = 1_000_000_000
        self.boot = BOOT

    def now_ns(self) -> int:
        return self.time

    def boot_id(self) -> str:
        return self.boot


class Host:
    def __init__(self, observation: custody.Observation) -> None:
        """Hold explicit fake observation data, never a real host adapter."""
        self.observation = observation
        self.changed = None
        self.calls = 0

    def observe(self, _request: custody.Request) -> custody.Observation:
        self.calls += 1
        return self.observation

    def reobserve(self, observation: custody.Observation) -> custody.Observation:
        return self.changed or observation


class Supervisor:
    """Explicit fake observations confer no production authentication."""

    def __init__(self, clock: Clock) -> None:
        """Record fake protocol calls only."""
        self.clock = clock
        self.starts = 0
        self.inspections = 0
        self.closes = 0
        self.corrupt = None
        self.fail_start = False
        self.timeout = False
        self.owner = None

    def live(self, lease: custody.Lease, owner: custody.Owner | None = None) -> custody.OwnerObservation:
        owner = owner or custody.Owner(
            "containers-userns-unused-" + lease.nonce,
            custody.Process(os.getpid() + 1000, 202, lease.coordinator.pgid + 1, 0, custody.Group("/outside", 1, 88)),
        )
        observation = custody.OwnerObservation(
            lease,
            owner,
            self.clock.time,
            custody.Lifetime.LIVE,
            acknowledged=True,
            service_root_owned=True,
            group_absent=False,
            cgroup_absent=False,
        )
        return self.corrupt(observation) if self.corrupt is not None else observation

    def start_unused_owner(self, intent: custody.ArmIntent, _deadline_ns: int) -> custody.OwnerObservation:
        lease = intent.lease
        self.starts += 1
        if self.fail_start:
            raise RuntimeError
        if self.timeout:
            self.clock.time += custody.HANDSHAKE_NS
        observation = self.live(lease)
        self.owner = observation.owner
        return observation

    def inspect_owner(self, lease: custody.Lease, owner: custody.Owner, _deadline_ns: int) -> custody.OwnerObservation:
        self.inspections += 1
        return self.live(lease, owner)

    def request_close(self, _lease: custody.Lease, _owner: custody.Owner, _deadline_ns: int) -> None:
        self.closes += 1

    def observe_termination(self, lease: custody.Lease, owner: custody.Owner) -> custody.OwnerObservation:
        return replace(self.live(lease, owner), lifetime=custody.Lifetime.DEAD, group_absent=True, cgroup_absent=True)


class CustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        real_stat, real_fstat = os.stat, os.fstat

        def root_owned(info: os.stat_result) -> SimpleNamespace:
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            return SimpleNamespace(**{**fields, "st_uid": 0})

        self.stack.enter_context(patch.object(custody, "ROOT", self.root))
        self.stack.enter_context(patch.object(custody.os, "geteuid", return_value=0))
        self.stack.enter_context(
            patch.object(custody.os, "stat", side_effect=lambda *args, **kw: root_owned(real_stat(*args, **kw)))
        )
        self.stack.enter_context(patch.object(custody.os, "fstat", side_effect=lambda fd: root_owned(real_fstat(fd))))
        self.stack.enter_context(patch.object(custody, "_self_start", return_value=101))
        self.sources, self.fds = {}, []
        value = json.loads((REPO / ".github/docker-userns-policy-source.json").read_bytes())
        for index, path in enumerate(custody.SOURCE_PATHS):
            data = f"inert source fixture {index}".encode()
            self.sources[path] = data
            file = self.root / f"input-{index}"
            file.write_bytes(data)
            fd = os.open(file, os.O_RDONLY | os.O_CLOEXEC)
            self.stack.callback(os.close, fd)
            self.fds.append(custody.SourceFD(path, fd))
        value["source"]["files"] = [
            {"path": name, "size": len(data), "sha256": digest(data)} for name, data in self.sources.items()
        ]
        manifest = json.dumps(value).encode()
        parser, abi = b"\x7fELFfake parser", b"fake ABI4"
        helpers = (b"reviewed helper one", b"reviewed helper two")
        self.cohort = custody.Cohort(
            "ubuntu",
            "26.04",
            "x86_64",
            "7.0.0-test",
            "ubuntu26",
            "20261020.1.0",
            "5.0.2",
            digest(parser),
            digest(abi),
            ("userns_create",),
        )
        authority = custody.BootstrapAuthority(digest(b"trusted system interpreter"), tuple(map(digest, helpers)))
        self.admission = custody.Admission(manifest, digest(manifest), self.cohort, authority)
        self.clock = Clock()
        run = custody.Run(
            "a" * 40,
            "b" * 40,
            "c" * 40,
            "17",
            "2",
            "unused-custody",
            "Strukturpiloten/containers",
            492,
            "TheRealBecks/issue442-main-reconciled",
            "github-hosted",
            "pull_request",
            "github-pr-merge",
        )
        coordinator = custody.Process(os.getpid(), 101, os.getpgid(0), 0, custody.Group("/coordinator", 1, 77))
        self.request = custody.Request(run, self.clock.time + custody.MAX_TOTAL_NS, 1001, 1002, coordinator.cgroup)
        observation = custody.Observation(
            run,
            self.cohort,
            BOOT,
            coordinator,
            parser,
            abi,
            (b"Y\n", b"1\n", b"userns_create\n", b"yes\n"),
            (identity(10, 0o755), *(identity(index + 11) for index in range(5))),
            child.Interpreter(12345, authority.interpreter_sha256),
            helpers,
            (identity(20), identity(21)),
            "/usr/sbin/apparmor_parser",
            "/etc/apparmor.d/abi/4.0",
            b"",
        )
        self.host = Host(observation)
        self.seal_count = 0

        def seal(module: str, data: bytes) -> child.Source:
            self.seal_count += 1
            path = self.root / f"fake-sealed-{self.seal_count}"
            path.write_bytes(data)
            path.chmod(0o400)
            return child.Source(module, os.open(path, os.O_RDONLY | os.O_CLOEXEC), len(data), digest(data))

        self.stack.enter_context(patch.object(child, "seal", side_effect=seal))

        def build(
            _interpreter: child.Interpreter, sources: tuple[child.Source, ...], lease: child.Build, _clock: child.Clock
        ) -> child.Outcome:
            self.assertEqual(tuple(item.module for item in sources), child.MODULES)
            for item, path in zip(sources, custody.SOURCE_PATHS, strict=False):
                self.assertEqual(child.bytes_at(item.descriptor, item.size), self.sources[path])
                self.assertEqual(child.fcntl.fcntl(item.descriptor, child.fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            return child.Outcome(policy(lease.name), dead=True)

        self.builder = self.stack.enter_context(patch.object(child, "build", side_effect=build))

    def prepare(self) -> custody.Locator:
        return custody.prepare_unused(self.admission, self.request, tuple(self.fds), self.host, self.clock)

    def record(self, locator: custody.Locator) -> custody.Record:
        with custody._store(locator) as store:
            return store.load()

    def directory(self, locator: custody.Locator) -> Path:
        return self.root / (custody.PREFIX + locator.nonce)

    def armed(self) -> tuple[custody.Locator, Supervisor]:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        custody.arm_unused(locator, supervisor, self.clock)
        return locator, supervisor

    @contextmanager
    def caller(self, process: custody.Process) -> Iterator[None]:
        with (
            patch.object(custody.os, "getpid", return_value=process.pid),
            patch.object(custody.os, "getpgid", return_value=process.pgid),
            patch.object(custody, "_self_start", return_value=process.start_ticks),
        ):
            yield

    def test_prepared_state_has_never_facts_original_deadline_and_sealed_sources(self) -> None:
        locator = self.prepare()
        record = self.record(locator)
        self.assertEqual(record.state, custody.State.PREPARED)
        self.assertFalse(record.child_pending)
        self.assertFalse(record.owner_attempted)
        self.assertIsNone(record.owner)
        self.assertEqual((record.policy_load, record.container_create), ("never", "never"))
        self.assertEqual(
            set(self.directory(locator).iterdir()), {self.directory(locator) / leaf for leaf in custody.MODES}
        )
        self.assertEqual(record.lease.deadline_ns, self.request.original_deadline_ns)
        self.assertEqual(record.lease.work_until_ns, record.lease.deadline_ns - custody.CLEANUP_NS)
        self.assertEqual(record.lease.policy_sha256, digest(policy(record.lease.policy_name)))
        self.builder.assert_called_once()

    def test_no_root_host_or_bootstrap_default_can_prepare(self) -> None:
        with patch.object(custody.os, "geteuid", return_value=1000), self.assertRaises(custody.CustodyError):
            self.prepare()
        with self.assertRaises(custody.CustodyError):
            custody.prepare_unused(self.admission, self.request, tuple(self.fds), None, self.clock)
        with self.assertRaises(custody.CustodyError):
            custody.prepare_unused(
                replace(self.admission, bootstrap=None), self.request, tuple(self.fds), self.host, self.clock
            )
        self.builder.assert_not_called()

    def test_new_run_accepts_fresh_identities_and_reproduces_new_policy_digest(self) -> None:
        first = self.record(self.prepare()).lease
        self.request = replace(self.request, run=replace(self.request.run, workflow_run="18"))
        self.host.observation = replace(
            self.host.observation,
            run=self.request.run,
            boot=OTHER_BOOT,
            identities=(identity(100, 0o755), *(identity(index + 101) for index in range(5))),
        )
        self.clock.boot = OTHER_BOOT
        second = self.record(self.prepare()).lease
        self.assertEqual(first.cohort, second.cohort)
        self.assertNotEqual(first.identities, second.identities)
        self.assertNotEqual(first.boot, second.boot)
        self.assertNotEqual(first.policy_sha256, second.policy_sha256)
        self.assertNotEqual(first.nonce, second.nonce)

    def test_cohort_content_path_capabilities_and_helper_substitution_refuse(self) -> None:
        original = self.host.observation
        variants = [
            replace(original, parser=b"changed"),
            replace(original, abi=b"changed"),
            replace(original, parser_path="/unreviewed/parser"),
            replace(original, parser_capabilities=None),
            replace(original, features=(b"Y\n", b"0\n", b"userns_create\n", b"yes\n")),
            replace(original, cohort=replace(self.cohort, kernel="other-kernel")),
            replace(original, helpers=(b"unchecked", b"unchecked")),
            replace(original, identities=(replace(identity(1), owner=1000),) * 6),
        ]
        for observation in variants:
            with self.subTest(observation=observation), self.assertRaises(custody.CustodyError):
                self.host.observation = observation
                self.prepare()
        self.builder.assert_not_called()

    def test_foreign_context_and_unsupported_architecture_refuse(self) -> None:
        for change in (
            {"repository": "other/containers"},
            {"pull_request": 493},
            {"provider": "self-hosted"},
            {"event": "push"},
            {"checkout_identity": "head"},
            {"head_ref": "unreviewed"},
        ):
            with self.subTest(change=change), self.assertRaises(custody.CustodyError):
                custody.prepare_unused(
                    self.admission,
                    replace(self.request, run=replace(self.request.run, **change)),
                    tuple(self.fds),
                    self.host,
                    self.clock,
                )
        with self.assertRaises(custody.CustodyError):
            custody.prepare_unused(
                replace(self.admission, cohort=replace(self.cohort, architecture="aarch64")),
                self.request,
                tuple(self.fds),
                self.host,
                self.clock,
            )
        self.builder.assert_not_called()

    def test_source_substitution_alias_and_unknown_manifest_keys_refuse(self) -> None:
        path = self.root / "input-0"
        original = path.read_bytes()
        path.write_bytes(b"wrong")
        with self.assertRaises(custody.CustodyError) as caught:
            self.prepare()
        self.assertEqual(self.record(caught.exception.locator).state, custody.State.RETAINED)
        path.write_bytes(original)
        os.link(path, self.root / "alias")
        with self.assertRaises(custody.CustodyError):
            self.prepare()
        value = json.loads(self.admission.manifest)
        value["unexpected"] = True
        raw = json.dumps(value).encode()
        with self.assertRaises(custody.CustodyError):
            custody.prepare_unused(
                replace(self.admission, manifest=raw, manifest_sha256=digest(raw)),
                self.request,
                tuple(self.fds),
                self.host,
                self.clock,
            )
        self.builder.assert_not_called()

    def test_child_uncertainty_is_sticky_and_cannot_be_rearmed(self) -> None:
        self.builder.side_effect = child.ChildError(dead=False)
        with self.assertRaises(custody.CustodyError) as caught:
            self.prepare()
        locator = caught.exception.locator
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)
        self.assertTrue(self.record(locator).child_pending)
        supervisor = Supervisor(self.clock)
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(supervisor.starts, 0)

    def test_sealing_failure_is_never_started_and_not_a_pending_child(self) -> None:
        with (
            patch.object(child, "seal", side_effect=child.ChildError()),
            self.assertRaises(custody.CustodyError) as caught,
        ):
            self.prepare()
        self.assertFalse(caught.exception.child_pending)
        self.assertEqual(self.record(caught.exception.locator).state, custody.State.RETAINED)
        self.assertFalse(self.record(caught.exception.locator).child_pending)
        self.builder.assert_not_called()

    def test_failed_child_with_proven_cleanup_is_retained_without_pending_lifetime(self) -> None:
        failure = child.ChildError(lifetime=child.Lifetime.DEAD)
        self.builder.side_effect = failure
        with self.assertRaises(custody.CustodyError) as caught:
            self.prepare()
        self.assertIs(caught.exception.__cause__, failure)
        self.assertFalse(caught.exception.child_pending)
        self.assertFalse(self.record(caught.exception.locator).child_pending)
        self.assertEqual(self.record(caught.exception.locator).state, custody.State.RETAINED)

    def test_post_child_primary_failure_does_not_erase_known_death(self) -> None:
        with (
            patch.object(self.host, "reobserve", side_effect=[self.host.observation, RuntimeError]),
            self.assertRaises(custody.CustodyError) as caught,
        ):
            self.prepare()
        self.assertFalse(caught.exception.child_pending)
        self.assertFalse(self.record(caught.exception.locator).child_pending)

    def test_in_invocation_identity_drift_prevents_import(self) -> None:
        self.host.changed = replace(self.host.observation, identities=(identity(100, 0o755),) * 6)
        with self.assertRaises(custody.CustodyError) as caught:
            self.prepare()
        self.builder.assert_not_called()
        self.assertEqual(self.record(caught.exception.locator).state, custody.State.RETAINED)

    def test_absent_supervisor_never_synthesizes_readiness(self) -> None:
        locator = self.prepare()
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, None, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.PREPARED)

    def test_full_ack_reobservation_and_single_arm_attempt(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        self.assertEqual(record.state, custody.State.ARMED)
        self.assertEqual((supervisor.starts, supervisor.inspections), (1, 1))
        self.assertEqual(record.owner, supervisor.owner)
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(supervisor.starts, 1)

    def test_false_ack_inside_slice_kill_group_and_timeouts_are_retained(self) -> None:
        corruptions = [
            lambda obs: replace(obs, lease=replace(obs.lease, nonce="f" * 32)),
            lambda obs: replace(obs, lease=replace(obs.lease, deadline_ns=obs.lease.deadline_ns + 1)),
            lambda obs: replace(obs, owner=replace(obs.owner, service="name-only")),
            lambda obs: replace(obs, service_root_owned=False),
            lambda obs: replace(obs, acknowledged=False),
            lambda obs: replace(
                obs,
                owner=replace(
                    obs.owner,
                    process=replace(obs.owner.process, cgroup=custody.Group("/coordinator/inside", 1, 100)),
                ),
            ),
            lambda obs: replace(
                obs, owner=replace(obs.owner, process=replace(obs.owner.process, pgid=obs.lease.coordinator.pgid))
            ),
        ]
        for corruption in corruptions:
            locator = self.prepare()
            supervisor = Supervisor(self.clock)
            supervisor.corrupt = corruption
            with self.subTest(corruption=corruption), self.assertRaises(custody.CustodyError):
                custody.arm_unused(locator, supervisor, self.clock)
            self.assertEqual(self.record(locator).state, custody.State.RETAINED)
            with self.assertRaises(custody.CustodyError):
                custody.arm_unused(locator, supervisor, self.clock)
            self.assertEqual(supervisor.starts, 1)
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        supervisor.timeout = True
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)

    def test_uncertain_start_and_reobserved_pid_reuse_retain(self) -> None:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        supervisor.fail_start = True
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        original = supervisor.inspect_owner

        def reused(lease: custody.Lease, owner: custody.Owner, deadline_ns: int) -> custody.OwnerObservation:
            observation = original(lease, owner, deadline_ns)
            return replace(
                observation,
                owner=replace(observation.owner, process=replace(observation.owner.process, start_ticks=999)),
            )

        supervisor.inspect_owner = reused
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)

    def test_original_deadline_reserve_and_reboot_never_renew(self) -> None:
        self.request = replace(self.request, original_deadline_ns=self.clock.time + custody.CLEANUP_NS)
        with self.assertRaises(custody.CustodyError):
            self.prepare()
        self.request = replace(self.request, original_deadline_ns=self.clock.time + 2 * custody.MAX_TOTAL_NS)
        locator = self.prepare()
        lease = self.record(locator).lease
        self.assertEqual(lease.deadline_ns, lease.start_ns + custody.MAX_TOTAL_NS)
        self.clock.time = lease.work_until_ns
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, Supervisor(self.clock), self.clock)
        self.assertEqual(self.record(locator).lease.deadline_ns, lease.deadline_ns)
        self.clock.boot = OTHER_BOOT
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, Supervisor(self.clock), self.clock)

    def test_cancelled_closure_is_not_promoted_to_normal(self) -> None:
        locator, supervisor = self.armed()
        custody.request_close_unused(locator, supervisor, self.clock)
        record = self.record(locator)
        self.assertEqual(record.state, custody.State.CLOSING)
        self.assertEqual(supervisor.closes, 1)
        observation = supervisor.live(record.lease, record.owner)
        with self.caller(record.owner.process):
            receipt = custody.finalize_unused(locator, observation, custody.Cause.CANCELLED, self.clock)
            self.assertEqual(custody.finalize_unused(locator, observation, custody.Cause.NORMAL, self.clock), receipt)
        self.assertEqual(receipt.cause, custody.Cause.CANCELLED)
        self.assertEqual(receipt.qualification, "none")

    def test_expiry_wins_race_and_wrong_current_owner_cannot_finalize(self) -> None:
        locator, supervisor = self.armed()
        custody.request_close_unused(locator, supervisor, self.clock)
        record = self.record(locator)
        with self.assertRaises(custody.CustodyError):
            custody.finalize_unused(
                locator, supervisor.live(record.lease, record.owner), custody.Cause.NORMAL, self.clock
            )
        self.clock.time = record.lease.work_until_ns
        observation = supervisor.live(record.lease, record.owner)
        with self.caller(record.owner.process):
            receipt = custody.finalize_unused(locator, observation, custody.Cause.EXPIRY, self.clock)
            self.assertEqual(custody.finalize_unused(locator, observation, custody.Cause.NORMAL, self.clock), receipt)
        self.assertEqual(receipt.cause, custody.Cause.EXPIRY)

    def test_expiry_boundaries_are_work_cutoff_inclusive_and_final_cutoff_exclusive(self) -> None:
        for boundary, accepted in (("W-1", False), ("W", True), ("D-1", True), ("D", False)):
            self.request = replace(self.request, original_deadline_ns=self.clock.time + custody.MAX_TOTAL_NS)
            locator, supervisor = self.armed()
            record = self.record(locator)
            self.clock.time = {
                "W-1": record.lease.work_until_ns - 1,
                "W": record.lease.work_until_ns,
                "D-1": record.lease.deadline_ns - 1,
                "D": record.lease.deadline_ns,
            }[boundary]
            observation = supervisor.live(record.lease, record.owner)
            before = (self.directory(locator) / "state.json").read_bytes()
            with self.subTest(boundary=boundary), self.caller(record.owner.process):
                if accepted:
                    receipt = custody.finalize_unused(locator, observation, custody.Cause.EXPIRY, self.clock)
                    self.assertEqual(receipt.cause, custody.Cause.EXPIRY)
                else:
                    with self.assertRaises(custody.CustodyError):
                        custody.finalize_unused(locator, observation, custody.Cause.EXPIRY, self.clock)
                    self.assertEqual((self.directory(locator) / "state.json").read_bytes(), before)

    def test_no_closed_idempotence_or_disposal_is_accepted_at_or_after_final_cutoff(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        live = supervisor.live(record.lease, record.owner)
        with self.caller(record.owner.process):
            custody.finalize_unused(locator, live, custody.Cause.CANCELLED, self.clock)
        for moment in (record.lease.deadline_ns, record.lease.deadline_ns + 1):
            self.clock.time = moment
            live = supervisor.live(record.lease, record.owner)
            with (
                self.subTest(moment=moment),
                self.caller(record.owner.process),
                self.assertRaises(custody.CustodyError),
            ):
                custody.finalize_unused(locator, live, custody.Cause.NORMAL, self.clock)
            with self.assertRaises(custody.CustodyError):
                custody.request_close_unused(locator, supervisor, self.clock)
            with self.assertRaises(custody.CustodyError):
                custody.dispose_unused(locator, supervisor.observe_termination(record.lease, record.owner), self.clock)
        self.assertEqual(self.record(locator).cause, custody.Cause.CANCELLED)
        self.assertTrue(self.directory(locator).exists())

    def test_close_adapter_crossing_final_cutoff_or_reboot_cannot_return_success(self) -> None:
        for fault in ("deadline", "reboot"):
            self.request = replace(self.request, original_deadline_ns=self.clock.time + custody.MAX_TOTAL_NS)
            locator, supervisor = self.armed()
            lease = self.record(locator).lease

            def late(
                _lease: custody.Lease,
                _owner: custody.Owner,
                _end: int,
                *,
                _fault: str = fault,
                _bound: custody.Lease = lease,
            ) -> None:
                if _fault == "deadline":
                    self.clock.time = _bound.deadline_ns
                else:
                    self.clock.boot = OTHER_BOOT

            supervisor.request_close = late
            with self.subTest(fault=fault), self.assertRaises(custody.CustodyError):
                custody.request_close_unused(locator, supervisor, self.clock)
            self.assertEqual(self.record(locator).lease.deadline_ns, lease.deadline_ns)
            self.assertEqual(self.record(locator).state, custody.State.CLOSING)

    def test_cleanup_can_complete_at_d_minus_one_without_renewing_any_deadline(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        self.clock.time = record.lease.deadline_ns - 1
        custody.request_close_unused(locator, supervisor, self.clock)
        observation = supervisor.live(record.lease, record.owner)
        with self.caller(record.owner.process):
            custody.finalize_unused(locator, observation, custody.Cause.EXPIRY, self.clock)
        custody.dispose_unused(locator, supervisor.observe_termination(record.lease, record.owner), self.clock)
        self.assertFalse(self.directory(locator).exists())

    def test_arm_start_finishing_at_d_does_not_issue_a_new_inspection(self) -> None:
        locator = self.prepare()
        lease = self.record(locator).lease
        supervisor = Supervisor(self.clock)
        original = supervisor.start_unused_owner

        def late(bound: custody.Lease, end: int) -> custody.OwnerObservation:
            result = original(bound, end)
            self.clock.time = lease.deadline_ns
            return result

        supervisor.start_unused_owner = late
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(supervisor.starts, 1)
        self.assertEqual(supervisor.inspections, 0)
        self.assertEqual(self.record(locator).state, custody.State.ARM_INTENT)

    def test_final_durable_write_crossing_deadline_reports_failure_without_receipt(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        self.clock.time = record.lease.deadline_ns - 1
        original = custody._Store.save

        def late(store: custody._Store, updated: custody.Record) -> None:
            original(store, updated)
            if updated.state is custody.State.CLOSED:
                self.clock.time = record.lease.deadline_ns

        observation = supervisor.live(record.lease, record.owner)
        with (
            patch.object(custody._Store, "save", new=late),
            self.caller(record.owner.process),
            self.assertRaises(custody.CustodyError),
        ):
            custody.finalize_unused(locator, observation, custody.Cause.CANCELLED, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.CLOSED)
        self.assertEqual(self.record(locator).cause, custody.Cause.CANCELLED)

    def test_disposal_finishing_late_fails_without_recreating_removed_state(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        with self.caller(record.owner.process):
            custody.finalize_unused(
                locator, supervisor.live(record.lease, record.owner), custody.Cause.NORMAL, self.clock
            )
        dead = supervisor.observe_termination(record.lease, record.owner)
        original = os.rmdir

        def late(*arguments: object, **options: object) -> None:
            original(*arguments, **options)
            self.clock.time = record.lease.deadline_ns

        with patch.object(custody.os, "rmdir", side_effect=late), self.assertRaises(custody.CustodyError):
            custody.dispose_unused(locator, dead, self.clock)
        self.assertFalse(self.directory(locator).exists())

    def test_prepare_and_arm_recheck_after_final_persistence_and_context_exit(self) -> None:
        original_store = custody._store

        @contextmanager
        def delayed(locator: custody.Locator) -> Iterator[custody._Store]:
            with original_store(locator) as store:
                yield store
                current = store.load()
            self.clock.time = current.lease.work_until_ns

        with patch.object(custody, "_store", new=delayed), self.assertRaises(custody.CustodyError):
            self.prepare()
        self.request = replace(self.request, original_deadline_ns=self.clock.time + custody.MAX_TOTAL_NS)
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        with patch.object(custody, "_store", new=delayed), self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertNotEqual(self.record(locator).state, custody.State.PREPARED)

    def test_disposal_waits_for_closed_state_and_complete_independent_owner_death(self) -> None:
        locator, supervisor = self.armed()
        record = self.record(locator)
        dead = supervisor.observe_termination(record.lease, record.owner)
        with self.assertRaises(custody.CustodyError):
            custody.dispose_unused(locator, dead, self.clock)
        with self.caller(record.owner.process):
            custody.finalize_unused(
                locator, supervisor.live(record.lease, record.owner), custody.Cause.NORMAL, self.clock
            )
        for observation in (
            None,
            supervisor.live(record.lease, record.owner),
            replace(dead, cgroup_absent=False),
            replace(dead, group_absent=False),
        ):
            with self.subTest(observation=observation), self.assertRaises(custody.CustodyError):
                custody.dispose_unused(locator, observation, self.clock)
            self.assertTrue(self.directory(locator).exists())
        custody.dispose_unused(locator, dead, self.clock)
        self.assertFalse(self.directory(locator).exists())

    def test_prearm_owner_can_close_but_cannot_claim_its_own_death(self) -> None:
        locator = self.prepare()
        lease = self.record(locator).lease
        observation = custody.OwnerObservation(
            lease,
            custody.Owner("coordinator", lease.coordinator),
            self.clock.time,
            custody.Lifetime.LIVE,
            acknowledged=False,
            service_root_owned=False,
            group_absent=False,
            cgroup_absent=False,
        )
        receipt = custody.finalize_unused(locator, observation, custody.Cause.NORMAL, self.clock)
        self.assertEqual(receipt.outcome, "closed-unused")
        dead = replace(observation, lifetime=custody.Lifetime.DEAD, group_absent=True)
        with self.assertRaises(custody.CustodyError):
            custody.dispose_unused(locator, dead, self.clock)
        with patch.object(custody.os, "getpid", return_value=lease.coordinator.pid + 2000):
            custody.dispose_unused(locator, dead, self.clock)

    def test_hostile_leaves_and_stale_or_malformed_state_refuse(self) -> None:
        for fault in ("symlink", "hardlink", "extra", "unknown-key", "load-claim", "stale"):
            locator = self.prepare()
            directory = self.directory(locator)
            if fault == "symlink":
                (directory / "policy").unlink()
                (directory / "policy").symlink_to(self.root / "input-0")
            elif fault == "hardlink":
                os.link(directory / "policy", self.root / ("alias-" + locator.nonce))
            elif fault == "extra":
                (directory / "unexpected").write_bytes(b"inert")
            elif fault in {"unknown-key", "load-claim"}:
                value = json.loads((directory / "state.json").read_bytes())
                value["unexpected" if fault == "unknown-key" else "policy_load"] = "loaded"
                (directory / "state.json").write_text(json.dumps(value))
            else:
                old = (directory / "state.json").read_bytes()
                custody.arm_unused(locator, Supervisor(self.clock), self.clock)
                (directory / "state.json").write_bytes(old)
            with self.subTest(fault=fault), self.assertRaises(custody.CustodyError):
                custody.arm_unused(locator, Supervisor(self.clock), self.clock)
            self.assertTrue(directory.exists())

    def test_locator_substitution_and_concurrent_lock_refuse(self) -> None:
        locator = self.prepare()
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(
                replace(locator, directory=custody.DirectoryIdentity(999, 999)), Supervisor(self.clock), self.clock
            )
        with custody._store(locator), self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, Supervisor(self.clock), self.clock)

    def test_owner_reads_exact_intent_while_starter_waits_without_lock_recursion(self) -> None:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        original = supervisor.start_unused_owner
        seen = []

        def ready(intent: custody.ArmIntent, deadline: int) -> custody.OwnerObservation:
            before = self.record(locator)
            seen.append(custody.read_owner_intent(locator, intent, self.clock))
            self.assertEqual(self.record(locator), before)
            self.assertEqual(before.state, custody.State.ARM_INTENT)
            with self.assertRaises(custody.CustodyError):
                custody.read_owner_intent(locator, replace(intent, generation=intent.generation + 1), self.clock)
            return original(intent, deadline)

        supervisor.start_unused_owner = ready
        custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.record(locator).generation, seen[0].generation + 1)
        with self.assertRaises(custody.CustodyError):
            custody.read_owner_intent(locator, seen[0], self.clock)

    def test_competing_close_changes_intent_and_is_never_overwritten_or_promoted(self) -> None:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        original = supervisor.start_unused_owner
        changed = []

        def compete(intent: custody.ArmIntent, deadline: int) -> custody.OwnerObservation:
            with self.assertRaises(custody.CustodyError):
                custody.request_close_unused(locator, supervisor, self.clock)
            changed.append(self.record(locator))
            return original(intent, deadline)

        supervisor.start_unused_owner = compete
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(self.record(locator), changed[0])
        self.assertEqual(changed[0].state, custody.State.RETAINED)
        self.assertEqual(supervisor.inspections, 0)

    def test_arm_rechecks_actual_coordinator_after_ready(self) -> None:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        original = supervisor.start_unused_owner

        def replaced(intent: custody.ArmIntent, deadline: int) -> custody.OwnerObservation:
            observation = original(intent, deadline)
            self.stack.enter_context(patch.object(custody, "_self_start", return_value=999))
            return observation

        supervisor.start_unused_owner = replaced
        with self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)
        self.assertEqual(supervisor.inspections, 0)

    def test_changed_generation_or_lease_after_ready_is_never_overwritten(self) -> None:
        for change in ("generation", "lease"):
            locator = self.prepare()
            supervisor = Supervisor(self.clock)
            changed = []
            context = SimpleNamespace(
                change=change, locator=locator, changed=changed, start=supervisor.start_unused_owner
            )

            def mutate(
                intent: custody.ArmIntent, deadline: int, *, context: SimpleNamespace = context
            ) -> custody.OwnerObservation:
                record = self.record(context.locator)
                updated = replace(record, generation=record.generation + 1)
                if context.change == "lease":
                    updated = replace(updated, lease=replace(record.lease, manifest_sha256="f" * 64))
                # Fault injection bypasses the valid writer, but retains valid finite schema/hash framing.
                data = custody._json(asdict(updated))
                directory = self.directory(context.locator)
                (directory / "state.json").write_bytes(data)
                with (directory / "journal").open("ab") as stream:
                    stream.write(custody._json({"generation": updated.generation, "sha256": digest(data)}) + b"\n")
                context.changed.append(updated)
                return context.start(intent, deadline)

            supervisor.start_unused_owner = mutate
            with self.subTest(change=change), self.assertRaises(custody.CustodyError):
                custody.arm_unused(locator, supervisor, self.clock)
            self.assertEqual(self.record(locator), changed[0])
            self.assertEqual(supervisor.inspections, 0)

    def test_handshake_crossing_on_lock_reacquisition_never_commits_arm(self) -> None:
        locator = self.prepare()
        supervisor = Supervisor(self.clock)
        original = custody._store
        calls = 0
        reacquire_call = 2

        @contextmanager
        def delayed(locator: custody.Locator) -> Iterator[custody._Store]:
            nonlocal calls
            with original(locator) as store:
                calls += 1
                if calls == reacquire_call:
                    self.clock.time += custody.HANDSHAKE_NS
                yield store

        with patch.object(custody, "_store", side_effect=delayed), self.assertRaises(custody.CustodyError):
            custody.arm_unused(locator, supervisor, self.clock)
        self.assertEqual(supervisor.inspections, 0)
        self.assertEqual(self.record(locator).state, custody.State.RETAINED)

    def test_unused_boundary_must_be_actual_nonroot_coordinator_cgroup(self) -> None:
        self.request = replace(self.request, runtime_slice=custody.Group("/invented", 1, 100))
        with self.assertRaises(custody.CustodyError):
            self.prepare()
        self.request = replace(self.request, runtime_slice=custody.Group("/", 1, 1))
        self.host.observation = replace(
            self.host.observation,
            coordinator=replace(self.host.observation.coordinator, cgroup=self.request.runtime_slice),
        )
        with self.assertRaises(custody.CustodyError):
            self.prepare()

    def test_no_mutation_or_production_entrypoint_exists(self) -> None:
        self.assertEqual(
            {item.value for item in custody.State},
            {"preparing", "prepared", "arm_intent", "armed_unused", "closing_unused", "closed_unused", "retained"},
        )
        self.assertEqual(
            {name for name in custody.SupervisorPort.__dict__ if not name.startswith("_")},
            {"start_unused_owner", "inspect_owner", "request_close", "observe_termination"},
        )
        for name in ("docker_userns_custody.py", "docker_userns_custody_child.py"):
            text = (REPO / "scripts" / name).read_text()
            ast.parse(text)
            for forbidden in ("--add", "--remove", "--replace", "docker run", "sudo", "setpriv", "__main__"):
                self.assertNotIn(forbidden, text)


class ChildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(importlib.abc.SourceLoader)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.clock = Clock()
        self.name = "dockerlens-127-upstream-rootless-17-2-" + "a" * 32
        self.lease = child.Build(
            self.name, 1001, 1002, self.clock.time + 5_000_000_000, self.clock.time + 65_000_000_000
        )
        self.data = (
            (
                b"from pathlib import Path\nfrom native_outer_diagnostic_capture import PREFIX\n"
                b"location = Path(__file__)\ndef profile_bytes(name):\n return PREFIX + name.encode()\n"
            ),
            b"PREFIX = b'complete-unchanged:'\n",
        )
        self.sources = []
        for index, (module, raw) in enumerate(zip(child.MODULES, self.data, strict=True)):
            path = self.root / f"source-{index}"
            path.write_bytes(raw)
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            self.stack.callback(os.close, fd)
            self.sources.append(child.Source(module, fd, len(raw), digest(raw)))
        self.sources = tuple(self.sources)
        real_fstat, real_fcntl = os.fstat, child.fcntl.fcntl

        def root_stat(fd: int) -> SimpleNamespace:
            info = real_fstat(fd)
            return SimpleNamespace(
                **{**{name: getattr(info, name) for name in dir(info) if name.startswith("st_")}, "st_uid": 0}
            )

        self.stack.enter_context(patch.object(child.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.object(child.os, "fstat", side_effect=root_stat))
        # Explicit fake Linux sealing provider: never an operational fallback.
        self.stack.enter_context(patch.object(child, "SEALS", 15))
        for name, value in (
            ("F_GET_SEALS", 90_001),
            ("F_ADD_SEALS", 90_002),
            ("F_SEAL_WRITE", 1),
            ("F_SEAL_GROW", 2),
            ("F_SEAL_SHRINK", 4),
            ("F_SEAL_SEAL", 8),
        ):
            self.stack.enter_context(patch.object(child.fcntl, name, value, create=True))
        self.stack.enter_context(
            patch.object(
                child.fcntl,
                "fcntl",
                side_effect=lambda fd, command, *args: (
                    15 if command == child.fcntl.F_GET_SEALS else real_fcntl(fd, command, *args)
                ),
            )
        )
        self.interpreter = child.Interpreter(12345, "d" * 64)

    def proof(self) -> bytes:
        return json.dumps(
            {"schema": 1, "uid": 1001, "gid": 1002, "groups": [], "nnp": 1, "capabilities": "zero"}
        ).encode()

    def test_sealing_algorithm_uses_all_required_seals_and_returns_only_a_readonly_fd(self) -> None:
        path = self.root / "fake-kernel-memfd"
        writable = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        real_fcntl = child.fcntl.fcntl
        additions = []

        def fake_kernel(descriptor: int, command: int, *arguments: int) -> int:
            if command == child.fcntl.F_ADD_SEALS:
                additions.append(arguments[0])
                return 0
            return real_fcntl(descriptor, command, *arguments)

        with (
            patch.object(child.os, "memfd_create", return_value=writable, create=True),
            patch.object(child.os, "MFD_CLOEXEC", 1, create=True),
            patch.object(child.os, "MFD_ALLOW_SEALING", 2, create=True),
            patch.object(child.fcntl, "fcntl", side_effect=fake_kernel),
        ):
            source = child.seal("canonical_policy", b"inert complete bytes")
        try:
            self.assertEqual(additions, [child.SEALS])
            self.assertEqual(child.bytes_at(source.descriptor, source.size), b"inert complete bytes")
            with self.assertRaises(OSError):
                os.write(source.descriptor, b"forbidden")
            with self.assertRaises(OSError):
                os.fstat(writable)
        finally:
            os.close(source.descriptor)

    @contextmanager
    def executing(
        self,
        *,
        ids: tuple[int, int, int] = (1001, 1001, 1001),
        groups: tuple[int, ...] = (),
        status: bytes | None = None,
    ) -> Iterator[SimpleNamespace]:
        status = status or b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"
        fake_os = SimpleNamespace(**vars(os))
        fake_os.getresuid = lambda: ids
        fake_os.getresgid = lambda: (1002, 1002, 1002)
        fake_os.getgroups = lambda: list(groups)
        fake_os.close = MagicMock()
        fake_os.write = MagicMock(side_effect=lambda _fd, raw: len(raw))
        fake_os.listdir = lambda _path: ["0", "1", "2", *(str(item.descriptor) for item in self.sources)]
        ctypes, libc = MagicMock(), MagicMock()
        ctypes.CDLL.return_value = libc
        libc.prctl.side_effect = [0, 1]
        output = io.BytesIO()
        arguments = [
            "wrapper",
            "12345",
            "12346",
            *(f"{item.descriptor}:{item.size}:{item.sha256}" for item in self.sources),
            self.name,
            "1001",
            "1002",
            "2",
        ]
        with (
            patch.dict(sys.modules, {"os": fake_os, "ctypes": ctypes, "resource": MagicMock(), "signal": MagicMock()}),
            patch.object(sys, "meta_path", list(sys.meta_path)),
            patch.object(sys, "path", []),
            patch.object(sys, "dont_write_bytecode", new=True),
            patch.object(sys, "argv", arguments),
            patch.object(sys, "stdout", SimpleNamespace(buffer=output)),
            patch("builtins.open", return_value=io.BytesIO(status)),
        ):
            yield SimpleNamespace(os=fake_os, ctypes=ctypes, libc=libc, output=output)

    def test_descriptor_loader_executes_complete_source_without_workspace_paths(self) -> None:
        with self.executing() as context:
            exec(child.CODE, {})  # noqa: S102 - fixed child code; all privilege/kernel interfaces are explicit fakes.
        self.assertEqual(context.output.getvalue(), b"complete-unchanged:" + self.name.encode())
        proof = json.loads(context.os.write.call_args.args[1])
        self.assertEqual(proof["uid"], 1001)
        self.assertEqual(proof["gid"], 1002)
        self.assertEqual(proof["groups"], [])
        self.assertEqual(proof["nnp"], 1)
        self.assertEqual(context.libc.prctl.argtypes, [context.ctypes.c_int, *([context.ctypes.c_ulong] * 4)])

    def test_saved_ids_groups_capabilities_and_nnp_fail_before_first_source_import(self) -> None:
        clean = b"CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nNoNewPrivs: 1\n"
        variants = [
            {"ids": (0, 0, 0)},
            {"ids": (1001, 1001, 0)},
            {"groups": (0,)},
            *(
                {"status": clean.replace(key + b": 0", key + b": 1")}
                for key in (b"CapEff", b"CapPrm", b"CapInh", b"CapAmb")
            ),
            {"status": clean.replace(b"NoNewPrivs: 1", b"NoNewPrivs: 0")},
        ]
        for options in variants:
            with self.subTest(options=options), self.executing(**options) as context, self.assertRaises(SystemExit):
                exec(child.CODE, {})  # noqa: S102 - exercise pre-import guard with fake credentials and proc status.
            context.os.write.assert_not_called()
            self.assertEqual(context.output.getvalue(), b"")
        with self.executing() as context, self.assertRaises(SystemExit):
            context.os.getresgid = lambda: (1002, 1002, 0)
            exec(child.CODE, {})  # noqa: S102 - saved-GID failure is entirely mocked.
        context.os.write.assert_not_called()

    def test_unknown_source_import_does_not_search_ambient_workspace(self) -> None:
        path = self.root / "ambient_extra.py"
        path.write_bytes(b"raise AssertionError('workspace imported')\n")
        first = self.root / "source-0"
        first.write_bytes(b"import ambient_extra\ndef profile_bytes(name): return b'wrong'\n")
        self.sources = (
            replace(self.sources[0], size=first.stat().st_size, sha256=digest(first.read_bytes())),
            self.sources[1],
        )
        with self.executing(), self.assertRaises(ModuleNotFoundError):
            exec(child.CODE, {})  # noqa: S102 - fixture import fails under simulated isolated interpreter paths.

    def test_popen_drops_before_exec_and_inherits_only_the_closed_descriptor_set(self) -> None:
        process = MagicMock()
        before = ((1,), b"trusted-interpreter")
        with (
            patch.object(child, "_interpreter", return_value=before),
            patch.object(child.subprocess, "Popen", return_value=process) as start,
            patch.object(child, "_capture", return_value=(b"policy", self.proof())),
            patch.object(child, "_stop", return_value=(0, True)),
        ):
            outcome = child.build(self.interpreter, self.sources, self.lease, self.clock)
        arguments = start.call_args.args[0]
        options = start.call_args.kwargs
        self.assertEqual(arguments[:5], ["/proc/self/fd/12345", "-I", "-B", "-S", "-c"])
        self.assertEqual(arguments[5], child.CODE)
        self.assertEqual((options["user"], options["group"], options["extra_groups"]), (1001, 1002, ()))
        self.assertTrue(options["close_fds"])
        self.assertTrue(options["start_new_session"])
        self.assertEqual(options["env"], child.ENV)
        self.assertNotIn("preexec_fn", options)
        self.assertEqual(options["pass_fds"], (12345, int(arguments[7]), *(item.descriptor for item in self.sources)))
        self.assertEqual(outcome, child.Outcome(b"policy", dead=True))

    def test_output_status_receipt_and_lifetime_disagreement_never_pass(self) -> None:
        for status, dead, proof in (
            (1, True, self.proof()),
            (0, False, self.proof()),
            (0, True, b"{}"),
            (0, True, self.proof().replace(b'"nnp": 1', b'"nnp": true')),
            (0, True, self.proof().replace(b'"uid": 1001', b'"uid": 1001, "uid": 1001')),
        ):
            with (
                self.subTest(status=status, dead=dead, proof=proof),
                patch.object(child, "_interpreter", return_value=((1,), b"trusted")),
                patch.object(child.subprocess, "Popen", return_value=MagicMock()),
                patch.object(child, "_capture", return_value=(b"policy", proof)),
                patch.object(child, "_stop", return_value=(status, dead)),
                self.assertRaises(child.ChildError),
            ):
                child.build(self.interpreter, self.sources, self.lease, self.clock)

    def test_final_interpreter_validation_must_finish_before_original_child_deadline(self) -> None:
        parent_work_until_ns = self.lease.deadline_ns + 10_000_000_000
        before = ((1,), b"trusted")
        validation_calls = 2
        for offset, accepted in ((-1, True), (0, False), (1, False)):
            self.clock.time = self.lease.deadline_ns - 2_000_000_000
            calls = 0

            def interpreter(_value: child.Interpreter, *, _offset: int = offset) -> tuple[tuple[int, ...], bytes]:
                nonlocal calls
                calls += 1
                if calls == validation_calls:
                    self.clock.time = self.lease.deadline_ns + _offset
                return before

            with (
                self.subTest(offset=offset),
                patch.object(child, "_interpreter", side_effect=interpreter),
                patch.object(child.subprocess, "Popen", return_value=MagicMock()),
                patch.object(child, "_capture", return_value=(b"policy", self.proof())),
                patch.object(child, "_stop", return_value=(0, True)),
            ):
                self.assertLess(self.lease.deadline_ns, self.lease.cleanup_deadline_ns)
                if accepted:
                    self.assertEqual(
                        child.build(self.interpreter, self.sources, self.lease, self.clock),
                        child.Outcome(b"policy", dead=True),
                    )
                else:
                    with self.assertRaises(child.ChildError) as caught:
                        child.build(self.interpreter, self.sources, self.lease, self.clock)
                    self.assertEqual(caught.exception.lifetime, child.Lifetime.DEAD)
                    self.assertFalse(caught.exception.pending)
                self.assertLess(self.clock.time, parent_work_until_ns)
            self.assertEqual(calls, 2)

    def test_primary_capture_failure_keeps_independently_proven_group_death(self) -> None:
        primary = child.ChildError(dead=False)
        with (
            patch.object(child, "_interpreter", return_value=((1,), b"trusted")),
            patch.object(child.subprocess, "Popen", return_value=MagicMock()),
            patch.object(child, "_capture", side_effect=primary),
            patch.object(child, "_stop", return_value=(0, True)),
            self.assertRaises(child.ChildError) as caught,
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertIs(caught.exception.__cause__, primary)
        self.assertEqual(caught.exception.lifetime, child.Lifetime.DEAD)
        self.assertFalse(caught.exception.pending)

    def test_unknown_cleanup_and_constructor_uncertainty_are_never_declared_absent(self) -> None:
        with (
            patch.object(child, "_interpreter", return_value=((1,), b"trusted")),
            patch.object(child.subprocess, "Popen", return_value=MagicMock()),
            patch.object(child, "_capture", side_effect=child.ChildError()),
            patch.object(child, "_stop", return_value=(None, False)),
            self.assertRaises(child.ChildError) as caught,
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertEqual(caught.exception.lifetime, child.Lifetime.UNKNOWN)
        self.assertTrue(caught.exception.pending)
        with (
            patch.object(child, "_interpreter", return_value=((1,), b"trusted")),
            patch.object(child.subprocess, "Popen", side_effect=OSError),
            patch.object(child, "_stop") as stop,
            self.assertRaises(child.ChildError) as caught,
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertEqual(caught.exception.lifetime, child.Lifetime.UNKNOWN)
        self.assertTrue(caught.exception.pending)
        stop.assert_not_called()

    def test_prelaunch_failure_is_explicitly_never_started(self) -> None:
        with (
            patch.object(child, "SEALS", new=None),
            patch.object(child.subprocess, "Popen") as start,
            self.assertRaises(child.ChildError) as caught,
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertEqual(caught.exception.lifetime, child.Lifetime.NEVER_STARTED)
        self.assertFalse(caught.exception.pending)
        start.assert_not_called()

    def test_expiry_after_preflight_but_before_popen_is_still_never_started(self) -> None:
        original = child.os.pipe2

        def late(flags: int) -> tuple[int, int]:
            result = original(flags)
            self.clock.time = self.lease.deadline_ns
            return result

        with (
            patch.object(child, "_interpreter", return_value=((1,), b"trusted")),
            patch.object(child.os, "pipe2", side_effect=late),
            patch.object(child.subprocess, "Popen") as start,
            self.assertRaises(child.ChildError) as caught,
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertEqual(caught.exception.lifetime, child.Lifetime.NEVER_STARTED)
        self.assertFalse(caught.exception.pending)
        start.assert_not_called()

    def test_unsupported_sealing_and_short_remaining_budget_refuse_before_process(self) -> None:
        with (
            patch.object(child, "SEALS", new=None),
            patch.object(child.subprocess, "Popen") as start,
            self.assertRaises(child.ChildError),
        ):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        start.assert_not_called()
        with patch.object(child, "SEALS", new=None), self.assertRaises(child.ChildError):
            child.seal("canonical_policy", b"inert")
        with patch.object(child.subprocess, "Popen") as start, self.assertRaises(child.ChildError):
            child.build(
                self.interpreter,
                self.sources,
                replace(self.lease, deadline_ns=self.clock.time + 999_999_999),
                self.clock,
            )
        start.assert_not_called()

    def test_lingering_group_and_expired_cleanup_have_no_fresh_wait_budget(self) -> None:
        process = MagicMock(pid=77)
        process.wait.return_value = 0
        with patch.object(child.os, "killpg"):
            self.assertEqual(child._stop(process, self.lease, self.clock), (0, False))
        self.clock.time = self.lease.cleanup_deadline_ns
        process.poll.return_value = None
        process.wait.reset_mock()
        with patch.object(child.os, "killpg", side_effect=[None, ProcessLookupError]):
            self.assertEqual(child._stop(process, self.lease, self.clock), (None, False))
        process.wait.assert_not_called()

    def test_fractional_second_does_not_round_up_and_nonroot_has_no_runner(self) -> None:
        with patch.object(child.os, "geteuid", return_value=1000), self.assertRaises(child.ChildError):
            child.build(self.interpreter, self.sources, self.lease, self.clock)
        self.assertLess(child.CODE.index("os.getresuid()"), child.CODE.index("class SourceLoader"))
        self.assertLess(child.CODE.index("os.close(int(receipt))"), child.CODE.index("class SourceLoader"))
        self.assertNotIn("sys.path.insert", child.CODE)
        self.assertNotIn("RunnerProfile", child.CODE)
        self.assertNotIn("consumer_mode", child.CODE)


if __name__ == "__main__":
    unittest.main()
