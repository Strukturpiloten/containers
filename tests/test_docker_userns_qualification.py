"""Hermetic controls for the new native contract; no profile or runtime mutation."""

from __future__ import annotations

import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import docker_runner_security as reader
from scripts import docker_userns_qualification as qualification

PRIVATE = "must-not-publish-raw-host-value"


class FixedHostControls(unittest.TestCase):
    def setUp(self) -> None:
        self.values = {
            reader.ENABLED: b"Y",
            reader.RESTRICT: b"1",
            reader.USERNS: b"1024",
            qualification.LEGACY_CLONE: b"1",
        }

    def test_fixed_scalar_reads_reuse_bounded_reader_and_preserve_original_deadline(self) -> None:
        with (
            patch.object(reader, "_read", side_effect=self.values.__getitem__) as read,
            patch.object(qualification.time, "monotonic_ns", return_value=10),
        ):
            result = qualification.observe_controls(100)
        self.assertEqual(
            result, qualification.HostControls(enabled=True, restricted_userns=1, maximum_userns=1024, legacy_clone=1)
        )
        self.assertEqual(
            [call.args[0] for call in read.call_args_list],
            [reader.ENABLED, reader.RESTRICT, reader.USERNS, qualification.LEGACY_CLONE],
        )

    def test_only_explicit_missing_legacy_clone_is_permitted(self) -> None:
        for missing, code in (
            (qualification.LEGACY_CLONE, errno.ENOENT),
            (qualification.LEGACY_CLONE, errno.EACCES),
            (reader.ENABLED, errno.ENOENT),
            (reader.RESTRICT, errno.ENOENT),
            (reader.USERNS, errno.ENOENT),
        ):

            def read(path: Path, *, missing: Path = missing, code: int = code) -> bytes:
                if path == missing:
                    raise OSError(code, PRIVATE)
                return self.values[path]

            with (
                self.subTest(missing=missing, code=code),
                patch.object(reader, "_read", side_effect=read),
                patch.object(qualification.time, "monotonic_ns", return_value=10),
            ):
                if missing == qualification.LEGACY_CLONE and code == errno.ENOENT:
                    self.assertIsNone(qualification.observe_controls(100).legacy_clone)
                else:
                    with self.assertRaisesRegex(qualification.QualificationError, "host-unavailable") as error:
                        qualification.observe_controls(100)
                    self.assertNotIn(PRIVATE, str(error.exception))

    def test_disabled_unknown_malformed_and_overflow_controls_refuse(self) -> None:
        for path, values in (
            (reader.ENABLED, (b"N", b"1", b"yes", b"", PRIVATE.encode())),
            (reader.RESTRICT, (b"0", b"2", b"yes", b"01", PRIVATE.encode())),
            (
                reader.USERNS,
                (
                    b"0",
                    b"-1",
                    b"+1",
                    b"01",
                    b"1\x00",
                    b"",
                    b"9" * 21,
                    str(qualification.MAX_NAMESPACES + 1).encode(),
                    PRIVATE.encode(),
                ),
            ),
            (qualification.LEGACY_CLONE, (b"0", b"2", b"", b"true", PRIVATE.encode())),
        ):
            for value in values:
                observed = self.values | {path: value}
                with (
                    self.subTest(path=path, value=value),
                    patch.object(reader, "_read", side_effect=observed.__getitem__),
                    patch.object(qualification.time, "monotonic_ns", return_value=10),
                    self.assertRaises(qualification.QualificationError) as error,
                ):
                    qualification.observe_controls(100)
                self.assertNotIn(PRIVATE, str(error.exception))

    def test_unknown_reader_errors_and_real_symlink_or_overflow_never_admit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized"
            oversized.write_bytes(b"1" * (reader.MAX_FILE + 1))
            symbolic = Path(directory) / "symbolic"
            symbolic.symlink_to(oversized)
            for target in (oversized, symbolic):
                with (
                    self.subTest(target=target),
                    patch.object(reader, "ENABLED", target),
                    patch.object(qualification.time, "monotonic_ns", return_value=10),
                    self.assertRaisesRegex(qualification.QualificationError, "host-unavailable"),
                ):
                    qualification.observe_controls(100)

    def test_expiry_at_every_boundary_or_cancellation_prevents_later_reads(self) -> None:
        for boundary in range(5):
            with (
                self.subTest(boundary=boundary),
                patch.object(qualification.time, "monotonic_ns", side_effect=[10] * boundary + [100]),
                patch.object(reader, "_read", side_effect=self.values.__getitem__) as read,
                self.assertRaisesRegex(qualification.QualificationError, "deadline"),
            ):
                qualification.observe_controls(100)
            self.assertEqual(read.call_count, boundary)
        with (
            patch.object(reader, "_read") as read,
            self.assertRaisesRegex(qualification.QualificationError, "cancelled"),
        ):
            qualification.observe_controls(100, cancelled=lambda: True)
        read.assert_not_called()

    def test_drift_guard_does_not_treat_changed_limits_as_equivalent_permission(self) -> None:
        with (
            patch.object(reader, "_read", side_effect=self.values.__getitem__),
            patch.object(qualification.time, "monotonic_ns", return_value=10),
        ):
            original = qualification.observe_controls(100)
            self.assertEqual(qualification.guard_controls(original, 100), original)
            self.values[reader.USERNS] = b"2048"
            with self.assertRaisesRegex(qualification.QualificationError, "host-drift"):
                qualification.guard_controls(original, 100)


class RecordingPort:
    """Model external effects independently of the state machine implementation."""

    def __init__(self, failure: str | None = None, error: type[BaseException] = RuntimeError) -> None:
        """Inject a failure at one independently named external boundary."""
        self.events: list[str] = []
        self.failure, self.error = failure, error

    def event(self, name: str) -> None:
        self.events.append(name)
        if name == self.failure:
            raise self.error(PRIVATE)

    def admit(self, _binding: qualification.NativeBinding) -> None:
        self.event("admit")

    def clean_owner(self, _binding: qualification.NativeBinding) -> None:
        self.event("clean-owner")

    def arm(self, _binding: qualification.NativeBinding) -> None:
        self.event("independent-owner-ready")

    def guard(self, _binding: qualification.NativeBinding) -> None:
        self.event("guard")

    def persist(self, state: qualification.State, _container: str | None) -> None:
        self.event(state.value)

    def load(self) -> None:
        self.event("physical-load")

    def bind_subject(self, _container: str, _binding: qualification.NativeBinding) -> None:
        self.event("held-task-profile-readback")

    def remove_subject(self, _container: str | None) -> None:
        self.event("guest-removal-and-positive-absence")

    def unload(self) -> None:
        self.event("exact-unload-and-positive-absence")

    def dispose(self) -> None:
        self.event("finalizer-death-then-store-disposal")

    def retain(self) -> None:
        self.event("retain")


def binding() -> qualification.NativeBinding:
    """Use a finite independent candidate fixture without native activity."""
    return qualification.NativeBinding(
        candidate="a" * 40,
        run="1",
        attempt="2",
        job="smoke-build",
        architecture="amd64",
        phase="clean-control",
        image="docker-29-conformance-rootless",
        archive_sha256="b" * 64,
        manifest_digest="sha256:" + "c" * 64,
        config_digest="sha256:" + "d" * 64,
        owner="e" * 32,
        runtime_slice="strukturpiloten" + "e" * 32 + ".slice",
        slice_identity="1:2",
        deadline_ns=1000,
    )


class LeaseOrdering(unittest.TestCase):
    def test_exact_positive_sequence_has_intent_before_every_effect_and_endpoint_before_unload(self) -> None:
        port = RecordingPort()
        lease = qualification.ProfileLease(binding(), port)
        lease.prepare()
        lease.create_intent()
        lease.bind("f" * 64)
        lease.close()
        self.assertEqual(
            port.events,
            [
                "admit",
                "clean-owner",
                "arm-intent",
                "independent-owner-ready",
                "armed",
                "guard",
                "load-intent",
                "physical-load",
                "guard",
                "loaded",
                "guard",
                "create-intent",
                "guard",
                "held-task-profile-readback",
                "attached",
                "guard",
                "remove-intent",
                "guest-removal-and-positive-absence",
                "removed",
                "guard",
                "unload-intent",
                "exact-unload-and-positive-absence",
                "closed",
                "finalizer-death-then-store-disposal",
            ],
        )

    def test_every_failure_or_cancellation_is_sticky_and_never_disposes(self) -> None:
        faults = (
            "admit",
            "clean-owner",
            "arm-intent",
            "independent-owner-ready",
            "armed",
            "guard",
            "load-intent",
            "physical-load",
            "loaded",
            "create-intent",
            "held-task-profile-readback",
            "attached",
            "remove-intent",
            "guest-removal-and-positive-absence",
            "removed",
            "unload-intent",
            "exact-unload-and-positive-absence",
            "closed",
        )
        for fault in faults:
            for error in (RuntimeError, KeyboardInterrupt):
                with self.subTest(fault=fault, error=error):
                    port = RecordingPort(fault, error)
                    lease = qualification.ProfileLease(binding(), port)
                    with self.assertRaises(error):
                        lease.prepare()
                        lease.create_intent()
                        lease.bind("f" * 64)
                        lease.close()
                    self.assertEqual(lease.state, qualification.State.RETAINED)
                    self.assertEqual(port.events[-1], "retain")
                    self.assertNotIn("finalizer-death-then-store-disposal", port.events)
                    previous = list(port.events)
                    with self.assertRaises(qualification.QualificationError):
                        lease.close()
                    self.assertEqual(port.events, [*previous, "retain"])

    def test_unknown_create_is_never_reinterpreted_as_no_guest(self) -> None:
        port = RecordingPort()
        lease = qualification.ProfileLease(binding(), port)
        lease.prepare()
        lease.create_intent()
        with self.assertRaises(qualification.QualificationError):
            lease.close()
        self.assertNotIn("guest-removal-and-positive-absence", port.events)
        self.assertNotIn("exact-unload-and-positive-absence", port.events)

    def test_unknown_load_never_grants_a_second_load_or_unload(self) -> None:
        port = RecordingPort("physical-load")
        lease = qualification.ProfileLease(binding(), port)
        with self.assertRaises(RuntimeError):
            lease.prepare()
        with self.assertRaises(qualification.QualificationError):
            lease.prepare()
        self.assertEqual(port.events.count("physical-load"), 1)
        self.assertNotIn("exact-unload-and-positive-absence", port.events)

    def test_retain_failure_preserves_original_cancellation(self) -> None:
        port = RecordingPort("physical-load", KeyboardInterrupt)
        port.retain = lambda: (_ for _ in ()).throw(RuntimeError("retain failed"))
        with self.assertRaisesRegex(KeyboardInterrupt, PRIVATE):
            qualification.ProfileLease(binding(), port).prepare()


if __name__ == "__main__":
    unittest.main()
