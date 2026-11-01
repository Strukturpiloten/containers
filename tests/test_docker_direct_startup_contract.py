"""Independent inert direct diagnostic identity, time, privacy and causal controls."""

from __future__ import annotations

import copy
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, replace

from scripts import docker_direct_startup_contract as direct
from scripts import docker_userns_qualification as qualified


def binding() -> direct.DirectDiagnosticBinding:
    """Create the exact direct B identity without translating it through image29."""
    return direct.DirectDiagnosticBinding(
        candidate="a" * 40,
        run="145",
        attempt="1",
        job="smoke-build",
        architecture="amd64",
        phase="direct-profiled",
        image="docker-20.10-rootless",
        archive_sha256="b" * 64,
        manifest_digest="sha256:" + "c" * 64,
        config_digest="sha256:" + "d" * 64,
        owner="e" * 32,
        runtime_slice="strukturpiloten" + "e" * 32 + ".slice",
        slice_identity="1:2",
        deadline_ns=900_000_000_001,
        purpose="direct-startup-diagnostic",
        admission_sha256="f" * 64,
        workflow_context_sha256="1" * 64,
        variant="direct-uid1000-profiled-b",
        launcher="direct",
        expected_uid="1000",
        arm="B",
    )


def guest(*, ready: bool = False) -> dict:
    """Supply independently authored actual-actor and installed-tool facts."""
    return {
        "actor": {
            "Uid": ["1000"] * 4,
            "Gid": ["1000"] * 4,
            "Groups": ["1000"],
            "CapInh": ["0000000000000000"],
            "CapPrm": ["0000000000000000"],
            "CapEff": ["0000000000000000"],
            "CapBnd": ["000001ffffffffff"],
            "CapAmb": ["0000000000000000"],
            "NoNewPrivs": ["0"],
            "Seccomp": ["0"],
            "Seccomp_filters": ["0"],
            "uid_mapSha256": "1" * 64,
            "gid_mapSha256": "2" * 64,
            "namespaceDepth": 2,
            "guestPid": 1,
            "namespaces": {
                kind: {"sha256": token * 64, "relationship": relationship}
                for kind, token, relationship in (
                    ("user", "3", "same-host"),
                    ("mnt", "4", "owned-distinct"),
                    ("pid", "5", "owned-distinct"),
                )
            },
        },
        "executables": {
            "launcherSha256": "6" * 64,
            "rootlesskitSha256": "7" * 64,
            "rootlesskitVersion": "1.2.3",
            "engineVersion": "4.5.6",
        },
        "postExecVerified": ready,
    }


def arm(name: str) -> dict:
    """Keep a typed A failure and a running-ready B without inventing a B exit."""
    token = "a" if name == "A" else "b"
    return {
        "arm": name,
        "image": "docker-20.10-rootless",
        "architecture": "amd64",
        "qualification": "none",
        "startup": "rootlesskit-child-start-eperm" if name == "A" else "ready",
        "nativeExitCode": 1 if name == "A" else None,
        "cleanupVerified": True,
        "factsComplete": True,
        "nonPolicyFactsSha256": "c" * 64,
        "sourceIdentitySha256": "d" * 64,
        "ownership": dict.fromkeys(
            ("ownerSha256", "storeSha256", "sliceSha256", "networkSha256", "guestSha256", "volumesSha256"), token * 64
        ),
        "kernelAttribution": "none-observed",
        "namespaceControls": {
            "availability": "unavailable-post-exec-actor-equivalence",
            "controls": ["U", "M", "UM"],
            "attempted": 0,
        },
        "profileBound": name == "B",
        "guest": guest(ready=name == "B"),
    }


class DirectBindingTests(unittest.TestCase):
    def test_only_the_two_actual_image_architecture_uid_arm_tuples_validate(self) -> None:
        first = binding()
        first.validate()
        second = replace(first, image="docker-26-rootless", architecture="arm64")
        second.validate()
        self.assertNotEqual(first.digest(), second.digest())
        for values in (
            {"image": "docker-20.10-rootless", "architecture": "arm64"},
            {"image": "docker-26-rootless", "architecture": "amd64"},
            {"image": "docker-29-conformance-rootless"},
            {"expected_uid": "0"},
            {"expected_uid": 1000},
            {"expected_uid": True},
            {"arm": "A"},
            {"arm": "enforcement"},
            {"launcher": "systemd"},
            {"phase": "clean-control"},
            {"phase": "enforcement"},
            {"job": "build"},
            {"purpose": "maintained-prerequisite"},
            {"variant": "native29"},
            {"deadline_ns": True},
        ):
            with self.subTest(values=values), self.assertRaises(direct.DirectDiagnosticError):
                replace(first, **values).validate()

    def test_native29_binding_cannot_be_used_as_a_direct_diagnostic_surrogate(self) -> None:
        values = {
            key: value
            for key, value in asdict(binding()).items()
            if key not in {"variant", "launcher", "expected_uid", "arm"}
        }
        with self.assertRaises(qualified.QualificationError):
            qualified.NativeBinding(**values).validate()
        values.update(image="docker-29-conformance-rootless", phase="clean-control")
        with self.assertRaises(qualified.QualificationError):
            qualified.NativeBinding(**values).validate()

    def test_identity_and_failure_text_are_closed_without_private_values(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            for values in (
                {"candidate": "PRIVATE_DIRECT_CANARY"},
                {"config_digest": "sha256:PRIVATE_DIRECT_CANARY"},
                {"owner": "PRIVATE_DIRECT_CANARY"},
                {"slice_identity": "PRIVATE_DIRECT_CANARY"},
            ):
                with self.assertRaisesRegex(
                    direct.DirectDiagnosticError, "^direct startup diagnostic contract refused$"
                ):
                    replace(binding(), **values).validate()
        self.assertEqual(output.getvalue(), "")


class DirectDeadlineTests(unittest.TestCase):
    def test_one_pair_clock_and_fixed_b_allowance_do_not_renew_or_spend_cleanup(self) -> None:
        clock = direct.PairDeadline(1_000_000_000, 901_000_000_000)
        self.assertEqual(clock.arm_deadline(1_000_000_000), 361_000_000_000)
        self.assertEqual(clock.arm_deadline(541_000_000_000), 901_000_000_000)
        with self.assertRaises(direct.DirectDiagnosticError):
            clock.arm_deadline(541_000_000_001)
        self.assertEqual(clock.remaining(800_000_000_000, 180), 41.0)
        self.assertEqual(clock.remaining(800_000_000_000, 180, cleanup=True), 101.0)
        with self.assertRaises(direct.DirectDiagnosticError):
            clock.remaining(841_000_000_000, 5)

    def test_truthy_non_boolean_cannot_remove_cleanup_reserve(self) -> None:
        clock = direct.PairDeadline(1, 900_000_000_001)
        for cleanup in (1, "false", [], None):
            with self.subTest(cleanup=cleanup), self.assertRaises(direct.DirectDiagnosticError):
                clock.remaining(1, 10, cleanup=cleanup)

    def test_invalid_expired_backward_bool_and_enlarged_clocks_refuse(self) -> None:
        for clock, now in (
            (direct.PairDeadline(started_ns=True, deadline_ns=901), 1),
            (direct.PairDeadline(started_ns=1, deadline_ns=True), 1),
            (direct.PairDeadline(1, 900_000_000_002), 1),
            (direct.PairDeadline(2, 900), 1),
            (direct.PairDeadline(1, 900), 900),
            (direct.PairDeadline(1, 900), True),
        ):
            with self.subTest(clock=clock, now=now), self.assertRaises(direct.DirectDiagnosticError):
                clock.validate(now)


class DirectPairTests(unittest.TestCase):
    def test_profile_effect_never_claims_a_namespace_cause_or_qualifies(self) -> None:
        a, b = arm("A"), arm("B")
        self.assertEqual(direct.compare_pair(a, b), "profile-dependent-startup")
        for attribution in ("unavailable", "none-observed", "inconclusive", "exact-owned-userns-denial"):
            a["kernelAttribution"] = attribution
            self.assertEqual(direct.compare_pair(a, b), "profile-dependent-startup")
            self.assertEqual(a["qualification"], "none")
            self.assertEqual(b["qualification"], "none")
        b.update(startup="rootlesskit-child-start-eperm", nativeExitCode=1)
        b["guest"]["postExecVerified"] = False
        self.assertEqual(direct.compare_pair(a, b), "profile-not-demonstrated-remedy")
        b.update(startup="other-failure", nativeExitCode=2)
        self.assertEqual(direct.compare_pair(a, b), "inconclusive")

    def test_generic_a_unverified_cleanup_missing_facts_swaps_and_reuse_cannot_continue(self) -> None:
        for which, key, value in (
            ("A", "startup", "other-failure"),
            ("A", "nativeExitCode", 0),
            ("A", "nativeExitCode", True),
            ("A", "cleanupVerified", False),
            ("B", "cleanupVerified", False),
            ("A", "factsComplete", False),
            ("B", "factsComplete", False),
            ("B", "sourceIdentitySha256", "f" * 64),
            ("B", "qualification", "complete"),
        ):
            a, b = arm("A"), arm("B")
            (a if which == "A" else b)[key] = value
            with self.subTest(which=which, key=key, value=value), self.assertRaises(direct.DirectDiagnosticError):
                direct.compare_pair(a, b)
        with self.assertRaises(direct.DirectDiagnosticError):
            direct.compare_pair(arm("B"), arm("A"))
        for key in arm("A")["ownership"]:
            a, b = arm("A"), arm("B")
            b["ownership"][key] = a["ownership"][key]
            with self.subTest(reused=key), self.assertRaises(direct.DirectDiagnosticError):
                direct.compare_pair(a, b)

    def test_changed_nonpolicy_facts_are_inconclusive_and_unknown_fields_refuse(self) -> None:
        a, b = arm("A"), arm("B")
        b["nonPolicyFactsSha256"] = "f" * 64
        self.assertEqual(direct.compare_pair(a, b), "inconclusive")
        for mutation in (
            lambda value: value.update({"unexpected": "PRIVATE_DIRECT_CANARY"}),
            lambda value: value["namespaceControls"].update(attempted=3),
            lambda value: value.update(nativeExitCode=0),
        ):
            changed = copy.deepcopy(arm("B"))
            mutation(changed)
            with self.assertRaises(direct.DirectDiagnosticError):
                direct.validate_arm(changed)

    def test_malformed_records_always_use_the_closed_refusal(self) -> None:
        for field in ("arm", "startup", "kernelAttribution"):
            for value in ([], {}, 1, None, True):
                malformed = arm("A")
                malformed[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(direct.DirectDiagnosticError):
                    direct.validate_arm(malformed)
        for field, value in (("attempted", False), ("attempted", 0.0), ("controls", ("U", "M", "UM"))):
            malformed = arm("B")
            malformed["namespaceControls"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(direct.DirectDiagnosticError):
                direct.validate_arm(malformed)

    def test_exact_reviewed_three_control_argv_remain_unavailable(self) -> None:
        self.assertEqual(
            direct.NAMESPACE_CONTROLS,
            (
                ("U", ("/usr/bin/unshare", "--user", "--", "/usr/bin/true")),
                ("M", ("/usr/bin/unshare", "--mount", "--propagation", "unchanged", "--", "/usr/bin/true")),
                ("UM", ("/usr/bin/unshare", "--user", "--mount", "--propagation", "unchanged", "--", "/usr/bin/true")),
            ),
        )
        self.assertEqual(
            direct.optional_controls(),
            {
                "availability": "unavailable-post-exec-actor-equivalence",
                "controls": ["U", "M", "UM"],
                "attempted": 0,
            },
        )
