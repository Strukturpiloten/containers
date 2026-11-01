"""Exact manual selector, declaration, matrix and payload closure regressions."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts import ci_validation_scope as scope
from scripts import docker_direct_startup_contract as contract
from scripts import docker_direct_startup_plan as planner


class DirectPlanTests(unittest.TestCase):
    def context(self) -> scope.Context:
        """Supply the exact original manual source identity."""
        return scope.Context("workflow_dispatch", contract.PROFILE, contract.PROFILE, contract.BRANCH, "a" * 40, "main")

    def selection(self) -> dict:
        """Keep diagnostic startup separate from OOM and ordinary qualification."""
        return {
            "validationProfile": contract.PROFILE,
            "focusedRuntimeRequested": "witness-diagnostic",
            "focusedRuntime": "direct-startup-diagnostic",
            "oomAccountingMode": "qualification",
            "qualification": "none",
        }

    def test_only_two_real_rows_and_their_same_architecture_payloads_can_be_published(self) -> None:
        context = self.context()
        plan = planner.build_plan(context)
        self.assertEqual(
            plan["smokeBuildMatrix"]["include"],
            [
                {
                    "name": "docker-20.10-rootless",
                    "arch": "amd64",
                    "runner": "ubuntu-26.04",
                    "stage": 0,
                    "payloadName": "docker-20.10-payload",
                },
                {
                    "name": "docker-26-rootless",
                    "arch": "arm64",
                    "runner": "ubuntu-26.04-arm",
                    "stage": 0,
                    "payloadName": "docker-26-payload",
                },
            ],
        )
        self.assertEqual(
            [(row["name"], row["arch"]) for row in plan["payloadMatrix"]["include"]],
            [("docker-20.10-payload", "amd64"), ("docker-26-payload", "arm64")],
        )
        self.assertEqual(plan["qualification"], "none")
        self.assertEqual(plan["selection"]["reverseDependencies"], [])
        self.assertTrue(scope.validate_plan(plan, self.selection(), context)["hasImages"])

    def test_wrong_event_ref_source_profile_or_branch_stops_before_matrix_publication(self) -> None:
        context = self.context()
        for values in (
            {"event_name": "pull_request"},
            {"ref_name": "main"},
            {"source_revision": "0" * 40},
            {"source_revision": True},
            {"default_branch": "other"},
            {"selected_profile": "full"},
        ):
            with self.subTest(values=values), self.assertRaises(contract.DirectDiagnosticError):
                planner.build_plan(replace(context, **values))

    def test_unknown_boolean_missing_reordered_widened_and_cross_architecture_fields_refuse(self) -> None:
        context = self.context()
        plan = planner.build_plan(context)
        mutations = (
            lambda value: value.update(extra="PRIVATE_PLAN_CANARY"),
            lambda value: value.update(qualification="complete"),
            lambda value: value["smokeBuildMatrix"]["include"][0].update({"stage": False}),
            lambda value: value["smokeBuildMatrix"]["include"][0].update(arch="arm64"),
            lambda value: value["smokeBuildMatrix"]["include"].reverse(),
            lambda value: value["payloadMatrix"]["include"].pop(),
            lambda value: value["stageMatrices"][0]["buildMatrix"]["include"].append(
                {"name": "docker-29-conformance-rootless"}
            ),
            lambda value: value["selection"].update(reverseDependencies=["other"]),
        )
        for mutation in mutations:
            changed = copy.deepcopy(plan)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(scope.ScopeError):
                scope.validate_plan(changed, self.selection(), context)
        selection = self.selection()
        selection.update(focusedRuntime="witness-diagnostic", oomAccountingMode="diagnostic")
        with self.assertRaises(scope.ScopeError):
            scope.validate_plan(plan, selection, context)

    def test_direct_declaration_or_internal_dependency_drift_is_not_a_planner_exception(self) -> None:
        loaded = planner.container_engine._load_images()
        for field, value in (("tests", {"docker": {"launcher": "systemd"}}), ("dependencies", {"internal": ["other"]})):
            changed = copy.deepcopy(loaded)
            next(image for image in changed if image["name"] == "docker-20.10-rootless")[field] = value
            with (
                self.subTest(field=field),
                patch.object(planner.container_engine, "_load_images", return_value=changed),
                self.assertRaises(contract.DirectDiagnosticError),
            ):
                planner.build_plan(self.context())


if __name__ == "__main__":
    unittest.main()
