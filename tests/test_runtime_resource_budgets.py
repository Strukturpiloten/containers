"""Resource limits for nested Docker probes without starting service containers."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts.runtime_docker import _run_nested_docker, run_docker
from scripts.runtime_resource_budgets import (
    CPU_LIMIT,
    MEMORY_LIMIT_BYTES,
    PIDS_LIMIT,
    IsolatedStoreDiskBudget,
    outer_container_limits,
    verify_outer_container_limits,
)
from scripts.runtime_tests import ProbeError


class DockerResourceBudgetTests(unittest.TestCase):
    def test_outer_runs_have_limits_before_daemon_start(self) -> None:
        ctx = MagicMock()
        ctx.image_ref = "localhost/docker:test"
        ctx.directory = Path("isolated-docker-budget-test")
        ctx.podman.return_value = "Docker version 29.8.1"
        ctx.start.side_effect = ProbeError("stop before starting services")
        profile = {"mode": "rootful", "outerPrivilege": "privileged"}
        with (
            patch("scripts.runtime_docker.IsolatedStoreDiskBudget"),
            self.assertRaisesRegex(ProbeError, "stop before starting services"),
        ):
            run_docker(ctx, profile, archive=Path("unused.tar"), allow_privileged=True, skip_nested=False)
        cli_args = ctx.podman.call_args_list[0].args
        outer_args = ctx.start.call_args.kwargs["options"]
        for flag, value in zip(outer_container_limits()[::2], outer_container_limits()[1::2], strict=True):
            self.assertEqual(cli_args[cli_args.index(flag) + 1], value)
            self.assertEqual(outer_args[outer_args.index(flag) + 1], value)
        self.assertIn("--privileged", outer_args)
        self.assertEqual(outer_args[outer_args.index("--cgroupns") + 1], "private")
        self.assertIn("--volume", outer_args)  # The offline fixture mount remains intact.

    def test_disk_checkpoint_after_outer_start_still_cleans_up_owned_container(self) -> None:
        ctx = MagicMock()
        ctx.directory = Path("task-owned-store")
        ctx.image_ref = "localhost/docker:test"
        ctx.start.return_value = "outer-id"
        budget = MagicMock()
        budget.checkpoint.side_effect = [None, None, None, ProbeError("disk budget exceeded")]
        profile = {"mode": "rootful", "outerPrivilege": "privileged"}
        with self.assertRaisesRegex(ProbeError, "disk budget exceeded"):
            _run_nested_docker(ctx, profile, "0", budget)
        ctx.logs.assert_called_once_with("outer-id")
        ctx.podman.assert_any_call(
            "signal owned Docker daemon PID 1", "exec", "outer-id", "sh", "-c", "kill -TERM 1", check=False
        )
        ctx.podman.assert_any_call("wait for owned Docker daemon exit", "wait", "outer-id", timeout=30)

    def test_effective_cgroup_limits_are_recorded_and_unbounded_values_fail(self) -> None:
        ctx = MagicMock()
        ctx.checks = []
        ctx.exec.return_value = f"{CPU_LIMIT * 100000} 100000\n{MEMORY_LIMIT_BYTES}\n{PIDS_LIMIT}"
        verify_outer_container_limits(ctx, "outer-id")
        check = ctx.checks[-1]
        self.assertEqual(check["status"], "passed")
        self.assertEqual(check["requested"]["memoryBytes"], MEMORY_LIMIT_BYTES)
        self.assertEqual(check["readback"]["pids"], PIDS_LIMIT)

        ctx.exec.return_value = "max 100000\nmax\nmax"
        with self.assertRaisesRegex(ProbeError, "not enforced"):
            verify_outer_container_limits(ctx, "outer-id")
        self.assertEqual(ctx.checks[-1]["status"], "failed")

    def test_disk_admission_and_growth_use_only_the_task_store(self) -> None:
        with tempfile.TemporaryDirectory(prefix="strukturpiloten-budget-test-") as directory:
            root = Path(directory)
            ctx = SimpleNamespace(directory=root, _sudo=[], checks=[])
            limit = 1024**2
            with (
                self.assertRaisesRegex(ProbeError, "exceeded"),
                IsolatedStoreDiskBudget(ctx, limit_bytes=limit, poll_seconds=0.01),
            ):
                (root / "growth").write_bytes(b"x" * (2 * limit))
            check = ctx.checks[-1]
            self.assertEqual(check["status"], "failed")
            self.assertEqual(check["limitBytes"], limit)
            self.assertGreater(check["overshootBytes"], 0)
            self.assertGreaterEqual(check["samples"], 2)

            ctx.checks.clear()
            with self.assertRaisesRegex(ProbeError, "exceeded"), IsolatedStoreDiskBudget(ctx, limit_bytes=limit):
                self.fail("oversized store should fail admission before nested work")
            self.assertEqual(ctx.checks[-1]["status"], "failed")

            (root / "growth").unlink()
            ctx.checks.clear()
            with IsolatedStoreDiskBudget(ctx, limit_bytes=limit):
                pass
            self.assertEqual(ctx.checks[-1]["status"], "passed")
            self.assertEqual(ctx.checks[-1]["overshootBytes"], 0)

    def test_disk_sampler_retries_transient_disappearance_but_not_permission_errors(self) -> None:
        ctx = SimpleNamespace(directory=Path("task-owned-store"), _sudo=[], checks=[])
        budget = IsolatedStoreDiskBudget(ctx)
        budget._du_once = MagicMock(
            side_effect=[
                (1, "", "du: cannot access 'gone': No such file or directory"),
                (0, "4096\ttask-owned-store", ""),
            ]
        )
        budget._measure()
        self.assertEqual(budget.samples, 1)
        self.assertEqual(budget.transient_retries, 1)
        self.assertEqual(budget._du_once.call_count, 2)

        budget._du_once = MagicMock(return_value=(1, "", "du: cannot read 'secret': Permission denied"))
        with self.assertRaisesRegex(ProbeError, "Permission denied"):
            budget._measure()
        budget._du_once.assert_called_once_with()

    def test_disk_sampler_timeout_kills_its_process_group(self) -> None:
        ctx = SimpleNamespace(directory=Path("task-owned-store"), _sudo=[], checks=[])
        budget = IsolatedStoreDiskBudget(ctx)
        process = MagicMock()
        process.pid = 12345
        process.communicate.side_effect = [subprocess.TimeoutExpired("du", 5), ("", "")]
        process.poll.return_value = None
        with (
            patch("scripts.runtime_resource_budgets.subprocess.Popen", return_value=process),
            patch("scripts.runtime_resource_budgets.os.killpg") as kill_group,
            self.assertRaisesRegex(ProbeError, "timed out"),
        ):
            budget._measure()
        kill_group.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(process.communicate.call_count, 2)


if __name__ == "__main__":
    unittest.main()
