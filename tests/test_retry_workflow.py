"""Exercise the retry workflow's publication-only failure gate."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


class RetryEligibilityTests(unittest.TestCase):
    @staticmethod
    def _workflow_script() -> str:
        workflow = yaml.safe_load(Path(".github/workflows/retry-failed-publish-jobs.yml").read_text(encoding="utf-8"))
        return str(workflow["jobs"]["retry-failed-jobs"]["steps"][0]["run"])

    def _run_retry(self, failed_jobs: str) -> bool:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            gh = directory / "gh"
            gh.write_text(
                "#!/bin/bash\n"
                'case "$*" in\n'
                "  *'/jobs?filter=latest&per_page=100'*) printf '%s\\n' \"${FAILED_JOBS}\" ;;\n"
                "  *'/rerun-failed-jobs'*) touch \"${RETRY_MARKER}\" ;;\n"
                "  *) printf '1\\tcompleted\\tfailure\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            sleep = directory / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            sleep.chmod(0o755)
            marker = directory / "retried"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{directory}:{env['PATH']}",
                    "FAILED_ATTEMPT": "1",
                    "FAILED_JOBS": failed_jobs,
                    "GITHUB_REPOSITORY": "Strukturpiloten/containers",
                    "RETRY_MARKER": str(marker),
                    "RUN_ID": "100",
                }
            )
            result = subprocess.run(  # noqa: S603
                ["/bin/bash", "-c", self._workflow_script()],
                capture_output=True,
                check=False,
                env=env,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return marker.exists()

    def test_nested_publication_and_release_failures_are_retried(self) -> None:
        self.assertTrue(self._run_retry("Publish example / Publish image\nPublish example / Finalize release"))

    def test_legacy_publication_job_is_retried(self) -> None:
        self.assertTrue(self._run_retry("Publish example\nFinalize release example"))

    def test_build_or_validation_failure_prevents_blanket_retry(self) -> None:
        self.assertFalse(self._run_retry("Publish example / Publish image\nPublish example / Build amd64"))
        self.assertFalse(self._run_retry("Plan image builds"))


if __name__ == "__main__":
    unittest.main()
