"""Offline producer controls for the fixed archived Debian 11 systemd fixture."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.metadata_schema import validate_metadata_schema

ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE = ROOT / "images/docker/conformance"
PACKAGE = "20.10.5+dfsg1-1+deb11u2"
ENGINE = "20.10.5+dfsg1"


class Debian11ConformanceMetadataTests(unittest.TestCase):
    def test_metadata_preserves_exact_vendor_base_and_two_architectures(self) -> None:
        path = ROOT / "images/docker/docker-debian-11-conformance-rootless/container.yaml"
        source = path.read_text()
        self.assertTrue(source.startswith("---\n"))
        metadata = yaml.safe_load(source)
        validate_metadata_schema(metadata, schema_path=ROOT / "container.schema.json", display_path=str(path))
        self.assertEqual(metadata["name"], "docker-debian-11-conformance-rootless")
        self.assertEqual(metadata["version"], "v1.0.0")
        self.assertEqual(metadata["build"]["architectures"], ["amd64", "arm64"])
        self.assertEqual(
            metadata["tests"]["docker"],
            {"mode": "rootless", "launcher": "systemd", "outerPrivilege": "privileged", "nestedRuntime": True},
        )
        args = metadata["build"]["args"]
        self.assertEqual(
            args["DISTRO_IMAGE"]["value"],
            "docker.io/library/debian:11@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9",
        )
        self.assertEqual(args["ENGINE_PACKAGE"]["value"], "docker.io")
        self.assertEqual(args["ENGINE_PACKAGE_VERSION"]["value"], PACKAGE)
        self.assertEqual(args["ENGINE_VERSION"]["value"], ENGINE)
        self.assertNotIn("payload", metadata["build"])
        self.assertEqual(metadata["lifecycle"]["state"], "legacy")
        self.assertIn("manually reviewed fixed compatibility input", metadata["lifecycle"]["supportBoundary"])
        self.assertIn("Native conformance remains unqualified", metadata["lifecycle"]["supportBoundary"])
        inputs = metadata["inputs"]
        self.assertIn("images/docker/platforms/install-packages.sh", inputs)
        self.assertIn("images/docker/conformance/**", inputs)
        historical = yaml.safe_load(
            (ROOT / "images/docker/docker-29-8-1-conformance-rootless/container.yaml").read_text()
        )
        for value in historical["inputs"]:
            if value.startswith(("scripts/", ".github/")) or value == "shared/oci-labels.env":
                self.assertIn(value, inputs)
        self.assertFalse(any("upstream" in value or "payload.yaml" in value for value in inputs))

    def test_recipe_uses_vendor_stage_and_keeps_compiler_out_of_final_stage(self) -> None:
        source = (CONFORMANCE / "debian.Containerfile").read_text()
        packaged, compiler, final = source.split("FROM ")[1:]
        self.assertTrue(packaged.startswith("${DISTRO_IMAGE} AS packaged\n"))
        self.assertIn('"${ENGINE_PACKAGE}" 1000:1000 "${ENGINE_PACKAGE_VERSION}"', packaged)
        self.assertIn('verify-debian-package before-systemd "${ENGINE_PACKAGE_VERSION}" "${ENGINE_VERSION}"', packaged)
        self.assertTrue(compiler.startswith("packaged AS probe\n"))
        self.assertIn('sh /build-probe.sh "${DISTRO_ID}"', compiler)
        self.assertIn("verify-debian-package after-compiler", compiler)
        self.assertTrue(final.startswith("packaged\n"))
        self.assertLess(final.index("install-systemd.sh"), final.index("verify-debian-package after-systemd"))
        self.assertIn("COPY --from=probe /probe/docker-resource-probe", final)
        self.assertIn("USER 0\nSTOPSIGNAL SIGRTMIN+3", final)
        self.assertNotIn("build-probe.sh", final)
        self.assertNotIn("gcc", final)
        self.assertNotIn("payload", source)
        self.assertNotIn("fetch", source)

    def test_distro_and_mode_boundaries_run_before_package_effects(self) -> None:
        systemd = (CONFORMANCE / "install-systemd.sh").read_text().split("provenance=", 1)[0]
        compiler = (CONFORMANCE / "build-probe.sh").read_text().split("export DEBIAN_FRONTEND", 1)[0]
        for distro, mode, success in (
            ("debian-11", "rootless", True),
            ("debian-13", "rootless", True),
            ("debian-13", "rootful", True),
            ("debian-11", "rootful", False),
            ("debian-12", "rootless", False),
            ("debian-14", "rootless", False),
            ("debian-13", "unknown", False),
        ):
            with self.subTest(distro=distro, mode=mode):
                result = subprocess.run(  # noqa: S603 — authored offline script with task-local command substitutes.
                    ["/bin/sh", "-c", systemd, "installer", mode, distro], capture_output=True, check=False
                )
                self.assertEqual(result.returncode == 0, success)
        for distro, success in (("debian-11", True), ("debian-13", True), ("debian-12", False), ("debian-14", False)):
            with self.subTest(compiler=distro):
                result = subprocess.run(  # noqa: S603 — authored offline script with task-local command substitutes.
                    ["/bin/sh", "-c", compiler, "compiler", distro], capture_output=True, check=False
                )
                self.assertEqual(result.returncode == 0, success)

    def test_guest_setup_keeps_vendor_isolation_and_narrow_packaged_path(self) -> None:
        source = (CONFORMANCE / "install-systemd.sh").read_text()
        self.assertIn('if [ "$distro" = debian-11 ]; then', source)
        self.assertIn(
            "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/sh"
            "are/docker.io/contrib",
            source,
        )
        self.assertIn('"$provenance/conformance-package-path"', source)
        self.assertIn("docker.service docker.socket containerd.service", source)
        self.assertIn("mask systemd-sysctl.service systemd-modules-load.service", source)
        self.assertIn('cp /lib/systemd/system/systemd-journald.service "$provenance/vendor-journald-unit"', source)
        self.assertIn("touch /var/lib/systemd/linger/dockertest", source)
        self.assertIn("/etc/systemd/system/user@1000.service.d/delegate.conf", source)
        self.assertIn("chown -R 1000:1000 /home/docker", source)
        self.assertNotIn("gcc", source)
        journal = (CONFORMANCE / "journal-boundary.conf").read_text()
        self.assertIn("CapabilityBoundingSet=~CAP_AUDIT_CONTROL", journal)


class Debian11PackageVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.provenance = self.directory / "provenance"
        self.provenance.mkdir()
        (self.provenance / "package-version").write_text(PACKAGE + "\n")
        (self.provenance / "provenance-kind").write_text("distro-package\n")
        for name in ("subuid", "subgid"):
            (self.directory / name).write_text("dockertest:100000:65536\n")
        self.helpers = self.directory / "contrib"
        self.helpers.mkdir()
        for name in ("dockerd-rootless.sh", "dockerd-rootless-setuptool.sh"):
            path = self.helpers / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        source = (CONFORMANCE / "verify-debian-package.sh").read_text()
        source = source.replace("/usr/share/strukturpiloten/docker", str(self.provenance))
        source = source.replace("/usr/share/docker.io/contrib", str(self.helpers))
        for name in ("subuid", "subgid"):
            source = source.replace("/etc/" + name, str(self.directory / name))
        self.script = self.directory / "verify.sh"
        self.script.write_text(source)
        self.write_stub(
            "dpkg-query",
            'printf "%s\\n" "$*" >> "$QUERY_LOG"\n'
            '[ "${QUERY_EXIT:-0}" = 0 ] || exit "$QUERY_EXIT"\n'
            'printf "%s\\n%s\\n" "${PACKAGE_STATUS:-install ok installed}" "${PACKAGE_REVISION:?}"\n',
        )
        self.write_stub(
            "id",
            'case "$1" in -u) printf "%s\\n" "${ACCOUNT_UID:-1000}" ;; -g) printf "%s\\n" "${ACCOUNT'
            '_GID:-1000}" ;; *) exit 70 ;; esac\n',
        )
        self.write_stub(
            "getent",
            'case "$1:$2" in passwd:1000|passwd:dockertest) printf "%s:x:1000:1000::%s:/bin/sh\\n" '
            '"${ACCOUNT_NAME:-dockertest}" "${ACCOUNT_HOME:-/home/docker}" ;; group:1000) printf "'
            '%s:x:1000:\\n" "${GROUP_NAME:-dockertest}" ;; *) exit 70 ;; esac\n',
        )
        self.write_stub(
            "stat",
            'case "$3" in /home/docker) printf "%s\\n" "${HOME_OWNER:-1000:1000}" ;; /run/user/1000'
            ') printf "%s\\n" "${RUNTIME_OWNER:-1000:1000 700}" ;; *) exit 70 ;; esac\n',
        )
        self.write_stub("docker", 'printf "Docker version %s, build vendor-cli\\n" "${CLI_VERSION:?}"\n')
        self.write_stub("dockerd", 'printf "Docker version %s, build vendor-daemon\\n" "${DAEMON_VERSION:?}"\n')
        self.environment = os.environ | {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "PACKAGE_REVISION": PACKAGE,
            "CLI_VERSION": ENGINE,
            "DAEMON_VERSION": ENGINE,
            "QUERY_LOG": str(self.directory / "queries"),
        }

    def write_stub(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + source)
        path.chmod(0o755)

    def verify(self, phase: str, **changes: str) -> subprocess.CompletedProcess[str]:
        # Command discovery is a process boundary; all production checks and fresh
        # queries execute, while absolute vendor paths remain independently fixed.
        wrapper = """command() {
    case "$1:$2" in
        -v:docker) printf '%s\\n' "${CLI_PATH:-/usr/bin/docker}" ;;
        -v:dockerd) printf '%s\\n' "${DAEMON_PATH:-/usr/sbin/dockerd}" ;;
        *) return 70 ;;
    esac
}
script="$1"
shift
. "$script"
"""
        return subprocess.run(  # noqa: S603 — authored offline script with task-local command substitutes.
            ["/bin/sh", "-c", wrapper, "verify", str(self.script), phase, PACKAGE, ENGINE],
            env=self.environment | changes,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_fresh_before_after_and_compiler_queries_record_actual_readbacks(self) -> None:
        for phase in ("before-systemd", "after-systemd", "after-compiler"):
            result = self.verify(phase)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (self.provenance / ("package-" + phase)).read_text(), "install ok installed\n" + PACKAGE + "\n"
            )
            self.assertEqual(
                (self.provenance / ("dockerd-version-" + phase)).read_text(),
                "Docker version " + ENGINE + ", build vendor-daemon\n",
            )
        queries = (self.directory / "queries").read_text().splitlines()
        self.assertEqual(len(queries), 3)
        self.assertTrue(all("${Status}\\n${Version}\\n docker.io" in query for query in queries))

    def test_after_setup_refuses_removal_drift_query_failure_and_wrong_engine(self) -> None:
        self.assertEqual(self.verify("before-systemd").returncode, 0)
        for changes in (
            {"PACKAGE_STATUS": "deinstall ok config-files"},
            {"PACKAGE_STATUS": "unknown ok not-installed"},
            {"PACKAGE_REVISION": "20.10.5+dfsg1-1+deb11u4"},
            {"PACKAGE_REVISION": "20.10.5+dfsg1-1+deb11u1"},
            {"QUERY_EXIT": "2"},
            {"CLI_VERSION": "20.10.24"},
            {"DAEMON_VERSION": "20.10.24"},
            {"DAEMON_PATH": "/usr/local/bin/dockerd"},
            {"CLI_PATH": "/usr/local/bin/docker"},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.verify("after-systemd", **changes).returncode, 0)
                self.assertFalse((self.provenance / "package-after-systemd").exists())

    def test_before_setup_requires_installed_package_and_packaged_rootless_helpers(self) -> None:
        for changes in (
            {"PACKAGE_STATUS": "deinstall ok config-files"},
            {"PACKAGE_REVISION": "20.10.5+dfsg1-1+deb11u4"},
            {"QUERY_EXIT": "1"},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.verify("before-systemd", **changes).returncode, 0)
        for name in ("dockerd-rootless.sh", "dockerd-rootless-setuptool.sh"):
            with self.subTest(helper=name):
                (self.helpers / name).chmod(0o644)
                self.assertNotEqual(self.verify("before-systemd").returncode, 0)
                (self.helpers / name).chmod(0o755)
        self.assertFalse((self.provenance / "package-before-systemd").exists())

    def test_before_setup_refuses_stale_vendor_record_and_nonvendor_origin(self) -> None:
        for path, value in (("package-version", PACKAGE + ".unexpected\n"), ("provenance-kind", "upstream-static\n")):
            with self.subTest(path=path):
                original = (self.provenance / path).read_text()
                (self.provenance / path).write_text(value)
                self.assertNotEqual(self.verify("before-systemd").returncode, 0)
                (self.provenance / path).write_text(original)
        self.assertFalse((self.provenance / "package-before-systemd").exists())

    def test_missing_before_record_and_unsupported_phase_fail_closed(self) -> None:
        self.assertNotEqual(self.verify("after-systemd").returncode, 0)
        query_count = len((self.directory / "queries").read_text().splitlines())
        self.assertNotEqual(self.verify("unknown").returncode, 0)
        self.assertEqual(len((self.directory / "queries").read_text().splitlines()), query_count)

    def test_actual_account_home_and_runtime_directory_are_required(self) -> None:
        for changes in (
            {"ACCOUNT_UID": "1001"},
            {"ACCOUNT_GID": "1001"},
            {"ACCOUNT_NAME": "someoneelse"},
            {"GROUP_NAME": "someoneelse"},
            {"ACCOUNT_HOME": "/home/someoneelse"},
            {"HOME_OWNER": "0:0"},
            {"RUNTIME_OWNER": "1000:1000 755"},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.verify("before-systemd", **changes).returncode, 0)
        for name in ("subuid", "subgid"):
            with self.subTest(name=name):
                (self.directory / name).write_text("someoneelse:100000:65536\n")
                self.assertNotEqual(self.verify("before-systemd").returncode, 0)
                (self.directory / name).write_text("dockertest:100000:65536\n")
        self.assertFalse((self.provenance / "package-before-systemd").exists())


class Debian11InstallerSelectorTests(unittest.TestCase):
    def installer(
        self, arguments: list[str], *, validation_exit: int = 0
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            apt = directory / "apt"
            (apt / "sources.list.d").mkdir(parents=True)
            binary = directory / "bin"
            binary.mkdir()
            log = directory / "commands"
            stub = binary / "apt-get"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\ncase "$1" in install) exit 73 ;; esac\n')
            stub.chmod(0o755)
            dpkg = binary / "dpkg"
            dpkg.write_text('#!/bin/sh\n[ "$1" = --validate-version ] || exit 70\nexit "$VALIDATION_EXIT"\n')
            dpkg.chmod(0o755)
            source = (ROOT / "images/docker/platforms/install-packages.sh").read_text()
            source = source.replace("/etc/apt/", str(apt) + "/")
            source = source.replace("/usr/share/strukturpiloten/docker", str(directory / "provenance"))
            script = directory / "installer.sh"
            script.write_text(source)
            result = subprocess.run(  # noqa: S603 — authored offline script with task-local command substitutes.
                ["/bin/sh", str(script), *arguments],
                env=os.environ
                | {
                    "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                    "COMMAND_LOG": str(log),
                    "VALIDATION_EXIT": str(validation_exit),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            return (
                result,
                log.read_text() if log.exists() else "",
                (apt / "sources.list").read_text() if (apt / "sources.list").exists() else "",
            )

    def test_exact_selector_preserves_signed_archives_and_package_name_queries(self) -> None:
        result, commands, sources = self.installer(["debian-11", "docker.io", "1000:1000", PACKAGE])
        self.assertEqual(result.returncode, 73)
        self.assertEqual(
            commands.splitlines(),
            [
                "update",
                "--yes upgrade",
                "install --yes --no-install-recommends busybox ca-certificates curl docker.io="
                + PACKAGE
                + " iproute2 iptables passwd procps tar",
            ],
        )
        self.assertEqual(
            sources.splitlines(),
            [
                "deb [check-valid-until=no] http://archive.debian.org/debian bullseye main",
                "deb [check-valid-until=no] http://archive.debian.org/debian-security bullseye-security main",
            ],
        )
        source = (ROOT / "images/docker/platforms/install-packages.sh").read_text()
        self.assertIn('apt-cache policy "$engine_package"', source)
        self.assertIn("'${Version}\\n' \"$engine_package\"", source)
        self.assertNotIn("trusted=yes", source)
        self.assertNotIn("allow-unauthenticated", source)

    def test_existing_three_argument_route_does_not_add_security_or_pin(self) -> None:
        result, commands, sources = self.installer(["debian-11", "docker.io", "1000:1000"])
        self.assertEqual(result.returncode, 73)
        self.assertIn("curl docker.io iproute2", commands)
        self.assertNotIn("docker.io=", commands)
        self.assertNotIn("debian-security", sources)

    def test_unsupported_empty_malformed_and_invalid_versions_refuse_before_apt(self) -> None:
        for args, validation_exit in (
            (["debian-12", "docker.io", "1000:1000", PACKAGE], 0),
            (["debian-11", "containerd", "1000:1000", PACKAGE], 0),
            (["debian-11", "docker.io", "root", PACKAGE], 0),
            (["debian-11", "docker.io", "1000:1000", ""], 0),
            (["debian-11", "docker.io", "1000:1000", PACKAGE + " bad"], 0),
            (["debian-11", "docker.io", "1000:1000", "not-a-version"], 1),
            (["debian-11", "docker.io", "1000:1000", PACKAGE, "extra"], 0),
        ):
            with self.subTest(args=args):
                result, commands, sources = self.installer(args, validation_exit=validation_exit)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(commands, "")
                self.assertEqual(sources, "")
