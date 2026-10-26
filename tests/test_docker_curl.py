"""Check Docker curl installation/provenance with extracted commands and fake tools."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = "/usr/share/strukturpiloten/docker"
DISTRO_SCRIPT = ROOT / "images/docker/platforms/install-packages.sh"
DISTRO_CASES = (
    (
        "debian-11|debian-12|debian-13|ubuntu-22.04|ubuntu-24.04|ubuntu-26.04",
        "apt-get",
        "curl",
        (
            "apt-get install --yes --no-install-recommends busybox ca-certificates curl $engine_package "
            "iproute2 iptables passwd procps tar"
        ),
        r"dpkg-query --show --showformat='${binary:Package}=${Version}\n' | sort",
    ),
    (
        "fedora-43|fedora-44",
        "dnf",
        "curl-minimal",
        (
            "dnf --assumeyes install --setopt=install_weak_deps=False busybox ca-certificates curl-minimal "
            "$engine_package iproute iptables iptables-nft procps-ng shadow-utils tar"
        ),
        r"rpm --query --all --queryformat '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort",
    ),
    (
        "opensuse-leap-16.0|opensuse-tumbleweed",
        "zypper",
        "curl",
        (
            "zypper --non-interactive install --no-recommends busybox ca-certificates curl $engine_package "
            "iproute2 iptables procps shadow tar"
        ),
        r"rpm --query --all --queryformat '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort",
    ),
    (
        "alpine-3.24",
        "apk",
        "curl",
        "apk add --no-cache busybox ca-certificates curl $engine_package iproute2 iptables procps shadow tar",
        "apk info --verbose | sort",
    ),
    (
        "arch",
        "pacman",
        "curl",
        (
            "pacman --sync --noconfirm --needed busybox ca-certificates curl $engine_package "
            "iproute2 iptables-nft procps-ng shadow tar"
        ),
        "pacman --query | sort",
    ),
)


class DockerCurlTests(unittest.TestCase):
    def recipes(self) -> list[tuple[str, str, tuple[str, str, str], tuple[str, str, str]]]:
        source = DISTRO_SCRIPT.read_text(encoding="utf-8").replace("\\\n", " ")
        probe = next(line.strip() for line in source.splitlines() if line.startswith("/usr/bin/curl "))
        expected_probe = '/usr/bin/curl --disable --version > "$provenance/curl-version"'
        recipes = []
        for selector, manager, package, expected_install, query in DISTRO_CASES:
            branch = source.split(f"    {selector})\n", 1)[1].split("\n        ;;", 1)[0]
            install = next(
                line.strip()
                for line in branch.splitlines()
                if line.strip().startswith(manager + " ")
                and '"$engine_package"' in line
                and ("install" in line or line.strip().startswith(("apk add ", "pacman --sync --noconfirm")))
            )
            inventory = next(line.strip() for line in branch.splitlines() if '"$provenance/os-packages"' in line)
            self.assertLess(branch.index(install), branch.index(inventory))
            self.assertLess(branch.index(install), branch.index('if [ "$mode" = rootless ]'))
            expected_inventory = query + ' > "$provenance/os-packages"'
            # The shared package install precedes the rootless-only additions.
            recipes.extend(
                (
                    selector + ":" + mode,
                    package,
                    (install, inventory, probe),
                    (expected_install, expected_inventory, expected_probe),
                )
                for mode in ("rootful", "rootless")
            )
        for mode in ("rootful", "rootless"):
            source = (ROOT / f"images/docker/upstream/{mode}.Containerfile").read_text(encoding="utf-8")
            lines = [line.strip().removesuffix("; \\") for line in source.splitlines()]
            install = next(line for line in lines if line.startswith("apk add "))
            inventory = next(line for line in lines if line.startswith("apk info "))
            probe = next(line for line in lines if line.startswith("/usr/bin/curl "))
            packages = (
                "ca-certificates curl iproute2 iptables procps tar"
                if mode == "rootful"
                else "ca-certificates curl fuse-overlayfs iproute2 iptables procps shadow shadow-subids slirp4netns tar"
            )
            self.assertLess(source.index(install), source.index(inventory))
            self.assertLess(source.index(install), source.index(probe))
            self.assertLess(source.index(probe), source.index("COPY --from=payload"))
            recipes.append(
                (
                    "upstream:" + mode,
                    "curl",
                    (install, inventory, probe),
                    (
                        "apk add --no-cache " + packages,
                        "apk info -vv > " + PROVENANCE + "/os-packages",
                        "/usr/bin/curl --disable --version > " + PROVENANCE + "/curl-version",
                    ),
                )
            )
        return recipes

    def check_commands(self, actual: tuple[str, str, str], expected: tuple[str, str, str]) -> None:
        for command, wanted in zip(actual, expected, strict=True):
            self.assertEqual(shlex.split(command), shlex.split(wanted))

    def exercise(self, commands: tuple[str, str, str], package: str, fault: str = "none") -> None:
        install, inventory, _probe = commands
        with tempfile.TemporaryDirectory(prefix="docker-curl-control-") as temporary:
            directory = Path(temporary)
            tools = directory / "bin"
            tools.mkdir()
            trace = directory / "calls"
            (tools / "sort").symlink_to("/usr/bin/sort")
            install_args = shlex.split(install.replace('"$engine_package"', "vendor-engine"))
            query_args = shlex.split(inventory.split("|", 1)[0].split(">", 1)[0])
            package_list = f"{package}=fixture-revision\nother-package=retained-revision\n"
            version = "curl fixture-version\nProtocols: http https\n"
            body = (
                f"#!{sys.executable}\nimport json, pathlib, sys\n"
                "name=pathlib.Path(sys.argv[0]).name\nargs=[name, *sys.argv[1:]]\n"
                f"with pathlib.Path({str(trace)!r}).open('a') as stream:\n"
                " stream.write(json.dumps(args)+'\\n')\n"
                f"if args == {install_args!r}: pass\n"
                f"elif args == {query_args!r}: sys.stdout.write({package_list!r})\n"
                f"elif args == ['curl', '--disable', '--version']:\n"
                f" sys.stdout.write({version!r}); sys.exit({42 if fault == 'failure' else 0})\n"
                "else: sys.exit(97)\n"
            )
            for name in {install_args[0], query_args[0], "curl"}:
                if name == "curl" and fault == "missing":
                    continue
                executable = tools / name
                executable.write_text(body, encoding="utf-8")
                executable.chmod(0o600 if name == "curl" and fault == "not_executable" else 0o700)
            # Only the three checked snippets run. Never run full provisioning;
            # absolute image paths are mapped into this private test directory.
            script = "set -eu\n" + "\n".join(commands)
            script = script.replace(PROVENANCE, shlex.quote(str(directory)))
            script = script.replace("/usr/bin/curl", shlex.quote(str(tools / "curl")))
            result = subprocess.run(  # noqa: S603
                ["/bin/sh", "-c", script],
                env={"PATH": str(tools), "provenance": str(directory), "engine_package": "vendor-engine"},
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            self.assertEqual(result.stdout, "")
            self.assertEqual((directory / "os-packages").read_text(encoding="utf-8"), package_list)
            calls = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
            expected_calls = [install_args, query_args]
            if fault not in ("missing", "not_executable"):
                expected_calls.append(["curl", "--disable", "--version"])
            self.assertEqual(calls, expected_calls)
            if fault == "none":
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((directory / "curl-version").read_text(encoding="utf-8"), version)
            else:
                self.assertNotEqual(result.returncode, 0)

    def test_every_distro_branch_and_upstream_mode_installs_and_records_curl(self) -> None:
        for name, package, actual, expected in self.recipes():
            with self.subTest(recipe=name):
                self.check_commands(actual, expected)
                self.exercise(actual, package)

    def test_missing_nonexecutable_or_failed_fixed_probe_fails_construction(self) -> None:
        for name, package, actual, expected in self.recipes():
            for fault in ("missing", "not_executable", "failure"):
                with self.subTest(recipe=name, fault=fault):
                    self.check_commands(actual, expected)
                    self.exercise(actual, package, fault)

    def test_removed_install_probe_or_complete_provenance_is_detected(self) -> None:
        for name, package, actual, expected in self.recipes():
            install, inventory, probe = actual
            for damaged in (
                (install.replace(" " + package + " ", " "), inventory, probe),
                (install, inventory, ""),
                (install, "", probe),
                (install, inventory.replace(" > ", " | grep curl > "), probe),
                (install, inventory, probe.replace("--disable ", "")),
            ):
                with self.subTest(recipe=name, damaged=damaged), self.assertRaises(AssertionError):
                    self.check_commands(damaged, expected)

    def test_inventory_moved_before_install_is_rejected_from_recipe_source(self) -> None:
        read_text = Path.read_text
        for name, _package, (install, inventory, _probe), _expected in self.recipes():
            selector, mode = name.rsplit(":", 1)
            if selector == "upstream":
                target = ROOT / f"images/docker/upstream/{mode}.Containerfile"
                source = read_text(target, encoding="utf-8")
                start, end = 0, len(source)
                separator = "; \\\n    "
            else:
                target = DISTRO_SCRIPT
                source = read_text(target, encoding="utf-8").replace("\\\n", " ")
                start = source.index(f"    {selector})\n")
                end = source.index("\n        ;;", start)
                separator = "\n        "
            # Move the real inventory command, leaving a shell no-op in its old
            # position. Only in-memory source changes; no provisioning is run.
            region = source[start:end].replace(inventory, ":", 1)
            region = region.replace(install, inventory + separator + install, 1)
            changed = source[:start] + region + source[end:]
            with (
                self.subTest(recipe=name),
                mock.patch.object(
                    Path,
                    "read_text",
                    autospec=True,
                    side_effect=lambda path, *, selected=target, replacement=changed, **kwargs: (
                        replacement if path == selected else read_text(path, **kwargs)
                    ),
                ),
                self.assertRaises(AssertionError),
            ):
                self.recipes()


if __name__ == "__main__":
    unittest.main()
