# Podman compatibility images

These images run Podman inside a container so CI pipelines can test software against different Podman versions and distributor package variants. Boxferry is the primary use case: it must recognize deployments created on old and current systems, including systems without Quadlet support.

They are test fixtures, not production container hosts. A container reproduces the packaged Podman binary and userspace, but it cannot reproduce the original host kernel, a booted systemd instance, host cgroups, or host SELinux/AppArmor policy. Use virtual machines when those host properties are part of the test.

## Image families

The repository provides two complementary families:

- **Upstream-source images** isolate the behavior of exact Podman release tags from 5.4 through 6.1. They build the upstream source without a distribution's Podman patch set.
- **Distro-package images** install Podman from an operating system's own repositories. They preserve that distribution's package revision, dependencies, helpers, libraries, and downstream patch policy. Each OS release owns its nested-CI configuration; the images do not claim to preserve every host-level default.

Every target has separate `-rootful` and `-rootless` images. Rootful/rootless describes the user running Podman inside the outer container; it does not describe the outer host runtime and does not remove the need for nested-container privileges.

### Exact upstream releases

| Podman line | Published names | Exact Podman version | Runtime base | Podman patch source | Architectures | Rootful | Rootless |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5.4 | `podman-5.4-{rootful,rootless}` | 5.4.2 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 5.5 | `podman-5.5-{rootful,rootless}` | 5.5.2 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 5.6 | `podman-5.6-{rootful,rootless}` | 5.6.2 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 5.7 | `podman-5.7-{rootful,rootless}` | 5.7.1 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 5.8 | `podman-5.8-{rootful,rootless}` | 5.8.6 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 6.0 | `podman-6.0-{rootful,rootless}` | 6.0.2 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |
| 6.1 | `podman-6.1-{rootful,rootless}` | 6.1.0 | Fedora Minimal 44 | Upstream tag; no distro Podman patches | AMD64, ARM64 | Yes | Yes |

The multi-stage source recipe compiles Podman in a toolchain stage and copies only its output into the runtime stage. Podman, Netavark, and Aardvark DNS sources are pinned to verified commits. Fedora runtime packages are upgraded on every build; “no distro Podman patches” applies to the Podman source, not to its Fedora runtime dependencies.

### Distribution packages

Package versions in this table were observed from the stable repositories on 2026-08-23. They are observations, not pins: a daily build installs the newest package revision offered for that OS release. The exact installed revision is always recorded inside the image.

| OS target and image-name prefix | Official base tag | Observed Podman package | Podman patch source | Architectures | Rootful | Rootless |
| --- | --- | --- | --- | --- | --- | --- |
| Debian 11 — `podman-debian-11-` | `debian:11` | `3.0.1+dfsg1-3+deb11u5` | Debian-managed | AMD64, ARM64 | Yes | Yes |
| Debian 12 — `podman-debian-12-` | `debian:12` | `4.3.1+ds1-8+deb12u1+b3` | Debian-managed | AMD64, ARM64 | Yes | Yes |
| Debian 13 — `podman-debian-13-` | `debian:13` | `5.4.2+ds1-2+b2` | Debian-managed | AMD64, ARM64 | Yes | Yes |
| Ubuntu 22.04 — `podman-ubuntu-22.04-` | `ubuntu:22.04` | `3.4.4+ds1-1ubuntu1.22.04.3` | Ubuntu-managed | AMD64, ARM64 | Yes | Yes |
| Ubuntu 24.04 — `podman-ubuntu-24.04-` | `ubuntu:24.04` | `4.9.3+ds1-1ubuntu0.2` | Ubuntu-managed | AMD64, ARM64 | Yes | Yes |
| Ubuntu 26.04 — `podman-ubuntu-26.04-` | `ubuntu:26.04` | `5.7.0+ds2-3build1` | Ubuntu-managed | AMD64, ARM64 | Yes | Yes |
| Fedora 43 — `podman-fedora-43-` | `fedora:43` | 5.8.4 | Fedora-managed | AMD64, ARM64 | Yes | Yes |
| Fedora 44 — `podman-fedora-44-` | `fedora:44` | 5.8.4 | Fedora-managed | AMD64, ARM64 | Yes | Yes |
| openSUSE Leap 16.0 — `podman-opensuse-leap-16.0-` | `opensuse/leap:16.0` | 5.4.2 | openSUSE-managed | AMD64, ARM64 | Yes | Yes |
| openSUSE Tumbleweed — `podman-opensuse-tumbleweed-` | `opensuse/tumbleweed:latest` | 6.0.2 | openSUSE-managed, rolling | AMD64, ARM64 | Yes | Yes |
| Red Hat UBI 8 — `podman-ubi-8-` | `ubi8/ubi:latest` | 4.9.4 | Red Hat-managed | AMD64, ARM64 | Yes | Yes |
| Red Hat UBI 9 — `podman-ubi-9-` | `ubi9/ubi:latest` | 5.8.2 | Red Hat-managed | AMD64, ARM64 | Yes | Yes |
| Red Hat UBI 10 — `podman-ubi-10-` | `ubi10/ubi:latest` | 5.8.2 | Red Hat-managed | AMD64, ARM64 | Yes | Yes |
| CentOS Stream 9 — `podman-centos-stream-9-` | `centos:stream9` | 5.8.5 | CentOS Stream-managed | AMD64, ARM64 | Yes | Yes |
| CentOS Stream 10 — `podman-centos-stream-10-` | `centos:stream10` | 6.1.0 | CentOS Stream-managed | AMD64, ARM64 | Yes | Yes |
| Alpine 3.24 — `podman-alpine-3.24-` | `alpine:3.24` | `5.8.6-r0` | Alpine-managed | AMD64, ARM64 | Yes | Yes |
| Arch Linux — `podman-arch-` | `archlinux:base` | `6.1.0-1` | Arch-managed, rolling | AMD64 only | Yes | Yes |

Append `rootful` or `rootless` to a prefix from the first column. For example:

```text
ghcr.io/strukturpiloten/podman-debian-11-rootless
ghcr.io/strukturpiloten/podman-ubuntu-24.04-rootful
ghcr.io/strukturpiloten/podman-arch-rootless
```

Rocky Linux and AlmaLinux are intentionally not duplicated; the UBI targets cover the required RHEL package families. Arch is AMD64-only because its official base image does not provide the ARM64 platform used by this repository.

## Versions, tags, and inspection

For upstream-source images, the image version equals the exact Podman release, such as `v6.1.0`.

For distro-package images, `v1.0.0` is the version of the Strukturpiloten image contract. It does not freeze the distro's Podman RPM/APK/DEB revision. Daily rebuilds can update that native revision without changing the image contract version.

Inspect both values from any distro image:

```sh
podman run --rm ghcr.io/strukturpiloten/podman-debian-12-rootful:v1.0.0 podman --version
podman run --rm ghcr.io/strukturpiloten/podman-debian-12-rootful:v1.0.0 \
  cat /usr/share/strukturpiloten/podman-package-version
```

Maintained tags (`latest`, `vX.Y.Z`, `vX.Y`, and `vX`) move after successful security rebuilds. Pin the manifest digest when the exact artifact must not change. The immutable `sha-*` and `run-*` tags provide additional audit identities.

## Running nested Podman

The images use `CMD ["podman", "--help"]` and no entrypoint. This makes an argument-free run self-describing while allowing CI to replace the command with `podman`, `sh`, `cat`, or another diagnostic tool. An `ENTRYPOINT ["podman"]` would turn a command such as `sh` into `podman sh` and make compatibility diagnostics unnecessarily difficult.

### Rootless example

Rootless images run as UID/GID 1000 and store images under `/home/podman/.local/share/containers`:

```sh
sudo podman run --rm \
  --privileged \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  --security-opt label=disable \
  --volume podman-debian-12-rootless:/home/podman/.local/share/containers \
  ghcr.io/strukturpiloten/podman-debian-12-rootless:v1.0.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootless
```

Rootless operation requires unprivileged user namespaces, working subordinate UID/GID mappings, `newuidmap`/`newgidmap`, and FUSE overlay support. AppArmor profiles commonly applied by outer container runtimes can deny the storage bind mount even after inner Podman enters its user namespace. The exact upstream profiles disable AppArmor for the trusted outer container while retaining rootless UID 1000, the seccomp profile, and reduced capabilities. Distro-package profiles use the privileged boundary explained below.

The outer Podman command runs rootfully with an isolated image store. This avoids coupling the inner OCI runtime directory to the host user's UID, which differs between local systems and GitHub-hosted runners. The image process still starts as UID/GID 1000, and the automated test rejects it unless `podman info` reports rootless mode.

The distro-package rootless images are tested in a privileged outer container. Distribution packaging of `newuidmap`, file capabilities, seccomp, and AppArmor varies enough that an unprivileged outer container does not provide a portable test boundary. The image still starts as UID/GID 1000, and the test asserts that Podman reports rootless mode. Treat the privileged outer container as rootful access to the runner despite that inner identity.

The exact upstream rootless images use the narrower unprivileged outer profile because their Fedora runtime and subordinate-ID setup are controlled by the shared source-build recipe.

### Automated nested-runtime coverage

| Image profiles | Build and CLI check | Nested `podman run` check | Reason |
| --- | --- | --- | --- |
| All rootful profiles | Yes | Yes | The trusted outer test container supplies the required mount and namespace privileges. |
| Upstream-source, Debian, Ubuntu, Fedora, CentOS Stream, Alpine, and Arch rootless profiles | Yes | Yes | Their `newuidmap`/`newgidmap` path works inside the nested test boundary. |
| UBI 8, 9, and 10 plus openSUSE Leap and Tumbleweed rootless profiles | Yes | No | Their subordinate-ID helpers reject writing the second nested user namespace's `uid_map`. Replacing those helpers would stop testing the distribution package environment. |

These rootless images remain useful for package, CLI, filesystem, and inspection compatibility. Test operations that must create their Podman user namespace on a UBI or openSUSE host in a VM or dedicated runner instead of another container. Every exception is explicit in the image's `tests.podman.nestedRuntime` metadata; CI does not infer it from an image name.

### Rootful example

Rootful images run Podman as root and store images under `/var/lib/containers`:

```sh
podman run --rm \
  --privileged \
  --device /dev/fuse \
  --security-opt label=disable \
  --volume podman-6.1-rootful:/var/lib/containers \
  ghcr.io/strukturpiloten/podman-6.1-rootful:v6.1.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootful
```

Rootful Podman must create storage mounts and namespaces. Adding `SYS_ADMIN` and `MKNOD` alone can still fail when the outer runtime's seccomp or AppArmor policy rejects those mount operations, so the portable nested-rootful invocation is privileged. Use it only for trusted images on isolated runners. Never expose unrelated repository or deployment secrets to jobs that execute nested containers.

Docker on a Linux host can run the same outer container with equivalent `docker run` flags; the inner engine remains Podman and does not use the Docker daemon. Docker Desktop and non-Linux systems depend on their Linux VM exposing `/dev/fuse`, user namespaces, and the required mount operations, so they are not guaranteed environments.

Never share a storage volume between Podman versions, OS targets, or root modes. Storage formats and database migrations are part of what compatibility testing can change.

## Build and test architecture

The exact upstream images use the multi-stage `images/podman/shared/Containerfile`. Distro-package images use one recipe per OS release under `images/podman/platforms/`; a platform recipe is shared only by its rootful and rootless variants. Package names, account setup, OCI runtime selection, and cgroup behavior therefore cannot leak between Debian, Ubuntu, Fedora, UBI, openSUSE, Alpine, or Arch targets.

Test one image locally on an AMD64 Linux host with Podman and `/dev/fuse`:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine test-podman-image \
  --image podman-debian-12-rootless
```

The command performs a no-cache build from the digest-pinned base, verifies the packaged Podman CLI and recorded package revision, then runs the same nested-container check used by Actions. Rootful profiles are loaded into rootful Podman through `sudo -n`. Rootless profiles deliberately use the host user's rootless Podman: the outer user namespace supplies the subordinate-ID range that `newuidmap` must divide again for the inner engine. Configure passwordless permission for rootful Podman or use `--skip-nested`. Local ARM64 checks require an ARM64 host or correctly configured emulation.

## CI and fidelity limits

The nested configurations use host namespaces and FUSE overlay storage because the images do not boot an init system. Most targets use `crun` with disabled cgroup management. The runc-based openSUSE Leap target keeps cgroups enabled because runc cannot execute the disabled-cgroups OCI configuration. Tumbleweed also keeps cgroups enabled because its rolling package can select runc for a nested workload even when crun is the configured preference. These settings are suitable for CLI and nested-container compatibility tests, but they intentionally differ from some distro host defaults and do not provide a complete systemd or Quadlet environment.

You can test whether a distro package contains the Quadlet generator and how Boxferry handles its presence or absence, but starting systemd units requires a more complete environment. Use a VM when a test depends on boot order, systemd generators, host cgroup delegation, kernel storage drivers, host networking, SELinux/AppArmor rules, or distribution installer behavior.

GitHub Actions always verify the Podman CLI. Same-repository pull requests, default-branch builds, and scheduled builds additionally load the built image and run a minimal nested container. Fork pull requests do not receive the privileged nested test profile.

## Maintenance and legacy targets

All supported bases and installed packages are upgraded during the daily no-cache build. This picks up fixes only while the selected distribution and Podman line still publish them. It cannot turn an end-of-life target into a supported one.

Debian 11 is retained deliberately because Boxferry must read deployments from old systems. Debian 11 LTS ends on 2026-08-31. After that boundary the image is a legacy compatibility fixture, not a security-maintained execution environment. Keep its CI isolated, do not give it unrelated secrets, and freeze the last reproducible package/base combination if public repositories stop serving it.

The older upstream-source Podman lines have the same limitation: they remain useful behavior fixtures even when upstream no longer patches them. Prefer a currently maintained Podman and OS line for new production deployments.
