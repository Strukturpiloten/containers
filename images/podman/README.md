# Podman compatibility images

These images run Podman inside a container so CI pipelines can test software against different Podman versions and distributor package variants. Boxferry is the primary use case: it must recognize deployments created on old and current systems, including systems without Quadlet support.

They are test fixtures, not production container hosts. A container reproduces the packaged Podman binary and userspace, but it cannot reproduce the original host kernel, a booted systemd instance, host cgroups, or host SELinux/AppArmor policy. Use virtual machines when those host properties are part of the test.

## Image families

The repository provides two complementary families:

- **Upstream-source images** isolate the behavior of exact Podman release tags from 5.4 through 6.1. They build the upstream source without a distribution's Podman patch set.
- **Distro-package images** install Podman from an operating system's own repositories. They preserve that distribution's package revision, dependencies, helpers, libraries, and downstream patch policy. The repository overlays a common configuration for nested CI operation; it does not claim to preserve every host-level default.

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
podman run --rm \
  --device /dev/fuse \
  --security-opt label=disable \
  --volume podman-debian-12-rootless:/home/podman/.local/share/containers \
  ghcr.io/strukturpiloten/podman-debian-12-rootless:v1.0.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootless
```

Rootless operation requires unprivileged user namespaces, working subordinate UID/GID mappings, `newuidmap`/`newgidmap`, and FUSE overlay support. Host policy can still deny one of those features.

The Debian 11 and Ubuntu 22.04 images contain Podman 3. Its older nested-rootless namespace handling commonly requires a privileged outer container. The publishing workflow applies that fallback only to trusted default-branch and scheduled smoke tests for those two images; pull requests run only their unprivileged CLI check. Treat the same fallback as privileged rootful access to the host despite the inner Podman process using UID 1000.

### Rootful example

Rootful images run Podman as root and store images under `/var/lib/containers`:

```sh
podman run --rm \
  --cap-add SYS_ADMIN \
  --cap-add MKNOD \
  --device /dev/fuse \
  --security-opt label=disable \
  --volume podman-6.1-rootful:/var/lib/containers \
  ghcr.io/strukturpiloten/podman-6.1-rootful:v6.1.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootful
```

`SYS_ADMIN` is broad, and disabling SELinux labels weakens isolation. `--privileged` is a last-resort compatibility fallback for trusted images on isolated runners, not the default invocation. Never expose unrelated repository or deployment secrets to jobs that execute untrusted nested containers.

Docker on a Linux host can run the same outer container with equivalent `docker run` flags; the inner engine remains Podman and does not use the Docker daemon. Docker Desktop and non-Linux systems depend on their Linux VM exposing `/dev/fuse`, user namespaces, and the required mount operations, so they are not guaranteed environments.

Never share a storage volume between Podman versions, OS targets, or root modes. Storage formats and database migrations are part of what compatibility testing can change.

## CI and fidelity limits

The common nested configuration uses host namespaces, FUSE overlay storage, and disabled cgroup management because the images do not boot an init system. That is suitable for CLI and nested-container compatibility tests. It intentionally differs from some distro host defaults and is not a complete systemd or Quadlet environment.

You can test whether a distro package contains the Quadlet generator and how Boxferry handles its presence or absence, but starting systemd units requires a more complete environment. Use a VM when a test depends on boot order, systemd generators, host cgroup delegation, kernel storage drivers, host networking, SELinux/AppArmor rules, or distribution installer behavior.

GitHub Actions smoke tests verify the Podman CLI on pull requests. Trusted default-branch and scheduled builds additionally load the built image and run a minimal nested container before publication.

## Maintenance and legacy targets

All supported bases and installed packages are upgraded during the daily no-cache build. This picks up fixes only while the selected distribution and Podman line still publish them. It cannot turn an end-of-life target into a supported one.

Debian 11 is retained deliberately because Boxferry must read deployments from old systems. Debian 11 LTS ends on 2026-08-31. After that boundary the image is a legacy compatibility fixture, not a security-maintained execution environment. Keep its CI isolated, do not give it unrelated secrets, and freeze the last reproducible package/base combination if public repositories stop serving it.

The older upstream-source Podman lines have the same limitation: they remain useful behavior fixtures even when upstream no longer patches them. Prefer a currently maintained Podman and OS line for new production deployments.
