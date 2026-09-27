# Docker compatibility images

These images run Docker Engine inside an isolated Linux container so native importer tests can inspect real Docker resources. Podman launches the outer container. Neither a host Docker daemon nor its socket is used. These are test fixtures, not production Docker hosts: they share the runner kernel, cgroups, and security policy.

## Upstream Engine catalogue

Each line has a `docker-<line>-rootful` and a `docker-<line>-rootless` image. The selected patch is refreshed within its line; image tags identify the exact Engine release. A digest identifies one immutable published build, while the readable version tag may move after a reviewed OS rebuild.

| Line | Engine and CLI | containerd | runc | RootlessKit | Status |
| --- | --- | --- | --- | --- | --- |
| 20.10 | 20.10.24 | 1.6.20 | 1.1.5 | 0.14.4 | Legacy fixture |
| 23 | 23.0.6 | 1.6.21 | 1.1.7 | 1.1.0 | Legacy fixture |
| 24 | 24.0.9 | 1.7.13 | 1.1.12 | 1.1.1 | Legacy fixture |
| 25 | 25.0.5 | 1.7.13 | 1.1.12 | 2.0.2 | Legacy fixture |
| 26 | 26.1.4 | 1.7.18 | 1.1.12 | 2.0.2 | Legacy fixture |
| 27 | 27.5.1 | 1.7.25 | 1.2.4 | 2.3.2 | Legacy fixture |
| 28 | 28.5.2 | 1.7.28 | 1.3.3 | 2.3.4 | Legacy fixture |
| 29 | 29.8.1 | 2.3.5 | 1.5.1 | 3.1.0 | Current selected fixture |

The Engine, CLI, containerd, and runc binaries come from Docker's official static Engine archive. RootlessKit and `dockerd-rootless.sh` come from Docker's separate rootless-extras archive for the same release. These binaries are **assembled from verified upstream artifacts**, not compiled by this repository. Every payload manifest records both per-architecture SHA256 checksums, upstream URLs, component versions, and available source revision IDs. The payload build verifies SHA256 before extraction and records the observed versions under `/usr/share/strukturpiloten/docker/` in each final image. `components.txt` lists the exact inputs; `os-packages` lists installed Alpine packages. Rootful images do not install the rootless helper binaries even though both variants derive from the same checked payload.

The shared payload is a build-only OCI artifact. It is assembled once per Engine release and architecture in a build run, then supplied to both final recipes through `BUILD_PAYLOAD_IMAGE`. It has no public `container.yaml`, release tag, or invented registry digest. The final images alone have public image metadata. The pinned common runtime base is Alpine 3.24 at its multi-architecture manifest digest recorded in each image. Runtime packages receive repository updates during image builds; old static Engine binaries and their vendored dependencies do not receive fixes from an Alpine rebuild. Retire a legacy line when its compatibility value no longer justifies isolated testing.

Compose and Buildx are separate products and are not installed. No Compose-provider behavior is implied. Distribution-package Docker images are a separate family whose package revision and userspace will follow each distribution, rather than this shared Alpine payload.

## Runtime modes and admission

The rootful image starts `dockerd` as UID 0 with `/var/lib/docker` as its data root. The rootless image starts `dockerd-rootless.sh` as UID 1000 with a separate home data root, subordinate UID/GID ranges, RootlessKit, `slirp4netns`, and `fuse-overlayfs`. Both expose only a Unix socket inside their disposable outer container. The launcher forwards termination to the daemon. Do not share a data-root volume between versions or modes.

The metadata declares `tests.docker.mode` and the required outer privilege explicitly. A rootless *inner* daemon still needs a trusted, privileged outer Podman boundary on the tested Linux runner. Rootless outer Podman started the 20.10 daemon during pilot work but failed to start its nested runc workload; this does not establish a usable unprivileged outer profile. Test jobs use an isolated rootful outer Podman store, task-owned names and volumes, bounded timeouts, and cleanup readback. No global prune is used.

Build metadata requests AMD64 and ARM64 as unmerged CI admission candidates. The payload manifests include verified ARM64 archive checksums, but ARM64 native evidence is pending; publication and compatibility claims require ARM64 daemon, API, network, storage, port, mount, and cleanup results first. A green cross-build or emulated binary execution is not sufficient. Linux kernel and host security behavior still need dedicated host testing when they matter.

## Validation

The native contract starts each daemon, checks the actual Engine and CLI/API range, confirms root mode and storage driver, loads a synthetic image into the inner daemon, and exercises named and bind mounts, a user network and DNS, a published TCP port, health/restart settings, and owned cleanup. It uses the final image itself as an offline nested fixture. Run it against one built OCI archive on a Linux runner with passwordless rootful Podman:

```sh
.venv/bin/python -m scripts.runtime_tests \
  --metadata images/docker/docker-20.10-rootful/container.yaml \
  --archive /path/to/docker-20.10-rootful-amd64.oci.tar \
  --arch amd64 --sudo --allow-privileged \
  --evidence /tmp/docker-20.10-rootful-evidence.json
```

The admission pilot on an AMD64 Linux host ran Docker 20.10.24 and 29.8.1 in both daemon modes on Alpine 3.24. All four started, reported the expected API version and root mode, and ran a real nested Alpine container. The full native contract passed for both 20.10 modes. CI must record full contract evidence for 29 and the six middle lines before admission. Observed final pilot image sizes were about 211 MiB (20.10 rootful), 271 MiB (20.10 rootless), 242 MiB (29 rootful), and 275 MiB (29 rootless) before final image-size optimization. Pilot payload builds took roughly 16–18 seconds; final runtime builds took roughly 10–18 seconds each on this host. These are observations, not time budgets or reproducibility claims.

## Distribution-packaged Engine catalogue

Each distribution has `docker-<distribution>-rootful` and `docker-<distribution>-rootless` images. These install the distribution's Docker or Moby packages with its own package manager, rather than the upstream static Engine archive. The AMD64 package-only builds on 2026-09-27 recorded these installed Engine package revisions; repositories may publish newer revisions on a subsequent build.

| Distribution | Native Engine package revision | `dockerd --version` Engine version |
| --- | --- | --- |
| Alpine 3.24 | `docker-29.5.3-r1` | `29.5.3` |
| Arch Linux | `docker 1:29.8.1-1` | `29.8.1` |
| Debian 11 | `docker.io 20.10.5+dfsg1-1+deb11u2` | `20.10.5+dfsg1` |
| Debian 12 | `docker.io 20.10.24+dfsg1-1+deb12u1+b6` | `20.10.24+dfsg1` |
| Debian 13 | `docker.io 26.1.5+dfsg1-9+deb13u1` | `26.1.5+dfsg1` |
| Fedora 43 | `moby-engine 29.6.2-1.fc43.x86_64` | `29.6.2` |
| Fedora 44 | `moby-engine 29.7.2-1.fc44.x86_64` | `29.7.2` |
| openSUSE Leap 16.0 | `docker 29.4.0_ce-160000.7.1.x86_64` | `29.4.0-ce` |
| openSUSE Tumbleweed | `docker 29.7.2_ce-41.1.x86_64` | `29.7.2-ce` |
| Ubuntu 22.04 | `docker.io 29.1.3-0ubuntu3~22.04.2` | `29.1.3` |
| Ubuntu 24.04 | `docker.io 29.1.3-0ubuntu3~24.04.2` | `29.1.3` |
| Ubuntu 26.04 | `docker.io 29.1.3-0ubuntu4.1` | `29.1.3` |

Debian 13 also installs its separate native `docker-cli` package. Debian 11 uses the signed archived Bullseye main repository: its live security index advertises `20.10.5+dfsg1-1+deb11u4`, but the corresponding package download returned HTTP 404 during this build, so the archived `+deb11u2` revision is the observed installed version. Both modes install the distribution's BusyBox package for the offline nested HTTP fixture. Rootless images additionally install the distribution's RootlessKit, `slirp4netns`, `fuse-overlayfs`, and subordinate-ID tools. Build evidence in each image records the package manager's selected source, the installed Engine package revision, the full installed package list, and the observed binary versions under `/usr/share/strukturpiloten/docker/`.

Both modes declare a separate Docker data-root volume and use only an internal Unix socket. Rootless runs as UID 1000 with subordinate UID/GID ranges and the distribution's RootlessKit. The AMD64 builds only prove package availability, installed binary provenance, and image construction. Daemon startup, API compatibility, nested workloads, and cleanup have **not** yet passed the native contract for these distribution images. Their ARM64 builds and native contract are pending CI admission; Arch requests AMD64 only because its official base image does not provide ARM64.
