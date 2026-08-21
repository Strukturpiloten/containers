# Podman images

This family publishes separate rootful and rootless nested-container images for every Podman line from 5.4 through 6.1. All images use Fedora Minimal 44, build Podman from an immutable upstream Git commit, and support `linux/amd64` and `linux/arm64`.

## Build design

The shared Containerfile uses a named builder stage for the Go and Rust toolchains and copies only Podman and the Podman 6 networking helpers into a clean Fedora runtime stage. Podman, Netavark, and Aardvark DNS sources are pinned to configured Git commits and checked during the build. The Fedora base is digest-pinned, package caches are removed in the layer that creates them, and the final images contain no compiler toolchain.

There is deliberately no separately published `podman-base` image. It would become another public image that needs releases and security maintenance, would not remove the per-version Podman compilation, and would make the initial pull request depend on a package that cannot exist until after the first merge. The shared multi-stage recipe gives all variants the same runtime without creating a repository-internal image dependency, so every image remains in workflow stage 0.

Fedora packages are upgraded during every build. The build workflow runs daily so mutable release tags receive current Fedora security fixes.

## Runtime contract

Nested Podman changes kernel namespaces, mounts, cgroups, and networking. Start with the reduced-privilege invocation for the selected mode.

Rootless Podman runs as UID/GID 1000 and needs FUSE storage, an SELinux-label exception on SELinux hosts, unprivileged user namespaces, and its own persistent storage:

```sh
podman run --rm \
  --device /dev/fuse \
  --security-opt label=disable \
  --volume podman-6-1-rootless-storage:/home/podman/.local/share/containers \
  ghcr.io/strukturpiloten/podman-6.1-rootless:v6.1.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootless
```

Rootful Podman additionally needs `SYS_ADMIN` and `MKNOD`:

```sh
podman run --rm \
  --cap-add SYS_ADMIN \
  --cap-add MKNOD \
  --device /dev/fuse \
  --security-opt label=disable \
  --volume podman-6-1-rootful-storage:/var/lib/containers \
  ghcr.io/strukturpiloten/podman-6.1-rootful:v6.1.0 \
  podman run --rm quay.io/libpod/alpine:latest echo nested-rootful
```

`SYS_ADMIN` is a broad capability, and disabling SELinux labeling reduces isolation. If the host runtime or kernel still prevents nested operation, `--privileged` is the compatibility fallback, not the default recommendation. It grants the outer container broad host access and should only be used with trusted images on controlled hosts.

Never share one storage volume between Podman versions or between rootful and rootless images. Rootless refers to the Podman process inside the outer container; it does not make an outer `--privileged` invocation safe.

Docker can run these images on Linux hosts by replacing the outer `podman run` with `docker run` and keeping the equivalent flags. Podman itself still runs the nested containers; it does not use the Docker daemon as its engine. Docker Desktop and non-Linux hosts depend on their Linux VM exposing the required kernel features and `/dev/fuse`, so they are not guaranteed environments for these images.

The default nested configuration uses host namespaces and disables cgroup management because no init system runs inside the image. Resource limits and systemd/Quadlet workloads therefore need an explicit cgroup/systemd configuration. Override `/etc/containers/containers.conf` when stricter namespace isolation or a different cgroup setup is required.

Tags such as `v6.1.0`, `v6.1`, and `v6` are maintained release channels and can move after a daily rebuild. Pin the published `sha256:` manifest digest when an immutable deployment is required.

## Lifecycle

The daily build refreshes Fedora packages and maintained tags, but it cannot add upstream Podman fixes to a line that no longer receives releases. Upstream currently supports the latest release and the 5.8 line for critical fixes through June 2027. Use 6.1 for new deployments. The other lines are compatibility images and should be upgraded as soon as the consuming workload permits.
