# Getting started

## Find an image and check its evidence

Use the [complete catalogue](image-catalogue.md) to choose an image name, then read its family guide and image metadata under `images/<family>/<image>/container.yaml`. The metadata declares the version, architecture, lifecycle state, intended admission, and runtime profile. The generated catalogue may show `unknown` for build, registry, or runtime coverage when matching evidence was not supplied. Confirm a published digest and [maintenance evidence](maintenance-evidence.md) before relying on it.

Images use `ghcr.io/strukturpiloten/<image-name>`. Public GHCR packages usually pull anonymously; if a pull returns an authorization error, check package visibility and access before assuming the image is absent. For a known published reference, inspect the registry index digest:

```sh
skopeo inspect --format '{{.Digest}}' docker://ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
podman pull ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
podman image inspect ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
```

Use the returned `sha256:` index digest in a deployment reference and verify that it matches the release's maintenance evidence. A pull of a mutable tag on another day can resolve to a different digest. See [tags and versions](tags-and-versions.md).

## Run a simple service example

The notify_push image starts as an unprivileged user on port 7867. It needs a readable Nextcloud configuration and working Nextcloud, database, and Redis services for real push delivery:

```sh
podman run --rm --publish 7867:7867 \
  --volume ./nextcloud-config.php:/nextcloud/config/config.php:ro \
  ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
```

This is a startup example, not a complete Nextcloud installation. Consult the [notify_push guide](../images/nextcloud/nextcloud-notifypush/README.md) and [choosing images](choosing-images.md) for stack requirements. The PHP-FPM images likewise need application source, a web server, configuration, and persistent data supplied by your stack.

## Inspect a compatibility image

Docker and Podman compatibility images are for isolated tests on a suitable Linux runner. Inspecting a packaged CLI is a low-impact first check:

```sh
podman run --rm ghcr.io/strukturpiloten/podman-debian-12-rootful:v1.0.0 podman --version
podman run --rm ghcr.io/strukturpiloten/docker-debian-12-rootful:v1.0.0 dockerd --version
```

Nested container workloads need the privileged outer runtime, `/dev/fuse`, isolation, and storage separation described in the [Podman](../images/podman/README.md#running-nested-podman) and [Docker](../images/docker/README.md#runtime-modes-and-admission) guides. Rootless inside a privileged outer container does not make the runner unprivileged. Some Podman rootless profiles deliberately exclude the nested workload check, and Debian 11 Docker rootless needs `--oom-score-adj=0` on its outer container. Check the image's runtime evidence before choosing it for a test.
