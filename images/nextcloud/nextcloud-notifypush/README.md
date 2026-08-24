# Nextcloud notify_push

`ghcr.io/strukturpiloten/nextcloud-notifypush` packages the Nextcloud `notify_push` server as a small, non-root runtime image for AMD64 and ARM64.

## Runtime contract

- The process runs as Alpine's unprivileged `guest` user (UID 405).
- The service listens on TCP port 7867.
- The default command is `/notify_push /nextcloud/config/config.php`.
- Mount the Nextcloud configuration so that the default path is readable, or replace the command with the required config path.

Example:

```sh
podman run --rm \
  --publish 7867:7867 \
  --volume ./nextcloud-config.php:/nextcloud/config/config.php:ro \
  ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
```

## Build and updates

The multi-stage build compiles the metadata-pinned upstream `notify_push` tag for the target musl architecture, then copies only the binary into a digest-pinned Alpine runtime. Git, Rust, and build artifacts are not present in the final image.

`container.yaml` is authoritative for the upstream version, builder, runtime base, architectures, and Strukturpiloten image version. Renovate proposes supported input updates, and the daily rebuild refreshes Alpine packages. Use a maintained tag plus digest for automated updates or a digest alone for an immutable artifact.
