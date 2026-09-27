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

The multi-stage build verifies the metadata-pinned upstream `notify_push` tag against its immutable commit, requires the upstream `Cargo.lock` with `cargo build --locked`, and compiles for the target musl architecture. Git, Rust, and build artifacts are absent from the final image. The image keeps `/usr/share/strukturpiloten/application-components.txt` with the upstream commit, lockfile hash, and actual Rust/Cargo versions; its build and runtime Alpine package lists are beside it.

`container.yaml` is authoritative for the paired upstream version and commit, builder, runtime base, architectures, and Strukturpiloten image version. Renovate proposes a version and commit together. Daily rebuilds refresh Alpine packages without silently moving the application source or locked Rust dependencies. Use a maintained tag plus digest for automated updates or a digest alone for an immutable artifact.
