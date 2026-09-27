# Nextcloud PHP-FPM

`ghcr.io/strukturpiloten/nextcloud-phpfpm` is the shared PHP-FPM runtime for Strukturpiloten Nextcloud deployments. It supports AMD64 and ARM64.

## Included runtime

- PHP-FPM from the digest-pinned official Alpine-based PHP image;
- Composer and the PHP extensions declared in the Containerfile;
- ffmpeg, Git, Supercronic, CA certificates, and timezone data;
- the shared `check_variables_and_directories.sh` container utility.

The working directory is `/var/www/nextcloud`, PHP-FPM listens on port 9000, and the health check validates the PHP-FPM configuration. Application code, Nextcloud configuration, web-server configuration, cron definitions, and persistent data are supplied by the consuming stack.

## Build and updates

`container.yaml` is authoritative for the PHP runtime, extension-installer image, architectures, data path, and Strukturpiloten image version. Both external images are digest-pinned. Composer, APCu, Imagick, and Redis have exact versions in `container.yaml`; their Renovate updates require maintainer review and build validation. The image verifies their installed versions and records them, the installer image reference, and the installed Alpine package list under `/usr/share/strukturpiloten/`. Daily rebuilds refresh Alpine packages while retaining those application pins and the selected PHP base.

Use a maintained tag plus digest when the deployment should receive reviewed rebuilds. Pin only the digest when the artifact must remain byte-for-byte fixed.
