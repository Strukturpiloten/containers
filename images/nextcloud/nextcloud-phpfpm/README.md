# Nextcloud PHP-FPM

`ghcr.io/strukturpiloten/nextcloud-phpfpm` is the shared PHP-FPM runtime for Strukturpiloten Nextcloud deployments. It supports AMD64 and ARM64.

## Included runtime

- PHP-FPM from the digest-pinned official Alpine-based PHP image;
- Composer and the PHP extensions declared in the Containerfile;
- ffmpeg, Git, Supercronic, CA certificates, and timezone data;
- the shared `check_variables_and_directories.sh` container utility.

The working directory is `/var/www/nextcloud`, PHP-FPM listens on port 9000, and the health check validates the PHP-FPM configuration. Application code, Nextcloud configuration, web-server configuration, cron definitions, and persistent data are supplied by the consuming stack.

## Build and updates

`container.yaml` is authoritative for the PHP runtime, extension-installer image, architectures, data path, and Strukturpiloten image version. Both external images are digest-pinned. Renovate proposes supported updates, and the daily rebuild refreshes Alpine packages and PHP extensions against the selected PHP base.

Use a maintained tag plus digest when the deployment should receive reviewed rebuilds. Pin only the digest when the artifact must remain byte-for-byte fixed.
