# TYPO3 PHP-FPM

`ghcr.io/strukturpiloten/typo3-phpfpm` is the shared PHP-FPM runtime for Strukturpiloten TYPO3 deployments. It supports AMD64 and ARM64.

## Included runtime

- PHP-FPM from the digest-pinned official Alpine-based PHP image;
- Composer and the TYPO3-oriented PHP extensions declared in the Containerfile;
- Git, Supercronic, CA certificates, and timezone data;
- the shared `check_variables_and_directories.sh` container utility.

The working directory is `/var/www/typo3`, PHP-FPM listens on port 9000, and the health check validates the PHP-FPM configuration. TYPO3 source, site configuration, web-server configuration, cron definitions, and persistent data are supplied by the consuming stack.

## Versions and updates

`container.yaml` is authoritative for the PHP runtime, extension-installer image, architectures, data path, and Strukturpiloten image version. Both external images are digest-pinned. Renovate proposes supported updates, and the daily rebuild refreshes Alpine packages and PHP extensions against the selected PHP base.

The monorepo-owned release line starts at `v2.0.0`. Historical `v1.*` tags belong to the former TYPO3 image repository and are not modified by this automation.

Use a maintained tag plus digest when the deployment should receive reviewed rebuilds. Pin only the digest when the artifact must remain byte-for-byte fixed.
