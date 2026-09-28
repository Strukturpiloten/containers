# TYPO3 PHP-FPM

`ghcr.io/strukturpiloten/typo3-phpfpm` is the shared PHP-FPM runtime for Strukturpiloten TYPO3 deployments. It supports AMD64 and ARM64.

## Included runtime

- PHP-FPM from the digest-pinned official Alpine-based PHP image;
- Composer and the TYPO3-oriented PHP extensions declared in the Containerfile;
- Git, Supercronic, CA certificates, and timezone data;
- the shared `check_variables_and_directories.sh` container utility.

The working directory is `/var/www/typo3`, PHP-FPM listens on port 9000, and CI sends a real FastCGI request to the running PHP-FPM service. For an orchestrator liveness probe, run `php -r '$s = @fsockopen("127.0.0.1", 9000, $errno, $error, 2); if (!$s) exit(1); fclose($s);'` inside the container. Container stop sends SIGQUIT for graceful shutdown. TYPO3 source, site configuration, web-server configuration, cron definitions, and persistent data are supplied by the consuming stack.

## Stack integration

Mount your existing TYPO3 project at `/var/www/typo3` and connect a web server to PHP-FPM on the private container network at port 9000. For a basic runtime check with project files already present in `./typo3`:

```sh
podman run --rm --detach --name typo3-phpfpm \
  --volume ./typo3:/var/www/typo3:ro \
  ghcr.io/strukturpiloten/typo3-phpfpm:v2.0.0
podman exec typo3-phpfpm php -r '$s = @fsockopen("127.0.0.1", 9000, $errno, $error, 2); if (!$s) exit(1); fclose($s);'
podman stop typo3-phpfpm
```

This checks PHP-FPM startup only. A real TYPO3 deployment needs its project-writable directories and persistent data mounted with suitable permissions, plus a web server, database, site configuration, and separate scheduler or cron setup. Do not publish FastCGI port 9000 directly to the internet. The image version describes this PHP runtime contract; it is not a TYPO3 application version. Inspect `/usr/share/strukturpiloten/application-components.txt` and the SBOM for installed versions.

For an existing application project, the [Compose integration guide](../../../docs/application-compose.md) explains how to adapt private FastCGI networking, mounts, and image digest updates. Follow the [artifact verification guide](../../../docs/verify-artifacts.md) before promoting a reviewed digest.

## Versions and updates

`container.yaml` is authoritative for the PHP runtime, extension-installer image, architectures, data path, and Strukturpiloten image version. Both external images are digest-pinned. Composer, APCu, Imagick, and Redis have exact versions in `container.yaml`; their Renovate updates require maintainer review and build validation. The image verifies their installed versions and records them, the installer image reference, and the installed Alpine package list under `/usr/share/strukturpiloten/`. Daily rebuilds refresh Alpine packages while retaining those application pins and the selected PHP base.

The monorepo-owned release line starts at `v2.0.0`. Historical `v1.*` tags belong to the former TYPO3 image repository and are not modified by this automation.

Use a maintained tag plus digest when the deployment should receive reviewed rebuilds. Pin only the digest when the artifact must remain byte-for-byte fixed.
