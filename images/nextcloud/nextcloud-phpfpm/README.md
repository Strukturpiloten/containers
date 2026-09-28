# Nextcloud PHP-FPM

`ghcr.io/strukturpiloten/nextcloud-phpfpm` is the shared PHP-FPM runtime for Strukturpiloten Nextcloud deployments. It supports AMD64 and ARM64.

## Included runtime

- PHP-FPM from the digest-pinned official Alpine-based PHP image;
- Composer and the PHP extensions declared in the Containerfile;
- ffmpeg, Git, Supercronic, CA certificates, and timezone data;
- the shared `check_variables_and_directories.sh` container utility.

The working directory is `/var/www/nextcloud`, PHP-FPM listens on port 9000, and CI sends a real FastCGI request to the running PHP-FPM service. For an orchestrator liveness probe, run `php -r '$s = @fsockopen("127.0.0.1", 9000, $errno, $error, 2); if (!$s) exit(1); fclose($s);'` inside the container. Container stop sends SIGQUIT for graceful shutdown. Application code, Nextcloud configuration, web-server configuration, cron definitions, and persistent data are supplied by the consuming stack.

## Stack integration

Mount your existing Nextcloud application at `/var/www/nextcloud` and connect a web server to PHP-FPM on the private container network at port 9000. For a basic runtime check with application files already present in `./nextcloud`:

```sh
podman run --rm --detach --name nextcloud-phpfpm \
  --volume ./nextcloud:/var/www/nextcloud:ro \
  ghcr.io/strukturpiloten/nextcloud-phpfpm:v1.0.0
podman exec nextcloud-phpfpm php -r '$s = @fsockopen("127.0.0.1", 9000, $errno, $error, 2); if (!$s) exit(1); fclose($s);'
podman stop nextcloud-phpfpm
```

This checks PHP-FPM startup only. A real Nextcloud deployment also needs its application-writable directories and persistent data mounted with suitable permissions, a web server, database, Redis if configured, and separate cron scheduling. Do not publish FastCGI port 9000 directly to the internet. The image version describes this PHP runtime contract; inspect `/usr/share/strukturpiloten/application-components.txt` and the SBOM for installed versions.

## Build and updates

`container.yaml` is authoritative for the PHP runtime, extension-installer image, architectures, data path, and Strukturpiloten image version. Both external images are digest-pinned. Composer, APCu, Imagick, and Redis have exact versions in `container.yaml`; their Renovate updates require maintainer review and build validation. The image verifies their installed versions and records them, the installer image reference, and the installed Alpine package list under `/usr/share/strukturpiloten/`. Daily rebuilds refresh Alpine packages while retaining those application pins and the selected PHP base.

Use a maintained tag plus digest when the deployment should receive reviewed rebuilds. Pin only the digest when the artifact must remain byte-for-byte fixed.
