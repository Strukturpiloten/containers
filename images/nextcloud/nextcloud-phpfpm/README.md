# Nextcloud PHP-FPM

Nextcloud PHP-FPM runtime image with PHP extensions, ffmpeg and Strukturpiloten container utilities.

The image is built from [Containerfile](Containerfile) and published as:

```text
ghcr.io/strukturpiloten/nextcloud-phpfpm
```

The current external base image is declared in [container.yaml](container.yaml) so Renovate and the GitHub Actions workflow can update and build from the same source of truth.
