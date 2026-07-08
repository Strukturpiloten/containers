# Nextcloud notify_push

Nextcloud notify_push binary built from source with a minimal Alpine runtime.

The image is built from [Containerfile](Containerfile) and published as:

```text
ghcr.io/strukturpiloten/nextcloud-notifypush
```

The current external base images are declared in [container.yaml](container.yaml) so Renovate and the GitHub Actions workflow can update and build from the same source of truth.
