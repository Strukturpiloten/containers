# TYPO3 PHP-FPM

TYPO3 PHP-FPM runtime image with TYPO3 extensions and Strukturpiloten container utilities.

The image is built from [Containerfile](Containerfile) and published as:

```text
ghcr.io/strukturpiloten/typo3-phpfpm
```

The current external base image is declared in [container.yaml](container.yaml) so Renovate and the GitHub Actions workflow can update and build from the same source of truth.

The monorepo-managed release line starts at `v2.0.0`. Historical `v1.*` tags belong to the former TYPO3 image repository and are not modified by this automation.
