# Strukturpiloten Containers

This repository is the public monorepo for company-maintained container images.

## Concept

The detailed monorepo concept is documented in [docs/container-monorepo-concept.md](docs/container-monorepo-concept.md).

The short version:

- Each image lives in `images/<project>/<name>/` with its own `Containerfile`, `container.yaml`, README, and tests.
- `container.yaml` describes registry coordinates, build arguments, per-image OCI metadata, external dependencies, internal dependencies, and changed-file inputs.
- Static OCI label values shared across all images (`OCI_LICENSES`, `OCI_VENDOR`, `OCI_SOURCE`) are defined once in `shared/oci-labels.env`.
- GitHub Actions should calculate a dependency graph from all `container.yaml` files, build changed images in topological order, and include reverse dependencies when an internal base image changes.
- Snapshot builds publish immutable `sha-<git-sha>` tags and the current branch tag. The `latest` tag is reserved for the default branch.
- Renovate should track external image references in `images/**/container.yaml`, tooling versions in workflows, GitHub Actions digests, and image-specific Containerfile dependencies such as `INSTALL_PHP_EXTENSIONS_VERSION`.

## Current Images

- [images/typo3/typo3-phpfpm](images/typo3/typo3-phpfpm) builds `ghcr.io/strukturpiloten/typo3-phpfpm` for `linux/amd64` and `linux/arm64`.

## Automation

- [.github/workflows/publish-images.yml](.github/workflows/publish-images.yml) builds and publishes images with Buildah, Podman, and Skopeo. It also signs images with Cosign, generates Syft SBOMs, and publishes GitHub attestations. The workflow is generated from [.github/workflow-templates/publish-images.yml.j2](.github/workflow-templates/publish-images.yml.j2) and image metadata so dependency stage jobs are not hand-written.
- [.github/renovate.json](.github/renovate.json) tracks external container image digests in `container.yaml`, GitHub Actions pinned to commit SHAs, Syft, Cosign, and `install-php-extensions`.
- [scripts/container_engine.py](scripts/container_engine.py) validates image metadata, calculates dependency-aware build stages, generates the publish workflow, builds architecture archives, publishes manifests, and emits GitHub Actions outputs. Run it through `uv run --python 3.14 python -m scripts.container_engine`.
