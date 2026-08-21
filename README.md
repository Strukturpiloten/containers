# Strukturpiloten Containers

This repository is the public monorepo for company-maintained container images.

## Concept

The detailed monorepo concept is documented in [docs/container-monorepo-concept.md](docs/container-monorepo-concept.md).

The short version:

- Each image lives in `images/<project>/<name>/` with its own `Containerfile`, `container.yaml`, README, and optional image-specific tests.
- `container.yaml` describes registry coordinates, build arguments, per-image OCI metadata, external dependencies, internal dependencies, and changed-file inputs.
- `container.schema.json` is the strict, editor-readable contract for every `container.yaml`; the Python validator adds dependency-graph and repository-policy checks.
- Static OCI label values shared across all images (`OCI_LICENSES`, `OCI_VENDOR`, `OCI_SOURCE`) are defined once in `shared/oci-labels.env`.
- GitHub Actions should calculate a dependency graph from all `container.yaml` files, build changed images in topological order, and include reverse dependencies when an internal base image changes.
- Every build first publishes a unique immutable run tag. After signing and attestations succeed, push builds promote an immutable `sha-<git-sha>` tag plus the mutable branch tag; `latest` is reserved for the default branch. Scheduled rebuilds never overwrite SHA tags.
- Renovate tracks digest-pinned external image references in `images/**/container.yaml`, tooling versions, and commit-pinned GitHub Actions. Helper binaries such as `install-php-extensions` are copied from digest-pinned build images so their version and integrity update together.

## Current Images

- [images/typo3/typo3-phpfpm](images/typo3/typo3-phpfpm) builds `ghcr.io/strukturpiloten/typo3-phpfpm` for `linux/amd64` and `linux/arm64`.
- [images/nextcloud/nextcloud-phpfpm](images/nextcloud/nextcloud-phpfpm) builds `ghcr.io/strukturpiloten/nextcloud-phpfpm` for `linux/amd64` and `linux/arm64`.
- [images/nextcloud/nextcloud-notifypush](images/nextcloud/nextcloud-notifypush) builds `ghcr.io/strukturpiloten/nextcloud-notifypush` for `linux/amd64` and `linux/arm64`.

## Automation

- [.github/workflows/publish-images.yml](.github/workflows/publish-images.yml) builds and publishes images with Buildah, Podman, and Skopeo. It also signs images with Cosign, generates Syft SBOMs, and publishes GitHub attestations. The workflow is generated from [.github/workflow-templates/publish-images.yml.j2](.github/workflow-templates/publish-images.yml.j2) and image metadata so dependency stage jobs are not hand-written.
- [.github/workflows/ci.yml](.github/workflows/ci.yml) validates pull requests without registry write permissions.
- [.github/workflows/release-image.yml](.github/workflows/release-image.yml) promotes a selected immutable SHA snapshot built from an already-merged version commit to SemVer tags and a GitHub Release. It never releases from `latest` and does not modify repository files.
- [.github/renovate.json](.github/renovate.json) tracks external container image digests in `container.yaml`, GitHub Actions pinned to commit SHAs, Syft, Cosign, and `install-php-extensions`.
- [scripts/container_engine.py](scripts/container_engine.py) validates image metadata, calculates dependency-aware build stages, generates the publish workflow, builds architecture archives, publishes manifests, and emits GitHub Actions outputs. Run it through `uv run --python 3.14 python -m scripts.container_engine`.

Before opening a pull request, run:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```
