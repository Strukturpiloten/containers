# Strukturpiloten Containers

This repository is the public monorepo for company-maintained container images.

## Concept

The detailed monorepo concept is documented in [docs/container-monorepo-concept.md](docs/container-monorepo-concept.md).

The short version:

- Each image lives in `images/<project>/<name>/` with its own `Containerfile`, `container.yaml`, README, and optional image-specific tests.
- `container.yaml` describes registry coordinates, build arguments, per-image OCI metadata, external dependencies, internal dependencies, and changed-file inputs.
- `container.schema.json` is the strict, editor-readable contract for every `container.yaml`; the Python validator adds dependency-graph and repository-policy checks.
- Static OCI label values shared across all images (`OCI_LICENSES`, `OCI_VENDOR`, `OCI_SOURCE`) are defined once in `shared/oci-labels.env`.
- GitHub Actions calculates a dependency graph from all `container.yaml` files, builds changed images in topological order, and includes reverse dependencies when an internal base image changes. Daily scheduled builds rebuild every image without cache; manual runs can target all images, one image, or one image family.
- Every build first publishes a unique immutable run tag. After signing and attestations succeed, push builds promote an immutable `sha-<git-sha>` tag plus mutable branch tags. Verified default-branch builds automatically create missing GitHub Releases from `container.yaml` and refresh the declared SemVer tags. OCI digests, run tags, and SHA tags remain the immutable identities.
- Renovate tracks digest-pinned external image references in `images/**/container.yaml`, tooling versions, and commit-pinned GitHub Actions. Helper binaries such as `install-php-extensions` are copied from digest-pinned build images so their version and integrity update together.

## Current Images

- [images/typo3/typo3-phpfpm](images/typo3/typo3-phpfpm) builds `ghcr.io/strukturpiloten/typo3-phpfpm` for `linux/amd64` and `linux/arm64`.
- [images/nextcloud/nextcloud-phpfpm](images/nextcloud/nextcloud-phpfpm) builds `ghcr.io/strukturpiloten/nextcloud-phpfpm` for `linux/amd64` and `linux/arm64`.
- [images/nextcloud/nextcloud-notifypush](images/nextcloud/nextcloud-notifypush) builds `ghcr.io/strukturpiloten/nextcloud-notifypush` for `linux/amd64` and `linux/arm64`.

## Automation

- [.github/workflows/publish-images.yml](.github/workflows/publish-images.yml) builds and publishes images with Buildah, Podman, and Skopeo. It signs images with Cosign, generates Syft SBOMs, publishes GitHub attestations, and automatically finalizes metadata-declared releases. The workflow is generated from [.github/workflow-templates/publish-images.yml.j2](.github/workflow-templates/publish-images.yml.j2) and image metadata so dependency stage jobs are not hand-written.
- [.github/workflows/ci.yml](.github/workflows/ci.yml) validates pull requests and smoke-builds affected architectures without registry write permissions. Its `Required CI` job is the stable repository-ruleset check.
- [.github/renovate.json](.github/renovate.json) tracks external container image digests in `container.yaml`, GitHub Actions pinned to commit SHAs, Syft, Cosign, and `install-php-extensions`.
- [scripts/container_engine.py](scripts/container_engine.py) validates image metadata and forward-only version changes, calculates dependency-aware build stages, generates the publish workflow, builds architecture archives, publishes manifests, and finalizes releases. Run it through `uv run --python 3.14 python -m scripts.container_engine`.

Consumers that need automatic maintenance should use a readable tag together with a digest, for example `v1.2.3@sha256:...`, and let Renovate update the digest. A running container still needs an explicit pull/redeploy or Podman auto-update policy after a tag moves.

Before opening a pull request, run:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```
