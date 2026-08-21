# Container monorepo concept

This document describes a public monorepo for Strukturpiloten container images. The repository should become the single source for reusable company container images, while product or stack repositories, for example `typo3-container`, consume released images by immutable tags and digests.

The first image to move into this repository is `typo3-phpfpm` from `typo3-container/compose/typo3-phpfpm/typo3-phpfpm`.

## Goals

- Keep every reusable container image in one public repository.
- Build multi-architecture OCI images for `linux/amd64` and `linux/arm64`.
- Publish images to GitHub Container Registry under `ghcr.io/strukturpiloten/<image>`.
- Support internal image dependencies, for example one image based on PHP and another image based on the previously built PHP image.
- Build images in dependency order and pass freshly built internal image digests to dependent builds.
- Keep Renovate updates working for base images, GitHub Actions, and build tooling.

## Existing workflow in `typo3-container`

The current `typo3-container` repository already has a good baseline for secure image publishing:

- `publish-images.yml` builds one image for `amd64` and `arm64` with Buildah, exports per-architecture OCI archives, combines them into a multi-arch manifest, and pushes `sha-<commit>`, branch, and `latest` tags.
- Scheduled and manually dispatched builds use `--no-cache`; normal push builds use `--pull-always`.
- Published images are inspected with Skopeo to resolve the index digest and per-architecture digests.
- Syft generates per-architecture SBOMs.
- Cosign signs the image digest.
- GitHub artifact attestations record provenance and attach SBOM attestations.
- Renovate tracks pinned image tags and digests in `.env.tmpl`, TYPO3 package versions, `install-php-extensions`, Syft, Cosign, `container-setup`, and GitHub Actions.

The monorepo should keep the secure build pieces, but replace single-image assumptions with image metadata, change detection, dependency graph planning, and per-image builds.

## Repository layout

Recommended layout:

```text
containers/
  README.md
  LICENSE
  container.schema.json
  docs/
    container-monorepo-concept.md
  images/
    php-base/
      container.yaml
      Containerfile
      README.md
    typo3/
      typo3-phpfpm/
        container.yaml
        Containerfile
        README.md
        rootfs/
        tests/
  shared/
    container-utilities/
      shell/
        check_variables_and_directories.sh
  scripts/
    container_engine.py
  pyproject.toml
  uv.lock
  .containerignore
  .github/
    renovate.json
    workflows/
      ci.yml
      publish-images.yml
      release-image.yml
  tests/
```

`images/<family>/<name>` owns one public image. Its `Containerfile`, image-specific documentation, tests, fixtures, and optional root filesystem files live together.

`shared/` contains files used by multiple images. For `typo3-phpfpm`, the current `deps/container-utilities/shell/check_variables_and_directories.sh` should move or be mirrored to `shared/container-utilities/shell/check_variables_and_directories.sh` so the monorepo build context can remain the repository root.

`scripts/` contains workflow logic that is too complex for inline YAML. Complex scripting should be Python, executed through `uv`, and checked with `ruff`. Reusable commands should be exposed as Python modules such as `uv run --python 3.14 python -m scripts.container_engine ...`; shell should be limited to short composite-action install steps.

`.containerignore` keeps the build context small and prevents development files, workflow files, documentation, logs, and generated artifacts from being sent to the builder.

## Image metadata

Every image should have an `images/<family>/<name>/container.yaml` file. The workflows use this file to validate the image, plan builds, and determine dependency order.

`container.schema.json` is the strict metadata contract. Each metadata file includes a YAML language-server schema comment for editor feedback. Repository validation additionally enforces unique names and registry references, dependency mappings, build-input coverage, final runtime-base selection, and an acyclic dependency graph.

Static OCI label values that are shared across all images (`OCI_LICENSES`, `OCI_VENDOR`, `OCI_SOURCE`) are defined once in `shared/oci-labels.env` and loaded by the build script for every image. Per-image metadata only needs to define `title` and `description`.

Example for the first migrated image:

```yaml
name: typo3-phpfpm
image: ghcr.io/strukturpiloten/typo3-phpfpm
title: TYPO3 PHP-FPM
description: TYPO3 PHP-FPM runtime image with TYPO3 extensions and container utilities

build:
  context: ../..
  containerfile: Containerfile
  architectures:
    - amd64
    - arm64
  runtimeBaseArg: PODMAN_TYPO3PHPFPM_BASE_IMAGE
  args:
    PODMAN_TYPO3PHPFPM_BASE_IMAGE:
      value: docker.io/php:8.5.7-fpm-alpine3.22@sha256:95588bfaf1b890e3fc1f308a0a23539c4f03ce28a4fc770473ae3899d6669777
      type: external-image
    PODMAN_TYPO3_DATA_DIR_CONTAINER:
      value: /var/www/typo3
      type: static

dependencies:
  internal: []
  external:
    - name: php
      image: docker.io/php
      arg: PODMAN_TYPO3PHPFPM_BASE_IMAGE

inputs:
  - images/typo3/typo3-phpfpm/**
  - shared/container-utilities/**
  - scripts/container_engine.py
  - .github/workflows/publish-images.yml
```

For images based on another image from the same repository, use `dependencies.internal`:

```yaml
build:
  runtimeBaseArg: BASE_IMAGE
  args:
    BASE_IMAGE:
      value: ghcr.io/strukturpiloten/php-base@sha256:<released-fallback-digest>
      type: internal-image

dependencies:
  internal:
    - image: php-base
      arg: BASE_IMAGE
  external: []
```

The build planner resolves `php-base` first, reads its freshly published digest, and passes `BASE_IMAGE=ghcr.io/strukturpiloten/php-base@sha256:<digest>` into dependent builds. If only the dependent image is selected, the digest-pinned `internal-image` value is the released fallback. Dependent images never use mutable internal tags.

## First migration: `typo3-phpfpm`

Move the current image recipe from `typo3-container` into:

```text
images/typo3/typo3-phpfpm/Containerfile
```

The current `Dockerfile`-style recipe can stay almost unchanged. The main adjustments are:

- Rename the file to `Containerfile` for conventional OCI image repositories.
- Keep the repository root as build context so shared files can be copied from `shared/`.
- Change `COPY deps/container-utilities/...` to `COPY shared/container-utilities/...` after the shared utilities are moved.
- Keep `PODMAN_TYPO3PHPFPM_BASE_IMAGE` as a build argument in `container.yaml` so Renovate and the build planner can manage it.
- Keep OCI labels, but set `OCI_SOURCE`, `OCI_DOCUMENTATION`, and `OCI_URL` to the `containers` repository.

After the move, `typo3-container` should become a consumer of `ghcr.io/strukturpiloten/typo3-phpfpm:<version>@sha256:<digest>`. Its local build option can be removed later, or kept temporarily for development while the prebuilt image is the default.

## Build process

The generated `publish-images.yml` workflow is responsible for image publishing on `main`, manual dispatch, and scheduled rebuilds. Its dependency stage jobs are generated from the current `dependencies.internal` graph, so the repository does not maintain a separate hard-coded stage count.

Jobs:

1. `plan`

   - Parse and validate all `images/**/container.yaml` files.
   - Determine changed files with `git diff` for pushes.
   - Match changed files against each image's `inputs` list.
   - On scheduled rebuilds, select all images.
   - Expand the selected set to include reverse internal dependencies when an internal base image is selected.
   - Topologically sort selected images by `dependencies.internal`.
   - Emit a JSON build plan with stages, images, architectures, and build args.

2. `build-arch-image`

   - Build each selected image for each architecture with Buildah.
   - Use `--pull-always` for all builds.
   - Use `--no-cache` for scheduled builds and manual forced rebuilds.
   - Export per-architecture OCI archives as short-lived artifacts.

3. `publish-image`

   - Download architecture archives.
   - Create a multi-arch manifest with Podman.
   - Publish a unique immutable `run-<run-id>-<attempt>-sha-<commit>` tag as the verification source.

4. `inspect-sign-attest`

   - Resolve the index digest and per-architecture digests with Skopeo.
   - Generate per-architecture SBOMs with Syft.
   - Sign the index digest with Cosign.
   - Attach provenance and SBOM attestations.
   - Only after verification succeeds, promote the immutable `sha-<commit>` tag and mutable branch tag. For `main`, also promote `latest`.
   - Refuse to overwrite an existing SHA tag. Scheduled and manual rebuilds only move mutable branch/default tags and retain their unique run tag.
   - Write one result artifact per image containing its exact index and architecture digests. Later dependency stages consume these results as `image@sha256:...` references.

The important part is that the build planner owns dependency order. GitHub Actions matrices can build independent images in parallel, but images in later dependency stages must wait for earlier stages so they can consume exact internal digests. Because GitHub Actions `needs` relationships are static YAML, the workflow file is generated and checked in. The generator computes the required number of dependency stages from image metadata and renders `.github/workflow-templates/publish-images.yml.j2` with Jinja2.

Regenerate and check the workflow with:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

## Build order and dependency graph

Each image is a node in a directed graph. `dependencies.internal` creates edges.

Example:

```text
php-base
  -> typo3-phpfpm
      -> typo3-cli
```

The planner produces stages like this:

```json
[
  ["php-base"],
  ["typo3-phpfpm"],
  ["typo3-cli"]
]
```

Images in the same stage can build in parallel. The next stage starts only after all required upstream images were published and their digests were resolved.

When `php-base` is rebuilt, `typo3-phpfpm` and `typo3-cli` should also be selected because their effective base image changed. When only `typo3-cli` changes, `php-base` and `typo3-phpfpm` do not need to rebuild.

If a cycle is configured, for example `a -> b -> a`, validation fails before any build starts.

## Renovate in the monorepo

Renovate should live at `.github/renovate.json` in the monorepo. It should keep the existing policies from `typo3-container` and add monorepo-aware managers.

Recommended Renovate behavior:

- Continue extending `config:recommended` and `helpers:pinGitHubActionDigests`.
- Keep GitHub Actions pinned to commit digests and allow Renovate to update them.
- Track external image references in `images/**/container.yaml` and optionally in `images/**/Containerfile`.
- Track the digest-pinned `php-extension-installer` build image in `container.yaml` so the helper version and integrity update together.
- Track Syft and Cosign versions in workflows.
- Automerge digest updates for external container images.
- Automerge patch and minor updates for selected tooling, matching the current policy.
- Do not use Renovate to update internal image dependencies during the same monorepo build. The build planner should inject internal digests.

## Local development

The scripts used by the workflows should also work locally. A developer should be able to run:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine plan --event-name workflow_dispatch --ref-name main --default-branch main --sha "$(git rev-parse HEAD)" --output build-plan.json
uv run --frozen --python 3.14 python -m scripts.container_engine build-arch-image --plan build-plan.json --entry-json '{"name":"typo3-phpfpm","arch":"amd64"}' --output-dir /tmp/oci-archives
```

Local builds can tag images as `localhost/<image>:dev` and should not sign, attest, or publish unless explicit flags are passed.

## Open implementation decisions

- Whether scheduled rebuilds should select all images or only images with an explicit `build.scheduled: true` flag.
- Whether shared utilities should be copied into this monorepo or kept as a submodule under `shared/container-utilities`.

## Per-image versioning and releases

Each image has its own independent SemVer version, tracked in the `version` field of its `container.yaml`. This allows releasing one image without affecting others, for example bumping `nextcloud-notifypush` from `0.1.0` to `0.2.0` after a Rust base image update without releasing new `nextcloud-phpfpm` or `typo3-phpfpm` versions.

### Tag strategy

| Tag type                              | Example                       | Mutability | When pushed                            |
| ------------------------------------- | ----------------------------- | ---------- | -------------------------------------- |
| `run-<id>-<attempt>-sha-<commit>`     | `run-42-1-sha-a1b2c3...`     | immutable  | Every build attempt                    |
| `sha-<commit>`                        | `sha-a1b2c3...`               | immutable  | Verified push build; never overwritten |
| `<branch>`                            | `main`                        | mutable    | Verified builds for that branch        |
| `latest`                              | `latest`                      | mutable    | Verified default-branch builds         |
| `v<major>.<minor>.<patch>[-<suffix>]` | `v1.2.3` or `v1.2.3-rc.1`    | immutable  | Release workflow                       |
| `v<major>.<minor>`                    | `v1.2`                        | mutable    | Stable release workflow only           |
| `v<major>`                            | `v1`                          | mutable    | Stable release workflow only           |

### Release workflow

Releases use a two-phase process so the registry image, OCI labels, Git commit, Git tag, and GitHub Release all identify the same build:

1. Change the image's `version` in `container.yaml` through a pull request and merge it to the default branch.
2. `publish-images.yml` builds that commit, verifies it, and promotes its immutable `sha-<commit>` snapshot with matching revision and version labels.
3. Trigger `release-image.yml` from the default branch with the image name, already-merged version, and full source commit SHA. The source commit must be part of the default branch.
4. The workflow resolves only `sha-<source-commit>`, verifies its digest and OCI revision/version labels, and refuses to overwrite an existing exact SemVer tag.
5. Stable releases promote `v<x.y.z>`, `v<x.y>`, and `v<x>`; prereleases promote only their exact prerelease tag.
6. GitHub creates `<image>/v<x.y.z>` at the same commit together with the GitHub Release.

Git tags are prefixed with the image name (`<image>/v<x.y.z>`) to avoid collisions between independent image release lines.

### Consumer pinning

Consumer repositories (for example `typo3-container`, `nextcloud`) should always reference images with both a version tag and a digest:

```text
ghcr.io/strukturpiloten/typo3-phpfpm:v1.2.3@sha256:<digest>
```

The version tag provides readability, the digest guarantees immutability.

### Renovate interaction

Renovate manages dependency updates (base images, GitHub Actions, tooling), not image versions. When Renovate updates a base image in `container.yaml`:

1. Renovate creates a PR with the updated base image reference.
2. Digest and minor/patch updates are automerged per the existing Renovate rules.
3. Pull-request CI validates the update before merge.
4. After merge, `publish-images.yml` rebuilds the affected image and its reverse dependencies, then promotes verified snapshot and mutable tags.
5. A human changes `container.yaml` through a pull request when a new company image version should be released, waits for its immutable snapshot, and then invokes `release-image.yml`.

Renovate does not create issues or PRs for image version bumps. Version bumps are a manual, deliberate decision.
