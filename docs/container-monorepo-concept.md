# Container monorepo concept

This document describes a public monorepo for Strukturpiloten container images. The repository should become the single source for reusable company container images, while product or stack repositories, for example `typo3-container`, consume released images by immutable tags and digests.

The first image to move into this repository is `typo3-phpfpm` from `typo3-container/compose/typo3-phpfpm/typo3-phpfpm`.

## Goals

- Keep every reusable container image in one public repository.
- Build multi-architecture OCI images for `linux/amd64` and `linux/arm64`.
- Publish images to GitHub Container Registry under `ghcr.io/strukturpiloten/<image>`.
- Support internal image dependencies, for example one image based on PHP and another image based on the previously built PHP image.
- Build images in dependency order and pass freshly built internal image digests to dependent builds.
- Release only images that were actually rebuilt and whose release candidate digest differs from the last released digest.
- Keep independent version and release lines per image.
- Keep Renovate updates working for base images, GitHub Actions, build tooling, and release branches.

## Existing workflow in `typo3-container`

The current `typo3-container` repository already has a good baseline for secure image publishing:

- `publish-images.yml` builds one image for `amd64` and `arm64` with Buildah, exports per-architecture OCI archives, combines them into a multi-arch manifest, and pushes `sha-<commit>`, branch, and `latest` tags.
- Scheduled and manually dispatched builds use `--no-cache`; normal push builds use `--pull-always`.
- Published images are inspected with Skopeo to resolve the index digest and per-architecture digests.
- Syft generates per-architecture SBOMs.
- Cosign signs the image digest.
- GitHub artifact attestations record provenance and attach SBOM attestations.
- `release.yml` prepares a SemVer release line branch, builds a release candidate image, pins the candidate digest into `.env.tmpl`, writes `.release.env`, and opens a release PR.
- `finalize-release.yml` runs after the release PR is merged into a `v<major>.<minor>` branch. It validates the metadata, promotes the candidate digest to final tags, creates the Git tag, and creates the GitHub Release.
- Renovate tracks pinned image tags and digests in `.env.tmpl`, TYPO3 package versions, `install-php-extensions`, Syft, Cosign, `container-setup`, GitHub Actions, and selected release branches.

The monorepo should keep the secure build pieces, but replace single-image assumptions with image metadata, change detection, dependency graph planning, and per-image releases.

## Repository layout

Recommended layout:

```text
containers/
  README.md
  LICENSE
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
  release-state/
    typo3-phpfpm.json
  .github/
    renovate.json
    workflows/
      validate.yml
      publish-images.yml
      prepare-releases.yml
      finalize-releases.yml
```

`images/<family>/<name>` owns one public image. Its `Containerfile`, image-specific documentation, tests, fixtures, and optional root filesystem files live together.

`shared/` contains files used by multiple images. For `typo3-phpfpm`, the current `deps/container-utilities/shell/check_variables_and_directories.sh` should move or be mirrored to `shared/container-utilities/shell/check_variables_and_directories.sh` so the monorepo build context can remain the repository root.

`scripts/` contains workflow logic that is too complex for inline YAML. Complex scripting should be Python, executed through `uv`, and checked with `ruff`. Reusable commands should be exposed as Python modules such as `uv run --python 3.14 python -m scripts.container_engine ...`; shell should be limited to short composite-action install steps.

`.containerignore` keeps the build context small and prevents development files, workflow files, documentation, logs, and generated artifacts from being sent to the builder.

`release-state/` contains small generated JSON files with the latest released version, digest, source revision, and input fingerprint per image. These files make release PRs explicit and reviewable.

## Image metadata

Every image should have an `images/<family>/<name>/container.yaml` file. The workflows use this file to validate the image, plan builds, determine dependency order, and create releases.

Example for the first migrated image:

```yaml
name: typo3-phpfpm
image: ghcr.io/strukturpiloten/typo3-phpfpm
title: TYPO3 PHP-FPM
description: TYPO3 PHP-FPM runtime image with TYPO3 extensions and container utilities
license: AGPL-3.0-only
vendor: Strukturpiloten

build:
  context: ../..
  containerfile: Containerfile
  architectures:
    - amd64
    - arm64
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

release:
  enabled: true
  versioning: semver
  defaultBump: patch
  stableTags:
    - v{{ version }}
    - "{{ version }}"
    - "{{ major }}.{{ minor }}"
    - "{{ major }}"
    - latest
  prereleaseTags:
    - v{{ version }}
    - "{{ version }}"
```

For images based on another image from the same repository, use `dependencies.internal`:

```yaml
dependencies:
  internal:
    - image: php-base
      arg: BASE_IMAGE
  external: []
```

The build planner resolves `php-base` first, reads its freshly published digest, and passes `BASE_IMAGE=ghcr.io/strukturpiloten/php-base@sha256:<digest>` into dependent builds. Dependent images should not use mutable internal tags during the same workflow run.

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

The `publish-images.yml` workflow should be responsible for non-release image publishing on `main`, manual dispatch, and scheduled rebuilds.

Recommended jobs:

1. `validate`

   - Parse all `images/**/container.yaml` files.
   - Check required fields, image names, paths, architectures, tag templates, and dependency references.
   - Fail on dependency cycles.

2. `plan`

   - Determine changed files with `git diff` for pull requests and pushes.
   - Match changed files against each image's `inputs` list.
   - On scheduled rebuilds, select images with `release.enabled: true` or an explicit `build.scheduled: true` flag.
   - Expand the selected set to include reverse internal dependencies when an internal base image is selected.
   - Topologically sort selected images by `dependencies.internal`.
   - Emit a JSON build plan with stages, images, architectures, build args, candidate tags, and release eligibility.

3. `build-arch-image`

   - Build each selected image for each architecture with Buildah.
   - Use `--pull-always` for all builds.
   - Use `--no-cache` for scheduled builds, manual forced rebuilds, and release candidate builds.
   - Export per-architecture OCI archives as artifacts.

4. `publish-manifest`

   - Download architecture archives.
   - Create a multi-arch manifest with Podman.
   - Publish temporary immutable tags, for example `sha-<commit>` and `build-<run-id>-<attempt>`.
   - For `main`, also publish a moving development tag such as `main` or `latest-build`. Avoid using release tags here.

5. `inspect-sign-attest`

   - Resolve the index digest and per-architecture digests with Skopeo.
   - Generate per-architecture SBOMs with Syft.
   - Sign the index digest with Cosign.
   - Attach provenance and SBOM attestations.
   - Write one result entry per image to a `build-results.json` artifact.

6. `release-plan`

   - Compare the new digest and input fingerprint with `release-state/<image>.json` and the latest released GHCR digest.
   - Mark only changed, release-enabled images as release candidates.

The important part is that the build planner owns dependency order. GitHub Actions matrices can build independent images in parallel, but images in later dependency stages must wait for earlier stages so they can consume exact internal digests.

## Build order and dependency graph

Each image is a node in a directed graph. `dependencies.internal` creates edges.

Example:

```text
php-base
  -> typo3-phpfpm
      -> typo3-cli
```

The planner should produce stages like this:

```json
[
  ["php-base"],
  ["typo3-phpfpm"],
  ["typo3-cli"]
]
```

Images in the same stage can build in parallel. The next stage starts only after all required upstream images were published and their digests were resolved.

When `php-base` is rebuilt, `typo3-phpfpm` and `typo3-cli` should also be selected because their effective base image changed. When only `typo3-cli` changes, `php-base` and `typo3-phpfpm` do not need to rebuild.

If a cycle is configured, for example `a -> b -> a`, validation must fail before any build starts.

## Release model

Git tags and GitHub Releases are repository-wide, so the monorepo needs image-prefixed release tags.

Recommended tag format:

```text
<image>/v<major>.<minor>.<patch>
```

Examples:

```text
typo3-phpfpm/v1.0.0
php-base/v2.3.1
```

Recommended release branch format:

```text
release/<image>/v<major>.<minor>
```

Examples:

```text
release/typo3-phpfpm/v1.0
release/php-base/v2.3
```

Container image tags stay simple inside each GHCR package:

```text
ghcr.io/strukturpiloten/typo3-phpfpm:v1.0.0
ghcr.io/strukturpiloten/typo3-phpfpm:1.0.0
ghcr.io/strukturpiloten/typo3-phpfpm:1.0
ghcr.io/strukturpiloten/typo3-phpfpm:1
ghcr.io/strukturpiloten/typo3-phpfpm:latest
```

Pre-releases should only receive exact version tags:

```text
ghcr.io/strukturpiloten/typo3-phpfpm:v1.1.0-rc.1
ghcr.io/strukturpiloten/typo3-phpfpm:1.1.0-rc.1
```

Recommended release flow:

1. A build on `main` or a release branch produces candidate images and records digests in `build-results.json`.
2. `release-plan` selects only images where the new digest or input fingerprint differs from the last released state.
3. For each selected image, the workflow calculates the next SemVer version. Dependency-only rebuilds default to `patch`; explicit labels or manifest fields can request `minor` or `major`.
4. The workflow opens one release PR that updates `release-state/<image>.json` files for the selected images only.
5. The release PR body lists every image, candidate digest, previous release, next version, and tag plan.
6. After the PR is merged with a merge commit, `finalize-releases.yml` validates the metadata, promotes each candidate digest to final GHCR tags, creates image-prefixed Git tags, and creates one GitHub Release per image.

This keeps the safety properties of the current `typo3-container` release process, but it allows a single monorepo run to release `typo3-phpfpm` while skipping every unchanged image.

The release PR can be automerged after required checks pass if fully automatic releases are desired. The core rule should still be: no changed candidate digest, no release entry, no tag promotion.

## Release state

Each image should have a generated state file:

```json
{
  "image": "typo3-phpfpm",
  "version": "1.0.0",
  "gitTag": "typo3-phpfpm/v1.0.0",
  "containerImage": "ghcr.io/strukturpiloten/typo3-phpfpm",
  "digest": "sha256:...",
  "sourceRevision": "...",
  "inputFingerprint": "sha256:...",
  "releasedAt": "2026-06-21T00:00:00Z"
}
```

The input fingerprint should be generated from:

- The image's `container.yaml`.
- The image's `Containerfile` and files matched by `inputs`.
- Shared files used by the image.
- Exact external dependency references, including digests.
- Exact internal dependency image digests used as build args.
- Relevant build scripts and workflow versions.

The fingerprint should also be written as an OCI label or annotation, for example `org.strukturpiloten.container.input-fingerprint`.

## Renovate in the monorepo

Renovate should live at `.github/renovate.json` in the monorepo. It should keep the existing policies from `typo3-container` and add monorepo-aware managers.

Recommended Renovate behavior:

- Continue extending `config:recommended` and `helpers:pinGitHubActionDigests`.
- Keep GitHub Actions pinned to commit digests and allow Renovate to update them.
- Track external image references in `images/**/container.yaml` and optionally in `images/**/Containerfile`.
- Track `INSTALL_PHP_EXTENSIONS_VERSION` in `images/**/Containerfile`.
- Track Syft and Cosign versions in workflows.
- Automerge digest updates for external container images.
- Automerge patch and minor updates for selected tooling, matching the current policy.
- Do not use Renovate to update internal image dependencies during the same monorepo build. The build planner should inject internal digests.
- Maintain `baseBranchPatterns` for active release branches from the release workflow, because Renovate reads repository configuration from the default branch.

For release branches, the current `typo3-container` pattern can be generalized: after a new image release line is created, a workflow opens a PR against `main` to update Renovate's `baseBranchPatterns` with selected `release/<image>/v<major>.<minor>` branches. The number of tracked branches can be controlled globally or per image.

## Pull request validation

Pull requests should run validation without publishing final release tags:

- Validate all metadata files.
- Detect changed images and dependency expansion.
- Build changed images when feasible.
- Run image-specific tests from `images/<family>/<name>/tests`.
- Generate an unpublished or temporary build result for inspection.

PR builds should not promote SemVer tags and should not create GitHub Releases.

## Local development

The scripts used by the workflows should also work locally. A developer should be able to run:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine plan --event-name workflow_dispatch --ref-name main --default-branch main --sha "$(git rev-parse HEAD)" --output build-plan.json
uv run --frozen --python 3.14 python -m scripts.container_engine build-arch-image --plan build-plan.json --entry-json '{"name":"typo3-phpfpm","arch":"amd64"}' --output-dir /tmp/oci-archives
```

Local builds can tag images as `localhost/<image>:dev` and should not sign, attest, or publish unless explicit flags are passed.

## Open implementation decisions

- Whether release PRs should always require human review or can be automerged for Renovate-only patch rebuilds.
- Whether scheduled rebuilds should select all release-enabled images or only images with an explicit `build.scheduled: true` flag.
- Whether shared utilities should be copied into this monorepo or kept as a submodule under `shared/container-utilities`.
- Whether version bumps should be driven only by manifest policy and labels, or by conventional commits scoped to image names.
