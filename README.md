# Strukturpiloten Containers

This repository builds and publishes the public container images maintained by Strukturpiloten. Image definitions, dependency pins, release versions, build inputs, and architecture support live with the image they describe. GitHub Actions validates that metadata and handles builds, signing, attestations, and releases.

## Image catalog

| Family | Images | Architectures | Documentation |
| --- | --- | --- | --- |
| Podman | Exact upstream Podman 5.4–6.1 and distro-packaged compatibility images, each rootful and rootless | AMD64 and ARM64; Arch is AMD64-only | [Podman compatibility images](images/podman/README.md) |
| Nextcloud | `nextcloud-phpfpm`, `nextcloud-notifypush` | AMD64, ARM64 | [PHP-FPM](images/nextcloud/nextcloud-phpfpm/README.md), [notify_push](images/nextcloud/nextcloud-notifypush/README.md) |
| TYPO3 | `typo3-phpfpm` | AMD64, ARM64 | [TYPO3 PHP-FPM](images/typo3/typo3-phpfpm/README.md) |

Published image names use `ghcr.io/strukturpiloten/<image-name>`.

## Repository contract

- `images/<family>/<image>/container.yaml` is the source of truth for one published image.
- `container.schema.json` defines the metadata format. Repository validation adds dependency-graph, build-path, digest-pinning, and version-progression checks.
- Containerfiles use the repository root as their build context. Shared runtime files belong under `shared/` or a family-specific shared directory.
- External base images are pinned by digest. Renovate proposes digest and supported dependency updates through pull requests.
- Internal image dependencies use exact digests and build in topological stages. Independent images remain in stage 0 and build in parallel.
- Static OCI label values shared by every image live in `shared/oci-labels.env`; image-specific title, description, version, source revision, and documentation URL come from the build plan.

The current architecture and maintenance rules are described in [Container repository architecture](docs/container-monorepo-concept.md).

## Builds and releases

Pull requests run validation and smoke-build affected images without publishing. The stable `Required CI` job is intended for the repository ruleset.

Merges to `main` build affected images and reverse dependencies. A daily scheduled run rebuilds every scheduled image without cache so supported base distributions and installed packages can contribute security fixes even when no repository file changed. Manual runs may select all images, one image, or an image family; normal operation does not require manual releases.

After a build succeeds, the workflow publishes an immutable run tag, inspects the manifest, creates SBOMs, signs the image, and attaches provenance and SBOM attestations. Only then does it update maintained tags and automatically create any missing image-scoped GitHub Release declared by `container.yaml`.

### Tag behavior

| Reference | Mutability | Intended use |
| --- | --- | --- |
| OCI digest (`sha256:…`) | Immutable | Reproducible deployments and rollback |
| `run-<run>-<attempt>-sha-<commit>` | Immutable | Audit trail for one workflow attempt |
| `sha-<commit>` | Immutable | Verified image built from one repository commit |
| branch and `latest` | Maintained | Follow successful rebuilds on that branch |
| `vX.Y.Z`, `vX.Y`, `vX` | Maintained | Follow the declared compatibility line, including security rebuilds |

Consumers should use a readable maintained tag together with a digest, for example `v1.2.3@sha256:…`, and let Renovate update the digest when the maintained tag moves. Running workloads still require a pull and redeploy or a configured auto-update policy.

## Local validation

Run the same non-publishing checks before opening a pull request:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

When image metadata changes the internal dependency depth, regenerate the checked-in publishing workflow:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow
```
