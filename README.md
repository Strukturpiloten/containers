# Strukturpiloten Containers

Container image definitions for application stacks and isolated compatibility tests, with published artifacts at `ghcr.io/strukturpiloten/<image-name>`.

Browse the [image catalogue](https://containers.strukturpiloten.de/) for every image, its purpose, architectures, lifecycle, and registry observations. Each image has a permanent reference page. The [repository catalogue](docs/image-catalogue.md) provides the deterministic declarations used by CI. An `unknown` build or registry status does not mean publication succeeded.

| Family | Choose it for | Start here |
| --- | --- | --- |
| [Docker Engine](images/docker/README.md) | Testing real Docker daemon and API behavior across upstream lines and distribution packages | `docker-29-rootful`, `docker-debian-12-rootless` |
| [Podman](images/podman/README.md) | Testing Podman behavior across exact upstream lines and distribution packages | `podman-6.1-rootless`, `podman-debian-12-rootful` |
| [Nextcloud PHP-FPM](images/nextcloud/nextcloud-phpfpm/README.md) | Supplying a PHP-FPM runtime to a Nextcloud application stack | `nextcloud-phpfpm` |
| [Nextcloud notify_push](images/nextcloud/nextcloud-notifypush/README.md) | Running the Nextcloud push service alongside an existing stack | `nextcloud-notifypush` |
| [TYPO3 PHP-FPM](images/typo3/typo3-phpfpm/README.md) | Supplying a PHP-FPM runtime to a TYPO3 application stack | `typo3-phpfpm` |

Docker and Podman images are isolated compatibility fixtures. They share the runner kernel and need the outer runtime privileges documented for each profile; they are not production container hosts. The PHP-FPM images provide a runtime, not Nextcloud or TYPO3 application code. See [choosing an image](docs/choosing-images.md) before selecting a tag.

## Use an image

Find the image in the [catalogue](docs/image-catalogue.md), read its family guide and image metadata, then verify that its registry digest and required runtime evidence exist. For a quick inspection of a published image:

```sh
podman pull ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
podman image inspect ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
```

The image version is a release of this repository's image contract. It is not necessarily the version of every installed component; for example, the TYPO3 PHP-FPM image does not contain TYPO3 itself. Maintained tags, including exact SemVer tags, can move after a reviewed rebuild. For a reproducible deployment, record the manifest digest and use a readable tag with that digest, such as `ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0@sha256:<verified-index-digest>`. Read [tags and versions](docs/tags-and-versions.md) for inspection and update steps.

## Documentation

- [Documentation index](docs/index.md) and [getting started](docs/getting-started.md)
- [Choosing images](docs/choosing-images.md), [tags and versions](docs/tags-and-versions.md), and [security and support](docs/security-and-support.md)
- [Contributing](CONTRIBUTING.md) and [build and release operations](docs/operations.md)
- [Maintenance evidence](docs/maintenance-evidence.md) and [vulnerability scanning](docs/vulnerability-scanning.md)

The documentation is published at **https://containers.strukturpiloten.de/**. The linked repository guides remain available alongside the website.

## Repository and releases

Each `images/<family>/<image>/container.yaml` declares one image, including its version, architectures, build inputs, lifecycle policy, and runtime checks. `container.schema.json` defines the metadata format. Image builds use the repository root as context; shared runtime files live under `shared/` or a family-specific shared directory. External base images are pinned by digest, and Renovate proposes reviewed updates. Internal image dependencies use exact digests and build in topological stages. Static common OCI label values live in `shared/oci-labels.env`.

Pull requests run validation, selected builds, runtime probes, and vulnerability admission checks. Publishing jobs verify the multi-architecture image, create SBOMs, signatures, and attestations, then promote maintained tags and create image-scoped releases. The [operations guide](docs/operations.md) covers planning, publication, rollback, and recovery. The [maintenance evidence guide](docs/maintenance-evidence.md) explains how to verify a published digest against runtime and scan evidence.

## Local validation

Run the repository checks before opening a pull request:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

For a single Podman compatibility profile on a Linux host with Podman and `/dev/fuse`:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine test-podman-image \
  --image podman-debian-12-rootless
```

The nested check requires the privilege boundary described in the [Podman guide](images/podman/README.md#build-and-test-architecture). Use `--skip-nested` for only a build and CLI check. When image metadata changes internal dependency depth, regenerate the checked-in workflow with `uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow`.
