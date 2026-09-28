# Contributing

Contributions to image recipes, metadata, documentation, and tests are welcome. For a bug or a proposed image, open a [GitHub issue](https://github.com/Strukturpiloten/containers/issues) with the image name, architecture, reference or digest, expected behavior, and a minimal reproduction. Avoid posting credentials, private configuration, or sensitive vulnerability details in a public issue. See [Security](SECURITY.md) for security reports.

Before editing an image, read its `images/<family>/<image>/container.yaml`, family README, and the [image selection guide](docs/choosing-images.md). Each image has one metadata file that declares its version, architectures, lifecycle, build inputs, and runtime checks. A new image needs metadata conforming to `container.schema.json`, a build recipe, appropriate smoke/runtime coverage, and catalogue navigation. Place shared runtime code under `shared/` or the family shared directory; image builds use the repository root as context. Pin external base images by digest. Do not substitute a mutable tag for an internal image dependency.

For a package or upstream version update, record what changed and how the installed version is verified. Distro-package images may select newer package revisions at build time; an image contract version is not an installed software version. Preserve the documented support boundary and avoid presenting compatibility fixtures as production hosts. For a new or changed nested-runtime profile, state the outer privilege, devices, namespaces, and any intentionally excluded checks in metadata and documentation. The [Docker](images/docker/README.md) and [Podman](images/podman/README.md) guides describe the tested boundaries.

Run the local checks from the repository root:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

If a change alters the internal dependency graph, regenerate the checked-in workflow with `uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow`. Relevant runtime checks need a suitable Linux host; read the [operations guide](docs/operations.md#test-a-change) and record which profiles and architectures were actually exercised. A skipped nested check is not evidence that nested workloads work.

Documentation under `docs/` is linked from the [documentation index](docs/index.md). Keep image-specific runtime details in its family or image README, link to source metadata, and explain evidence limits. The public site uses `/guides/<doc-stem>/` and `/images/<image-name>/` routes after publication. Avoid fixed image counts or registry-success claims in prose: the catalogue is generated from metadata and optional evidence.

Open a pull request that explains the user-visible behavior and test evidence. Publishing and maintained-tag promotion run in GitHub Actions after the repository's admission checks; a passing local build alone does not establish registry availability or native runtime coverage. Repository source is covered by [LICENSE](LICENSE); upstream binaries, packages, bases, and libraries bundled into images retain their own licenses. Review image SBOMs and upstream notices for redistribution obligations.
