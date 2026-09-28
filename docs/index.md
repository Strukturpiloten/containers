# Documentation

Start with the [image catalogue](image-catalogue.md) to see every declared image and its lifecycle policy. The catalogue's `unknown` evidence fields mean that build or registry evidence was not supplied to the generator; they are not claims that an image is available or unavailable.

| Task | Guide |
| --- | --- |
| Pull and inspect a first image | [Getting started](getting-started.md) |
| Match a runtime or compatibility target | [Choosing images](choosing-images.md) |
| Select a tag, digest, and update policy | [Tags and versions](tags-and-versions.md) |
| Integrate an existing application project | [Compose integration](application-compose.md) |
| Verify signatures, provenance, SBOMs, and release evidence | [Verify published artifacts](verify-artifacts.md) |
| Check evidence, support scope, and report a concern | [Security and support](security-and-support.md) |
| Read JSON or Markdown exports | [Catalogue data and discovery](data-and-discovery.md) |
| Change a recipe or metadata | [Contributing](../CONTRIBUTING.md) |
| Build, release, or recover a publication | [Operations](operations.md) |

The [Docker](../images/docker/README.md), [Podman](../images/podman/README.md), [Nextcloud PHP-FPM](../images/nextcloud/nextcloud-phpfpm/README.md), [Nextcloud notify_push](../images/nextcloud/nextcloud-notifypush/README.md), and [TYPO3 PHP-FPM](../images/typo3/typo3-phpfpm/README.md) guides describe family-specific runtime behavior. The [maintenance evidence](maintenance-evidence.md), [vulnerability scanning](vulnerability-scanning.md), [workflow configuration](workflow-configuration.md), and [monorepo concept](container-monorepo-concept.md) guides cover repository operations and design.

The public documentation site is **https://containers.strukturpiloten.de/**, with image pages at `/images/<image-name>/` and guides at `/guides/<guide-name>/`. The repository files linked here remain available alongside the published site.
