# Tags, versions, and publication history

Every image has its own `version` in `container.yaml`. A version such as `v1.0.0` describes the Strukturpiloten image contract and release line. It is not a promise that all bundled software has that version. In a distro-package Docker or Podman image, package revisions can change when the distribution repository changes and the image is rebuilt. `typo3-phpfpm:v2.0.0` supplies a PHP runtime; it does not include TYPO3 version 2.0.0 or TYPO3 application code. Inspect the component manifest under `/usr/share/strukturpiloten/`, the image SBOM, and the image's own guide for installed versions.

| Reference | Movement | Use |
| --- | --- | --- |
| `image@sha256:<index-digest>` | Immutable content identity | Reproducible deployments, audit, rollback |
| `image:run-<run>-<attempt>-sha-<commit>` | Immutable publication identity | Identify one workflow attempt |
| `image:sha-<commit>` | Immutable source identity for a verified build | Trace a repository revision |
| `image:vX.Y.Z` | Maintained alias, even at exact SemVer | Follow reviewed rebuilds of a declared image version |
| `image:vX.Y`, `image:vX` | Maintained aliases | Follow a minor or major release line |
| `image:latest` and branch tags | Maintained aliases | Follow successful publications on a branch |

For readable configuration and reproducible pulls, use a tag with a verified digest, for example `ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0@sha256:<verified-index-digest>`. The digest fixes the content; the tag communicates the intended line. Let an update tool propose digest changes for review. Moving a tag does not update already running containers; pull and redeploy or configure an explicit auto-update policy.

## Inspect the current artifact

Resolve a published tag to an index digest with `skopeo`; then compare the digest, source revision, architecture, and runtime/vulnerability evidence with the [maintenance release record](maintenance-evidence.md):

```sh
skopeo inspect --format '{{.Digest}}' docker://ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
skopeo inspect --raw docker://ghcr.io/strukturpiloten/nextcloud-notifypush:v1.0.0
```

A tag only describes its current target. GitHub's image-scoped source-version release records the original declared version; a later rebuild of the same version receives a separate `<imageName>/maintenance/<runId>-<runAttempt>` release with durable evidence. Do not treat one source-version release date as the date of every retained-version rebuild.

## Read timestamps correctly

| Field or event | Meaning |
| --- | --- |
| Source commit time | When the source revision was committed; not a container build time. |
| `buildSucceededAt` | When the recorded build succeeded. |
| `publishedAt` | When a verified image was published, if recorded by publication evidence. |
| Package or release activity | When an upstream package, repository, or GitHub release changed; not proof this image was rebuilt or pulled. |
| `observedAt` | When a registry reference was checked; the mutable tag can move later. |

Keep these values separate when comparing releases. An absent timestamp or `unknown` evidence means no matching record was supplied to the catalogue; do not infer a successful build or a failure from it. The [operations guide](operations.md#promotion-release-and-rollback) describes guarded rollback of a maintained alias to a verified digest.
