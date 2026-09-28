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

## Dated registry examples

A public registry inspection on **2026-09-28 at 07:42 UTC** resolved these aliases. This is a point-in-time tag observation, not a promise about their current targets or proof that each historical digest still receives maintenance. The full observations and evidence state are in the [registry snapshot](registry-observations.md); re-resolve any tag before using it.

| Image | Aliases at the observed `latest` digest | Older resolved alias and digest |
| --- | --- | --- |
| `podman-5.8-rootless` | `latest`, `main`, `v5`, `v5.8`, `v5.8.7` → `sha256:7c5089a0895c9ba0a14876bc0369356cf368729975006ab037189a29e1d5d9ba` | `v5.8.6` → `sha256:1b29f88f2c58be615b7e74b58c2ede683115c934645a6d9573a10d701e74a2f7` |
| `podman-6.1-rootless` | `latest`, `main`, `v6`, `v6.1`, `v6.1.2` → `sha256:ee22811400ea82b31f0c3bf4f6530ff50465faa87bf9e201856e83b6e36ce58a` | `v6.1.0` → `sha256:5fe9b8068a8e40de1189b23434ba3e2b84ff4e3b576fe2a844e25582ad6b181e` |
| `typo3-phpfpm` | `latest`, `main`, `v2`, `v2.0`, `v2.0.0` → `sha256:151bb805aec2a184b59626fe989613034f2547e754cca0ae00634868d213a491` | Earlier `v1.0.0`, `v1.0.1`, and `v1.0.2` each resolved to a different digest from the former image repository. |

For TYPO3, `v2.0.0` is the current PHP-FPM **image** contract line. It does not mean TYPO3 2.0.0 is installed; the runtime has no TYPO3 application code. The historical `v1.*` aliases remain registry history and are not moved by this monorepo's release automation. Exact digest pinning preserves an old artifact but does not confer ongoing security support.

## Read timestamps correctly

| Field or event | Meaning |
| --- | --- |
| Source commit time | When the source revision was committed; not a container build time. |
| `buildSucceededAt` | When the recorded build succeeded. |
| `publishedAt` | When a verified image was published, if recorded by publication evidence. |
| Package or release activity | When an upstream package, repository, or GitHub release changed; not proof this image was rebuilt or pulled. |
| `observedAt` | When a registry reference was checked; the mutable tag can move later. |

Keep these values separate when comparing releases. An absent timestamp or `unknown` evidence means no matching record was supplied to the catalogue; do not infer a successful build or a failure from it. The [operations guide](operations.md#promotion-release-and-rollback) describes guarded rollback of a maintained alias to a verified digest.
