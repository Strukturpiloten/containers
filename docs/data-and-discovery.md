# Catalogue data and discovery

The documentation site publishes machine-readable catalogue data alongside the human-readable pages. The intended canonical site is https://containers.strukturpiloten.de/; these endpoints become available after GitHub Pages, the custom domain, and DNS are configured.

| Path | Content |
| --- | --- |
| /data/catalogue.json | Versioned, enriched image declarations with a separate optional registry observation per image. |
| /data/catalogue.schema.json | JSON Schema for the enriched catalogue. |
| /data/declarations.json | Deterministic lifecycle report generated from repository metadata without a registry network request. |
| /data/registry-snapshot.json | Timestamped public GHCR observations and verified maintenance evidence, if the trusted refresh has run. |
| /data/registry-snapshot.schema.json | JSON Schema for the registry snapshot. |
| /markdown/images/<image-name>.md | Markdown export of a rendered image page. |
| /markdown/guides/<guide-name>.md | Markdown export of a guide. |

The catalogue uses schemaVersion 1, identifies the source revision, and supplies a canonical image page URL. Each row contains the image's declared version, architectures, base, lifecycle policy, documentation and source links, plus its optional observation. A declaration is not proof of publication. The declaredTags field describes tag policy; only observation.tags.currentAliases states which aliases actually resolved to the observed latest digest. The observation.tags.history field groups other resolved aliases by digest, and unresolved contains listed tags whose digest was not checked.

The snapshot's per-image status can be observed, stale, or unavailable. An observedAt value records when the registry was checked. A stale result retains an older verified observation after a failed refresh; read refreshError and ageSeconds before using it. An unavailable entry has no current digest. The optional latest.evidence status says whether a matching immutable maintenance release asset was verified. A buildSucceededAt timestamp is present only when that evidence verifies a build; publishedAt is unknown when no trustworthy publication timestamp exists. OCI config creation time, source commit time, package activity, and registry observation time are different events and must not be substituted for one another.

For automation, read the schemas, check schemaVersion, match an exact image name and architecture, and require an observation with a digest and the evidence level your workflow needs. Pin the resulting image@sha256:<index-digest> and review later digest updates. A mutable SemVer tag can move on a maintenance rebuild without changing the declared image version. Distribution-installed Docker and Podman revisions can also change on rebuild. The TYPO3 and Nextcloud PHP-FPM image versions describe PHP runtime contracts, not bundled application versions; those applications are supplied by the consuming stack.

The root /llms.txt provides a concise navigation list for text-oriented readers. Markdown exports are alternate representations of the same published documentation. They do not replace digest verification or provide any guarantee of search or AI ranking. Use the [image catalogue](image-catalogue.md) for browsing and [maintenance evidence](maintenance-evidence.md) for the proof behind a published artifact.
