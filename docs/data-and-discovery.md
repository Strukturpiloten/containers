# Catalogue data and discovery

`latest.declarationAlignment` independently compares the published version, architectures, build arguments, and payload checksum with repository declarations. `matched` reports those fields agree, `different` lists the differences, and `unknown` means no current comparison was supported. Saved snapshots bind a comparison to the declaration inputs used at collection; a later catalogue build reports `unknown` if those inputs changed or an older snapshot lacks that binding. A matching release proof can still describe an older published artifact while newer declarations are awaiting publication; do not confuse valid evidence for a digest with evidence that the current source inputs have been published.

The catalogue schema validates the declaration fields and observation envelope. Validate nested tag, digest, platform, and evidence fields using the image-entry definitions in `/data/registry-snapshot.schema.json` as well; the catalogue's envelope validation alone does not prove their consistency. Both documents identify their schema version. A future incompatible version requires an explicit consumer update.

Markdown exports remain publicly retrievable, but `robots.txt` asks compliant search crawlers to skip `/markdown/` to reduce duplicate crawling. The linked HTML pages are the primary search documents. This does not guarantee deindexing, and it does not restrict direct access to the exports.

The documentation site at **https://containers.strukturpiloten.de/** publishes machine-readable catalogue data alongside its human-readable pages.

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

Published multi-architecture indexes include the image description and canonical reference URL in `org.opencontainers.image.description`, the index annotation GitHub documents for multi-architecture package descriptions. The `org.opencontainers.image.documentation` annotation and per-architecture image label also carry that URL for OCI clients. An explicit tagged index-version page can display the description and URL as text, but a GHCR package overview can select another package version and omit them. The linked repository README leads to the [image catalogue](image-catalogue.md) when that happens. GitHub controls its package-page display; the URL is not guaranteed to be clickable there. New metadata appears after normal publication, while existing immutable versions retain their original metadata.

On a GHCR package page, open **Versions**, choose the entry tagged **latest**, and compare its displayed digest with the catalogue. Tags associated with signatures or other verification artifacts are separate package versions and are not the runtime image.
