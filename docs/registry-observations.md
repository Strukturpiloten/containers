# Registry observation snapshot

The checked-in [image catalogue](image-catalogue.md) is generated from canonical
`container.yaml` declarations without network access. A website deployment can
separately generate `registry-snapshot.json` with:

```sh
python -m scripts.docs_observations --output public/registry-snapshot.json \
  --previous public/previous-registry-snapshot.json
```

`--previous` is optional. The command reads public GHCR tags and content-addressed
index, architecture manifest, and configuration bytes anonymously. It resolves
`latest`, `main`, and version tags, groups those pointing at the current digest
as `currentAliases`, and groups older version tags by digest in `history`.
`listed` includes all tags. `unresolved` includes auxiliary tags such as run,
source revision, signature, and attestation references; their digests are not
claimed. An optional repository-scoped `GH_TOKEN` or `GITHUB_TOKEN` is used only
for ordinary GitHub release API reads. A broad personal token or authenticated
package-list permission is not required.

`latest.platforms` includes labels only after the raw index, architecture
manifest, and exact GHCR config bytes pass digest checks. `observedAt` records
when the collector read the registry; `configCreatedAt` is an image build label.
`publishedAt` remains `null` because neither identifies the exact time the
runnable image was published. A verified maintenance asset may separately
provide `buildSucceededAt`, which is a build success time and is not relabelled
as publication time.

Release evidence is `verified` only when a published immutable maintenance
release, its Git tag, unique asset, image name, version, source revision, run
identity, index digest, architecture manifest digests, and config digests match
the observed image. The publisher's consistency gate checks attached runtime
and vulnerability scan records. These states do not claim signature or
provenance verification; those fields remain `unknown`. If the release cannot
be read or matched, the registry observation remains visible while evidence is
`unavailable` with a reason.

`latest.declarationAlignment` separately compares the verified live release
with the current `container.yaml`: image version, runnable architectures,
build arguments, and payload manifest SHA-256 where present. `matched` means
those declarations agree. `different` includes field-level published and
declared values, such as a base-image digest updated after the latest image
publication. The release evidence remains verified for its observed digest
when the declaration has advanced. `unknown` means there is no verified
release asset from which to compare build inputs.

Each image refresh succeeds or fails independently. On failure, a previous
observation for the same image is kept as `stale` with its original
`observedAt`, updated `ageSeconds`, and `refreshFailed` reason. Without a prior
observation the image is `unavailable`. Consumers should show these states and
never treat an old digest as a current registry check. The command validates
the resulting file against [the snapshot schema](registry-snapshot.schema.json)
and does not alter the checked-in catalogue.
