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
`publishedAt` is recorded prospectively when a workflow copies at least one
maintained alias and then reads back every selected maintained alias at the
verified index digest. It is carried by the matching immutable maintenance
asset. Existing historical assets without that field remain `null`; an
already-current alias on a retry does not create a guessed timestamp. This
time is distinct from the initial immutable index upload and from the later
release-asset publication. `buildSucceededAt` is a separate build success
time and is never relabelled as publication time.

Release evidence is `verified` only when a published immutable maintenance
release, its Git tag, unique asset, image name, version, source revision, run
identity, index digest, architecture manifest digests, and config digests match
the observed image. The publisher's consistency gate checks attached runtime
and vulnerability scan records. These states do not claim signature or
provenance verification; those fields remain `unknown`. If the release cannot
be read or matched, the registry observation remains visible while evidence is
`unavailable` with a reason, except for the same-digest transient read failure
described below.

`latest.declarationAlignment` separately compares the verified live release
with the current `container.yaml`: image version, runnable architectures,
build arguments, and payload manifest SHA-256 where present. `matched` means
those declarations agree. `different` includes field-level published and
declared values, such as a base-image digest updated after the latest image
publication. The release evidence remains verified for its observed digest
when the declaration has advanced. `unknown` means no current comparison with
a verified release asset could be made.

Each image refresh succeeds or fails independently. On a registry failure, a
previous observation for the same image is kept as `stale` with its original
`observedAt`, updated `ageSeconds`, and `refreshFailed` reason. A transient
GitHub release read failure also retains the **whole prior observation** only
when the freshly inspected `latest` digest equals the prior digest and the
prior evidence was verified. The retained digest, tags, release proof, and
`publishedAt` retain their earlier meaning; `observedAt` is not advanced to
the attempted refresh time. Its `declarationAlignment` becomes `unknown`
because current declarations cannot be compared with the unavailable release
asset. A changed digest, missing release, or proof mismatch never restores
prior evidence: the fresh registry observation instead reports evidence as
`unavailable`. Without a prior observation, a registry failure makes the image
`unavailable`, while a GitHub release read failure leaves a fresh registry
observation with unavailable evidence. Consumers should show these states and
never treat a stale digest as a current registry check. The command validates
the resulting file against [the snapshot schema](registry-snapshot.schema.json)
and does not alter the checked-in catalogue.
