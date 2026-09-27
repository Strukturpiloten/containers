# Image maintenance evidence

`container.yaml` declares each image's lifecycle state, intended admission, review date, support boundary, and required runtime profiles. `production` is an intended policy state. It does not by itself prove registry availability, native runtime coverage, or vulnerability acceptance. The checked-in [image catalogue](image-catalogue.md) is generated from metadata alone, so those evidence columns are `unknown` until matching records are supplied.

Regenerate the catalogue with:

```sh
uv run --frozen python -m scripts.maintenance \
  --json-output docs/image-catalogue.json \
  --markdown-output docs/image-catalogue.md
```

To include evidence from a run, add `--evidence-dir DIR` containing unique `<name>-build-result.json` files and `<name>-<arch>-runtime-evidence.json` files. Runtime status can be `passed`, `failed`, or `skipped`; absent evidence is `unknown`, and skipped checks remain visible even under a passed profile. A build result must match metadata's image, version, source revision, index digest, and complete architecture digest map. `buildSucceededAt` is the build completion time, distinct from the source commit time.

Registry observations are optional. Supply `--registry-observations FILE` with a JSON object keyed by metadata image name. Each entry must contain `image`, `digest`, `reference`, and `observedAt`. The reference must be the immutable `image@sha256:...` corresponding to the recorded build index digest; `observedAt` needs an ISO timestamp with timezone. An observation reports what was checked at that time. It is not a guarantee that a mutable tag still points there.

The [Grype comparison action](../.github/actions/scan-vulnerabilities/action.yml) accepts a built OCI archive, its source revision, the image name and architecture, a maintained baseline tag of the same image, declared admission, and an output directory. It verifies the archive's image manifest/configuration digest, architecture and OCI source revision. For the baseline it resolves the tag to a registry index, selects exactly one architecture manifest, verifies that manifest by digest, and checks its configuration architecture. Both scans use pinned immutable sources. A candidate archive manifest digest is **not** the tar file's SHA-256, and can differ from the architecture manifest digest after publication rewrites transport metadata. The report preserves the prepublication source identity separately from the final published index and architecture digests.

The action installs Grype v0.119.0 from release assets whose AMD64 and ARM64 SHA-256 values are pinned alongside the version. It writes raw Grype JSON, scanner/database metadata, verified source identities, a comparison report, and an Actions summary. `scripts.vulnerability` compares vulnerability ID and package type/name, reporting new, fixed and remaining findings. New High/Critical findings with a known fixed version block `production` admission unless an unexpired scoped exception applies. Isolated-test findings remain visible but do not grant production admission. A missing or wrong baseline, architecture, source digest, or Grype source identity fails closed.

For local triage, run the action's source commands with your archive and baseline tag, then scan the two sources with Grype and run `python -m scripts.vulnerability --help` for report arguments. A policy exception belongs in [vulnerability-exceptions.json](../security/vulnerability-exceptions.json) and requires the exact image, architecture, candidate manifest digest, vulnerability ID, package type/name, owner, reason, and ISO expiry date. Exceptions expire automatically; changing a candidate digest requires a new review. The policy file starts empty.

On release finalization, `scripts.release_evidence` creates a JSON record and uploads it as an immutable GitHub Release asset named for the published index digest and run identity. The asset records both the release tag's original source revision and this maintenance build's source revision, so later rebuilds do not rewrite historical release provenance. Finalization verifies each published architecture manifest and records its configuration digest. When native runtime or scan evidence is supplied, the configuration digest must match the published one even if archive and registry manifest digests differ. The asset can embed runtime and scan reports from optional directories; absent reports remain empty. GitHub Actions artifacts with shorter retention are operational handoff, not the durable release record.
