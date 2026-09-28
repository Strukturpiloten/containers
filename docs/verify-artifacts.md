# Verify a published image and its attestations

The publisher signs the multi-architecture index with keyless Cosign, attaches a GitHub Actions SLSA provenance attestation to that index, and attaches a separate SPDX 2.3 SBOM attestation to each architecture manifest. It also publishes an immutable maintenance evidence release containing native runtime and vulnerability-scan records. These are separate checks: a valid signature identifies the publisher workflow and signed digest, while the evidence record describes the tested artifact. The [registry snapshot](registry-observations.md) does not verify Cosign signatures or provenance itself; its `signature` and `provenance` fields remain `unknown`.

The commands below use `skopeo`, `cosign` v3.1.3, `jq`, and `base64`. Start with an image tag you intend to deploy, then resolve it to an immutable index digest:

```sh
image=ghcr.io/strukturpiloten/nextcloud-notifypush
tag=v1.0.0
digest=$(skopeo inspect --format '{{.Digest}}' "docker://$image:$tag")
ref="$image@$digest"
digest_hex=$(printf '%s' "$digest" | cut -d: -f2)
printf '%s\n' "$ref"
```

Check that this exact digest appears in the image page's observation and in its [maintenance release evidence](maintenance-evidence.md). The following certificate identity is the trusted `main` publication workflow used by this repository; the OIDC issuer is GitHub Actions:

```sh
identity=https://github.com/Strukturpiloten/containers/.github/workflows/publish-one-image.yml@refs/heads/main
issuer=https://token.actions.githubusercontent.com
cosign verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --output json "$ref" > /tmp/containers-signature.json
jq -e --arg digest "$digest" \
  'any(.[]; .critical.image["docker-manifest-digest"] == $digest)' \
  /tmp/containers-signature.json
```

Verify the SLSA v1 attestation on the same index and inspect its signed statement. The subject digest must match the index you resolved, and the source commit and workflow run should match the maintenance release:

```sh
cosign verify-attestation \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --type https://slsa.dev/provenance/v1 \
  --output json "$ref" > /tmp/containers-provenance.json
jq -r '.payload' /tmp/containers-provenance.json | base64 -d > /tmp/containers-provenance-statement.json
jq -e --arg image "$image" --arg digest "$digest_hex" \
  'any(.subject[]; .name == $image and .digest.sha256 == $digest)' \
  /tmp/containers-provenance-statement.json
jq '.predicate.buildDefinition.resolvedDependencies, .predicate.runDetails.metadata.invocationId' \
  /tmp/containers-provenance-statement.json
```

The publisher scans each architecture manifest with Syft and attaches its SPDX document by that architecture digest. Verify the desired architecture's digest from the signed index, then verify its SBOM attestation:

```sh
arch=amd64
manifest_digest=$(skopeo inspect --raw "docker://$ref" |
  jq -r --arg arch "$arch" '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest')
test -n "$manifest_digest"
test "$manifest_digest" != null
manifest_digest_hex=$(printf '%s' "$manifest_digest" | cut -d: -f2)
cosign verify-attestation \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --type https://spdx.dev/Document/v2.3 \
  --output json "$image@$manifest_digest" > /tmp/containers-sbom.json
jq -r '.payload' /tmp/containers-sbom.json | base64 -d > /tmp/containers-sbom-statement.json
jq -e --arg image "$image" --arg digest "$manifest_digest_hex" \
  'any(.subject[]; .name == $image and .digest.sha256 == $digest)' \
  /tmp/containers-sbom-statement.json
jq '.predicate | {spdxVersion, name, packageCount: (.packages | length)}' \
  /tmp/containers-sbom-statement.json
```

Repeat for every architecture you use. A package list or a clean scan does not establish that all compiled dependencies are visible or that the image is vulnerability-free. Compare the release asset's image name, index and architecture digests, source revision, workflow run/attempt, runtime results, and scan reports with this same immutable reference. The [maintenance evidence guide](maintenance-evidence.md) explains that binding and the separate source-version and per-rebuild release records. If a command fails or any identity differs, stop using that digest until the discrepancy is understood.
