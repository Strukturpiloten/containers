# Strukturbo application images

`strukturbo-nautobot` packages Nautobot with DNS Models, Design Builder and the Strukturbo access registry. The initial image is for AMD64. The image contract version is independent of the installed application versions; see [metadata](strukturbo-nautobot/container.yaml) and the installed `/usr/share/strukturpiloten/strukturbo-nautobot.json` provenance record.

The registry maintains organization/tenant identities, public keys and draft access intent. Its browser workflow authenticates a Nautobot superuser and separates upload, review and atomic import. Import does not create operational accounts or install permissions. Live rollout and independent recovery acceptance belong to the bootstrap deployment workflow.

## Source and build inputs

The canonical app source remains in the private `Strukturpiloten/strukturbo-bootstrap` repository. [source.json](strukturbo-nautobot/source.json) pins an immutable commit. `sourceRef` selects the branch Renovate observes; fetching always uses `sourceCommit`. The initial source branch is the issue #2 bootstrap PR; switch the observed branch to `main` when that source is merged and retained there.

Before building, `scripts.nautobot_source` uses the host `gh` client to acquire that commit. It rejects archive links/traversal, bounds extraction, and verifies the app against its source qualification receipt. It stages the minimal app under ignored `.build-sources/strukturbo-nautobot/app`, with the full qualification tooling in a separate directory excluded from the image build context. Credentials are never written into this directory or passed to the image build.

In Actions, set `STRUKTURBO_SOURCE_TOKEN` to an automation token with Contents read access to the bootstrap repository. Existing installations may use `RELEASE_AUTOMATION_TOKEN` if it already has that access. The token is passed only to the source-fetch step. A fork without source access cannot build this private-source image; no unpinned public fallback is used. On a workstation, the existing host `gh` login can supply access.

The digest-pinned upstream Nautobot image supplies core and cryptography. Hash-locked runtime requirements add the two existing apps; hash-locked build requirements supply the wheel backend. The build checks these against the source's qualified dependency contract, installs the registry wheel without resolving dependencies, runs `pip check`, and compares installed Python/templates with the source manifest. The final provenance includes the source commit, archive/source hashes, installed versions, package file hashes and wheel checksum. Build inputs do not include infrastructure inventory, identity seeds or credentials.

Renovate tracks the base and disposable fixture image tags/digests in `container.yaml`, both requirements files, and the source branch commit in `source.json`. These inputs form one update group and inherit the repository's existing CI and automerge policy. A dependency change that conflicts with the qualified source contract fails build/runtime checks until the source is qualified for it.

## Runtime and qualification

The image runs as UID/GID 999 and starts Nautobot directly. It bypasses the upstream initialization wrapper, which would otherwise run migrations and optionally create/update a superuser on startup. Configuration is supplied at deployment time. Enable the three apps in the credential-aware Nautobot configuration; run the approved migration/static collection operation separately before starting writers. The image build performs no database migration.

The `nautobot` runtime profile loads the exact built OCI archive, acquires digest-pinned PostgreSQL/Redis fixtures and invokes the pinned bootstrap qualification tooling against the installed image. It uses disposable isolated containers, synthetic credentials, TLS and no live data. It checks wheel/source identity, migration consistency, registry models, object permissions, CSRF/session approval, stale/conflict rejection, audit rollback, replay, HTTPS/static/login, workers, scheduler and backup queue behavior. App source is not mounted or injected into the candidate. The complete existing-data migration and offline restore rehearsal is a separate bootstrap qualification; source-injection evidence alone does not satisfy it.

Prepare source locally:

```sh
uv run --frozen --python 3.14 python -m scripts.nautobot_source
```

Build through the normal [operations workflow](../../docs/operations.md), selecting image `strukturbo-nautobot`. PR CI builds/tests without publishing. A passing default-branch build publishes through the standard vulnerability, signing, SBOM and release-evidence gates. Check actual release evidence for tested digests and architectures.

To test an OCI archive acquired from the corresponding build run:

```sh
uv run --frozen --python 3.14 python -m scripts.runtime_tests \
  --image-name strukturbo-nautobot --archive /path/to/candidate.oci \
  --arch amd64 --evidence /tmp/strukturbo-nautobot-runtime.json
```

The source staging must correspond to the image's manifest. A subsequent acquisition refuses to overwrite existing staging; remove only that generated directory when preparing a different commit. The runtime harness removes its owned containers/store after recording evidence. No VM, Kubernetes cluster or application data is changed by these checks.
