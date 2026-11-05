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

On rootful GitHub runners, the profile detects the specific `containers-default-0.66.0//&crun` AppArmor stacking bug that blocks PostgreSQL signals ([runner evidence](https://github.com/Strukturpiloten/containers/actions/runs/41546802667)). Only that detected CI case passes `--fixture-apparmor-unconfined` to the disposable qualification stack. Runtime evidence explicitly marks fixture AppArmor enforcement as skipped; application, TLS, permission and cleanup checks still run. Other profiles and versions retain their default confinement. This option belongs to qualification tooling and does not configure a deployed service.

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

## Local DNS allocation candidate 0.3.0

The managed source manifest now selects merged bootstrap app 0.3.0 and verifies its separate `dns-identity-qualification.json` source receipt. Historical 0.1 and 0.2 receipts remain historical. The combined candidate enables DNS Models 2.3.0, Design Builder 3.1.2 and Strukturbo 0.3.0 during installed-wheel qualification.

Build target `apps-baseline` contains the same pinned Nautobot base and two hash-locked third-party apps, without the Strukturbo wheel. It is a newly built synthetic migration fixture matching the live plugin/version shape; it is not the retained live original image or its recovery contract. The default `final` target adds and verifies the installed Strukturbo wheel.

`build.githubActions: false` keeps this candidate out of GitHub Actions builds. Local OCI archives, source/build provenance, installed-wheel checks and synthetic restore receipts do not provide GitHub OIDC signatures or CI SLSA attestations. Publication and live selection require separate review and truthful trust metadata. No local candidate receipt selects the image for deployment.

The [0.3 local candidate receipt](strukturbo-nautobot/qualification-0.3.0.json)
binds the tested image to build recipe commit `8b2e5a22e1d704cb649033fcba5dcc89c107b33b`
and merged bootstrap app source `4c2995202f1b5e1febbc893ac7477d1bca059711`.
Later receipt/documentation commits do not claim that the image was rebuilt from
them. Installed qualification passed 90 app tests without source injection, followed
by TLS, HTTPS/static/login, worker/scheduler and backup queue checks. Local containers
regression passed 360 tests and metadata validation covered 97 images.

Bootstrap's separate `dns-identity-transition-qualification.json` records migration
from the new two-app synthetic baseline and independent pre-change/post-change
PostgreSQL/media restores. Pre-change restore checks exact rows/sequences, media,
account/login, key and app schema. Full runtime checks ran on post-change restore,
which also retains permanent DNS UUIDs/bindings, retired reservations and reviewed
request replay. The receipt binds both OCI archives, matching wheel, source archives
and raw logs retained in the bootstrap workspace. Existing installed 0.2 hardware
state and exact retained live original recovery are outside this new rehearsal.

No image was published or selected for live deployment. Bootstrap's production
registry descriptor remains the historical 0.1 contract; live 0.3 use needs reviewed
selection/rollout support and independent recovery acceptance before inventory/ID
imports. All commits for this local qualification use `[skip ci]`.
