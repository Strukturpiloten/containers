# Upstream release notifications and updates

The **Monitor upstream releases** workflow runs daily at **06:13 UTC** (08:13
Berlin summer time; 07:13 winter time). GitHub may delay scheduled jobs. It also
supports manual dispatch with `dry_run` enabled by default. A dry run produces a
release-plan artifact and summary without creating issues/PRs or executing
downloaded binaries.

## New compatibility lines

Discovery reads stable [Podman releases](https://github.com/podman-container-tools/podman/releases)
and the official [Docker Engine static archive indexes](https://download.docker.com/linux/static/stable/).
Docker candidates must have both Engine and rootless archives for AMD64 and
ARM64. Drafts, prereleases and incomplete releases are excluded. Source errors
fail the run; an unavailable API is never reported as “no new releases”.

The monitor compares releases with existing payload definitions, starting at
the oldest tracked line. A missing Podman **minor** line or Docker **major** line
creates an assigned issue labelled `upstream-release`. Docker 20.10 remains a
fixed minor compatibility line. Existing image families are retained.

Each issue includes release links and an integration checklist. Repeated daily
checks do not create duplicates. A newer release in the same missing line adds
one update comment without overwriting a maintainer's checklist. A closed issue
records a decision and is not automatically reopened or recreated.

Assignees are configured in `.github/upstream-releases.json`. Assignment generates
GitHub notifications; email delivery depends on each account's notification
settings. New image families still require implementation and review.

## Existing image updates

Renovate continues updating patches within the existing Podman minor lines.
For Docker, the monitor proposes updates within each existing major line (or
20.10). Active legacy compatibility images can receive upstream releases in
their own line; updates are skipped when all consumers have disabled admission.

Native AMD64 and ARM64 jobs download the official Engine/rootless archives and
inspect their binaries using `--version`. These jobs have read-only repository
permissions and never receive the PR automation credential. Archive hashes
record the downloaded HTTPS content; they are not upstream signatures.

Both architectures must agree on Engine, CLI, containerd, runc, RootlessKit and
recorded source revisions. A separate job validates this evidence and updates
the payload, all four archive hashes, both image versions/descriptions, component
provenance and generated catalogue together. It never executes archive binaries.
Image names and lifecycle settings are preserved.

Patch PRs enable platform auto-merge and pass normal PR CI and merge-queue checks.
Minor PRs require review. Queued candidates are left alone, and branch updates
never force-push over contributor changes. A rejected release is not proposed
again every day. Conflicts, inconsistent evidence and CI failures require
investigation; automation does not bypass them.

## One-time PR credential setup

The notification job uses the built-in `GITHUB_TOKEN` with `issues: write`.
Docker PR publication uses the repository secret **`RELEASE_AUTOMATION_TOKEN`**.
Use a dedicated repository-scoped bot credential with **Contents**, **Pull
requests**, and **Issues** read/write access. A GitHub App installation token
must be refreshed before it expires; do not store a short-lived token and expect
it to work indefinitely. A fine-grained PAT also requires renewal before expiry
and any approval required by organisation policy.

For a dedicated fine-grained PAT:

1. Create it under the bot account's **Settings → Developer settings → Personal
   access tokens → Fine-grained tokens**. Select `Strukturpiloten` as resource
   owner and grant access only to `containers`, with the three permissions above.
   Set an expiry and arrange renewal; obtain organisation approval if required.
2. Open this repository's **Settings → Secrets and variables → Actions → New
   repository secret**. Name it `RELEASE_AUTOMATION_TOKEN` and paste the token
   directly into GitHub's secret field.
3. Run **Monitor upstream releases** on `main` with `dry_run=false`. Check that
   the Docker update PR starts normal CI and patch updates enter the merge queue.

This separate credential is required because GitHub's built-in Actions token
[cannot add PRs to a merge queue](https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/automate-dependabot-with-actions#enabling-automerge-on-a-pull-request).
It also lets pushes/PR creation trigger normal CI without manual workflow
approval. No host credential is copied into repository secrets by this tooling.
The credential is available only to the final PR job on the default branch.

Keep repository auto-merge, `Required CI`, and the merge queue enabled. A missing
credential fails the PR job explicitly while release notifications can still
run. Do not replace it with `GITHUB_TOKEN` or bypass checks to work around that
failure.

## Operations

Open **Actions → Monitor upstream releases → Run workflow** on `main`. Start
with `dry_run=true` to inspect the plan. Use `dry_run=false` for notifications,
native probes and update PRs. The workflow retains its plan and native evidence
for seven days. It serializes scheduled/manual executions to avoid concurrent
issue and branch updates.

Inspect failed discovery or probe steps before retrying. An incomplete upstream
publication can become eligible on the next daily check. If PR creation or queue
entry fails, inspect the dedicated token's expiry, repository selection and
permissions. If CI fails, investigate the affected build; keep its required
checks enabled.
