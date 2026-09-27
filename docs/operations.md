# Build and release operations

Run these commands from the repository root. `container.yaml` is the image catalogue; the generated GitHub workflows are the execution path. Use `uv run --frozen --python 3.14` for Python commands so local planning uses the same locked dependencies as CI. The commands below that call `gh workflow run`, `gh run rerun`, `promote-image`, or `rollback-image` change GitHub or GHCR state; inspect their targets first.

## Plan and build

Validate metadata and preview a manual build before dispatching it:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine plan \
  --event-name workflow_dispatch --ref-name main --default-branch main \
  --sha "$(git rev-parse HEAD)" --scope image --target podman-5.4-rootless \
  --output /tmp/containers-build-plan.json
uv run --frozen --python 3.14 python -m scripts.container_engine plan-summary \
  /tmp/containers-build-plan.json
```

Change `--scope` to `all` (omit `--target`) or `family` with a family name such as `podman` to preview those selections. The plan expands internal reverse dependencies, allocates architecture builds to native runners, and deduplicates private payloads by manifest and architecture. The preview writes a local JSON file; it does not build or publish.

To request a real build from the default branch, run:

```sh
gh workflow run publish-images.yml --ref main -f scope=image -f target=podman-5.4-rootless
gh run list --workflow publish-images.yml --limit 5
gh run view RUN_ID --log-failed
```

A push to `main` selects changed images and their reverse dependencies; the daily schedule rebuilds scheduled images without cache. Manual `workflow_dispatch` supports `all`, one exact `image`, or one `family`. Pull requests use `ci.yml` for validation, selected smoke builds, and runtime checks without registry publication. The workflow builds private payloads first, then architecture OCI archives, then publishes the verified multi-architecture image. `build-arch-image` and `publish-image` are CI subcommands that require a plan, matrix entry, same-run artifacts, and GitHub context; use the workflow for an ordinary build.

## Test a change

Run the non-publishing repository checks before a pull request:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

For a Podman profile on a Linux host with Podman and `/dev/fuse`, `test-podman-image` builds the selected image and records runtime evidence. A source-built profile first builds its private payload locally. Use `--skip-nested` for a build and CLI check when the host cannot provide the nested-container privilege boundary:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine test-podman-image \
  --image podman-5.4-rootless --skip-nested \
  --evidence /tmp/podman-5.4-rootless-runtime-evidence.json
```

To render the declared lifecycle catalogue without build evidence, run:

```sh
uv run --frozen --python 3.14 python -m scripts.maintenance \
  --json-output /tmp/containers-catalogue.json \
  --markdown-output /tmp/containers-catalogue.md
```

Without supplied build and runtime evidence, the catalogue reports those observations as unknown rather than claiming a successful test. The CI runtime harness uses `scripts.runtime_tests` against the exact OCI archive from the architecture build. It records image name, architecture, profile, archive identity, individual checks, and overall status in a seven-day workflow artifact. Trusted repository runs can use privileged nested probes; fork pull requests cannot. Application and Docker profiles have their own metadata-driven probes. Local runtime checks launch disposable containers, so run them only on a host where that is intended.

## Diagnose and retry

For vulnerability policy failures, follow the [scanner triage guide](vulnerability-scanning.md#reproduce-a-scan-locally) before retrying. Read the failed job and the plan artifact before retrying; first check whether the automatic retry has already started. A failed payload or architecture build needs its source or runner issue fixed, followed by a new build request. Missing or mismatched same-run payload evidence fails closed; a registry tag is never used as a substitute. A failed internal dependency cannot silently switch to a mutable tag.

The `retry-failed-publish-jobs.yml` workflow automatically retries only publication or finalization failures on push, schedule, or manual runs. It waits two minutes, checks that the run is still the failed attempt, and stops after the configured attempt limit. It does not retry failed source builds or runtime checks. For a specific recoverable run, inspect it and then retry only failed jobs:

```sh
gh run view RUN_ID --log-failed
gh run rerun RUN_ID --failed
```

A rerun retains its source revision and must pass the publication identity and freshness checks. If a newer run has already promoted a different digest, the older attempt cannot move the maintained tag backward. Start a fresh build for a new source revision.

## Promotion, release, and rollback

The publish job pushes an immutable run tag, verifies its index, generates per-architecture SBOMs, signs the index, and attaches attestations. Its `promote-image` step moves eligible branch and SHA tags using the same-run build result and source identity. On `main`, `finalize-release` checks the published result, creates an image-scoped source-version release if needed, and moves the declared SemVer tags. The release action then creates a separate `<imageName>/maintenance/<runId>-<runAttempt>` release as a draft, attaches and verifies complete maintenance evidence, and publishes it. This ordering supports GitHub's immutable releases and retained-version rebuilds without modifying historical releases. The maintenance release is not marked as the repository's latest release. `*-build-result` and `*-release-result` workflow artifacts are retained for 30 days; the maintenance release asset persists separately.

Retrieve the maintenance release for the publication's recorded run identity, rather than expecting a new asset on its source-version release. Verify the asset's source, run, index and architecture bindings before using it for admission; see [image maintenance evidence](maintenance-evidence.md). A failed finalization may leave a recoverable draft. Retry the failed job so it can validate any existing asset and finish publication. If it reports an identity or content mismatch, investigate that mismatch instead of changing release immutability or removing existing releases.

Promotion is normally recovered by rerunning its failed workflow job. The underlying command requires the original GitHub run context, the immutable index digest, and the matching build-result file; it rejects a stale or unrelated run. For an operator replay *inside that same workflow context*, the invocation is:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine promote-image \
  --image ghcr.io/strukturpiloten/IMAGE --digest sha256:INDEX_DIGEST \
  --build-result IMAGE-build-result.json --default-branch main
```

To intentionally move one maintained tag back to a verified older digest, inspect the current digest and use the exact expected value as the guard:

```sh
skopeo inspect --format '{{.Digest}}' docker://ghcr.io/strukturpiloten/IMAGE:latest
uv run --frozen --python 3.14 python -m scripts.container_engine rollback-image \
  --image ghcr.io/strukturpiloten/IMAGE --tag latest \
  --digest sha256:PREVIOUS_INDEX_DIGEST \
  --expected-current-digest sha256:CURRENT_INDEX_DIGEST \
  --reason 'incident reference and reason'
```

Rollback requires an authenticated `skopeo` session with package write access. Rollback changes only the named maintained alias, not its immutable run tag or digest. Registry copy is not an atomic compare-and-swap: coordinate concurrent publishers, recheck the tag after the command, and cancel queued older runs during an incident. A later valid publication may advance it again.

## Local cleanup and evidence lifetime

The local runtime harness owns an isolated Podman store and removes its task-owned containers and image after a completed check. If runtime evidence reports `cleanupError`, resolve it before deleting the store. If a local build is interrupted, identify its exact task-owned store and check for all containers and mounts before removal. Do not run `podman system prune` against a shared/default store. For a store you explicitly created at the path below, this sequence refuses deletion while any container or mount remains in that store:

```bash
state=/tmp/strukturpiloten-build-check
test "$state" = /tmp/strukturpiloten-build-check || exit 1
containers=$(sudo podman --root "$state/root" --runroot "$state/runroot" \
  --tmpdir "$state/tmp" ps --all --quiet) || exit 1
test -z "$containers" || { printf 'store still has containers\n' >&2; exit 1; }
mounts=$(findmnt --kernel --raw --noheadings --output TARGET) || exit 1
while IFS= read -r target; do
  case "$target" in
    "$state"|"$state"/*)
      printf 'store still has mount: %s\n' "$target" >&2
      exit 1 ;;
  esac
done <<< "$mounts"
sudo rm -rf -- "$state"
```

Private payload, architecture OCI archive, and scanner debug workflow artifacts expire after one day; runtime evidence and normalized vulnerability reports expire after seven days. Published image digests, release records, and uploaded maintenance evidence are the durable audit trail. The [Podman image guide](../images/podman/README.md#build-and-test-architecture) records one build-only timing and storage measurement, including its host and storage-driver limits.

## Module map

| Module | Responsibility |
| --- | --- |
| `scripts/container_engine.py` | Validate metadata; select and plan builds; assemble, publish, promote, finalize, and roll back images. |
| `scripts/metadata_schema.py`, `container.schema.json` | Validate metadata shape before repository policy checks. |
| `scripts/policy.py`, `scripts/promotion.py` | Generate tags, compare versions, and reject stale publication identities. |
| `scripts/workflow_config.py`, `.github/automation.yml` | Validate canonical runner and tool versions used by generated workflows. |
| `scripts/build_payloads.py` | Validate private payload manifests and bind OCI archives to same-run revision, architecture, and hashes. |
| `scripts/runtime_tests.py`, `scripts/runtime_docker.py`, `scripts/oci_artifacts.py` | Run bounded metadata-driven runtime probes and verify the probed OCI archive identity. |
| `scripts/scan_sources.py`, `scripts/vulnerability.py` | Bind candidate/baseline architecture sources to digests and compare vulnerability scans against declared admission policy. |
| `scripts/maintenance.py`, `scripts/release_evidence.py` | Render the lifecycle catalogue from declared policy and supplied evidence; attach verified immutable evidence to a release. |
| `.github/workflows/ci.yml`, `.github/workflows/publish-images.yml` | Enter validation/smoke and staged publication respectively. |
| `.github/workflows/build-one-payload.yml`, `.github/workflows/publish-one-image.yml` | Build one private payload or build, publish, and finalize one public image. |
| `.github/workflows/retry-failed-publish-jobs.yml` | Retry eligible publication/finalization failures from the same workflow run. |

Edit `.github/workflow-templates/` and regenerate `.github/workflows/` with `generate-workflow` when workflow behavior changes. Keep image-specific runtime details beside each image family.
