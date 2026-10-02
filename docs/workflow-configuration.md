# Workflow configuration and updates

`.github/automation.yml` is the source for native runner labels, Python, uv, Syft,
and actionlint versions. `scripts/workflow_config.py` validates it and supplies
native architecture runners to the build planner. Literal workflow YAML is
rendered from `.github/workflow-templates/*.yml.j2`.

After changing configuration or a template, run:

```sh
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

CI checks every generated workflow, Python regression tests, and actionlint.
`Required CI` remains the branch-protection check. Treat a runner upgrade as an
infrastructure change: both native architecture builds and runtime contracts must
pass before merging. Ubuntu 26.04 labels are listed in GitHub's
[runner inventory](https://github.com/actions/runner-images#available-images).
The actionlint compatibility allowlist covers only those two labels until the
linter's built-in inventory catches up; successful scheduling and builds are
verified by GitHub CI.

Renovate updates canonical tool/runner values and the corresponding literals in
generated workflow YAML in the same dependency update. Its custom template
manager tracks action tags and commit digests together, alongside the native
manager's generated-workflow references. There are no privileged post-upgrade
commands. A missed source or generated update fails the generation check rather
than silently changing workflow behavior. Manually regenerate on the Renovate
branch if an update cannot be represented by its configured managers.

## Automatic dependency merges

The [upstream release monitor](upstream-releases.md) creates assigned issues for
missing Docker/Podman compatibility lines and proposes verified Docker Engine
updates. Renovate continues maintaining existing Podman patch lines and pinned
base-image digests.

Compatible patch and digest updates use Renovate's existing, narrowly scoped
automerge rules. A native GitHub merge queue removes the repeated rebase race:
after one PR merges, GitHub tests the next queued candidate against the new
`main`, without waiting for another Renovate execution. Renovate's platform
automerge adds eligible PRs to the queue. Real conflicts and failed checks still
need investigation; neither is overridden by the queue.

`Validate containers` runs on both `pull_request` and `merge_group` events. Queue
validation compares `merge_group.base_sha` with the checked-out queue revision,
so all changes in the candidate select their affected images and dependents.
Version validation uses that same base. Payloads, native architecture builds,
runtime checks, vulnerability admission, and the fail-closed `Required CI`
aggregate run as usual. Queue validation does not publish images; publication
starts after the merge reaches `main`.

Queue admission requires repository write access. Adding a PR to the queue
authorizes its combined code to run the privileged nested-container runtime
checks, including when that PR originated in a fork. Review fork changes before
enqueueing them. Queue validation uses read-only workflow permissions and does
not receive publication credentials.

### One-time repository activation

Workflow support must be merged before enabling this rule. An administrator
then opens [Settings → Rules → Rulesets](https://github.com/Strukturpiloten/containers/settings/rules)
and creates an active branch ruleset named `Merge queue`, targeting the default
branch, with an empty bypass list and **Require merge queue** enabled.

Use these initial settings:

| Setting | Value |
| --- | --- |
| Merge method | Squash |
| Build concurrency | 1 |
| Only merge non-failing pull requests | Enabled (`ALLGREEN`) |
| Status check timeout | 180 minutes |
| Minimum pull requests to merge | 1 |
| Maximum pull requests to merge | 1 |
| Wait time for minimum group size | 0 minutes |

Keep **Allow auto-merge** enabled in the repository's general settings. Keep the
existing `Required CI` ruleset and organisation review, history, and code quality
rules. The queue validates the current integration result, so eligible PRs do
not need repeated manual branch updates. These settings are repository state,
not something that merging the workflow file enables automatically.

After activation, check the merge queue and Actions for `merge_group` runs. A
successful candidate should merge and the next candidate should start without
another Renovate rebase. If there is no queue run, first check that this rule is
active, the PR has auto-merge enabled, and its required PR checks passed. If a
candidate fails, inspect its failing job; do not bypass `Required CI`. Renovate
still resolves eligible branch conflicts and discovers new upstream versions on
its normal runs. No daily rebase-button operation is part of this process.

Matching Docker and Podman distro digest inputs share a PR per upstream image
and release line. Existing Docker-prefixed group names are retained for branch
continuity. Distinct distro releases and the source-built Podman Fedora-minimal
base remain separate. Manual-review policies for other dependency types remain
unchanged.

# Build and publication boundaries

Each image's reusable publication workflow waits for that image's native builds.
A failed image does not block unrelated images. Up to four image workflows run
at once, each with at most two architecture builds; PR builds run eight at once.
Dependency stages still enforce order. A selected dependency without a valid
same-run result causes its dependent build to fail.

`build.payload` optionally references a private payload manifest. Payload builds
are deduplicated by manifest and architecture, with one OCI archive shared by
rootful/rootless consumers in the same workflow run. The importer verifies source
revision, manifest hash, architecture, and archive hash before importing into
local build storage. There is no registry fallback or public release for these
payloads. A changed payload must be declared in each consumer's `inputs`.

Archive transport artifacts last one day; they are intermediate workflow data,
not a long-term release record. Public image digests and release evidence are
produced by the normal publication and finalization jobs.

# Modules

The [operations guide](operations.md#module-map) maps the current planning, payload, runtime, vulnerability, publication, and maintenance modules to their responsibilities.

- `scripts/container_engine.py`: CLI, planning, and workflow orchestration.
- `scripts/workflow_config.py`: canonical automation settings.
- `scripts/build_payloads.py`: private payload validation and evidence-bound transfer.
- `scripts/promotion.py`: publication identity and freshness ordering.

Rollback uses an expected-current-digest guard. Registry tag updates are not an
atomic compare-and-swap operation: coordinate manual publishers and queued runs
when performing an incident rollback.
