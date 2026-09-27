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

- `scripts/container_engine.py`: CLI, planning, and workflow orchestration.
- `scripts/workflow_config.py`: canonical automation settings.
- `scripts/build_payloads.py`: private payload validation and evidence-bound transfer.
- `scripts/promotion.py`: publication identity and freshness ordering.

Rollback uses an expected-current-digest guard. Registry tag updates are not an
atomic compare-and-swap operation: coordinate manual publishers and queued runs
when performing an incident rollback.
