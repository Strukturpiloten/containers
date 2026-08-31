# Container repository architecture

This document is the operational design for the Strukturpiloten container monorepo. It describes the repository as it exists today. Image-specific runtime contracts belong in the corresponding `images/<family>/…/README.md`.

## Design goals

- Keep public company images in one reviewable repository.
- Build OCI images for the architectures declared by each image.
- Rebuild supported operating-system packages every day to pick up security fixes.
- Pin external build inputs and make published artifacts traceable to source.
- Build internal image dependencies in a deterministic order and consume them by digest.
- Require no manual release work after an approved metadata change reaches `main`.
- Keep image-specific behavior close to its Containerfile while sharing only genuinely common files.

## Layout and ownership

```text
images/<family>/<image>/
  Containerfile             # when the recipe is image-specific
  container.yaml            # required metadata for one public image
  README.md                 # runtime and maintenance contract

images/<family>/<shared>/   # recipes/configuration shared within one family
shared/                     # files shared across families
scripts/                    # build-plan, validation, publishing, and release logic
tests/                      # repository policy and automation tests
.github/workflow-templates/ # source templates for generated workflows
.github/workflows/          # pull-request and publishing entry points
```

One `container.yaml` represents one public registry image. A shared Containerfile does not imply a shared or separately published base image. Publish an internal base only when dependent images need its exact artifact as a real runtime dependency; do not publish one merely to reduce duplicated source text.

## Image metadata

`container.schema.json` is the machine-readable format contract. The repository validator also checks properties that JSON Schema cannot express conveniently: unique names and registry references, valid paths, complete external/internal dependency mappings, digest-pinned runtime bases, input coverage, supported architectures, and an acyclic internal dependency graph.

The important fields are:

| Field | Meaning |
| --- | --- |
| `name` | Repository-unique image name and workflow identifier |
| `version` | Maintained Strukturpiloten image compatibility line |
| `image` | Full GHCR repository without a tag |
| `title`, `description` | Per-image OCI metadata and human summary |
| `build.context`, `build.containerfile` | Build inputs relative to the repository root |
| `build.architectures` | Architectures that must build and publish |
| `build.runtimeBaseArg` | Build argument that identifies the final runtime base |
| `build.args` | Pinned image inputs and static build values |
| `dependencies` | External image pins and internal image edges |
| `inputs` | Paths that select this image after a source change |

Every external or fallback internal image value includes a `sha256` digest. The tag remains in the reference for readability and Renovate version detection; the digest is the build identity.

The `version` field describes the Strukturpiloten image contract, not necessarily the version of a program installed inside it. For example, a distro compatibility image can remain on image contract `v1.0.0` while its distribution updates Podman from one downstream package revision to another. Image documentation must state this distinction and provide a way to inspect the installed revision.

## Build selection and dependency stages

The planner loads every metadata file and calculates a directed graph from `dependencies.internal`.

- A pull request or push selects images whose `inputs` match changed files.
- A change to a global build input selects every image.
- Reverse dependencies are added when a selected internal base changes.
- A daily schedule selects every image unless it explicitly opts out.
- A manual dispatch can select all images, an exact image, or a family derived from the directory layout.
- Independent images build in stage 0. Internal dependency depth creates later stages automatically.

The generated workflow contains the number of stages required by the current graph. This is why `.github/workflows/publish-images.yml` is checked in but not edited by hand: `.github/workflow-templates/publish-images.yml.j2` and metadata are its sources.

Each architecture builds on a native GitHub runner with Buildah, `--pull-always`, and a source-commit timestamp. Scheduled and manually forced builds also use `--no-cache`. Per-architecture OCI archives are short-lived workflow artifacts; they are not releases.

When a later-stage image depends on an image built in the same run, it reads the verified result artifact and uses `image@sha256:<index-digest>`. Pull-request smoke builds and isolated dependent rebuilds use the digest-pinned fallback declared in metadata. Mutable internal tags are never dependency inputs.

## Verification and publication

Publishing uses a verify-before-promote sequence:

1. Build every declared architecture and export OCI archives.
2. Assemble and push an immutable run-specific manifest.
3. Inspect the index and record every architecture digest.
4. Generate a Syft SBOM for each architecture.
5. Sign the index with keyless Cosign.
6. Attach GitHub provenance and SBOM attestations.
7. Promote verified branch, `latest`, SHA, and declared SemVer tags as applicable.
8. Record the verified result for dependent stages.

Only the jobs that need registry, attestation, or release writes receive those permissions. Pull-request jobs have no publishing permissions.

The repository does not yet enforce a vulnerability-scanner policy. That work is tracked separately; an SBOM and signature do not by themselves prove that an image has no known vulnerabilities.

## Release and tag policy

The protected default branch is the release approval boundary. Changing an image's `version` through a reviewed pull request declares a new compatibility line. After merge, the workflow builds and verifies the image, creates the missing image-prefixed GitHub Release, and promotes the declared tags without a manual release dispatch.

Immutable identities:

- OCI manifest and architecture digests;
- unique `run-*` tags;
- verified `sha-<full-git-commit>` tags;
- the Git tag and commit associated with the initial GitHub Release.

Maintained pointers:

- branch and `latest` tags;
- exact stable and prerelease SemVer tags;
- stable minor and major aliases.

Maintained SemVer tags intentionally move after a successful daily security rebuild. This lets a readable version line receive supported base-image and package fixes. Consumers that require byte-for-byte immutability pin the digest. Consumers that want maintenance use a tag plus digest and automate reviewed digest updates.

Release finalization is idempotent. It refuses conflicting exact registry or Git tags and can reconcile a partially completed workflow without replacing an immutable source identity.

Transient publication failures have two bounded recovery layers. Idempotent registry reads, pushes, promotions, and SBOM scans make one initial attempt plus two retries, with a 120-second pause between attempts. Builds, validation, and smoke tests are not retried. If a trusted `push`, scheduled, or manually dispatched publication run still fails, the retry workflow waits 120 seconds and asks GitHub to rerun only failed jobs and their dependants. It never reruns successful jobs, excludes pull requests, and stops after two automatic reruns.

## Update policy

Renovate reads external image references from `container.yaml`, commit-pinned GitHub Actions, Python dependencies, and selected build tools. Narrow, compatible digest and patch updates may automerge only after required CI passes. Major, incompatible, and compatibility-line changes remain review decisions.

Renovate updates repository inputs; it does not update installed packages that come from a distro repository during a build. The daily no-cache rebuild and package-manager upgrade are responsible for those updates. Distro compatibility image base tags stay on their declared OS release while Renovate refreshes their pinned digests.

An old compatibility target is not automatically secure forever. Its documentation must identify vendor support boundaries. Once an OS or application line stops receiving fixes, retain it only when its testing value justifies the risk, label it as legacy, and run it in isolated CI without unrelated secrets.

## Documentation standard

Each image-family README should answer these questions directly:

1. What is the image for, and what is explicitly outside its scope?
2. Which public image names, versions, variants, architectures, and bases exist?
3. Where does the installed software come from, and who supplies patches?
4. What do the image version and native software version mean?
5. Which privileges, devices, mounts, ports, configuration, and persistent paths are required?
6. How should a CI job run the image?
7. What security boundaries and fidelity limits remain?
8. How is the image updated, deprecated, and inspected?

Use exact names and paths, small runnable examples, and tables for repeated facts. Separate current observations from durable contracts. Avoid claims such as “secure,” “production-ready,” or “fully compatible” unless the repository enforces a measurable definition.

## Local workflow

Run all validation from the repository root:

```sh
uv run --frozen --python 3.14 ruff format --check .
uv run --frozen --python 3.14 ruff check .
uv run --frozen --python 3.14 python -m unittest discover -s tests
uv run --frozen --python 3.14 python -m scripts.container_engine validate
uv run --frozen --python 3.14 python -m scripts.container_engine generate-workflow --check
```

Run `generate-workflow` without `--check` after changing dependency depth. Pull-request CI repeats these checks, smoke-builds every affected architecture, and reports the stable `Required CI` result used by the repository ruleset.
