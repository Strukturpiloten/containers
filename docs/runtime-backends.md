# Native smoke-test outer runtimes

`scripts.runtime_tests --outer-engine` selects a test caller's outer runtime,
independently of the image's inner `tests.docker.mode` or `tests.podman.mode`:

| Selection | Docker profile | Podman and application profiles |
| --- | --- | --- |
| `podman` (local default) | Podman | Podman |
| `docker` | Docker | Docker |
| `profile` (explicit GitHub caller) | Docker | Podman |

Unknown selections/profiles fail closed; there is no engine fallback. The shared
action selects `profile` after Buildah constructs the architecture OCI archive.
Inner rootless execution does not imply a rootless outer runtime.
Local development commands select `--outer-engine podman` explicitly; the local
`test-podman-image` caller also supplies that selection internally.

## Private Docker boundary

The Docker backend requires an explicit OCI archive and rootful execution on a
Linux systemd/cgroup-v2 host. It never uses ambient Docker/containerd sockets,
client contexts or credentials. Invocation-owned containerd root/state/socket and
Docker data/exec/config/socket paths are verified before image import. Skopeo
converts the OCI transport; the image configuration digest and architecture must
remain unchanged. Actual runtime versions and root identity are observed.

Transient services, not installed units or global daemon configuration, run both
daemons. Their processes and every outer container belong to one nonce-named
slice. Exact container IDs, labels, argv, UIDs, live cgroup placement and the
slice inode bind ownership. A separate expiry service acknowledges the original
monotonic deadline before workloads start; it stops that inode-bound slice even
if the Python caller is killed. Startup does not renew the aggregate budget or
consume its cleanup reserve. Killing sudo or only dockerd is not cleanup proof.
The original 1800-second aggregate includes startup, workloads and cleanup.
Cleanup commands are clamped to its remaining allowance; expired or late-returning
commands, store removal and completion envelopes cannot produce a passing result.

One task-owned bridge is checked for overlapping host routes before and after
creation. Docker-managed iptables, forwarding and masquerading changes are
disabled. Userland-proxy and the original published-localhost, inner-network and
DNS assertions remain; there is no host-network substitution. Actual proxy,
route, namespace and workload behavior still requires native qualification.

The existing observed 12 GiB budget covers private storage and transport files.
Cleanup removes exact resources, drains the complete slice and verifies kernel
cgroup, bridge and mount absence before deleting storage. Unknown ownership or
incomplete teardown retains storage and a failed cleanup result alongside the
original error. Global prune and ambient-store cleanup are prohibited.

## CI prerequisites and evidence

Docker-selected jobs require Docker CLI/daemon, containerd, systemd, `ip`,
GNU Coreutils `timeout` and existing Skopeo tooling. Before native services or
disk sampling, the existing command owner qualifies `gnutimeout` when present,
otherwise `timeout`, using a strict numeric GNU version banner. A selected
non-GNU, malformed, missing or failing provider is rejected without trying a
different provider. The canonical absolute executable is retained privately for
the invocation and reused by the privileged command watchdog, isolated root
diagnostic guard and disk sampler; root does not resolve a different executable.
Public evidence contains only `gnu-coreutils`, its numeric version and the
`prefixed`/`unprefixed` path kind, never the executable path or raw provider output.
After admission, public launch errors, command/sampler records and final evidence
also redact the retained path and its escaped spellings, including sudo errors
and late evidence rewrites. Exit statuses and unrelated actionable diagnostics
remain available; native parser return values, argv and held binary fixture
streams are not rewritten.

Ubuntu 26.04 supplies GNU Coreutils in the official parallel
[`gnu-coreutils` package](https://packages.ubuntu.com/resolute-updates/amd64/gnu-coreutils/download)
(`/usr/bin/gnutimeout`); a transitional `coreutils` package version does
not identify which implementation owns the unprefixed executable. Do not switch
the runner's default utilities or accept an alternative provider's exit status
as proof of descendant termination. The strict offline owner-death controls
still require both the guard and query to die by SIGKILL before the original
two-second deadline, followed by owned-process/group absence and reaping.
Actual runner presence and native behavior require refreshed exact-candidate CI
evidence; offline admission alone does not qualify a hosted runner toolchain.

No new download or package-installation path is added: the existing signed
Ubuntu build-tool installation is unchanged; missing Docker-side runner
prerequisites fail closed. Hosted-runner packages
lack independent project-pinned checksums: this is an explicit runner-environment
integrity exception, not an invented pin. Actual Docker/containerd/systemd
versions are recorded. This is an existing OS-provided prerequisite, not a new
download, package declaration or tool-version pin. Existing Renovate runner
extraction owns `(AMD64|ARM64)_RUNNER` in `.github/automation.yml` through the
`github-runners` datasource; `.github/renovate.json` groups those upgrades as
`GitHub Ubuntu runners`. Those definitions, generated consumers, image/payload
pins and managers are unchanged; no duplicate manager is added. The shared
resource-budget helper joins the backend/diagnostics sources as a global build
input so provider-policy changes select every consuming runtime image.

Additive `host.outerEngineSelection` and `host.outerRuntime` evidence does not
change inner mode or archive identity. CI admission derives the expected engine
from the exact profile and requires explicit `profile` selection, observed
versions, rootful private storage and, for Docker, a private Unix endpoint.
Podman version fields are never attached to Docker evidence.

An early rootless Docker launch failure may add explicitly non-acceptance
diagnostics. Read-only inspection is limited to the held, owner-verified
container through its private endpoint. Only closed privilege, AppArmor,
security-option and exit-state fields are recorded; raw metadata and stderr
are not published. A current-boot kernel journal query is confined to the
launch-to-failure window, with 64 records plus an overflow sentinel and a 64 KiB
capture limit. Only exact RootlessKit AppArmor user-namespace-denial record
counts or an unavailable reason are retained, never raw journal messages.
The fixed root-side reader owns a separate query process group, kills that
held group before reaping its direct child, and verifies group absence before
acknowledging teardown. Reaping a sudo/timeout launcher or observing exit 137
alone is not cleanup proof. Missing acknowledgement remains unverified.
An independently deadline-bound root watchdog inside that query group remains
active if the reader owner dies. Unverified query teardown blocks another
diagnostic capture and retains this invocation's private store, even after the
independent container/network/service/slice cleanup attempts. A later
observation cannot clear earlier lifetime uncertainty.
These are host-task-window observations, not proof of container causality.
The whole diagnostic attempt has a five-second cap within the original runtime
deadline, without consuming the 60-second cleanup reserve. Missing, truncated,
late or zero-count observations cannot qualify a prerequisite, waive a test,
or turn the original failure into a pass. No host security policy is changed.

Offline controls do not qualify either native architecture or resolve issue #344
and draft PR #429's systemd/delegation fixture. Its newer clean-control and OOM
diagnostic source is integrated with the explicit outer-engine policy here:
both independent fixture phases use Docker for GitHub's `profile` selection,
and isolated Podman for the local `podman` selection. Neither phase falls back.
Docker's aggregate watchdog is clipped to the existing phase deadline; startup,
cleanup reserve and the original pair deadline are not renewed. The pinned source
archive remains accounted outside both private stores and is verified across loads.

Only validated metadata for the reviewed systemd fixture can bind the systemd
launcher before containers exist. Run flags cannot opt a direct profile into
descendant admission. Docker uses private cgroup namespaces and bounded guest
runtime tmpfs mounts, without Podman's crun/systemd/annotation options. The
original CID-owned outer scope and private slice inode must still match when
guest PID 1 moves into a slash-bounded descendant. Resource limits are read at
the original outer boundary, independently of the PID 1 leaf. Physical teardown
still removes exact resources after an abnormal strict orderly shutdown; that
shutdown remains a failure even when removal succeeds.

Podman retains its complete existing conmon marker/PID custody observer. Docker
state is retained with explicit backend-not-applicable conmon sources and
unresolved attribution; no conmon identity or marker is synthesized. Strict OOM, clean-control,
lifecycle and cleanup assertions remain. DockerLens/BoxFerry's historically
shared outer stores have a different contract; this Python private-store adapter
is not copied from or imposed on those callers.

Runtime/action/test changes match the main publication workflow and may select
every image. A merge can publish images and finalize releases after its gates.
Non-publishing PR checks do not authorize that action: obtain publication
authorization before merging. Never change the publisher or skip its gates to
evade this boundary.
