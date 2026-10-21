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
`timeout` and existing Skopeo tooling. No new download or package-installation
path is added: the existing signed Ubuntu build-tool installation is unchanged;
missing Docker-side runner prerequisites fail closed. Hosted-runner packages
lack independent project-pinned checksums: this is an explicit runner-environment
integrity exception, not an invented pin. Actual Docker/containerd/systemd
versions are recorded. Existing runner/tool Renovate ownership in
`.github/automation.yml` is unchanged; image/payload pins and managers are
unchanged. New backend/helper source files are global build inputs.

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
and draft PR #429's separate systemd/delegation fixture. Strict OOM, clean-control,
lifecycle and cleanup assertions remain. DockerLens/BoxFerry's historically
shared outer stores have a different contract; this Python private-store adapter
is not copied from or imposed on those callers.

Runtime/action/test changes match the main publication workflow and may select
every image. A merge can publish images and finalize releases after its gates.
Non-publishing PR checks do not authorize that action: obtain publication
authorization before merging. Never change the publisher or skip its gates to
evade this boundary.
