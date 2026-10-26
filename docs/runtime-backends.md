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

### PR492 compile-only user-namespace observation

The dedicated userns-dryparse CI job is restricted to same-repository PR492 on
TheRealBecks/issue442-main-reconciled, executing the workflow's immutable merge candidate on the
AMD64 Ubuntu 26 host. Actual checkout HEAD must equal GITHUB_SHA; the source-checked PR head is
recorded separately and verified as the merge's second parent using fixed read-only Git without
replacement objects or lazy fetching. It independently checks the event, checkout, run/attempt,
host distribution, AppArmor controls,
kernel features and process capabilities. Its artifact has consumer
containers-ubuntu26-userns-dryparse, scope hostcompile-only and qualification none.
The planned fixture is docker-20.10-rootless, but no image build, container run, bootstrap,
policy load or host-policy change occurs. Ordinary smoke jobs and Required CI are unchanged.

[The active source manifest](../.github/docker-userns-policy-source.json) pins the unchanged
DockerLens TheRealBecks/issue127 candidate by commit, exact builder/helper dependency-closure
sizes and hashes, and MPL-2.0 license bytes/provenance. Public HTTPS retrieval accepts only those
immutable allowlisted resources, without credentials or redirects, into private nonsymlink custody.
An isolated non-root Python child invokes only the pure profile_bytes builder. The historical
dockerlens-127 profile-name prefix is only an identifier, not DockerLens consumer authority:
the actual Containers run/attempt and fresh nonce bind it. The policy name and ABI-4 bytes are not
rewritten; no native acceptance receipt or old producer admission is reused.

The preinstalled, root-owned regular ELF parser must be exactly 5.0.2, without SUID/SGID or file
capabilities. The isolated child sets and verifies NoNewPrivs=1 and zero effective, permitted,
inheritable and ambient capabilities before same-process exec; a separate closed receipt channel
is closed before exec. The capability bounding set need not be zero and supplies no admission.
Fixed options bypass config/cache, select single-process compilation, explicitly enable all
warnings and make them fatal, bind the trusted base/include directory, and skip kernel loading.
Exact canonical bytes are stdin; there is no policy-file operand or fallback. Relevant kernel
namespace and policy-version features must be known. Parser/ABI-4 and feature bytes, identity and
hashes are checked before/after each query; the artifact retains exact bounded ABI-4 bytes, selected
host facts, and only output counts/hashes and closed failure reasons.

Each child has CPU, output, wall-time and owned-group termination/reaping bounds; the observation
budget is 30 seconds, output is at most 128 KiB, and the workflow step has a one-minute timeout.
Local tests mock parser, network and kernel observations. Substitution, drift, warnings, unsupported
or missing facts, timeout/cancellation or uncertain child cleanup refuse the observation.
Even a successful compile is nonqualifying: it gives no guest label, native runtime support,
ARM64 evidence or attribution for the earlier RootlessKit failure. Loading policy needs a separately
reviewed cohort and independent finalizer; Stage 1 has no load-stage transition.

The manifest is the unique Renovate owner for the active DockerLens github-digest branch pin and
official apparmor/apparmor GitLab-tag parser version. Both share mandatory dashboard/human review
and disabled automerge; file hashes and parser contract must be reviewed together. Mismatched bytes
or an unreviewed parser-version change fail closed. Historic evidence has no matching manager path.
Existing checkout/upload Action pins and their template/generated managers are reused. Observed
preinstalled parser/ABI hashes use the explicit diagnostics-system-tool integrity exception, not
vendor checksums; no parser is downloaded or installed. The upstream
[5.0.2 contract](https://gitlab.com/apparmor/apparmor/-/tree/909affc32a13d14ae3a7ccf44d325ae63ce11baf)
defines only this compile command; no loaded cohort has been admitted.

### Validate-host diagnostics

The validate job captures a bounded, read-only security snapshot before repository checks and retains
only `docker-runner-security.json` for seven days. This describes the AMD64 validate-job host and the
collector process; it cannot establish the security context of a guest, RootlessKit, an ARM64 job,
or a native smoke-test job. Later experiments must collect their own cohort. The snapshot cannot
attribute a launch failure, qualify native support, or waive existing checks or runtime budgets.

The closed JSON records kernel release and architecture, AppArmor enablement and its restriction
on unprivileged user namespaces, the user-namespace limit, and optional collector-process Seccomp,
NoNewPrivs and profile kind. It excludes hostnames, UIDs, environment values, raw paths, profile
names and raw command output. Unavailable or malformed observations have explicit unknown states.
Only the existing fixed system `apparmor_parser --version` may run, without elevation and only from
a non-root collector after regular-file, ownership, permissions and ELF checks. Its bounded binary
hash and public file identity are checked around the query; its version is an observation without
a minimum-version admission rule. The query has a one-second limit, a 4 KiB output limit and owned
process-group cleanup. The complete collector has a four-second observation budget and emits at
most 8 KiB of JSON. It never loads policy, changes sysctls, installs tools or invokes a runtime.

Unavailable facts are ordinary JSON; collector implementation and artifact-upload failures are
not masked. The existing pinned `actions/upload-artifact` reference is reused. Its Jinja reference
is already covered by Renovate's pinned-action custom manager and its generated workflow reference
by the GitHub Actions manager. No pin or manager changes are needed. The optional OS-provided parser
uses the existing runner-environment integrity exception: no parser version is selected and no
independent package checksum is claimed.

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

## Hosted unused userns custody seam

The PR-492-only `userns-custody-unused` AMD64 Ubuntu 26 job exercises two real
unused ownership cycles: normal close and deliberate loss of the exact root
coordinator after durable arm. An independent root observer authenticates the
original service, waits for its finalization and process/cgroup termination,
and disposes only known custody/control leaves. Each cycle has at most 120
seconds, with work ending 60 seconds before its original final deadline. The
second cycle also remains capped by the original 240-second experiment
allowance recorded before checkout/setup; bootstrap never renews it. Unknown
start, identity, lifetime or disposal results fail and retain owned data. The
root-only immutable `start.json` binds the exact arm intent, generation,
control/custody identities and original handshake end before the single service
start. The foundation intent-read checks W; the service binder checks the
stricter original handshake end before and after intent-read and READY. ACK
binds that end and the protected record hash; service startup never derives a
fresh handshake allowance.

The canonical CI template contains the sole fixed root-bootstrap verifier. An
unprivileged driver supplies a bounded connected Git commit/tree/blob proof
and fetches the existing pinned DockerLens source closure. Root verifies the
workflow-selected immutable merge commit, ordered event parents, exact helper
closure and source bytes before copying or importing helpers. Root uses the
preinstalled root-owned system Python with isolated/no-site execution; uv and
checkout code run only unprivileged before this verification. The system
interpreter, standard library, environment clearer and systemd clients are an explicit OS trust-base
integrity exception, with actual versions, hashes and fresh identities recorded;
no project/vendor checksum or new downloaded tool is claimed. Helper/source
hashes and fresh identities are rechecked across both cycles.

The installed-tool scan records its first refusal in `systemToolsFailure`, with
closed tool (`SYSTEMCTL`, `SYSTEMD_RUN` or `ENV`), operation-site and
failure-category identifiers (`REFUSED`, `OS_ERROR`, `TIMEOUT`, `DECODE`,
`EMPTY_OUTPUT` or `INTERNAL`). Categories describe the failed operation, without
inferring its cause. This diagnostic
survives a partial scan or a later close failure; accepted `systemTools` facts
remain separate. It includes no exception text, command output or extra host
observations. The scan still stops at its first failure and uses the original
commands, deadlines and before/after tool comparison. The diagnostic itself
adds no admission or runtime authority.

A hosted observation refused `ENV / READ_LINKS / REFUSED`: the initial file
identity failed the single-link predicate. It did not record the numeric link
count or establish a packaging cause. The three fixed preinstalled OS tools
(`systemctl`, `systemd-run` and `env`) are borrowed executables, so their private
reader accepts a positive link count that remains stable in the full identity
rechecks. Only those fixed selections reach this policy. The shared `read_root`
entrypoint still requires exactly one link, even for a directly supplied OS-tool
path; parser, interpreter, source, custody and control files gain no exception.
Root ownership, trusted path traversal, no-follow open, regular-file and mode
checks, byte bounds, ELF/version checks, hashing, full descriptor/path identity
rechecks (including link count and timestamps), command arguments and budgets
remain in place. This bounded OS-tool contract does not establish native runtime
qualification or claim that the earlier runner had multiple links.

`.github/docker-userns-unused-admission.json` is a manually reviewed semantic
admission based on the audited Stage-1 Ubuntu 26 observation, bound to the
active source manifest and helper contracts. It never compares historical
inodes, PIDs or boot IDs. Source, parser-contract or helper updates invalidate
it. The existing Renovate source/parser manager remains the single pin owner;
humans must review and update admission rather than automatically rewriting
host fingerprints. The helper version authority is the selected Git tree, so
there is no self-referential commit pin. The new template/generated job reuses
the existing checkout/upload Action pins and runner configuration; ordinary
validation, dry-parse and publishing consumers retain their existing behavior.

The artifact reports `qualification=none`, `policy_load_run=false` and
`container_run=false`. Its `boundaryKind=unused-coordinator` identifies the
actual coordinator exclusion cgroup; it proves no Docker runtime-slice
placement. No profile load/remove, container operation, runtime API, sysctl
change or persistent unit is involved. A fixed credential-dropped child only
queries the held parser's version or attempts a write to a synthetic root-owned
leaf. Deliberate coordinator SIGKILL does not test cancellation of the entire
GitHub job or runner loss. Offline tests use synthetic providers; hosted
execution and an independent exact-source artifact audit are still required
before considering a subsequent load/guest experiment.

The bootstrap supervises only its fixed verified observer argv. It requires one
kernel thread, no pre-existing children and waitable SIGCHLD semantics, then
sets and verifies a process-local Linux subreaper. Capture enforces stdout and
stderr limits while the process is alive and requires both EOFs, the recorded
observer exit status and kernel ECHILD before acceptance. Timeout, cancellation,
overflow or unknown child membership remain failures. Teardown uses the same
original D, with a fixed reserve inside it; no positive minimum renews an expired
allowance. Only this process's bounded direct/adopted child list is considered,
and waitid/pidfd membership precedes signals. There is no process-wide scan or
process-group sweep. Independent systemd owners remain outside this descendant
custody and retain their existing lease/deadline and explicit cleanup proof.

The fork coordinator is held immediately and cannot start custody work until
its parent validates its exact identity and grants its pipe handshake. Failure
teardown may terminate that still-owned child before arm; this never counts as
the deliberate post-arm SIGKILL acceptance cycle. A failed pidfd or handshake,
observer error or cancellation still attempts exact-child termination/reaping
before original D, retaining unknown completion honestly. Cancellation wins
over a pending normal close, including cancellation seen during owner
observation. A cancellation first seen during the durable close or receipt write
cannot publish accepted normal evidence; a final post-write check refuses
success without overwriting terminal metadata. The initial write-denial probe
intersects its parent five-second work and six-second cleanup caps, captured
once at phase entry, with original bootstrap W/D. The child's independent alarm
grants no new allowance. Handoff/event/budget files open nonblocking and must
pass regular-file, ownership, link and bounded stable-read checks before use.

Observer capture and the top-level observer decide their final return only
after restoring prior signal handlers and propagating sticky cancellation.
Known status, EOF and completed child cleanup do not turn cancellation into
accepted success. No additional cleanup budget is created by these checks.

The complete fixed root program is carried by the canonical step's literal
`FIXED_ROOT_BOOTSTRAP` environment value. The short Bash step rejects an empty
value and marks it readonly before any workspace command. Its existing caller
capture function passes that one quoted value to isolated system Python with
`-c`, the same nine following arguments, stdin from `/dev/null`, and job-user
stdout capture. The decoded program, including the terminal error handler,
remains unchanged; the YAML carrier indentation and its historical raw hash
change. The program is neither loaded from the workspace nor evaluated by Bash.

This keeps the Bash transport small while retaining the full workflow and
ShellCheck validation. Published actionlint 1.7.12 writes a `run` script to its
ShellCheck pipe before starting the reader; an oversized script can block on
the available pipe capacity. Moving only the immutable program into the literal
environment carrier avoids that defect without disabling checks, changing host
settings or claiming an unreleased fixed tool version. Earlier cancelled or
timed-out validation attempts remain nonpasses.
