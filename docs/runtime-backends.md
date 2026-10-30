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
only the exact before/after inner-memory hooks read the owned outer cgroup
`memory.events` and `memory.events.local` through held host descriptors. Private
Docker incarnation, process birth, owned slice, cgroup2 mount/root and scope
bindings are checked around the reads; public evidence contains hashes, bounded
counters, finite availability and monotonic windows. Missing or malformed files,
changed identities and regressing counters cannot become zero or comparable
deltas. Known optional counters (including `sock_throttled`) are retained when
present, without defaulting absent fields to zero. `memory_localevents` semantics
are retained. Other Docker hooks retain only finite OCI fields, including stopped
state and exit code, and allocate no host counter reader. These observations remain
unresolved and grant no lifecycle or OOM acceptance; they do not attribute inner,
ancestor or kernel events. Raw host operands and collector output remain private.
Conmon sources remain explicitly not applicable; no conmon identity or marker is synthesized. Strict OOM, clean-control,
lifecycle and cleanup assertions remain. DockerLens/BoxFerry's historically
shared outer stores have a different contract; this Python private-store adapter
is not copied from or imposed on those callers.

Runtime/action/test changes match the main publication workflow and may select
every image. A merge can publish images and finalize releases after its gates.
Non-publishing PR checks do not authorize that action: obtain publication
authorization before merging. Never change the publisher or skip its gates to
evade this boundary.

## Hosted unused userns custody seam

Before the unchanged root bootstrap, the same PR-492-only job also runs
`scripts/python_runtime_fd_observation.py` directly with `/usr/bin/python3 -I -B -S`
as the ordinary job user. This separate, optional fixture observes nonstdio
descriptor metadata before and after importing `_ctypes` in its own isolated
child. It does not reproduce the privileged build child's complete import order,
environment, inherited descriptors or execution context. Device/inode matches to
the known Python executable, `_ctypes` extension or mapped libffi files identify
objects only; they establish no OFD identity, descriptor origin or root-failure
cause. An absence in this fixture cannot clear the original guard refusal.

The fixture enumerates at most 32 nonstdio descriptors, including high-numbered
ones, and closes its enumeration iterator before `fstat`. It never reads arbitrary
descriptor contents or retains their symlink targets. Every snapshot explicitly
reports `state=non-atomic` and a bounded `closedDuringSnapshot` count for entries
that returned `EBADF`. The fixture's own closed enumeration descriptor may
account for one entry; no disappeared descriptor's identity or origin is proven.
An empty descriptor list, including one with a zero closed count, is not an
atomic absence proof and cannot clear the original guard refusal. Bounded
process mappings are used internally only to identify strict public system libffi paths and check
their mapped device/inode; mappings and addresses are discarded. Root-owned,
nonwritable path components, bounded symlink resolution, regular-file/mode/size
checks and stable identities surround hashing of the known public files. Each
file is at most 32 MiB; at most four libffi files are hashed. Missing, unsupported,
unsafe or changed provenance is explicitly unavailable. The hashes are observed
system-file hashes under the existing OS-tool integrity exception, not vendor
checksums. No source-package version is inferred from a libffi filename or hash;
package/version provenance remains unavailable in this observation.

The ordinary-user parent launches only its fixed isolated system Python child,
with clean environment, closed inherited descriptors and `/dev/null` stdin. It
bounds combined stdout/stderr while the child lives, attempts exact-child
termination/reaping on failure, and closes both pipes. Parent and child share
one eight-second monotonic allowance after module startup, including a half-second
cleanup reserve; neither hashing nor capture renews it. Before the import child,
the parent uses the same bounded capture helper to query only fixed
`/usr/bin/gnutimeout --version`. A strict numeric GNU banner is required; only
closed `provider=gnu-coreutils`, numeric version and `pathKind=prefixed` survive.
The two owned children run sequentially under that original allowance. Missing,
bad or unqualified providers leave the observation unavailable. No mutable PATH
selection, fallback, installation or default-utility change is introduced.

An unverifiable child wait or pipe close records `cleanup=uncertain`. The
canonical CI step additionally wraps the complete interpreter startup and
collector in fixed `/usr/bin/gnutimeout --signal=TERM --kill-after=1s 9s`, without
foreground mode. GNU process-group behavior permits normal TERM cleanup and
group KILL one second later if necessary. The initial wrapper necessarily trusts
the declared OS binary before its in-budget version check; no positive
observation is accepted without that check. Actual hosted presence and watchdog
semantics still require fresh CI evidence. The existing observed OS-tool
integrity exception covers this bootstrap trust; no package, download, version
pin or vendor checksum is added, and existing Renovate ownership is unchanged.
The step seeds a closed unavailable JSON placeholder using Bash `printf`, writes
collector output to a fresh private temporary file, and replaces the final
artifact only after successful command completion. A missing provider or failed
wrapper preserves valid unavailable JSON and fails only this optional step.
Filesystem calls and Python process creation are not interruptible hard bounds;
kernel-uninterruptible tasks can outlast a signal. Elapsed time is also checked
after process creation and around bounded file reads, and overdue operations
refuse the observation. The existing one-minute step timeout is only an outer CI
backstop. Its complete JSON artifact is capped at 16 KiB. Validated public
GitHub run/attempt and source identifiers support later independent comparison
with the root artifact's observed binary hash; they are not attestations. The
separate `python-runtime-fd-observation` artifact always reports qualification
`none`, `policy_load_run=false` and `container_run=false`. Collection and upload
are optional and cannot replace the original root-bootstrap outcome or renew
the existing experiment deadline. No root call, policy operation, container
workload or dependency/pin is added. The existing pinned upload Action and its
template/generated Renovate ownership are reused without changes.

On an early systemd-rootless guest startup failure, optional diagnostics can
project only the fixed `user@1000.service` and dockertest `docker.service`
states, results, status codes and PIDs. Host inspect and journal evidence retain
priority inside the original five-second diagnostic allowance; the guest query
does not extend startup or diagnostic deadlines. Before guest execution, the
parent requires the held fixture/placement guard, and the root worker checks the
private rootful daemon, exact container identity, owner, derived slice, live
state and privilege. The unchanged placement guard refuses execution outside
the delegated guest leaf. Raw guest output, journals, errors, command arguments,
environment and private paths are not retained; bounded closed fields are
optional and cannot erase legacy host evidence if unavailable or oversized.
Host query teardown does not prove guest process death: exact-container cleanup
remains responsible and native behavior still needs fresh hosted evidence.

After a valid service projection, one separate optional private capture can classify
the last eight messages from the exact guest's current-boot journal, matching both
`_UID=1000` and `_SYSTEMD_USER_UNIT=docker.service`. It repeats the private-daemon,
full-CID ownership and guest placement checks inside the same original deadline.
Only the root worker sees raw JSON messages and their journal metadata in memory.
Private classifier input shares the existing 64 KiB query
cap and eight-record window; the parent receives only closed message labels and
bounded record/unknown counts under the unchanged 2 KiB closed-wire input limit.
Legacy service input also retains its separate 2 KiB limit. Generic permission
errors, unreviewed formats and warnings
remain unknown. Labels describe observed messages, not a proven cause or actor.
Malformed, oversized, unavailable, cancelled or late classification cannot erase
the existing service or host projection. Unverified query teardown still retains
the sticky custody latch and exact-container cleanup responsibility. The unchanged
1 KiB guest and 4 KiB optional diagnostic envelopes give existing service and host
fields priority over this new field. No query is retried or given extra time.

Guest manager `NoNewPrivs` remains explicitly `not-observed`: a service MainPID
alone does not bind a live process birth/identity through a proc read, and a unit
property would describe configuration rather than the observed process state.
No NNP override, security-policy change, service restart or startup wait is added.

After freezing the complete host, service and startup-log diagnostic, one further
optional root capture may read unit configuration. It repeats the private-daemon
and exact owned-container inspection, then one guarded exec makes two fixed
`systemctl show` calls: system `user@1000.service` and the existing UID1000 user-bus
`docker.service` contract. Each requests only `NoNewPrivileges` and
`RestrictNamespaces`. Missing user-bus data stays unobserved. These three extra
host query groups and two guest commands use the same original five-second
absolute diagnostic deadline and 60-second backend cleanup reserve. They are
additional operations, with no retry or renewed time allowance, and may not fit
the time remaining. Configuration stdout is capped at 2 KiB while reading, with
an overflow sentinel and the existing query-group drain; all older capture limits
and callers retain their original defaults.

Only root memory holds property text. Optional `unitNoNewPrivileges` and
`unitRestrictNamespaces` scalars enrich available baseline service objects without
replacing their fields. NNP accepts exact `yes` or `no`, otherwise `unknown`.
Namespace output accepts exact `yes`, exact `no`, or a distinct, single-space
allow-list of `cgroup ipc net mnt pid user uts time`, in any order. Recognized
lists become `user-allowed` or `user-excluded`; other bounded syntax is `unknown`.
Raw unit-file tilde syntax, aliases and numeric masks are not interpreted.
Duplicate or unknown properties, malformed sections, controls and non-ASCII
refuse the whole optional observation. A service with only unknown values gets
no enrichment. Unavailable, oversized, cancelled or late configuration preserves
the frozen baseline. Both the 1 KiB guest and 4 KiB complete record are previewed:
all new configuration is dropped before any old startup-log fallback, without
trimming previous evidence. Uncertain teardown retains the pending-reader latch
and exact-container cleanup responsibility.

These are later unit-configuration observations, separate from the earlier
service/startup snapshot. `yes` for namespace restriction reports all namespaces
restricted by the formatter; `no` reports no restriction from that property.
Neither means effective process permission. Neither NNP value establishes actual
manager NNP, inherited or implicit restrictions, installed filters, failure-time
state, container-incarnation continuity or the actor behind a child-start error.
Namespace enforcement depends on the installed systemd version and architecture;
reporting a setting does not prove that a filter was installed.
`startupLog.managerNoNewPrivs=not-observed` remains unchanged. No live-manager proc
inspection, security override, readiness success or new native acceptance follows from this
metadata. Legacy records without these fields remain unobserved.

The configuration contract was reviewed read-only on 2026-10-29 with Context7
followed by official sources when its versioned query did not supply formatter
details: systemd v257's
[D-Bus properties](https://github.com/systemd/systemd/blob/v257/src/core/dbus-execute.c),
[property formatter](https://github.com/systemd/systemd/blob/v257/src/shared/bus-print-properties.c),
[namespace formatter](https://github.com/systemd/systemd/blob/v257/src/shared/nsflags.c)
and [v257 namespace flags](https://github.com/systemd/systemd/blob/v257/src/shared/nsflags.h),
plus the current [systemd.exec manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
These LGPL-2.1-or-later sources were linked and paraphrased without copying an
implementation or executing an oracle. The current manual identifies systemd 262
and includes `time`; the v257 flag set has the seven earlier namespaces. These
references and authored fixtures do not attest installed versions or native
behavior. The bounded consumer audit found no change needed to the separate
DockerLens/BoxFerry acceptance contracts; failed diagnostic status remains failed.
Only already-installed systemctl and the existing guard are reused. No dependency,
software pin, managed extraction path or Renovate ownership changes are introduced.

Official JSON output in
[systemd v257](https://github.com/systemd/systemd/blob/v257/src/shared/logs-show.c#L1133-L1138)
and [v259](https://github.com/systemd/systemd/blob/v259/src/shared/logs-show.c#L1168-L1173)
adds string `__SEQNUM` and `__SEQNUM_ID` alongside cursor, timestamps and boot ID
before `output_fields` filters the remaining journal data. The classifier accepts
these two unused string keys and discards all metadata before returning the root
protocol. Authored fixtures cover four- and six-metadata-field variants; they do
not establish the actual guest's raw journal fields or installed systemd version.

Message literals were reviewed read-only on 2026-10-28 using Context7
`resolve-library-id`/`query-docs` and official-source `open`/`find`, without running
an external oracle or copying its implementation. References are
[RootlessKit v3.0.0 parent errors](https://github.com/rootless-containers/rootlesskit/blob/v3.0.0/pkg/parent/parent.go),
[Moby v28.5.2 daemon configuration errors](https://github.com/moby/moby/blob/v28.5.2/cmd/dockerd/daemon.go),
[Unix listener errors](https://github.com/moby/moby/blob/v28.5.2/daemon/listeners/listeners_linux.go),
[network initialization errors](https://github.com/moby/moby/blob/v28.5.2/daemon/daemon.go),
and [systemd v257 journalctl](https://github.com/systemd/systemd/blob/v257/man/journalctl.xml).
RootlessKit/Moby sources are Apache-2.0; the systemd references are LGPL-2.1-or-later.
These references do not attest the guest's installed versions; unmatched formats
remain unknown. No upstream implementation or oracle executable is redistributed.

Child-start message refinements were reviewed read-only on 2026-10-29 with
Context7 and official tagged sources, without running an oracle or copying its
implementation. RootlessKit v3.0.0's parent starts `/proc/self/exe` and wraps
`cmd.Start` errors. Go 1.25.3's
[`Cmd.Start`](https://github.com/golang/go/blob/go1.25.3/src/os/exec/exec.go)
propagates [`startProcess`](https://github.com/golang/go/blob/go1.25.3/src/os/exec_posix.go)
errors with operation `fork/exec`; its
[`PathError.Error`](https://github.com/golang/go/blob/go1.25.3/src/io/fs/fs.go)
joins operation, path and error text. Its
[`Errno.Error`](https://github.com/golang/go/blob/go1.25.3/src/syscall/syscall_unix.go)
uses the [Linux amd64 error table](https://github.com/golang/go/blob/go1.25.3/src/syscall/zerrors_linux_amd64.go).
Go's reference source is BSD-3-Clause; RootlessKit remains Apache-2.0.
These are source references, not evidence of the guest's compiled Go version.

Three separate message labels recognize the complete existing RootlessKit parent
error prefix followed by `fork/exec /proc/self/exe: ` and exactly `operation not
permitted`, `permission denied` or `resource temporarily unavailable`. No extra
text or newline is accepted for these refinements. Other suffixes, paths and
multiline messages retain the general child-start label when its prefix matches;
embedded or different prefixes remain unknown. A label observes text only: it
does not establish a numeric errno, the failed syscall, a policy actor, a cause or
guest manager `NoNewPrivs`. Authored positive and mismatch fixtures do not attest
the failing guest's actual suffix or identify why its child failed to start.

The existing diagnostics input ownership and already-installed guest journalctl
cover this change; there is no new dependency, software pin or Renovate extractor.

The stdlib-only `scripts/runtime_docker_systemd_guard.py` holds the existing
guard and fixed user-manager argv without expanding root import paths. The
root worker reads only a bounded stable no-follow snapshot of that literal
sibling. Its path is declared among the conformance image inputs, so a helper
change selects both image architectures. This extraction adds no dependency or
operational pin; existing image-input selection owns it and no Renovate manager
change is required.

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

Preparation can add one optional `workFailure` to the existing failure diagnostic.
It identifies a closed parent-side work site in the `CUSTODY`, `CHILD_PARENT` or
`HOSTED` source area. The finite site/category pairs live in the helper's
`WORK_FAILURES` table. Observation is local to preparation and its immediate
record readback; shared callers remain unobserved by default. The collector
keeps only closed immutable values, and the invocation's control object receives
only a sealed tuple. No exception, raw capture, path, credential ID or authored
source/policy content is included in the new detail.

Eligible work failures are captured before cleanup can mask them. Resource
release, retention cleanup, opaque file-read internals, unknown child lifetime
and child-internal causes remain unobserved. A proven-dead nonzero child status
can identify only the parent's status-validation refusal. The first completion
deadline after child cleanup is ambiguous and receives no work label. Composed
boot checks observe only an actual false predicate; opaque boot-read/close
exceptions cannot acquire an outer label. A valid legacy failure diagnostic
with invalid optional detail retains only its legacy fields; malformed base
records, unknown root fields and duplicate keys keep their existing refusal
behavior. Recording or capture failure adds no retry or fallback output.

These diagnostics add no reads, child channel, process, probe, wait, deadline or
runtime authority. The probe program and privilege receipts, strict custody reads,
and borrowed OS-tool rules remain unchanged. Successful initial tool scans,
staging and the synthetic write-denial probe do not establish a successful
normal custody cycle or native runtime qualification. A work label cannot
authorize readiness, cleanup or disposal of retained data.

Only a freshly recorded `CHILD_PARENT / B_BUILD_STATUS_REFUSAL / REFUSED` can also add
`buildStatusObservation` during preparation. Its three fields are integer `schema: 1`,
`terminationForm` (`EXIT_NONZERO`, `SIGNAL_ALRM`, `SIGNAL_XCPU`, `SIGNAL_XFSZ`,
`SIGNAL_KILL`, or `OTHER_SIGNAL`) and `receiptCheck` (`MATCH`, `EMPTY`, or `MISMATCH`).
Absence means unobserved. The observer consumes its single attempt before any new
qualification or parsing; identical later refusals cannot retry. Diagnostic errors
or an invalid extra field leave the original work failure independent.

This optional check is manually qualified only for the resident parent CPython
3.14.4 final runtime. It uses the already held Popen return code and, for an exact
Build with exact integer IDs, at most 1024 exact receipt bytes. Empty bytes need no
parser. Nonempty bytes must be ASCII without an actual NUL; other encodings, types
or bounds produce no extra observation. Eligible bytes go unchanged to the existing
receipt validator once, without an observer. Schema/duplicate or JSON syntax refusal
means `MISMATCH`; unexpected decoder, numeric-limit, recursion or allocation errors
omit the extra observation. No codec prewarming or additional I/O is used.

`MATCH` only means the held receipt passes that validator. It does not prove receipt
close, imports, rendering, readiness or completion. `EMPTY` does not prove setup never
ran, and signal names do not identify a cause: `SIGNAL_KILL` cannot distinguish OOM,
a hard limit or an external sender. The sealed pair retains only two closed strings,
adds no authority and shares the existing single bounded diagnostic write. Runtime
qualification is a semantic review constant, not a Python installer/version selector;
operational admission and existing Renovate managers therefore require no change.
Qualifying another runtime requires a fresh semantic review.

An optional `childGuardDeclaration` can accompany only that exact preparation
fault and an `EXIT_NONZERO / MATCH` pair. It contains integer `schema: 1` and one
closed `category`: `FD_FSTAT_NON_EBADF`, `FD_NOT_ALLOWLISTED`, or `RESULT_TYPE_OR_SIZE`.
The build child reserves exit values 111, 112 and 113 respectively at those three
existing negative guards. Every predicate, descriptor allowlist, operation order,
limit, receipt and positive path stays unchanged; all other failures keep their
old values. These declarations require the same single consumed attempt, the
unchanged receipt validator once, the reviewed parent runtime, and exact held
metadata for both manifest-pinned Source records. No source descriptor is read
or inspected again. Source changes require manual semantic requalification.

This is a producer-declared category, not proof of an actual host statement,
errno, descriptor/object/OFD identity, origin or cause. Interpreter/native-library
and finalization status collisions or replacement are not exhaustively excluded.
Absence means unobserved. Declaration failures, conflicts or invalid wire data
cannot erase an otherwise valid original fault or status pair. They cannot
authorize readiness, runtime work, cleanup or disposal.

Publication independently admits the complete control record against its existing
32768-byte compact ASCII limit and the complete artifact envelope against its
existing 131072-byte guard and sorted-output-plus-newline capture limit. Bounded
pure prospective JSON checks run only when a new declaration is present. Exact
JSON types, whole-tree budgets and at most 64-bit integer magnitudes are screened
before any prospective encoding, including dictionary keys. Unsupported shapes,
overflow or new-gate errors omit only declarations at the known diagnostic slots;
all original evidence and the original single write remain. Legacy-invalid cases
and no-declaration/normal paths keep their original serialization behavior.

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

## Experimental issue527 active qualification candidate

The separate `containers-ubuntu26-userns-active` contract is restricted to a
`workflow_dispatch` with `validation_profile=docker-rootless-diagnostic` on
`refs/heads/TheRealBecks/issue527`, the `smoke-build` job, and
`docker-29-conformance-rootless`. Other shared-action and publication contexts
keep their existing runtime path. Known ASCII upper/mixed-case diagnostic choices
normalize to the same canonical choice; bootstrap, producer, client and evidence
checks also retain and compare the exact raw requested value. Unknown, non-ASCII
or malformed choices refuse instead of skipping the scoped requirement. The old
`armed_unused` admission, immutable
bootstrap, and never-load observer are unchanged. The new admission records
`qualification: none`: source admission and hermetic checks do not establish
native compatibility, authorize a release, or establish ARM load support.

The workflow carries a separate fixed root-bootstrap literal. An unprivileged
producer supplies a finite Git commit/tree/blob proof and the existing pinned
SDK source closure. Before importing a helper, the literal requires the trusted
candidate, workflow, and checkout commits to be identical, verifies every
connected source object and source pin, and creates root-owned 0400 files in a
0700 stage. Root Python uses fixed `-I -B -S` execution from that stage; it never
imports the checkout under sudo. The SDK's immutable pure `profile_bytes`
builder is reused without invoking its active `RunnerProfile` CLI. The existing
`dockerlens-127-upstream-rootless-RUN-ATTEMPT-NONCE` spelling remains an identifier;
it does not confer DockerLens admission or policy authority.

The manually reviewed active admission requires Ubuntu 26.04 AMD64, kernel
`7.0.0-1017-azure`, parser 5.0.2, and the exact parser, ABI, feature and Python
3.14.4 fingerprints recorded in
[the active admission](../.github/docker-userns-active-admission.json).
Actual actor preflight reads the fixed AppArmor-enabled, restricted-userns and
maximum-userns scalar files. The legacy `unprivileged_userns_clone` control must
be `1` or explicitly absent with ENOENT; unreadable, malformed, disabled, or
changed controls refuse. ARM remains compile/observation-only and refuses load
until an independently reviewed ARM cohort exists.

`ImageVersion` is the workflow-reported per-job provenance value. It is frozen
once and compared exactly across bootstrap, phase custody, receipts and evidence
checks. It is neither an independent VM identity attestation nor a historical
compatibility pin. The unused admission's historical image cohort is not widened
by this contract.

Each actual root actor freshly opens `.ns_name`, `.ns_level`, and `.stacked`
directly under a held genuine `/sys/kernel/security/apparmor` securityfs
directory. They must be exactly `root\n`, `0\n`, and `no\n`. There is no `/policy/`
namespace read and no normalization of stacked labels. The guest's effective
profile is read through its held task's `attr/apparmor/current` and must equal the
generated name followed by ` (unconfined)\n`. Enforce, complain, namespace-qualified,
stacked, and other default-allow representations refuse. A mismatch retains
bounded raw bytes privately and exports only the source, length, digest and
match diagnostics.

The pre-exec actor namespace check is not a measured parser post-exec namespace
attestation. This candidate explicitly relies on the independently reviewed
trusted-fixed-OS assumption that executing the held pinned parser performs no
AppArmor namespace transition; its receipt records `measuredPostExec: false`.
That limitation remains visible to review and the evidence gate.

Each native phase has separate root-private locked custody, the same held source
archive identity, and the original phase deadline. A fresh same-source/VM
no-policy owner cycle must close before arming the real independent finalizer.
The finalizer acknowledges its exact source, PID/start incarnation, namespace,
cgroup and deadline from a separate `system.slice` service outside the runtime
slice and coordinator process group. Its verified runtime and stop allowances
fit within the original deadline. It begins emergency cleanup 75 seconds before
that deadline, ahead of the existing backend's 60-second expiry; no allowance is
renewed.

Durable load/create/remove/unload intents precede effects. The single detached
owned systemd guest receives the exact profile option and lease label after its
create intent; one-shot checks retain their existing options. The root helper
binds the CID, run labels, archive/configuration identity, live task incarnation,
cgroup and effective profile. An unknown reader, child lifetime, load, create or
absence outcome is sticky and retains custody. Emergency cleanup cannot infer
that an unacknowledged load/create intent succeeded or that no guest exists.

A contended custody lock is retried nonblockingly within the same original
absolute deadline. Every retry still checks the explicit release handshake
without taking the closing coordinator's held lock; no fresh allowance or forced
unlock is granted. Cancellation/coordinator-death causes remain sticky across
retries, and a cleanup effect's error is never mistaken for lock contention.
Exhaustion or an uncertain effect publishes a separate retained marker that
blocks later state reuse and disposal, including a late release after expiry.

Normal close first proves exact guest absence while the private endpoint is
alive, including the bound task's absence and an absent or recursively empty
exact guest cgroup. It then unloads only the exact profile and verifies registry
absence, holds the independent finalizer's pidfd before releasing it, proves
normal finalizer death and unit/cgroup absence, and removes custody. Only then
may ordinary native network/image/daemon/store teardown proceed. A later native
teardown failure remains a failure. Unverified scoped close retains the private
runtime rather than deleting its endpoint or store.

The active OS-release read first uses the existing trusted root-owned component
resolver, then the unchanged strict bounded reader on its canonical result and
checks that the alias still resolves consistently. Unsafe ownership/modes,
changed contents or alias targets, and missing targets still refuse. This fixes a
source portability defect for conventional trusted Ubuntu aliases; the failed
trial did not establish that this read caused its root preparation exit.

Failure receipts identify an actually executed producer, root bootstrap, root
RPC or client capture boundary. They contain only a finite checkpoint/reason,
verified routing/source hashes, completed comparison booleans and the existing
journal's last durable phase/intent, pending-reader/child flags and last recorded
owner disposition. Exception text, native paths, environment and raw host facts
are excluded. A launcher that emitted no valid receipt remains explicitly
`execution-unverified`; a printed bootstrap literal is not an emitted error or
proof that ARM reached bootstrap.

The client parses bounded nonzero root replies before failing and exports the
redacted receipt into the native evidence and explicit always-uploaded diagnostic
artifact before endpoint teardown. Invalid, oversized or mismatched replies
produce a closed client failure instead. A reporting lease locator grants no
cleanup authority: unknown/refused preparation still retains the runtime, and no
preflight category can automatically justify absence, unload or disposal.
Retention preserves the prior phase/intent and any uncertain durable write
rather than replacing that history with only `retained`.

The existing pure-builder call now has one scoped `WorkObserver`. Only its sealed,
validated worksite/status/guard enumerations and the exact finite `ChildError`
lifetime may accompany a failure. Never-started, unknown and proven-dead failures
all keep pending/retained state and grant no cleanup or retry authority. Producer
identity checks name the current finite validation group before each existing
comparison, without exporting raw values or changing any expected values; a
phase alone does not establish the cause of a previous ARM refusal.

Rejected descriptor diagnostics reuse the existing successful `fstat` witness to
report only file type bits and whether the current numeric slot matches the
retired interpreter slot, retired receipt slot, or another slot. Reuse does not
identify the descriptor's original owner or establish an allowlist defect.
An other-slot regular witness may additionally match the same file identity as
an already-read sealed source or previously visited stdio witness. A complete
`NO_MATCH` requires all three stdio witnesses; otherwise it reports
`STDIO_UNAVAILABLE`. These labels establish neither descriptor ownership nor a
shared open file description, and add no descriptor probe or inventory call.
Historical exit 112 and classification errors retain the generic refusal. The
final builder allowlist and its existing inventory syscalls are unchanged. An unprivileged subprocess
regression exercises the extracted production guard with real captured stdio and
inherited descriptors; it does not qualify the root builder or native runtime.
Producer ImageOS refusals distinguish missing/empty, explicit Ubuntu values and
other values through finite phases. Reported provenance binds AMD64 to
`ubuntu26` and ARM64 to `ubuntu26-arm64`; crossed pairs, whitespace and aliases
refuse. The producer, independent fixed active bootstrap and root context checks
agree on these exact pairs. This is reported workflow provenance, without a
claim of physical runner attestation or compatibility. The earlier unknown ARM
value is superseded by run `40859477908`'s finite `ubuntu26-arm64` observation.
These diagnostic changes introduce or change no dependency pin or Renovate
extraction/ownership rule.

Builder and version/write-denial children now use two fixed source-owned Python
stages in the same already deprivileged process. Before importing FFI, the
launcher binds the authored interpreter/receipt/source-or-tool identities,
requires distinct valid roles and stdio, and rejects every extra inherited
descriptor. It then establishes and reads back NNP using the trusted ctypes
setup, rechecks authored identities, marks only descriptors created during that
setup close-on-exec, and executes the same held interpreter with the existing
isolated flags and cleared environment. Payloads contain no ctypes setup; they
still check actual kernel UID/groups, zero capabilities and `NoNewPrivs: 1`.
Both builder and probe payloads perform their own exact final descriptor census.
This is not a general descriptor sanitizer, and setup success grants no authority.
The builder additionally requires `seen == allowed` after inventory: stdio 0–2
and both validated source descriptors must all remain present. Missing roles
refuse with generic exit 112. Extras still refuse immediately, and EBADF still
continues before the final completeness check. The SDK loader/output tail is
unchanged; the completeness predicate is an explicit guard strengthening.

The launcher arms the wall alarm once before FFI and sets the existing CPU/core/
file limits for the same PID across subsequent execs. Payloads never rearm the
alarm or renew a resource budget. The parent's original absolute deadline,
capture, privilege receipt and proven process-group death remain mandatory.
Owned ordinary-user tests cover two-stage mechanics and the combined delayed
alarm boundary; their root ownership, interpreter-link, supplementary-group and
unavailable-seal exceptions are explicit test limitations. They do not qualify
the root builder/native runtime or establish the cause of a historical native
failure. The internal unused-custody child hash is computed from the formatted
source; external software pins and Renovate ownership remain unchanged.

The ordinary fixture normalizes capability sets only in its owned child before
entering the unchanged production launcher. It verifies four zero capability
sets and unchanged NNP, preserves inherited descriptors including deliberate
extras, and forwards the same held interpreter and original allowances. A
bounded boolean audit and an exact private parent-state comparison verify the
boundary. This handles test-provider capability inheritance without changing
parent state or weakening production UID/capability/NNP checks.

ARM dispatch now stops before native runtime tests after the separate
`observe-arm` root operation. That operation authenticates the immutable stage,
imports its verified dependencies and holds the stage lock. It collects bounded
structured OS/kernel/machine, fixed tool/ABI/feature digests and identities,
CPython version, fixed control values, source bindings and strict root namespace
facts. Collection does not evaluate them as an AMD64 compatibility cohort.
Parser version uses only the existing bounded dropped-credential version probe,
with an interpreter digest calculated from the same job's held trusted OS file
under the documented preinstalled-tool integrity exception. No AMD64 interpreter
digest is borrowed for ARM, and observed values never grant admission.

Before that version child can start, an exclusive root-private
`observation-<nonce>` custody directory and pending marker are fsynced in the
existing stage lease area. Its binding records the authenticated bootstrap,
context, exact tools and original deadline bounds. Proven child death permits
retiring only the exact marker after tool and marker identity rechecks. Unknown
completion, interruption, replacement, durability failure or root crash keeps
custody; existing stage disposal refuses any remaining lease entry. These names
cannot address active RPC leases. No observation route constructs an active
profile lease, compiles/builds policy, loads/unloads profiles or creates guests.

The always-uploaded observation artifact has its own receipt kind, qualification
`none`, disposition `ARM_NOT_ADMITTED`, explicit false active/native/cleanup
authority, and only completed bounded facts plus finite failure metadata. It
cannot satisfy the active client or native evidence gate. The root operation
and ARM workflow step return non-success even after complete observation. ARM
loading remains refused; historical unused admission and bootstrap are unchanged.

Public observation receipts use schema v2's strict purpose-specific projection.
Private collection and custody retain their binding facts; publication removes
raw file identities and namespace IDs, retaining only bounded verified facts
and genuinely derived metadata checks. Valid partial observations remain
redacted and incomplete; malformed inputs produce empty facts and a finite
failure. Historical schema-v1 artifacts remain untouched. Neither receipt
version can satisfy the active client or grant qualification or cleanup authority.

The evidence gate requires both original clean-control/enforcement phases and
bound scoped evidence in this exact candidate context. It rejects absent or
mismatched receipts, host fingerprints, effective-profile evidence, task/scope
absence, finalizer termination, pending readers, or custody disposal. This is an
experimental qualification path; it carries no native passing result before a
reviewed exact-source hosted run completes.

The conformance image's machine-readable inputs include the new active files
and the reused root helper closure. Renovate retains its existing two source
manifest managers (`github-digest` and `gitlab-tags`) as the sole upstream pin
owners, including dashboard approval and no automerge. The coordinated review
rule now names the active admission. No manager rewrites active/unused cohort
fingerprints or the root verifier's manifest commitment: source/parser/helper
changes require coordinated manual re-admission and closure/proof regression
review, without adding duplicate upstream extraction.

The Docker guest-systemd conformance fixture may collect a separate
[leaf-after memory witness](../images/docker/conformance/README.md#diagnostic-leaf-after-witness)
only after its mandatory allocator has already exposed a typed outer OOM marker.
The witness uses the existing invocation-owned guest, daemon, image and original
budgets. Its fresh root counter baseline is purpose-tagged and never mixed with
the mandatory allocator's samples. Controller completion and private identity
bindings provide diagnostic observations only; the strict outer OOM and orderly
shutdown guards retain their existing refusal behavior. Unknown or incomplete
witness evidence grants no native qualification or attribution authority.
Closed last-entered and last-completed collection stages identify where an
unavailable witness stopped without publishing operands or exception text.
Cleanup progress is recorded separately and cannot replace that location;
controller completion retains its independent unavailable/failed/completed
meaning. A completed collection operation alone does not establish valid
accounting or successful controller termination.

An unavailable leaf witness may retain a closed release/await outcome and a
separate bounded failure capture. Exact owned CID/name binding precedes typed
OCI state; only fixed controller failure stages and received-signal tokens
leave private logs. One shared cap of at most two seconds is reduced by the
existing command timeout, work deadline and cleanup reserve, without renewal.
Unavailable observations remain unknown. Capture cannot overwrite the failed
collection stage, establish controller completion, identify an OOM cause or
change strict shutdown and cleanup requirements.

The witness archive barrier is confined to that diagnostic actor. CREATE and
rootfs/mount/marker preflight precede START, so preflight consumes the original
work allowance without starting the C alarm. New root-level witness markers
avoid the private tmpfs filesystem-view boundary; legacy allocator paths remain
unchanged. Single PUT outcomes are never retried when uncertain. HEAD metadata
is visibility evidence, not controller completion or OOM attribution.

The guarded outer guest carries bounded HTTP through its existing Docker CLI;
no final-guest curl, Python, target exec or new runtime authority is required.
Decoder and CLI stderr have separate bounded regular files and exact empty-file
custody proof. Shared deadline, complete framing, actual process outcomes and
cleanup must all succeed before a response is usable. The distinct held HTTP
response role cannot replace the image archive or become command stdin. Existing
runtime-input ownership already covers the two changed Python modules, while
the signed/pinned image and payload toolchain retains its existing update policy.
Source research and offline shell/protocol tests do not qualify native support.

Image and response stream custody also binds the original private directory's
identity, owner, mode and nonsymlink type. Held directory descriptors anchor
fixed-name allocation and are checked around I/O; directory substitution cannot
rebind a stream. Invalid response limits refuse before reads. The root observer's
private copy uses the absolute witness end without changing original runtime or
backend deadlines. Its timestamp validation makes no freshness or cause claim.
