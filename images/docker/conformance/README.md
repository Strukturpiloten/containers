# Guest-systemd Docker conformance fixture

`docker-29-conformance-rootless` declares one dedicated fixture: the current
verified Docker 29 static payload on the same pinned Debian 13 base as the
distribution images, for native AMD64 and ARM64. This declaration is not native
qualification or evidence that an image has been published. The existing direct
launch images retain their separate contract.

Guest PID 1 runs systemd as UID 0. An actual UID 1000 user manager starts the
rootless Docker service, which requests the systemd cgroup driver. Guest-only
linger state and `Delegate=yes` provide the intended user-service hierarchy.
The native harness must prove the actual daemon identity, user manager, service,
controller delegation, and stable cgroup hierarchy before it admits nested work.

GitHub selects an invocation-owned rootful Docker backend for this Docker profile;
local development explicitly selects isolated Podman, with no engine fallback.
Both use a private cgroup namespace. Podman retains crun, `--systemd=always`, and
crun's `run.oci.systemd.subgroup=container` annotation. Docker uses the private
daemon's systemd cgroup driver, its declared runc runtime and bounded `/run` and
`/run/lock` tmpfs mounts; no Podman option is sent to Docker. Its actual private
daemon metadata and installed runtime prerequisite version/hash are recorded
separately; a declared runtime path does not establish task-binary correspondence.
Guest systemd manages the private cgroup namespace root directly, creating its
own nonroot PID 1 leaf and user hierarchy. The guest receives no host Docker
socket, host DBus socket, or host cgroup bind mount. Docker's reviewed backend
owns its transient host services, slice and private network; the harness does not
reconfigure unrelated host services, controllers, cgroups, security profiles or
sysctls. Guest boot units
that could alter shared kernel state are masked; journald's audit capability is
removed and its actual descriptors and normal logging endpoints are checked.
Before admission, a bounded observer performs only passive proc/cgroup reads.
It records the first and last placement reasons while guest PID 1 or the observer
still occupies the namespace root, or subtree delegation is not ready. Missing
files, malformed data, unexpected nonroot placement, unavailable controllers,
and command errors fail immediately. The observer cannot admit daemon requests
or nested work. Placement, the first outer-limit read, and daemon API readiness
share one 45-second startup deadline beginning at outer launch, reduced by a
smaller configured command timeout; no stage renews that allowance. At most 45
placement samples run, with one-second pending cadence, a two-second per-sample
cap, remaining-deadline command timeouts and a 4000-byte output bound. Subsequent
smoke checks retain their existing independent command timeouts.

After placement admission, all execs must remain in the exact nonroot guest PID 1 leaf, with an empty,
root-owned namespace-root distributor and delegated CPU, memory and PID
controllers. Missing readiness or placement evidence fails closed.
Docker admission permits PID 1 to move below its exact CID-owned scope only for
this declared fixture, with the original private slice identity still verified.
The outer scope's resource limits remain distinct from PID 1's descendant leaf.
Only the existing read-only daemon-info readiness condition may be polled within
the remaining startup deadline. Each API sample has the normal pre/post placement
guard and returns a closed ready/pending marker; guard, OCI, I/O and malformed
marker failures are fatal and never restart placement admission. Both prior native
failures refused the first guarded exec but passed the same guard at shutdown;
their evidence did not identify the transient predicate. Fresh native runs remain
required to qualify this passive startup observation.

The historical Docker Engine 29.8.2 candidate was incompatible with the former
extra `payload` delegation subtree. Its [Moby revision 8af9fe3, `withRootless`](https://github.com/moby/moby/blob/8af9fe3a36bab3e039862a2ab1cef1880c9b4d03/daemon/oci_linux.go#L63)
reads `/sys/fs/cgroup/user.slice/user-<uid>.slice/cgroup.controllers` directly,
before converting the container spec; it does not discover a systemd prefix.
Both native architectures failed that lookup under `/payload` despite passing
the actual delegation readback. This is also tracked in [Moby #53531](https://github.com/moby/moby/issues/53531).
Removing the extra subtree lets the guest's actual systemd hierarchy match the
namespace-root-relative layout. No path aliases or controller migration are used.

[crun 1.21 exec placement](https://github.com/containers/crun/blob/1.21/src/libcrun/linux.c#L5052)
passes the container init PID to its cgroup mover. When the original cgroup
rejects an exec process with `EBUSY`, [its cgroup v2 fallback](https://github.com/containers/crun/blob/1.21/src/libcrun/cgroup-setup.c#L438)
reads that init PID's current cgroup and checks it against the original
container cgroup path, with bounded retries. The harness independently requires
the exec process to occupy the exact PID 1 leaf; fallback behavior alone is not
admission evidence. Moby's Apache-2.0 and crun's LGPL-2.1-or-later upstream sources
were inspected only for this diagnosis, not copied into the implementation or
redistributed in images. The layout correction remains unqualified until fresh
native AMD64 and ARM64 runs prove the complete contract below.

The existing outer CPU, memory, PID, command timeout, observed 12 GiB disk budget,
and exact-owned-resource cleanup remain mandatory. Inner enforcement additionally
requires a real 32 MiB memory limit, zero permitted swap, an actual OOM-killed
allocator, and a 16-PID limit that refuses an additional process. Inspecting a
Docker declaration alone is insufficient. The helper retains generic rootful
parsers for offline regression coverage; this does not declare or qualify another
image. Debian 11 conformance remains a later phase of issue #344. Its earlier
unlimited-swap/non-OOM result is not successful evidence.

### Clean control and fault-injection evidence

The systemd-rootless profile requires a clean ordinary-workload control before
the existing resource fault-injection phase. The phases use separate runtime
contexts, Podman stores, check lists and daemon storage, on the same architecture
and exact OCI archive identity. They run sequentially: positive control checks
and verified cleanup must finish before the enforcement context is created.
Failure, cancellation, identity drift, unknown cleanup or an expired work budget
must prevent progression. No new CLI or metadata switch disables this control.
Direct-launch profiles retain their existing contract.

Both phases use the canonical startup and ordinary storage, network, port and
health checks. Only the closed internal clean-control phase omits the deliberate
inner memory/OOM and PID fault injection; those probes remain mandatory in the
enforcement phase. Both phases still require the unchanged strict orderly
shutdown, including exit zero and `OOMKilled: false`. A passing clean control
does not explain or excuse a failed enforcement shutdown.

Work is capped at 300 seconds for the clean control and 900 seconds for the
pair, without increasing existing command, startup, CPU, memory, PID or disk
limits. Cleanup retains its bounded safety path even after a work deadline;
an overrun cannot become successful admission. Phase identity, checks,
observations, elapsed time and cleanup outcomes remain separately inspectable.
Supplied or exported input enters one private read-only snapshot outside both
stores; a retained descriptor supplies the actual bytes for both loads. The
canonical 12 GiB observer includes that snapshot alongside the active store
during copy/export, hashing, loading and native work. Snapshot replacement or
mutation fails custody/accounting. Caller-supplied archives are never deleted.

### OOM attribution boundaries

The R7 native runs failed because the final outer `OOMKilled` flag was true,
despite exit zero. Their live snapshots showed hierarchical counters changing
after the deliberate inner OOM, but did not prove what the actual monitor watched
or why the final flag changed. Local counters staying zero at sampled ancestors
do not prove absence of host or shutdown pressure.

Upstream source inspection supplies a hypothesis, not runtime attribution:
[Podman 5.7.0's exit-file reader](https://github.com/podman-container-tools/podman/blob/0370128fc8dcae93533334324ef838db8f8da8cb/libpod/container_internal.go#L199)
sets the flag when the persisted OOM marker exists, independently of the exit
code. Its
[conmon setup](https://github.com/podman-container-tools/podman/blob/0370128fc8dcae93533334324ef838db8f8da8cb/libpod/oci_conmon_common.go#L865)
passes the exact container's persistent directory.
[conmon 2.1.13](https://github.com/containers/conmon/blob/82de887596ed8ee6d9b2ee85e4f167f307bb569b/src/cgroup.c#L109)
watches `memory.events`, not `memory.events.local`, and creates an OOM marker
when the watched hierarchical OOM counters are nonzero. Both inspected upstream
revisions are Apache-2.0; their code was not copied or translated into this
harness. Those source versions are not attestation of the runner's actual
monitor binary, watch target or marker timing.

Diagnostic observations never change admission. Any further attribution must
bind the exact owned container, monitor process birth/executable identity,
observed watch and marker to the native run. Missing or ambiguous evidence stays
unresolved; snapshots alone do not provide accounting through shutdown. Neither
these source references nor an additional control run qualifies an image or
authorizes relaxing the strict shutdown predicate.
Conmon marker custody applies to Podman outer runs. Docker has no conmon source:
its observations explicitly report backend-not-applicable and unresolved
attribution while retaining the actual Docker state, including `OOMKilled`.
No marker or PID custody evidence is invented for Docker.

Run the repository harness against the exact built OCI archive on each native
architecture. GitHub's shared action selects `--outer-engine profile`; local
development selects `--outer-engine podman --sudo --allow-privileged` explicitly.
See the generated image page and
the [Docker guide](../README.md#runtime-modes-and-admission). A PR must remain
unqualified until both native architectures pass the full contract. A skipped
runtime check, offline test, cross-build, or passing direct-launch image cannot
substitute for that evidence.

The build action explicitly installs crun alongside existing OCI tools through
the runner's signed distribution repositories. This follows the existing native
package policy: package revisions track those repositories, rather than an
invented fixed package/checksum. Runtime evidence records the selected executable's
actual path, complete bounded version report, and SHA256, then proves readiness
and delegation. No additional Renovate extractor is appropriate for signed apt
package names; the new Debian base pin uses the existing metadata regex manager,
OS-release freeze rule, shared Debian 13 digest group, and digest approval policy.
The probe compiler is confined to a build stage; installed package and compiler
provenance are retained in the final image.

### Diagnostic leaf-after witness

The mandatory single-PID1 allocator, its genuine `137`/Docker OOM predicate,
its possibly unavailable after sample, and the strict outer OOM refusal remain
unchanged. Only after that primary probe has already exposed the typed outer
Docker OOM marker does the harness optionally run a separate diagnostic leaf.
Passing paths and Podman do not start this additional actor.

The opt-in repository-owned `memory-witness` mode runs as inner PID1 with one
bounded allocator child in the same 32 MiB, zero-swap, 16-PID leaf. It reads and
requires actual `memory.oom.group=0`; it never writes group policy or lowers an
OOM score. The child waits on a pipe while the driver binds both exact process
identities and the complete leaf membership. A fresh purpose-tagged root sample
precedes the start gate. The controller samples hierarchical and local memory
events before releasing its child, records direct `waitpid` signal status and
reaps the child, then samples the same populated leaf and holds it for the root
after sample. Separate bounded reads are not atomic. Raw identities, paths,
collector output and error operands remain private; public observations retain
hashes, counter sets, completed binding checks and monotonic window envelopes.
Closed `enteredStage` and `completedStage` facts retain the last collection
operation started and successfully returned, including unavailable observations.
They cover room checking, launch, binding, root-before sampling, release and
await-after, log reading, controller rebinding, retained hierarchy, root-after
sampling, projection validation, finish hold and completion wait. Null means
no operation completed yet. Separate `cleanupEnteredStage` and
`cleanupCompletedStage` facts use only `exact-owned-leaf` or null, alongside
the existing cleanup outcome; cleanup never overwrites the collection location.
A returned completion wait is distinct from controller success, and completed
sampling does not establish valid accounting until projection validation.
No raw commands, paths, process identities or exception text enter these facts.
On release/await failure, `awaitResult` retains only an actual closed guest
result: release failed, after sentinel observed, or polling exhausted. Guard,
transport and malformed-result failures remain unavailable; polling exhaustion
does not prove controller death or why the sentinel was not observed.
A separate `failureCapture` may retain exact-CID/name-bound typed OCI state
and fixed controller failure-stage/received-signal tokens from private logs.
C emits these tokens only on failure, in normal cleanup after retiring child
custody. Failure output and process-exit stdio flushing use nonblocking stdout;
if that mode cannot be enabled, the controller exits without a stdio fallback. Signal receipt is sampled once; it is not complete signal history. A SIGALRM
receipt is not timer-expiry or cause proof.
Capture has one nonrenewed cap of at most two seconds, clipped to the existing
command timeout, original work deadline and backend cleanup reserve. Both reads
share that allowance; expired, failed, oversized, truncated or malformed reads
remain unavailable. Capture progress never replaces the original collection
stages or establishes controller completion. Raw logs and OCI operands remain
private; existing success and mandatory allocator protocols are unchanged.

The witness alone uses rootfs markers `/boxferry-leaf-witness-start`, `.after`
and `.finish`; the mandatory allocator retains its legacy `/tmp` barrier.
The driver creates one stopped, nonce-labelled container from the actual loaded
image ID, then verifies its exact CID, name, command, mode, writable-rootfs
configuration and absence of covering mounts or tmpfs. All three marker entries
must be absent, using actual archive HEAD HTTP status with the same stopped
container bound before and after the reads. Any entry, including a dangling
symlink, refuses startup. Preflight finishes before starting the C controller.

Start and finish are single uncompressed archive PUTs containing one canonical
empty regular file. HEAD of the C-produced after marker acknowledges visibility
only when its exact name, zero size, Go regular-file mode and empty link target
are observed. Complete C telemetry, retained process/cgroup identity, counters,
root sampling and controller wait remain mandatory. An uncertain PUT may already
have changed the filesystem; it aborts without retry. No barrier operation execs
another process inside the bounded inner leaf. Archive workers and filesystem
writes can still perturb accounting; this is not a zero-perturbation claim.

The existing Docker CLI bridges raw HTTP only through the guarded outer guest
and the explicit mode-specific Unix endpoint. This deliberately uses the hidden
`system dial-stdio` command reviewed at CLI 29.9.2 revision
`a82e528901260c8df6073311379eac65f92db204`; Engine archive filesystem-view and
HEAD lstat behavior were reviewed at
`0367cbeb49b9d98cb0b4f51e95f7b54b4803e76c`. Both upstream sources are Apache-2.0;
no source was copied or redistributed. Future payload updates must review this
consumer under the existing manual payload-update policy. No new download,
software pin or Renovate manager is introduced.

The archive bridge preloads one validated request of at most 4096 bytes into
an identity-bound FIFO in its private `0700` scratch directory before launching
the CLI. On the selected Linux AMD64/ARM64 profile, a fresh FIFO has at least
one 4096-byte page of capacity; this bound does not rely on `PIPE_BUF`. Only the
supervisor retains the read/write keeper. The CLI receives a separately opened
read-only FIFO descriptor and can exit when the response completes while stdin
remains open, as supported by the reviewed CLI's response-first path. Actual
preload and CLI status, separate bounded empty stderr, outside-producer completion
proof, inode custody and verified cleanup remain required before a trusted
receipt. Setup, transfer and cleanup share the original absolute deadline and
reserve; no input writer runs in the background.

After CLI completion, the supervisor closes its keeper and requires a bounded
FIFO residual read to reach EOF with actual success and no remaining request
bytes, including NUL bytes. A complete HTTP response alone cannot acknowledge an
incomplete request transfer to CLI stdin.

Finite-file stdin can otherwise cause CLI write-half closure and cancellation
of a Go HTTP request context. The retained native preflight HEAD response was
499; its underlying handler error and cancellation cause were not measured.
This source-backed correction does not establish that native failure's cause or
qualify the witness. HTTP 499 remains rejected, and original allocator admission
and OOM/refusal requirements remain unchanged.

All six witness CLI routes use the explicit reviewed Unix endpoint and
`--tls=false` without an explicit `--tlsverify` flag. At that exact CLI revision,
`cli/flags/options.go` enables TLS for an explicitly supplied verification flag
even when false. Default endpoint initialization in `cli/command/cli.go` reads
CA data through `cli/context/tlsdata.go` before the Unix socket bypass in
`cli/context/docker/load.go`. The prior invocation thus has a source-proven
certless initialization defect. R16's native launch/archive-image failure lacked
the underlying exception, so it does not establish a CA-read cause. Source
research and the authored certless process-boundary regression cannot replace a
new native run. Exact Apache-2.0 source revision, license and hashes are retained
as private provenance; no upstream code or executable is copied, translated or
redistributed. Historical test version/API/image facts are not new operational
pins. Existing runtime-input and manual Docker payload/Renovate ownership remain
unchanged; no extra manager, environment fallback or runtime authority is added.

The exact Engine 29.9.2 HostConfig and CLI 29.9.2 vendored inspect type mark
`Tmpfs` as `omitempty`; the JSON template does not restore that empty optional
map. The driver accepts its absence as empty while still requiring an actual
HostConfig object, explicit `ReadonlyRootfs: false`, and separate top-level
Mounts evidence. Existing explicit-null/type allowances, unsafe destinations,
covering mount/Tmpfs rejection, identity bookends, deadlines and cleanup remain
unchanged. Versioned Moby/CLI Apache-2.0 and Go 1.26.10 BSD-3-Clause JSON source
references are retained in private R18 provenance; no oracle code is copied or
translated. The authored wire fixture is not a native inspect capture. Native
40998114033's preflight/rootfs reason and verified cleanup do not identify the
failed conjunct or prove an unsafe rootfs cause. This normalization and its
hermetic tests do not qualify native behavior or add a software pin/manager.

Host code supplies bounded base64 request bytes and parses a distinct held
response inode. The active image TAR's bytes, inode and offset remain untouched;
response-role descriptors cannot enter any image-load or stdin route. Read limits
are validated before seeking or reading. Both stream roles retain a directory FD,
bind its identity at private-directory creation, and verify the named and held
parent's UID, mode 0700 and directory type before and after I/O. Allocation uses
fixed names relative to that FD; renamed, replaced or symlinked parents refuse
further I/O without rebinding or touching the active image TAR. The
selected guest `/bin/dash` sets and verifies both soft and hard file-size limits
in the actual decoder and CLI ancestor, with core dumps disabled. Dash's
[documented file-size unit](https://manpages.debian.org/trixie/dash/dash.1.en.html#ulimit)
is 512 bytes: request preparation has the larger bound, while separate CLI stderr
is capped at one block. Empty-stderr proof pairs the held regular inode and name,
UID, mode, link count and exact zero size. Setup, decoder, CLI, custody or cleanup
failure cannot produce the success receipt. The supervisor validates a separate
held completion file and appends its receipt outside the bounded stdout pipeline;
producer death cannot turn HTTP payload into a trusted receipt. Complete HTTP
framing and the independently appended receipt are required; neither CLI nor `head` exit zero is HTTP success.

One protocol end is anchored before create from the existing command timeout,
work deadline and preserved backend cleanup reserve. Preflight never renews it;
full ten-second room must remain before START. The existing eight-second await
window additionally includes PUT, every implicit CLI ping, HEAD poll and sleep.
Late parsing, transport uncertainty or incomplete framing stays unavailable.
Only the root observer copy receives the absolute protocol end as a tighter
runtime deadline, so delayed entry cannot renew its allowance. The original
context and backend deadlines remain unchanged. HEAD stat timestamps require a
valid bounded RFC3339 calendar value; they establish no freshness or OOM cause.
The separate R15 failure capture retains its existing two-second cap under the
original work deadline and reserve. Closed archive operation/reason facts retain
where the protocol stopped without exposing requests, responses or operands.

One nonrenewable ten-second controller alarm covers all gates, allocation and
after hold, within the existing original work deadline and cleanup reserve.
Insufficient time, controller death, group killing, missing after data, changed
identities, non-SIGKILL termination or unsupported accounting produces bounded
unavailable evidence. The existing runtime watchdog and exact owned-guest
cleanup also bound stalled cleanup; a failed or unknown cleanup is not success.
Controller exit zero means observation completion only. Even a bound child
SIGKILL and increasing leaf counters do not identify the OOM cause, excuse the
outer marker, or qualify this image. Synthetic syscall-shim and mock tests are
not native namespace or genuine OOM evidence.
