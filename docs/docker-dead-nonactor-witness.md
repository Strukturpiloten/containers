# Decision: bounded dead nonactors in post-exec witness v2

Containers #577 owns this semantic correction. It does not identify the cause of
the six missing numeric observations from #573, authorize a native run, or
establish DockerLens/application acceptance. Native mechanism controls and fresh
exact-candidate CI remain required before qualification. No image, workflow,
dependency pin, helper-closure member or policy cap changes with this decision.

## Authority and trust boundary

The admitted kernel, root OS/runtime, root coordinator and existing independent
root owner are trusted. During a sample, no untrusted actor or concurrent
privileged operation may mutate or propagate mounts into the critical host proc
subtree. This is an operating premise, not a measurement made by the lease lock.
Privileged compatibility guests are not containment for malicious host-root
code. Environments unable to provide this premise are unsupported and must not
request this qualification.

The sampler holds a genuine fixed `/proc` root. Ordinary numeric/fixed proc
components use descriptor-relative `openat2` with `RESOLVE_BENEATH`,
`RESOLVE_NO_XDEV` and `RESOLVE_NO_MAGICLINKS`, with no fallback for unsupported
syscalls, mount substitution or any error. The admitted syscall ABI is explicitly
x86-64/AArch64. The kernel-produced relative `self` link must name this callback's
numeric PID. Additional observer, init and owner IDs consume the same 64-ID ledger.

For the literal final `ns/pid` link only, the resolver first acquires an
`O_PATH|O_NOFOLLOW` proc symlink and reads that held link. Its deliberate final
nsfs jump uses neither scoped lookup nor the two other resolver restrictions;
keeping BENEATH/IN_ROOT would reject that magic jump too. The result must be
nsfs, report `CLONE_NEWPID` through `NS_GET_NSTYPE`, and match the held link's
target identity. This is not an atomic follow of the held symlink. It relies on
the trusted critical-subtree premise and immutable active PID-namespace
membership. Existing live-actor user/mount namespace and executable/root magic
link checks retain their original separate held-object guards; the new resolver
does not grant a general magic-link exception.

Before owner-ready v2 publication, the existing long-lived owner opens its own
active PID namespace and retains that actual FD until terminal close, including
failure paths. The private ready record binds its device/inode/type to source,
lease and original owner identity; it never serializes an FD number. Each sample
reopens that namespace inside the original held owner proc/pidfd authentication
bracket. The callback retains this overlapping reference and compares actual
owner, callback-self and proc-view-init namespace objects with ready. A namespace
reference never permits continuation after owner death.

## Strict ready and atomic anchors

The first ready checkpoint remains strict: every required child must belong to
the original candidate union, and unique live RootlessKit selection, full UID,
parent, incarnation, cgroup, label, executable/hash and namespace checks remain.
The final candidate union must equal the original union; readback cannot repair
the accepted universe.

After all ready readbacks, the producer exclusively creates the root-private
0400 fixed leaf `witness-ready-v2.json`. It contains the original canonical outer,
parent and selected-child live states and PID locators, certified realm, ready
sample, and binding/source/lease commitments. Its digest is included in the same
atomic `state.json` replacement as successful ready v2. The original state size
guard still applies to each file. A partial/orphan leaf cannot authorize
coverage or be retried into successful ready. Authenticated terminal disposal
recognizes only this additional fixed private leaf, including an orphan; it
does not interpret its contents as cleanup authority or add wildcard cleanup.

Pre-close requires that exact digest-bound anchor and original live-role states.
It rejects every reserved original role PID before any missing-PID lookup,
irrespective of an apparent new start time.

## Positive dead-object proof

Let C0 be the original bounded cgroup candidate union and K the authenticated
held parent's original complete thread/child census for this checkpoint. Only
pre-close members of `K - C0` are eligible. C0 is never refreshed, and K must
remain exactly stable through the original thread/census readbacks.

For each eligible PID, the producer acquires a genuine held proc directory and a
flags-zero process pidfd before fresh snapshots. Twice per proof it reads stat,
status and the observer's pidfd fdinfo through the certified proc view. It
requires the same positive PID=Tgid, exact parent, positive unchanged start
ticks, full expected UID tuple, State Z, positive matching Pid/NSpid vectors and
readable whole-process pidfd. Both fresh snapshots must agree. Live, unknown,
foreign, unreadable, malformed, reaped or detached held objects refuse. A zombie
leader with surviving sibling threads refuses because its process pidfd is not
readable.

All initial proofs complete before live-child selection can exclude any dead
group. Descriptors remain held. The original live-role, complete census, cgroup,
unit, subject and canonical image file/path identity readbacks finish first,
including the image context manager's exit-time checks. Then every complete
dead proof is repeated against its initial canonical state. The original owner
must still be alive. No retry, sleep, drain, signal, freeze, reap, setns, helper
broker or new actor is introduced.

This relies on explicit Linux ABI premises: process-pidfd readiness after the
last thread exits; held proc descriptors do not rebind to a reused numeric PID;
and pidfd fdinfo supplies positive correlated Pid/NSpid while the original task
remains attached, with a detached/reaped shape refused. Merely having pidfd_open
is insufficient. Reviewed upstream v5.4 differs from v5.10/v7.0 fdinfo behavior;
this is not blanket Linux 5.x support or an exact distro-source equivalence claim.
See [pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html) and
[Linux 7.0 procfs](https://docs.kernel.org/7.0/filesystems/proc.html).

## Version routing and privacy

Historical nested v1 validation retains its original closed schema and meaning.
Authenticated legacy/failed-lease close and disposal still use that historical
route. New witness RPC success and current ordinary-runtime evidence require
complete nested v2. No historical bytes are upgraded to v2.

V2 adds an opaque ready-anchor digest and per-sample outer-role/realm digests,
dead-nonactor count/digest and complete-coverage Boolean. Ready always has zero
dead nonactors and the canonical empty-set digest. The original live sample
fields plus outer/realm commitments stay stable across checkpoints; only the
dead coverage count/digest may differ. Public diagnostics remain closed and
contain no raw PIDs, paths, labels, namespace identities or exception text.

## Unchanged resource envelope and verification limits

The deadline remains five seconds inside original work, 8192 bytes per proc
read, 512 KiB aggregate proc/cgroup data, 64 distinct IDs, 96 MiB aggregate
executable data and 32 MiB per executable. Every new proc/fdinfo/link read charges
actual bytes, including cap-plus-one refusal. No allowance is renewed.

Each dead group costs six proc reads initially and six finally, two retained
FDs, and transient bounded leaf readers. Six groups therefore cost 72 reads;
the independent compact dead fixtures charge 4488 bytes. Six groups with every
read at 8192 bytes would require 589824 bytes and must refuse under the existing
524288-byte aggregate cap. A large census is not promised to fit simply because
each individual read fits.

The complete hermetic systemd fixture runs the production owner authentication,
task snapshots, parent/child selection, complete thread census, cgroup walks,
three executable hash streams and both dead-proof passes. Kernel/syscall and
runtime boundaries are replaced. Its six-group pre-close sample measures 141
proc/cgroup reads, 8355 charged bytes including namespace/self links, 384
executable bytes, 12 distinct IDs and a 66-descriptor virtual peak. Separately
tested strict namespace acquisition can add at most two transient descriptors,
giving a conservative 68-descriptor fixture bound. All owned virtual descriptors
close on completion. These numbers describe a fixture, not a measured CI host.

For general finite envelopes, let P, T, D and M be candidate, parent-thread,
cgroup-directory and dead-group counts. Each is bounded by existing limits;
IDs share one ledger rather than four separate allowances. A conservative
successful/failed-path FD bound is `2D + T + 2M + 6P + 72`, including temporarily
retained ambiguous live matches, both cgroup walks, namespace/link readers,
realm and image custody. The independent individual maxima yield 776 owned
sample FDs; ledger sharing lowers realizable combinations. OS resource errors
still refuse. A conservative regular-read bound is
`31 + 15P + 10T + 2D + 12M`, plus at most `3P + 8` bounded proc-link reads.
The aggregate-byte and deadline guards remain authoritative well before these
maxima with large inputs.

A private anchor fixture with three 8192-byte cgroups and full-width u64
metadata serializes to 27227 bytes, below the existing 32768-byte state cap.
The current public receipt fixture is 6994 bytes (historical v1: 6307).
Oversized serialization refuses rather than increasing a cap. Source still
uses the existing 262144-byte helper cap and closure membership.

Focused tests cover strict-ready preservation, six-group proof ordering after
image exit checks, reserved PID reuse, wrong/live/malformed/detached fields,
surviving-thread readiness, final reap/reuse, owner death, resolver errors and
namespace mismatches, owner FD lifetime, partial ready publication, orphan
disposal, byte/ID/state boundaries, historical v1 and current-v2 consumers.
They do not discharge supported-kernel native controls. Retained versus reaped
pidfds, numeric reuse, a Z leader with live threads, cross-view correlation and
final fresh reads must still be exercised independently on admitted kernels and
architectures, followed by complete gates and fresh exact-candidate native CI.


## Mandatory independent native mechanism controls

The fixed test entry `tests/native_docker_dead_nonactor_fixture.py` is deliberately
outside generic unittest discovery. The shared native ready checkpoint invokes
`scripts/runtime_docker_dead_nonactor_controls.py` before any current-V2 ready
witness, for ordinary/direct routes and both systemd phases. Its source is read
once from the authenticated local Git blob of the existing binding's exact
candidate, independently of the production helper closure. The existing bounded
privileged command path executes those captured bytes with isolated Python and
imports production predicates solely from the authenticated immutable stage.
The fixture and launcher are global build/runtime inputs; the existing AMD64 and
ARM64 native registrations remain the consumers. No new matrix, image, tool pin,
dependency, production actor, RPC, helper-closure member or resource cap is added.

The disposable supervisor S stays outside observer O's PID namespace and proves
`NS_GET_PARENT(O) == S` before releasing O. O cannot discover its own ancestor
namespace through that ioctl. After checking its distinct mount namespace, O
makes propagation private and mounts fresh procfs for its own certified PID view.
Descendant init D alone forks and exactly reaps the controlled children. O holds
real proc directories and process pidfds and calls the original dead-state,
dead-set and final-readback predicates without modifying their depth or budgets.

The required closed outcomes are proc/resolver certification, retained depth-two
zombie success, exact-reap refusal, deterministic observer-numeric PID reuse,
fresh replacement positive proof, original reserved-role refusal, Z-leader/live-
sibling refusal and positive proof after the final sibling exits. Only after
D's exact reap and acknowledged idle fork barrier may O write its own private
`sys/kernel/ns_last_pid` once. O sets the original observer locator minus one,
allows one replacement fork, and requires the same observer number with a
different descendant coordinate and held kernel object. D's allocator is never
reset; no host/global sysctl, namespace, mount or allocator is changed. There is
no retry or fallback for a denied facility or unexpected allocation.

This tests stale held-object rejection and unconditional reserved-locator
rejection after actual reuse. It cannot infer arbitrary reuse before the very
first snapshot of an unreserved locator: a replacement satisfying every current
predicate has no observable historical identity to compare. Fresh replacement
success is the explicit positive control for that limit. The small fixture also
does not authenticate a RootlessKit ready anchor or replace ordinary native
ready/pre-close workload qualification.

All processes share one original three-second work boundary and one-second
cleanup reserve, clipped to the inherited command allowance. Exact direct-child
pidfds, parent-death protection and namespace-init teardown bound cleanup; a
failed signal still attempts the exact wait and descriptor closure. S's final
wait and unchanged original mount/user/active-PID identities are required before
success. Cleanup uncertainty, deadline expiry, missing capabilities, unsupported
ABI, malformed/extra/truncated output or a missing outcome fails the mandatory
step. Neither generic unit skips nor root UID alone establish capability support.

Only bounded closed observations with candidate/run/attempt/job, binding and
fixture source digests, architecture and kernel reach ordinary check evidence.
Captured response streams and exception operands stay private. Success is cached
only within the current backend invocation with the same association; failed
results never authorize ready. A well-formed closed unavailable/failed outcome
is preserved as failed check evidence, including when the command exits nonzero;
unparseable output and exception operands are never copied into that record.
This source design and its inert offline tests
are not evidence that either admitted architecture has executed these controls.
Fresh exact-candidate native runs and complete gates remain required.


## CI image-input prerequisite

The first PR #580 CI run stopped before native execution because the pinned
openSUSE Tumbleweed manifest was unavailable. Fresh anonymous registry observations
confirmed a current manifest for both required architectures. The four existing
Docker/Podman Tumbleweed metadata pins were refreshed together under their unchanged
Renovate extraction and digest group. This input recovery changes no witness
predicate or native admission rule and is not compatibility evidence. Fresh
required native CI remains mandatory; historical failed inputs remain evidence.
