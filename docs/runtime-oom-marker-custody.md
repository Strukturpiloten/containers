# Rootless fixture OOM marker custody

Podman outer runs retain strict native success predicates, including outer
`OOMKilled=false` and a verified orderly zero exit. The selected private Docker
systemd backend implements [mandatory parent lifetime accounting](runtime-backends.md#mandatory-docker-parent-oom-lifecycle-accounting):
typed zero-exit lifecycle states remain pending until independent original-probe
kill authority, quiescent whole-parent reconciliation and exact cleanup succeed.
The actual sticky Docker flag is retained; marker observations cannot provide
ledger authority or qualify an image. This implemented source contract still
can report accounting complete while native qualification remains none: no
maintained normal prerequisite exists for that private route yet. The focused
mandatory-accounting dispatch remains experimental and separate from the
witness-diagnostic choice. Ordinary evidence consumers reject that authority,
including status/exit-zero records. No earlier receipt gains admission; normal
prerequisite rollout and independent native qualification remain outstanding.

The marker observer applies to Podman outer runs. Docker outer runs retain actual
Docker state while reporting conmon sources as backend-not-applicable with
unresolved attribution. No conmon marker or held PID identity is invented there.

Before releasing the inner memory allocator, the optional host observer uses only
the existing exact-container monitor metadata. It holds the original PID1 pidfd
and starttime, original marker parent descriptors, an inotify watch on each held
parent, and the original conmon-watched `memory.events` descriptor plus its local
counter counterpart. It performs no process-argument or environment discovery,
global scans, runtime requests, controller writes, or marker writes.

Schema version 1 custody records contain fixed fields: kernel identities, bounded
counter values, exact-name marker create/close/delete events, observation times,
PID continuity, and marker lengths/hashes. At an observed close-write event the
helper captures an immutable bounded content record bound to that file version.
Later modifications invalidate current completion; previous completed versions
stay separately retained with sticky rewrite uncertainty. A close superseded by
a queued modification cannot seal the later writer's prefix. Proposed content
must also pass one bounded post-read event drain and a final metadata recheck;
new target writes or replacement discard the proposal. Post-read events cannot
recursively capture more content. Retained records describe a close observation
and stable read interval, not an atomic future snapshot or the writer's identity.
Timestamps describe
when the observer
read the event, not when the kernel generated it. Marker contents are never
printed. The original conmon watch remains recorded when later snapshot readback
is missing or changed; that uncertainty is sticky.

Sampling brackets allocation (including failed release/wait readback), shutdown,
the boundary before orderly-stop dispatch, and terminal state before owned cleanup.
That boundary proves PID liveness at observation, not successful request delivery
or uninterrupted liveness through the command's placement guard. Held
marker descriptors and retained creation events survive subsequent path removal;
missing, preexisting, replaced, renamed, partially read, or ambiguous evidence
remains unresolved. Event observation does not identify the marker's writer or
prove correspondence between a monitor binary and upstream source.

The helper expires at the earlier of 640 seconds and the existing work deadline
plus the existing 40-second orderly-stop allowance. It never renews native work
budgets. Phase exchanges allow two seconds, output writes half a second, and EOF
cleanup half a second. It accepts eight phase requests and retains at most 32
marker events. All directory headers, including unrelated names, count toward a
separate cumulative ceiling of 32,768, derived from the existing 512 KiB aggregate
byte limit divided by the 16-byte inotify header. Names and file reads still
consume that same byte budget, and unrelated names are never retained. The
1,024-read, 4 KiB per-file and 64 KiB per-message limits remain unchanged. Decode
and consume loops check the original absolute deadline; framing, lookahead and
the nonrecursive post-read bracket still complete before publishing content.
Overflow, expiry, interruption, unavailable kernel
interfaces and uncertain helper cleanup remain diagnostics, never admission.
EOF, error and timeout close the helper's read-only descriptors; uncertain driver
cleanup retains the helper's independent absolute expiry.
If the input pipe closes or the owned helper exits, the client can retain one
buffered terminal error record within the same exchange deadline and byte cap.
Only the closed versioned error schema is retained; missing, late, partial,
oversized or unknown records stay explicitly unavailable. Later phases may show
that previously retained error, without restarting or retrying the helper.
A failed request/response exchange or terminal drain permanently retires the
stream. Later phases reuse an unavailable result without a new deadline or
pipe/process operations; the original exchange failure remains explicit in its
phase. Final owned cleanup still closes the pipes and waits for the helper.
Terminal validation closes every nested watch, file identity, counter and
completed-content record, including numeric ranges, hashes and read intervals.
The watch must match the original owned source. Exception classes and uncertainty
labels use the producer's fixed vocabulary; unknown text or fields are rejected
before caching or forwarding. Producer schema changes require receiver review.

Terminal errors may additionally include `failureGuard`, a closed classification
of a known fixed deadline, budget, protocol, watch, identity or content guard.
The helper matches only an exact built-in `ValueError` with one plain string
argument against a static table; unknown errors omit the field. It never formats
or emits the exception message. The optional field is also omitted when the
complete record would exceed the existing message bound or its classification
preview fails; the original record is sent once without trimming or retrying.
The original exception-class `reason`, error status and unresolved attribution
remain unchanged. This classification adds no reads, timers, retries or allowance
and does not identify an OOM cause. Guards that already remain local unresolved
observations keep their existing handling.
The helper mapping and lightweight client deliberately duplicate the finite wire
values to preserve isolated helper startup and avoid loading its native-library
dependencies in the client. Protocol tests tie both definitions; absent fields
remain valid, while unknown or malformed classifications retire the stream.

The existing snapshot evidence schema and historical native evidence are retained.
No image recipe, software version, dependency, pin or operational workflow changes
are required; consequently existing Renovate ownership and extractors are
unchanged. New native AMD64 and ARM64 evidence is still required, and image
publication remains a separate operation.
