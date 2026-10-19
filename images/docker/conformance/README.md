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

The trusted outer runtime is rootful Podman with crun, a private cgroup namespace,
`--systemd=always`, and crun's `run.oci.systemd.subgroup=container` annotation.
Guest systemd manages the private cgroup namespace root directly, creating its
own nonroot PID 1 leaf and user hierarchy. The guest receives no host Docker
socket, host DBus socket, or host cgroup bind mount. The harness neither migrates
host controllers nor modifies host services, cgroups or sysctls. Guest boot units
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
Only the existing read-only daemon-info readiness condition may be polled within
the remaining startup deadline. Each API sample has the normal pre/post placement
guard and returns a closed ready/pending marker; guard, OCI, I/O and malformed
marker failures are fatal and never restart placement admission. Both prior native
failures refused the first guarded exec but passed the same guard at shutdown;
their evidence did not identify the transient predicate. Fresh native runs remain
required to qualify this passive startup observation.

The former extra `payload` delegation subtree is incompatible with the pinned
Docker Engine 29.8.2. Its [Moby revision 8af9fe3, `withRootless`](https://github.com/moby/moby/blob/8af9fe3a36bab3e039862a2ab1cef1880c9b4d03/daemon/oci_linux.go#L63)
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

Run the repository harness against the exact built OCI archive on each native
architecture, using `--sudo --allow-privileged`; see the generated image page and
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
