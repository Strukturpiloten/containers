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
`--systemd=always`, and crun's `run.oci.systemd.subgroup=container` and
`run.oci.delegate-cgroup=payload` annotations. The guest receives no host Docker
socket, host DBus socket, or host cgroup bind mount. The harness neither migrates
host controllers nor modifies host services, cgroups or sysctls. Guest boot units
that could alter shared kernel state are masked; journald's audit capability is
removed and its actual descriptors and normal logging endpoints are checked.
All execs must remain in the guest PID 1 leaf, with empty root and payload
distributor cgroups. Missing readiness or placement evidence fails closed.

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
