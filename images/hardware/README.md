# Strukturbo hardware tools

The hardware and provisioning candidates use `build.githubActions: false` to keep builds local. Actions plans exclude them for every trigger, including push, nightly and manual runs. This hold also excludes dependent images and must be removed in a reviewed change before remote builds/publication.

These generic Fedora 44 tool images support the separately maintained Strukturbo Hardware OS. They contain distribution packages and public builder tooling. The collector, operator keys, network configuration, enrollment credentials and device policy belong to the OS project and its reviewed runtime inputs.

| Image | Purpose | Qualified architecture |
| --- | --- | --- |
| [strukturbo-hardware-builder](strukturbo-hardware-builder/container.yaml) | mkosi 27.1, ukify, Fedora package/build tools | linux/amd64 |
| [strukturbo-hardware-discovery](strukturbo-hardware-discovery/container.yaml) | CPU, PCI, SMBIOS, NIC, storage and RDMA discovery tools | linux/amd64 |
| [strukturbo-hardware-admin](strukturbo-hardware-admin/container.yaml) | Shell, DNS, routing, SSH client and packet diagnostics | linux/amd64 |

All three are experimental, admitted only for isolated tests, and excluded from scheduled builds. Local qualification does not establish GHCR publication, firmware compatibility, HTTP boot, disk safety on physical hardware or production admission. No firmware updater or target OS installer is supplied by these images.

## Source and updates

The Fedora base is pinned by tag and digest. The builder additionally pins mkosi's release version, immutable Git commit and source-archive SHA-256. Its Containerfile verifies the archive before installation and checks the installed mkosi version against the selected release. Installed distribution package versions are recorded in `/usr/share/strukturbo/packages.txt`.

Renovate updates the mkosi version and commit together. The existing generated-files follow-up runs trusted default-branch code over the immutable PR data, checks the release tag against that commit using the fixed `systemd/mkosi` upstream, and regenerates the archive checksum. A mismatch fails before an archive is accepted. Downloaded archives are hashed only; this follow-up never extracts them or executes PR/source code. It inherits the repository's existing CI-gated platform automerge policy.

## Local runtime evidence

Build from the repository root with the metadata's exact build arguments and OCI source revision/version labels. Keep generated archives and evidence outside the source tree. To inspect an exported archive with the standard isolated runtime harness:

```sh
.venv/bin/python -m scripts.runtime_tests \
  --image-name strukturbo-hardware-discovery \
  --archive /absolute/path/to/discovery.oci.tar \
  --arch amd64 --sudo --evidence /absolute/path/to/discovery-runtime.json
```

Use the corresponding image name/archive for builder and administrator checks. The hardware profile runs read-only containers with networking disabled, all capabilities dropped and no-new-privileges. It checks required binaries and package records; builder checks its recorded mkosi version, discovery exercises CPU JSON output, and administrator checks its default shell. The harness uses its own isolated Podman store and cleans up its owned containers.

These checks do not mount host disks or supply hardware devices. Actual device visibility and privileges must be selected and tested by the OS integration. Target discovery must preserve installed disks; firmware or installation actions need their own reviewed operation.
