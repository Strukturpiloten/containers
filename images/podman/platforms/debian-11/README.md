# Debian 11 compatibility profile

Bullseye builds use the official signed Debian archive after the retirement of
security package files referenced by the old Bullseye security index. Archive
metadata expiry is disabled only for this archive source; signature and package
checksum verification remain enabled.

These images are historical compatibility fixtures. Rebuilding them does not
provide current Debian security maintenance. Both privilege modes use the same
archived distro Podman packages and retain native architecture/runtime checks.
