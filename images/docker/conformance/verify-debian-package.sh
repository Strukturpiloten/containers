#!/bin/sh
set -eu
phase="${1:?package verification phase required}"
expected_package="${2:?exact Docker package revision required}"
expected_engine="${3:?exact Docker Engine version required}"
case "$phase" in
    before-systemd|after-systemd|after-compiler) ;;
    *) echo 'Unsupported Debian conformance package verification phase' >&2; exit 1 ;;
esac
provenance=/usr/share/strukturpiloten/docker
# A stale Version field from a removed package is insufficient. Query installed
# state afresh on every invocation, independently of the vendor install record.
installed="$(dpkg-query --show --showformat='${Status}\n${Version}\n' docker.io)"
test "$installed" = "$(printf 'install ok installed\n%s' "$expected_package")"
test "$(cat "$provenance/package-version")" = "$expected_package"
test "$(cat "$provenance/provenance-kind")" = distro-package
if [ "$phase" != before-systemd ]; then
    test "$installed" = "$(cat "$provenance/package-before-systemd")"
fi
# Keep the fixed runtime guard's account contract; never adopt an arbitrary UID.
test "$(id -u dockertest)" = 1000
test "$(id -g dockertest)" = 1000
test "$(getent passwd 1000 | cut -d: -f1)" = dockertest
test "$(getent group 1000 | cut -d: -f1)" = dockertest
test "$(getent passwd dockertest | cut -d: -f6)" = /home/docker
test "$(stat -c '%u:%g' /home/docker)" = 1000:1000
test "$(stat -c '%u:%g %a' /run/user/1000)" = '1000:1000 700'
test "$(cat /etc/subuid)" = dockertest:100000:65536
test "$(cat /etc/subgid)" = dockertest:100000:65536
# Observe packaged binaries, not static payloads or guessed symlink replacements.
test "$(command -v docker)" = /usr/bin/docker
test "$(command -v dockerd)" = /usr/sbin/dockerd
test -x /usr/share/docker.io/contrib/dockerd-rootless.sh
test -x /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh
cli_version="$(docker --version)"
daemon_version="$(dockerd --version)"
test "$(printf '%s\n' "$cli_version" | sed -E 's/^Docker version ([^,]+),.*/\1/')" = "$expected_engine"
test "$(printf '%s\n' "$daemon_version" | sed -E 's/^Docker version ([^,]+),.*/\1/')" = "$expected_engine"
printf '%s\n' "$installed" > "$provenance/package-$phase"
printf '%s\n' "$cli_version" > "$provenance/docker-version-$phase"
printf '%s\n' "$daemon_version" > "$provenance/dockerd-version-$phase"
printf '%s\n' "$(command -v docker)" "$(command -v dockerd)" \
    /usr/share/docker.io/contrib/dockerd-rootless.sh \
    /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh \
    > "$provenance/binary-paths-$phase"
