#!/bin/sh
set -eux

mode="${1:?daemon mode required}"
test "${2:?distribution required}" = debian-13
provenance=/usr/share/strukturpiloten/docker
export DEBIAN_FRONTEND=noninteractive
apt-get update
# Packages are authenticated by the existing distribution's signed apt indexes.
apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus dbus-user-session libpam-systemd util-linux
apt-cache policy systemd systemd-sysv dbus dbus-user-session libpam-systemd util-linux \
    > "$provenance/conformance-source"
dpkg-query --show --showformat='${binary:Package}=${Version}\n' \
    | sort > "$provenance/os-packages"
dpkg-query --show --showformat='${binary:Package}=${Version}\n' \
    systemd dbus dbus-user-session libpam-systemd util-linux \
    > "$provenance/conformance-packages"
rm -rf /var/lib/apt/lists/*
mkdir -p /etc/strukturpiloten/docker /etc/systemd/system/user@1000.service.d
# The guest must not ask boot-time services to alter shared kernel state.
systemctl --root=/ mask systemd-sysctl.service systemd-modules-load.service \
    systemd-udevd.service systemd-udev-trigger.service systemd-remount-fs.service \
    systemd-tmpfiles-setup-dev.service systemd-tmpfiles-setup-dev-early.service \
    systemd-tmpfiles-setup.service systemd-tmpfiles-clean.service systemd-tmpfiles-clean.timer \
    systemd-timesyncd.service systemd-journald-audit.socket systemd-random-seed.service systemd-pstore.service \
    systemd-backlight@.service systemd-rfkill.service systemd-rfkill.socket
mkdir -p /etc/systemd/system/systemd-journald.service.d
cp /usr/local/share/conformance/journal-boundary.conf /etc/systemd/system/systemd-journald.service.d/boundary.conf
for unit in systemd-sysctl.service systemd-timesyncd.service systemd-journald-audit.socket \
    systemd-tmpfiles-setup.service systemd-tmpfiles-clean.service; do
    test "$(readlink "/etc/systemd/system/$unit")" = /dev/null
done
cp /etc/systemd/system/systemd-journald.service.d/boundary.conf "$provenance/journal-boundary"
cp /lib/systemd/system/systemd-journald.service "$provenance/vendor-journald-unit"
for unit in docker.service docker.socket containerd.service; do
    if [ -f "/lib/systemd/system/$unit" ] || [ -f "/usr/lib/systemd/system/$unit" ]; then
        systemctl --root=/ disable "$unit"
    fi
done
cp "/usr/local/share/conformance/$mode.json" /etc/strukturpiloten/docker/daemon.json
if [ "$mode" = rootless ]; then
    mkdir -p /var/lib/systemd/linger /home/docker/.config/systemd/user/default.target.wants
    # Guest-only linger state: no host login/session or host cgroup changes.
    touch /var/lib/systemd/linger/dockertest
    cp /usr/local/share/conformance/user-delegation.conf /etc/systemd/system/user@1000.service.d/delegate.conf
    cp /usr/local/share/conformance/docker-user.service /home/docker/.config/systemd/user/docker.service
    ln -s ../docker.service /home/docker/.config/systemd/user/default.target.wants/docker.service
    chown -R 1000:1000 /home/docker
    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -s /lib/systemd/system/user@.service /etc/systemd/system/multi-user.target.wants/user@1000.service
else
    cp /usr/local/share/conformance/docker-system.service /etc/systemd/system/docker.service
    systemctl enable docker.service
fi
printf '%s\n' "$mode" > "$provenance/conformance-mode"
rm -f /etc/machine-id /var/lib/systemd/random-seed
