#!/bin/sh
set -eu
test "$(id -u)" = 0
test -f /sys/fs/cgroup/cgroup.controllers
mkdir -p /run/docker /run/dbus /run/systemd/journal /run/log/journal /run/lock
if [ "$(cat /usr/share/strukturpiloten/docker/conformance-mode)" = rootless ]; then
    chown 1000:1000 /run/docker
fi
exec /sbin/init
