#!/bin/sh
set -eu
# Override this private guest JSON file to configure additional Unix sockets.
# There is no shell evaluation, ambient Docker context, or host socket lookup.
if [ "$(id -u)" = 0 ]; then
    exec dockerd --config-file=/etc/strukturpiloten/docker/daemon.json
fi
test "$(id -u)" = 1000
test -S /run/user/1000/bus
exec rootlesskit --net=slirp4netns --mtu=65520 --disable-host-loopback \
    --port-driver=builtin --copy-up=/etc --copy-up=/run --propagation=rslave \
    sh -ec '
        # Copy-up can retain a link into the inaccessible original /run.
        # Detach only this child-namespace link; never touch its target.
        if [ -L /run/containerd ]; then
            rm -- /run/containerd
        fi
        if [ -e /run/containerd ] && [ ! -d /run/containerd ]; then
            exit 1
        fi
        exec dockerd --config-file=/etc/strukturpiloten/docker/daemon.json
    '
