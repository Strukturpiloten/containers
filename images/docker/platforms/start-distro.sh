#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    exec dockerd \
        --host=unix:///var/run/docker.sock \
        --data-root=/var/lib/docker \
        --exec-root=/run/docker \
        "$@"
fi

: "${XDG_RUNTIME_DIR:?}"
: "${HOME:?}"
exec rootlesskit \
    --net=slirp4netns \
    --mtu=65520 \
    --disable-host-loopback \
    --port-driver=builtin \
    --copy-up=/etc \
    --copy-up=/run \
    --propagation=rslave \
    dockerd \
    --rootless \
    --host=unix:///run/user/1000/docker.sock \
    --data-root=/home/docker/.local/share/docker \
    --exec-root=/run/user/1000/docker \
    "$@"
