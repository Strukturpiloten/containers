#!/bin/sh
set -eu
exec dockerd \
    --host=unix:///var/run/docker.sock \
    --data-root=/var/lib/docker \
    --exec-root=/run/docker \
    "$@"
