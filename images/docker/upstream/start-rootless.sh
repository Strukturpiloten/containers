#!/bin/sh
set -eu
exec dockerd-rootless.sh \
    --host=unix:///run/user/1000/docker.sock \
    --data-root=/home/docker/.local/share/docker \
    --exec-root=/run/user/1000/docker \
    "$@"
