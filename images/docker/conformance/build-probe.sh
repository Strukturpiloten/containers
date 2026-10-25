#!/bin/sh
set -eux
test "${1:?distribution required}" = debian-13
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends gcc libc6-dev
mkdir /probe
dpkg-query --show --showformat='${binary:Package}=${Version}\n' | sort > /probe/compiler-packages
apt-cache policy gcc libc6 libc6-dev libc-dev-bin > /probe/compiler-source
cc -std=c99 -O2 -Wall -Wextra -Werror /resource-probe.c -o /probe/docker-resource-probe
