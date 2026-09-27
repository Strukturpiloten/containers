#!/bin/sh
set -eu

: "${ENGINE_VERSION:?}"
: "${DOCKER_ARCH:?}"
: "${ENGINE_SHA256:?}"
: "${ROOTLESS_SHA256:?}"

case "$DOCKER_ARCH" in
    x86_64|aarch64) ;;
    *) echo "Unsupported Docker architecture: $DOCKER_ARCH" >&2; exit 1 ;;
esac
case "$ENGINE_VERSION" in
    *[!0-9.]*|'') echo "Invalid Engine version: $ENGINE_VERSION" >&2; exit 1 ;;
esac
for digest in "$ENGINE_SHA256" "$ROOTLESS_SHA256"; do
    case "$digest" in
        *[!0-9a-f]*|'') echo "Invalid SHA256: $digest" >&2; exit 1 ;;
    esac
    test "${#digest}" -eq 64
done

base="https://download.docker.com/linux/static/stable/$DOCKER_ARCH"
mkdir -p /payload/engine /payload/rootless /payload/provenance
curl --fail --location --silent --show-error --retry 3 \
    "$base/docker-$ENGINE_VERSION.tgz" -o /tmp/docker.tgz
printf '%s  %s\n' "$ENGINE_SHA256" /tmp/docker.tgz | sha256sum -c -
curl --fail --location --silent --show-error --retry 3 \
    "$base/docker-rootless-extras-$ENGINE_VERSION.tgz" -o /tmp/rootless.tgz
printf '%s  %s\n' "$ROOTLESS_SHA256" /tmp/rootless.tgz | sha256sum -c -
tar -xzf /tmp/docker.tgz -C /payload/engine --strip-components=1
tar -xzf /tmp/rootless.tgz -C /payload/rootless --strip-components=1
test -x /payload/engine/dockerd
test -x /payload/engine/docker
test -x /payload/engine/containerd
test -x /payload/engine/runc
test -x /payload/rootless/rootlesskit
test -x /payload/rootless/dockerd-rootless.sh
/payload/engine/dockerd --version | grep -F "Docker version $ENGINE_VERSION,"
/payload/engine/docker --version | grep -F "Docker version $ENGINE_VERSION,"
printf '%s\n' "$ENGINE_VERSION" > /payload/provenance/engine-version
printf '%s\n' "$DOCKER_ARCH" > /payload/provenance/architecture
printf '%s\n' "$ENGINE_SHA256" > /payload/provenance/engine-archive-sha256
printf '%s\n' "$ROOTLESS_SHA256" > /payload/provenance/rootless-archive-sha256
/payload/engine/dockerd --version > /payload/provenance/dockerd-version
/payload/engine/docker --version > /payload/provenance/docker-version
/payload/engine/containerd --version > /payload/provenance/containerd-version
/payload/engine/runc --version > /payload/provenance/runc-version
/payload/rootless/rootlesskit --version > /payload/provenance/rootlesskit-version
{
    printf 'payload-kind=verified-upstream-static-archives\n'
    printf 'engine-archive=%s/docker-%s.tgz\n' "$base" "$ENGINE_VERSION"
    printf 'engine-sha256=%s\n' "$ENGINE_SHA256"
    printf 'rootless-archive=%s/docker-rootless-extras-%s.tgz\n' "$base" "$ENGINE_VERSION"
    printf 'rootless-sha256=%s\n' "$ROOTLESS_SHA256"
    printf 'architecture=%s\n' "$DOCKER_ARCH"
    cat /payload/provenance/dockerd-version
    cat /payload/provenance/docker-version
    cat /payload/provenance/containerd-version
    cat /payload/provenance/runc-version
    cat /payload/provenance/rootlesskit-version
} > /payload/provenance/components.txt
