ARG FEDORA_IMAGE

FROM ${FEDORA_IMAGE} AS podman-builder

ARG AARDVARK_COMMIT=""
ARG AARDVARK_VERSION=""
ARG NETAVARK_COMMIT=""
ARG NETAVARK_VERSION=""
ARG OCI_VERSION
ARG PODMAN_COMMIT
ARG PODMAN_REPOSITORY

ENV GOTOOLCHAIN=local \
    GOFLAGS=-mod=vendor

WORKDIR /src

RUN set -eux; \
    podman_major="${OCI_VERSION%%.*}"; \
    dnf --assumeyes --refresh upgrade; \
    dnf --assumeyes install --setopt=install_weak_deps=False \
        btrfs-progs-devel \
        gcc \
        git-core \
        glib2-devel \
        glibc-devel \
        golang \
        gpgme-devel \
        libassuan-devel \
        libgpg-error-devel \
        libseccomp-devel \
        libselinux-devel \
        make \
        pkgconf-pkg-config \
        shadow-utils-subid-devel \
        sqlite-devel \
        systemd-devel; \
    if [ "${podman_major}" = "6" ]; then \
        dnf --assumeyes install --setopt=install_weak_deps=False cargo protobuf-compiler rust; \
    fi; \
    dnf clean all; \
    rm -rf /var/cache/dnf

RUN set -eux; \
    git init podman; \
    cd podman; \
    git remote add origin "${PODMAN_REPOSITORY}"; \
    git fetch --depth=1 origin "refs/tags/v${OCI_VERSION}"; \
    git checkout --detach FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "${PODMAN_COMMIT}"; \
    make PREFIX=/usr podman rootlessport quadlet; \
    make DESTDIR=/out PREFIX=/usr install.bin; \
    if [ -d vendor/go.podman.io/common ]; then \
        common_vendor=vendor/go.podman.io/common; \
    else \
        common_vendor=vendor/github.com/containers/common; \
    fi; \
    install -D -m 0644 "${common_vendor}/pkg/config/containers.conf" \
        /out/usr/share/containers/containers.conf; \
    install -D -m 0644 "${common_vendor}/pkg/seccomp/seccomp.json" \
        /out/usr/share/containers/seccomp.json; \
    podman_major="${OCI_VERSION%%.*}"; \
    printf '%s\n' "${podman_major}" > /out/usr/share/containers/podman-major

RUN set -eux; \
    podman_major="${OCI_VERSION%%.*}"; \
    if [ "${podman_major}" = "6" ]; then \
        test -n "${NETAVARK_VERSION}"; \
        test -n "${NETAVARK_COMMIT}"; \
        test -n "${AARDVARK_VERSION}"; \
        test -n "${AARDVARK_COMMIT}"; \
        git init netavark; \
        cd netavark; \
        git remote add origin https://github.com/containers/netavark.git; \
        git fetch --depth=1 origin "refs/tags/v${NETAVARK_VERSION}"; \
        git checkout --detach FETCH_HEAD; \
        test "$(git rev-parse HEAD)" = "${NETAVARK_COMMIT}"; \
        CI=1 cargo build --locked --release; \
        install -D -m 0755 target/release/netavark /out/usr/libexec/podman/netavark; \
        cd /src; \
        git init aardvark-dns; \
        cd aardvark-dns; \
        git remote add origin https://github.com/containers/aardvark-dns.git; \
        git fetch --depth=1 origin "refs/tags/v${AARDVARK_VERSION}"; \
        git checkout --detach FETCH_HEAD; \
        test "$(git rev-parse HEAD)" = "${AARDVARK_COMMIT}"; \
        CI=1 cargo build --locked --release; \
        install -D -m 0755 target/release/aardvark-dns /out/usr/libexec/podman/aardvark-dns; \
    fi

FROM scratch AS payload
COPY --from=podman-builder /out/ /out/
