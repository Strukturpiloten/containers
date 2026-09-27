ARG ALPINE_IMAGE
ARG BUILD_PAYLOAD_IMAGE
FROM ${BUILD_PAYLOAD_IMAGE} AS payload
FROM ${ALPINE_IMAGE}

RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache ca-certificates fuse-overlayfs iproute2 iptables procps shadow shadow-subids slirp4netns tar; \
    addgroup -g 1000 docker; \
    adduser -D -u 1000 -G docker -h /home/docker docker; \
    printf 'docker:100000:65536\n' > /etc/subuid; \
    printf 'docker:100000:65536\n' > /etc/subgid; \
    chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap; \
    mkdir -p /run/user/1000 /home/docker/.local/share/docker /usr/share/strukturpiloten/docker; \
    chown -R docker:docker /run/user/1000 /home/docker; \
    chmod 0700 /run/user/1000; \
    apk info -vv > /usr/share/strukturpiloten/docker/os-packages
COPY --from=payload /payload/engine/ /usr/local/bin/
COPY --from=payload /payload/rootless/rootlesskit /usr/local/bin/rootlesskit
COPY --from=payload /payload/rootless/dockerd-rootless.sh /usr/local/bin/dockerd-rootless.sh
COPY --from=payload /payload/provenance/ /usr/share/strukturpiloten/docker/
COPY images/docker/upstream/start-rootless.sh /usr/local/bin/start-dockerd

ARG OCI_BASE_DIGEST=""
ARG OCI_BASE_NAME=""
ARG OCI_CREATED=""
ARG OCI_DESCRIPTION="Upstream Docker Engine for nested-container workloads"
ARG OCI_DOCUMENTATION=""
ARG OCI_LICENSES="Apache-2.0"
ARG OCI_REVISION=""
ARG OCI_SOURCE=""
ARG OCI_TITLE="Docker Engine rootless"
ARG OCI_URL=""
ARG OCI_VENDOR=""
ARG OCI_VERSION=""
LABEL org.opencontainers.image.base.digest="${OCI_BASE_DIGEST}" \
      org.opencontainers.image.base.name="${OCI_BASE_NAME}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="${OCI_DESCRIPTION}" \
      org.opencontainers.image.documentation="${OCI_DOCUMENTATION}" \
      org.opencontainers.image.licenses="${OCI_LICENSES}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="${OCI_TITLE}" \
      org.opencontainers.image.url="${OCI_URL}" \
      org.opencontainers.image.vendor="${OCI_VENDOR}" \
      org.opencontainers.image.version="${OCI_VERSION}"

ENV HOME=/home/docker \
    XDG_RUNTIME_DIR=/run/user/1000 \
    DOCKER_HOST=unix:///run/user/1000/docker.sock \
    DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
USER docker
CMD ["/usr/local/bin/start-dockerd"]
