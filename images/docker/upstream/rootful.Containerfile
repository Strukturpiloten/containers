ARG ALPINE_IMAGE
ARG BUILD_PAYLOAD_IMAGE
FROM ${BUILD_PAYLOAD_IMAGE} AS payload
FROM ${ALPINE_IMAGE}

RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache ca-certificates iproute2 iptables procps tar; \
    mkdir -p /var/lib/docker /run/docker /usr/share/strukturpiloten/docker; \
    apk info -vv > /usr/share/strukturpiloten/docker/os-packages
COPY --from=payload /payload/engine/ /usr/local/bin/
COPY --from=payload /payload/provenance/ /usr/share/strukturpiloten/docker/
COPY images/docker/upstream/start-rootful.sh /usr/local/bin/start-dockerd

ARG OCI_BASE_DIGEST=""
ARG OCI_BASE_NAME=""
ARG OCI_CREATED=""
ARG OCI_DESCRIPTION="Upstream Docker Engine for nested-container workloads"
ARG OCI_DOCUMENTATION=""
ARG OCI_LICENSES="Apache-2.0"
ARG OCI_REVISION=""
ARG OCI_SOURCE=""
ARG OCI_TITLE="Docker Engine rootful"
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

ENV DOCKER_HOST=unix:///var/run/docker.sock
CMD ["/usr/local/bin/start-dockerd"]
