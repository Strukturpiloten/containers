ARG DISTRO_IMAGE
FROM ${DISTRO_IMAGE} AS packaged
ARG DISTRO_ID
ARG ENGINE_PACKAGE
ARG ENGINE_PACKAGE_VERSION
ARG ENGINE_VERSION
COPY images/docker/platforms/install-packages.sh /usr/local/bin/install-docker-packages
COPY images/docker/conformance/verify-debian-package.sh /usr/local/bin/verify-debian-package
RUN sh /usr/local/bin/install-docker-packages "${DISTRO_ID}" "${ENGINE_PACKAGE}" 1000:1000 "${ENGINE_PACKAGE_VERSION}" \
    && sh /usr/local/bin/verify-debian-package before-systemd "${ENGINE_PACKAGE_VERSION}" "${ENGINE_VERSION}"

# Inherit the authenticated archive setup and package state. Compiler packages
# stay in this disposable stage; the final image starts from packaged again.
FROM packaged AS probe
COPY images/docker/conformance/resource-probe.c /resource-probe.c
COPY images/docker/conformance/build-probe.sh /build-probe.sh
RUN sh /build-probe.sh "${DISTRO_ID}" \
    && sh /usr/local/bin/verify-debian-package after-compiler "${ENGINE_PACKAGE_VERSION}" "${ENGINE_VERSION}"

FROM packaged
ARG MODE
COPY images/docker/conformance/ /usr/local/share/conformance/
COPY images/docker/conformance/start-daemon.sh /usr/local/bin/start-conformance-daemon
COPY images/docker/conformance/start-systemd.sh /usr/local/bin/start-conformance-systemd
RUN chmod 0755 /usr/local/bin/start-conformance-* \
    && sh /usr/local/share/conformance/install-systemd.sh "${MODE}" "${DISTRO_ID}" \
    && sh /usr/local/bin/verify-debian-package after-systemd "${ENGINE_PACKAGE_VERSION}" "${ENGINE_VERSION}"
COPY --from=probe /probe/docker-resource-probe /usr/local/bin/docker-resource-probe
COPY --from=probe /probe/compiler-packages /usr/share/strukturpiloten/docker/compiler-packages
COPY --from=probe /probe/compiler-source /usr/share/strukturpiloten/docker/compiler-source
ARG OCI_BASE_DIGEST=""
ARG OCI_BASE_NAME=""
ARG OCI_CREATED=""
ARG OCI_DESCRIPTION="Systemd Docker conformance fixture"
ARG OCI_DOCUMENTATION=""
ARG OCI_LICENSES="Apache-2.0"
ARG OCI_REVISION=""
ARG OCI_SOURCE=""
ARG OCI_TITLE="Docker conformance"
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
ARG DOCKER_HOST_VALUE
ARG STORAGE_PATH
ENV container=podman DOCKER_HOST=${DOCKER_HOST_VALUE}
VOLUME ${STORAGE_PATH}
USER 0
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/local/bin/start-conformance-systemd"]
