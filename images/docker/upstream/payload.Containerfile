ARG ALPINE_IMAGE
FROM ${ALPINE_IMAGE} AS fetch

ARG ENGINE_VERSION
ARG DOCKER_ARCH
ARG ENGINE_SHA256
ARG ROOTLESS_SHA256

RUN apk add --no-cache ca-certificates curl
COPY images/docker/upstream/fetch-payload.sh /usr/local/bin/fetch-payload
RUN ENGINE_VERSION="${ENGINE_VERSION}" DOCKER_ARCH="${DOCKER_ARCH}" \
    ENGINE_SHA256="${ENGINE_SHA256}" ROOTLESS_SHA256="${ROOTLESS_SHA256}" \
    /usr/local/bin/fetch-payload

FROM scratch
COPY --from=fetch /payload/ /payload/
