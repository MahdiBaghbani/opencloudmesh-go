# syntax=docker/dockerfile:1.7

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

ARG BASE_BUILD_IMAGE="golang:1.26.5-trixie"
ARG BASE_RUNTIME_IMAGE="debian:trixie-slim"
ARG OCM_IMAGE_VERSION="dev"
ARG OCM_IMAGE_REVISION="unknown"

##############################
### Build opencloudmesh-go ###
##############################
FROM ${BASE_BUILD_IMAGE} AS build

ENV CGO_ENABLED=0

RUN --mount=type=cache,id=opencloudmesh-go-apt-cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=opencloudmesh-go-apt-lists,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install \
    --no-install-recommends \
    --assume-yes \
    git \
    bash \
    make;

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN --mount=type=cache,id=opencloudmesh-go-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=opencloudmesh-go-go-build-cache,target=/root/.cache/go-build,sharing=locked \
    make build

# Bundle third-party NOTICE/LICENSE files for AGPL and linked-tree license obligations.
RUN --mount=type=cache,id=opencloudmesh-go-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    make licenses-install && make licenses-save

##############################
### Directory builder      ###
##############################
FROM ${BASE_RUNTIME_IMAGE} AS directory

RUN --mount=type=cache,id=opencloudmesh-go-runtime-apt-cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=opencloudmesh-go-runtime-apt-lists,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install \
    --no-install-recommends \
    --assume-yes \
    bash \
    ca-certificates;

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/bin /configs /usr/bin /tls

COPY --from=build /build/bin/opencloudmesh-go /app/bin/opencloudmesh-go
COPY docker/configs/ /configs/
COPY docker/scripts/ /usr/bin/
COPY docker/tls/ /tls/

RUN cp /tls/certificate-authority/dockypody.crt /usr/local/share/ca-certificates/dockypody.crt && \
    update-ca-certificates && \
    chmod 755 /app/bin/opencloudmesh-go && \
    chmod 755 /usr/bin/entrypoint.sh /usr/bin/entrypoint-init.sh && \
    chmod 700 /tls && \
    chmod 600 /tls/certificates/ocm-go.key && \
    chmod 644 /tls/certificates/ocm-go.crt && \
    chmod 644 /tls/certificate-authority/dockypody.crt

##############################
### Runtime image          ###
##############################
FROM ${BASE_RUNTIME_IMAGE}

ARG OCM_IMAGE_VERSION="dev"
ARG OCM_IMAGE_REVISION="unknown"
ARG BASE_RUNTIME_IMAGE="debian:trixie-slim"
ARG BASE_BUILD_IMAGE

LABEL org.opencontainers.image.title="opencloudmesh-go" \
    org.opencontainers.image.version="${OCM_IMAGE_VERSION}" \
    org.opencontainers.image.revision="${OCM_IMAGE_REVISION}" \
    org.opencontainers.image.base.name="${BASE_RUNTIME_IMAGE}" \
    io.opencloudmesh.go.version="${BASE_BUILD_IMAGE}"

RUN --mount=type=cache,id=opencloudmesh-go-final-apt-cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=opencloudmesh-go-final-apt-lists,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install \
    --no-install-recommends \
    --assume-yes \
    bash \
    ca-certificates;

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=directory /app /app
COPY --from=directory /configs /configs
COPY --from=directory /usr/bin /usr/bin
COPY --from=directory /tls /tls
COPY --from=directory /etc/ssl/certs /etc/ssl/certs
COPY --from=build /build/bin/licenses /app/licenses

ENV PATH="/app/bin:${PATH}"

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
CMD ["tail", "-F", "/var/log/opencloudmesh-go.log"]
