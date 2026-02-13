# syntax=docker/dockerfile:1.7

# SPDX-License-Identifier: AGPL-3.0-or-later
# DockyPody: container build scripts and images
# Copyright (C) 2025 Mahdi Baghbani <mahdi-baghbani@azadehafzar.io>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

ARG BASE_BUILD_IMAGE="golang:1.25-trixie"
ARG BASE_RUNTIME_IMAGE="debian:trixie-slim"

##############################
### Build opencloudmesh-go ###
##############################
FROM ${BASE_BUILD_IMAGE} AS build

ENV CGO_ENABLED=1

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
    make \
    build-essential \
    libsqlite3-dev \
    binutils;

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN --mount=type=cache,id=opencloudmesh-go-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=opencloudmesh-go-go-build-cache,target=/root/.cache/go-build,sharing=locked \
    make build

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

RUN mkdir -p /app/bin /configs /usr/bin

COPY --from=build /build/bin/opencloudmesh-go /app/bin/opencloudmesh-go
COPY docker/configs/ /configs/
COPY docker/scripts/ /usr/bin/

RUN chmod 755 /app/bin/opencloudmesh-go && \
    chmod 755 /usr/bin/entrypoint.sh /usr/bin/entrypoint-init.sh

##############################
### Runtime image          ###
##############################
FROM ${BASE_RUNTIME_IMAGE}

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

ENV PATH="/app/bin:${PATH}"

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
CMD ["tail", "-F", "/var/log/opencloudmesh-go.log"]
