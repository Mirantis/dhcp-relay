# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Image used to build binaries.
ARG BUILDER_IMAGE=golang:1.26-alpine

# Image used as base image. Runs as root so cap_add NET_RAW lands in the
# effective set. The relay opens an AF_PACKET raw socket which needs CAP_NET_RAW.
ARG BASE_IMAGE=gcr.io/distroless/static-debian13

# Use builder image to build binaries. Pinned to BUILDPLATFORM so cross-arch
# builds compile natively and let Go produce the TARGETARCH binary.
FROM --platform=$BUILDPLATFORM ${BUILDER_IMAGE} AS builder

# Configure golang module proxy URI.
ARG GOPROXY=proxy.golang.org

# BuildKit-provided target platform args, used to drive Go cross-compilation.
ARG TARGETOS
ARG TARGETARCH

# Set separate workdir for builder image.
WORKDIR /workspace

# Install in build dependencies. Fail fast if the builder is not Alpine since apk is required.
RUN test -f /etc/alpine-release || (echo "error: BUILDER_IMAGE must be Alpine-based (apk not found)" && exit 1) \
	&& apk add --no-cache gcc git make musl-dev

# Bring in golang dependencies to cache these layers.
COPY go.mod go.mod
COPY go.sum go.sum
RUN --mount=type=ssh env GOPROXY=${GOPROXY} go mod download -x || true

# Copy everything into builder image.
COPY . .

# Build binaries. Requires BuildKit with SSH agent forwarding: docker build --ssh default=$SSH_AUTH_SOCK
RUN --mount=type=ssh make GOPROXY=${GOPROXY} GOOS=${TARGETOS} GOARCH=${TARGETARCH} build

# Use base image directly as the final stage.
FROM ${BASE_IMAGE} AS final

# Set workdir for base image.
WORKDIR /

# Copy binaries into base image.
COPY --from=builder /workspace/BUILD/ /usr/local/bin/
