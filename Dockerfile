# Image used to build binaries.
ARG BUILDER_IMAGE=golang:1.20-alpine

# Image used as base image.
ARG BASE_IMAGE=alpine:latest

# Use builder image to build binaries.
FROM ${BUILDER_IMAGE} AS builder

# Configure golang module proxy URI.
ARG GOPROXY=proxy.golang.org

# Set separate workdir for builder image.
WORKDIR /workspace

# Install in build dependencies.
RUN apk add --no-cache gcc git make musl-dev

# Bring in golang dependencies to cache these layers.
COPY go.mod go.mod
COPY go.sum go.sum
RUN --mount=type=ssh env GOPROXY=${GOPROXY} go mod download -x || true

# Copy everything into builder image.
COPY . .

# Build binaries.
RUN --mount=type=ssh make GOPROXY=${GOPROXY} all

# Use base image.
FROM ${BASE_IMAGE}

# Set workdir for base image.
WORKDIR /

# Copy binaries into base image.
COPY --from=builder /workspace/BUILD/ /usr/local/bin/
