# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Makefile variables.
PROJECT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Project-specific variables.
IMAGE_DEFAULT_NAME := dhcp-relay
IMAGE_DISPLAY_NAME := "DHCPv4 Relay Agent"
IMAGE_DESCRIPTION := "DHCPv4 Relay Agent written in Golang"

# Name of output binary.
BIN_NAME := $(or $(BIN_NAME),dhcp-relay)

# Path to project root directory.
PROJECT_DIR := $(abspath $(or $(PROJECT_DIR),./))

# Artifacts output directory.
ARTIFACTS_DIR := $(abspath $(or $(ARTIFACTS_DIR), $(addprefix $(PROJECT_DIR),/BUILD)))

include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.common))
include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.docker))

all: check build

# Run all checks.
.PHONY: check
check: clean tidy lint test check-git-clean

# End-to-end tests via docker compose, split into phases for CI visibility.
.PHONY: test-e2e test-e2e-relay test-e2e-policy
.PHONY: test-e2e-scale test-e2e-scale-classic test-e2e-scale-policy
.PHONY: test-e2e-bench test-e2e-bench-classic test-e2e-bench-policy

# Run the gated phases in order (classic relay, MAC policy, scale on both setups).
test-e2e: test-e2e-relay test-e2e-policy test-e2e-scale

# Phase 1: classic relay behavior, no MAC policy.
test-e2e-relay:
	bash $(PROJECT_DIR)/e2e/relay.sh

# Phase 2: MAC policy / action map behavior.
test-e2e-policy:
	bash $(PROJECT_DIR)/e2e/policy.sh

# Phase 3: deterministic perfdhcp scale gate on the classic and policy relays.
test-e2e-scale: test-e2e-scale-classic test-e2e-scale-policy
test-e2e-scale-classic:
	bash $(PROJECT_DIR)/e2e/scale.sh classic
test-e2e-scale-policy:
	bash $(PROJECT_DIR)/e2e/scale.sh policy

# Informational perfdhcp benchmark on both setups. Not part of test-e2e.
test-e2e-bench: test-e2e-bench-classic test-e2e-bench-policy
test-e2e-bench-classic:
	bash $(PROJECT_DIR)/e2e/bench.sh classic
test-e2e-bench-policy:
	bash $(PROJECT_DIR)/e2e/bench.sh policy
