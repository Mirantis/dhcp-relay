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

# Artifacts output directory.
ARTIFACTS_DIR := $(abspath $(or $(ARTIFACTS_DIR), $(addprefix $(PROJECT_DIR),/BUILD)))

include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.common))
include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.docker))

.PHONY: all
all: check build

# Run all checks.
.PHONY: check
check: clean tidy check-git-clean lint test

# End-to-end tests via docker compose, split into phases for CI visibility.
.PHONY: test-e2e test-e2e-relay test-e2e-policy test-e2e-unnumbered
.PHONY: test-e2e-bench test-e2e-bench-short test-e2e-bench-long
.PHONY: test-e2e-bench-short-classic test-e2e-bench-short-policy
.PHONY: test-e2e-bench-long-classic test-e2e-bench-long-policy

# Run the gated correctness phases in order (classic relay, MAC policy, unnumbered relay).
test-e2e: test-e2e-relay test-e2e-policy test-e2e-unnumbered

# Phase 1: classic relay behavior, no MAC policy.
test-e2e-relay:
	bash $(PROJECT_DIR)/e2e/relay.sh

# Phase 2: MAC policy / action map behavior.
test-e2e-policy:
	bash $(PROJECT_DIR)/e2e/policy.sh

# Phase 3: unnumbered ingress via the link map and RFC 3527 Link Selection.
test-e2e-unnumbered:
	bash $(PROJECT_DIR)/e2e/unnumbered.sh

# Informational perfdhcp benchmark. Short runs are debug only, long runs emit summary tables.
# Not part of test-e2e. Short runs come first so a failure shows up on a tiny load.
test-e2e-bench: test-e2e-bench-short test-e2e-bench-long
test-e2e-bench-short: test-e2e-bench-short-classic test-e2e-bench-short-policy
test-e2e-bench-long: test-e2e-bench-long-classic test-e2e-bench-long-policy
test-e2e-bench-short-classic:
	bash $(PROJECT_DIR)/e2e/bench.sh classic short
test-e2e-bench-short-policy:
	bash $(PROJECT_DIR)/e2e/bench.sh policy short
test-e2e-bench-long-classic:
	bash $(PROJECT_DIR)/e2e/bench.sh classic long
test-e2e-bench-long-policy:
	bash $(PROJECT_DIR)/e2e/bench.sh policy long
