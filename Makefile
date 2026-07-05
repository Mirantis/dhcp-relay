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

# End-to-end tests via docker compose + pytest, split into phases for CI visibility.
.PHONY: test-e2e test-e2e-relay test-e2e-policy test-e2e-unnumbered
.PHONY: test-e2e-policy-reload test-e2e-linkmap test-e2e-giaddr test-e2e-release
.PHONY: test-e2e-broadcast test-e2e-chained test-e2e-multihomed
.PHONY: test-e2e-startup test-e2e-linkmap-reload test-e2e-twoserver test-e2e-nak
.PHONY: test-e2e-bench test-e2e-bench-short test-e2e-bench-long
.PHONY: test-e2e-bench-short-classic test-e2e-bench-short-policy
.PHONY: test-e2e-bench-long-classic test-e2e-bench-long-policy
.PHONY: lint-python

E2E_PYTEST := uv run --project $(PROJECT_DIR) --group e2e pytest -v
E2E_COMPOSE := docker compose -f $(PROJECT_DIR)/e2e/compose.yaml

.PHONY: test-e2e-build test-e2e-bench-build

# Prebuild the functional-phase images so the test phases hit the docker cache instead of
# building from scratch. The three relay variants share the dhcp-relay:e2e image built by relay.
test-e2e-build:
	COMPOSE_PROFILES=classic,policy,unnumbered $(E2E_COMPOSE) build relay kea relay-unnumbered-init

# Prebuild the benchmark images. Both bench modes share the dhcp-relay:e2e image built by relay.
test-e2e-bench-build:
	COMPOSE_PROFILES=classic,policy,bench $(E2E_COMPOSE) build relay kea perfdhcp

# Run the gated correctness phases in order.
test-e2e: test-e2e-relay test-e2e-policy test-e2e-unnumbered \
          test-e2e-policy-reload test-e2e-linkmap test-e2e-giaddr test-e2e-release \
          test-e2e-broadcast test-e2e-chained test-e2e-multihomed \
          test-e2e-startup test-e2e-linkmap-reload test-e2e-twoserver test-e2e-nak

# Phase 1: classic relay behavior, no MAC policy.
test-e2e-relay:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_relay.py

# Phase 2: MAC policy / action map behavior.
test-e2e-policy:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_policy.py

# Phase 3: unnumbered ingress via the link map and RFC 3527 Link Selection.
test-e2e-unnumbered:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_unnumbered.py

# Phase 4: MAC policy hot-reload robustness (malformed file keeps the previous policy).
test-e2e-policy-reload:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_policy_reload.py

# Phase 5: link-map NIC selector (name glob match and no-match drop).
test-e2e-linkmap:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_linkmap.py

# Phase 6: -giaddr override on the unnumbered path.
test-e2e-giaddr:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_giaddr.py

# Phase 7: DHCPRELEASE round-trip frees the lease in kea.
test-e2e-release:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_release.py

# Phase 8: broadcast-flag reply path.
test-e2e-broadcast:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_broadcast.py

# Phase 9: chained relay forward path, reply forwarding, and the hop-limit drop.
test-e2e-chained:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_chained.py

# Phase 10: multi-homed ingress relays one copy per interface address.
test-e2e-multihomed:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_multihomed.py

# Phase 11: fail-fast startup validation on bad config.
test-e2e-startup:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_startup.py

# Phase 12: link-map empty-map drop and malformed-reload robustness.
test-e2e-linkmap-reload:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_linkmap_reload.py

# Phase 13: per-client forward to a second DHCP server.
test-e2e-twoserver:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_twoserver.py

# Phase 14: crafted out-of-subnet REQUEST relays a DHCPNAK.
test-e2e-nak:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_nak.py

# Informational perfdhcp benchmark. Short runs are debug only, long runs emit summary tables.
# Not part of test-e2e. Short runs come first so a failure shows up on a tiny load.
test-e2e-bench: test-e2e-bench-short test-e2e-bench-long
test-e2e-bench-short: test-e2e-bench-short-classic test-e2e-bench-short-policy
test-e2e-bench-long: test-e2e-bench-long-classic test-e2e-bench-long-policy
test-e2e-bench-short-classic:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_bench.py -k "classic and short"
test-e2e-bench-short-policy:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_bench.py -k "policy and short"
test-e2e-bench-long-classic:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_bench.py -k "classic and long"
test-e2e-bench-long-policy:
	$(E2E_PYTEST) $(PROJECT_DIR)/e2e/test_bench.py -k "policy and long"

# Lint the Python e2e harness with black.
lint-python:
	uv run --project $(PROJECT_DIR) --group e2e black --check --diff $(PROJECT_DIR)/e2e
