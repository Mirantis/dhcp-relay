#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Phase 1 of the e2e suite. Relay runs without the mac policy flag so every client is relayed.

set -euo pipefail

cd "$(dirname "$0")"

# Policy free relay service. See compose.yaml.
RELAY_SVC="relay"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh

trap cleanup EXIT

echo "=== bringing up the policy-free relay stack ==="
docker compose up --build -d kea relay

# Wait for the kea control socket then zero its counters for this phase.
kea_ready
kea_reset_stats

echo "=== negative control: a non-relayed client on server-net must NOT get a lease ==="
expect_no_lease client-direct "kea handed a lease to a non-relayed client"

echo "=== happy path: relayed client ${MAC_ALLOWED} should get a lease ==="
# busybox udhcpc emulates a real client with hops 0 and a broadcast DISCOVER.
expect_lease client

echo "=== asserting the exchange actually went through the relay ==="
wait_log 'Option 82 -> Sub-option' \
  "relay never injected Option 82, traffic bypassed the relay"
wait_log_re '<-- 0x[0-9a-f]+: DHCP-(OFFER|ACK)' \
  "relay never wrote an OFFER/ACK back to the client interface"

echo "=== kea ground truth: the relayed client holds a lease with the ingress Option 82 ==="
assert_lease "$MAC_ALLOWED" "kea holds no lease for the relayed client"
assert_lease_opt82 "$MAC_ALLOWED" "relay did not store the ingress Option 82 in the lease"

echo "=== statelessness: a second distinct client ${MAC_BLOCKED} should also get a lease ==="
# No policy here so this is just a second client. Relaying it confirms no per client state.
expect_lease client-denied

echo "=== kea ground truth: exactly the two relayed clients hold leases ==="
assert_lease "$MAC_BLOCKED" "kea holds no lease for the second relayed client"
assert_lease_count 2 "kea lease table does not hold exactly the two relayed clients"

kea_report "classic relay"

echo "=== classic relay e2e: success ==="
