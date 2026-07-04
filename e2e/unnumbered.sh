#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Phase 3 of the e2e suite. The relay client NIC is unnumbered so relaying goes through the link map and
# RFC 3527 Link Selection. giaddr auto-derives from the server-facing address.

set -euo pipefail

cd "$(dirname "$0")"

# Unnumbered relay service. See compose.yaml.
RELAY_SVC="relay-unnumbered"
KEA_REPORT_TITLE="functional: unnumbered relay (link map + Link Selection)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh

trap cleanup EXIT

echo "=== seeding the link map (every ingress NIC maps to the client subnet) ==="
mkdir -p ./linkmap
printf '* 192.168.50.0/24\n' > ./linkmap/link-map.txt

echo "=== bringing up the unnumbered relay stack ==="
docker compose up --build -d kea relay-unnumbered relay-unnumbered-init

# The relay client NIC must be unnumbered before any client sends so wait for the init to flush it.
wait_unnumbered() {
  local i
  for i in $(seq 1 30); do
    if docker compose logs --no-color relay-unnumbered-init 2>/dev/null | grep -qF 'flushed client-net IPv4'; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: unnumbered init never flushed the client-net IPv4"
  echo "--- init logs ---"
  docker compose logs --no-color relay-unnumbered-init 2>/dev/null | tail -20
  exit 1
}
wait_unnumbered

relay_ready
kea_ready
kea_reset_stats

echo "=== happy path: a client on the unnumbered segment ${MAC_ALLOWED} should still get a lease ==="
expect_lease client

echo "=== asserting the request went through the relay on the unnumbered path ==="
wait_log 'Option 82 -> Sub-option' \
  "relay never injected Option 82, traffic bypassed the relay"
# Type=5 is the RFC 3527 Link Selection sub-option, emitted only on the unnumbered giaddr path. Asserting it
# guards against a false pass where the relay came up numbered (for example if the IP flush did not take).
wait_log 'Option 82 -> Sub-option: Type=5' \
  "relay did not emit the Link Selection sub-option, the unnumbered path was not exercised"
wait_log_re '<-- 0x[0-9a-f]+: DHCP-(OFFER|ACK)' \
  "relay never wrote an OFFER/ACK back to the client interface"

echo "=== kea ground truth: the client holds exactly one lease in the mapped subnet ==="
assert_lease "$MAC_ALLOWED" "kea holds no lease for the client on the unnumbered segment"
assert_lease_count 1 "kea lease table does not hold exactly the one client"

echo "=== unnumbered relay e2e: success ==="
