#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Scale gate. Drives N clients through the relay with perfdhcp requiring zero drops and kea ground truth.
# Usage scale.sh <classic|policy>

set -euo pipefail

cd "$(dirname "$0")"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=perf.sh
source ./perf.sh

perf_setup_mode "${1:-classic}"

trap 'cleanup; rm -f "${OUT:-}"' EXIT

N="${SCALE_CLIENTS:-200}"
RATE="${SCALE_RATE:-50}"
OUT="$(mktemp)"

echo "=== scale (${MODE}): bringing up kea + ${RELAY_SVC} ==="
docker compose up --build -d kea "$RELAY_SVC"
perf_build
kea_ready
kea_cmd '{"command":"lease4-wipe","arguments":{"subnet-id":1}}' >/dev/null
kea_reset_stats

echo "=== scale (${MODE}): ${N} clients at ${RATE}/s, zero drops required ==="
# perfdhcp exits non zero only on send errors. kea ground truth below is the real zero drop gate.
if ! perf_run "$OUT" -4 -r "$RATE" -R "$N" -n "$N" "${PERF_COMMON[@]}"; then
  echo "FAIL: perfdhcp reported errors through ${RELAY_SVC} (check promiscuous mode and the reply path; perfdhcp exits non-zero on send errors, not drops)"
  exit 1
fi

echo "=== scale (${MODE}): kea ground truth ==="
assert_stat_eq pkt4-discover-received "$N" "kea did not receive all relayed DISCOVERs"
assert_stat_eq pkt4-ack-sent "$N" "kea did not ACK all relayed clients"
assert_lease_count "$N" "kea lease table does not hold all relayed clients"

echo "=== scale e2e (${MODE}): success ==="
