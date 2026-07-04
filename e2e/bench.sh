#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# perfdhcp benchmark for classic or policy relay.
# Usage bench.sh <classic|policy> <short|long>
# short is a tiny debug only run with no tables and no gating. long emits the tables and fails on any drop.

set -euo pipefail

cd "$(dirname "$0")"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=perf.sh
source ./perf.sh

perf_setup_mode "${1:-classic}"

BENCH_SIZE="${2:-long}"
case "$BENCH_SIZE" in
  short|long) ;;
  *) echo "usage: size must be short or long, got: $BENCH_SIZE" >&2; exit 2 ;;
esac

# One descriptor names both the perfdhcp table and the kea view table so they agree.
# It mirrors the wording the functional phases use so the whole summary reads consistently.
case "$MODE" in
  classic) RELAY_DESC="policy-free relay" ;;
  policy)  RELAY_DESC="MAC-policy relay" ;;
esac

# long collects tables. short is debug only so it leaves SUMMARY unset and the kea title empty.
if [ "$BENCH_SIZE" = long ]; then
  KEA_REPORT_TITLE="${RELAY_DESC}"
else
  KEA_REPORT_TITLE=""
fi

# long gates on delivery. short never gates. BENCH_FAILED trips when a long scenario drops or fails.
BENCH_FAILED=0

trap cleanup EXIT

echo "=== benchmark (${MODE} ${BENCH_SIZE}): bringing up kea + ${RELAY_SVC} ==="
docker compose up --build -d kea "$RELAY_SVC"
perf_build
relay_ready
kea_ready

# assert_scenario_ok fails when perfdhcp saw any drop or did not receive every packet it sent.
assert_scenario_ok() {
  local label="$1" f="$2" sent recv drops
  sent="$(perf_field "$f" 'sent packets:')"
  recv="$(perf_field "$f" 'received packets:')"
  # Sum drops across both exchange stages so a loss in either DISCOVER-OFFER or REQUEST-ACK trips the gate.
  drops="$(perf_drops "$f")"

  if ! [[ "$sent" =~ ^[0-9]+$ ]] || ! [[ "$recv" =~ ^[0-9]+$ ]]; then
    echo "FAIL: ${label}: could not parse perfdhcp sent/received counts" >&2

    return 1
  fi

  if [ "$sent" -eq 0 ] || [ "$recv" -ne "$sent" ] || [ "$drops" -ne 0 ]; then
    echo "FAIL: ${label}: sent=${sent} received=${recv} drops=${drops} (want sent>0 and received==sent and drops==0)" >&2

    return 1
  fi

  return 0
}

# assert_kea_served gates on kea's own view so a relay that misroutes or mangles a packet perfdhcp still counts
# as received cannot pass. Bounds are retransmit safe since retries only inflate the counters.
assert_kea_served() {
  local label="$1" disc ack leases
  disc="$(kea_stat pkt4-discover-received)"
  ack="$(kea_stat pkt4-ack-sent)"
  leases="$(lease_count)"

  # Every granted lease implies a discover kea saw and an ack it sent so both counters must cover the leases.
  if [ "$leases" -le 0 ] || [ "$ack" -lt "$leases" ] || [ "$disc" -lt "$leases" ]; then
    echo "FAIL: ${label}: kea ground truth off (discover-received=${disc} ack-sent=${ack} leases=${leases}; want leases>0 and ack-sent>=leases and discover-received>=leases)" >&2

    return 1
  fi

  return 0
}

# run_scenario <label> <perfdhcp args...> runs one scenario on a wiped lease table.
# It appends a Markdown row only when SUMMARY is set. The short debug run leaves SUMMARY unset.
# In long mode a drop or a perf_run failure trips BENCH_FAILED so the whole run exits non zero.
run_scenario() {
  local label="$1"
  shift
  # result 0 wiped leases and result 3 is kea's empty code when the subnet already held none. Both mean the subnet is clear.
  kea_cmd '{"command":"lease4-wipe","arguments":{"subnet-id":1}}' | jq -e '.result == 0 or .result == 3' >/dev/null \
    || { echo "FAIL: lease4-wipe failed for ${label}" >&2; return 1; }
  kea_reset_stats

  local out
  out="$(mktemp)"
  TEMP_FILES+=("$out")
  if perf_run "$out" "$@"; then
    [ -n "${SUMMARY:-}" ] && perf_md_row "$label" "$out" >> "$SUMMARY"
    if [ "$BENCH_SIZE" = long ]; then
      assert_scenario_ok "$label" "$out" || BENCH_FAILED=1
      assert_kea_served "$label" || BENCH_FAILED=1
    fi
  else
    echo "WARN: perf_run failed (rc=$?) for ${label}" >&2
    [ -n "${SUMMARY:-}" ] && perf_md_row "${label} [FAILED]" "$out" >> "$SUMMARY"
    if [ "$BENCH_SIZE" = long ]; then
      BENCH_FAILED=1
    fi
  fi
  rm -f "$out"
}

if [ "$BENCH_SIZE" = long ]; then
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    SUMMARY="$GITHUB_STEP_SUMMARY"
  else
    SUMMARY="$(mktemp)"
    TEMP_FILES+=("$SUMMARY")
    echo "(summary written to $SUMMARY)"
  fi

  {
    echo "### Benchmark: ${RELAY_DESC}"
    echo
    perf_md_header
  } >> "$SUMMARY"
fi

case "$BENCH_SIZE" in
  short)
    run_scenario "DORA r5 N10" -4 -r 5 -R 10 -n 10 "${PERF_COMMON[@]}"
    ;;
  long)
    run_scenario "DORA r50 N200"   -4 -r 50  -R 200 -n 200 "${PERF_COMMON[@]}"
    run_scenario "DORA r100 N200"  -4 -r 100 -R 200 -n 200 "${PERF_COMMON[@]}"
    run_scenario "avalanche R200 r100" -4 --scenario avalanche -R 200 -r 100 "${PERF_COMMON[@]}"
    ;;
esac

echo "=== benchmark (${MODE} ${BENCH_SIZE}) complete ==="

if [ "$BENCH_FAILED" -ne 0 ]; then
  echo "=== benchmark (${MODE} ${BENCH_SIZE}) FAILED: a scenario dropped packets, see diagnostics above ===" >&2
  exit 1
fi
