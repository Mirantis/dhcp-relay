#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Informational perfdhcp benchmark for classic or policy relay.
# Usage bench.sh <classic|policy>

set -euo pipefail

cd "$(dirname "$0")"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=perf.sh
source ./perf.sh

perf_setup_mode "${1:-classic}"

trap cleanup EXIT

SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

echo "=== benchmark (${MODE}): bringing up kea + ${RELAY_SVC} ==="
docker compose up --build -d kea "$RELAY_SVC"
perf_build
kea_ready

# bench_scenario <label> <perfdhcp args...> runs one scenario on a wiped lease table.
bench_scenario() {
  local label="$1"
  shift
  kea_cmd '{"command":"lease4-wipe","arguments":{"subnet-id":1}}' >/dev/null \
    || { echo "WARN: lease4-wipe failed for ${label}" >&2; }
  kea_reset_stats

  local out
  out="$(mktemp)"
  TEMP_FILES+=("$out")
  if perf_run "$out" "$@"; then
    perf_md_row "$label" "$out" >> "$SUMMARY"
  else
    echo "WARN: perf_run failed (rc=$?) for ${label}" >&2
    perf_md_row "${label} [FAILED]" "$out" >> "$SUMMARY"
  fi
  rm -f "$out"
}

{
  echo "### Benchmark: ${MODE} relay"
  echo
  perf_md_header
} >> "$SUMMARY"

bench_scenario "DORA r50 N200"   -4 -r 50  -R 200 -n 200 "${PERF_COMMON[@]}"
bench_scenario "DORA r100 N200"  -4 -r 100 -R 200 -n 200 "${PERF_COMMON[@]}"
bench_scenario "avalanche R200 r100" -4 --scenario avalanche -R 200 -r 100 "${PERF_COMMON[@]}"

echo "=== benchmark (${MODE}) complete ==="
