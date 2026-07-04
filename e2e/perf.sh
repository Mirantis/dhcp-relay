#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Reusable perfdhcp driver and report parser. Sourced by scale.sh and bench.sh.

# PERF_COMMON and the MODE/RELAY_SVC set by perf_setup_mode are read by the sourcing scripts.
# shellcheck disable=SC2034

# Shared client parameters so the gate and benchmark drive identical traffic.
PERF_COMMON=(-b mac=02:00:ff:00:00:00 -W 5000000 -l eth0 192.168.50.2)

# perf_setup_mode sets MODE and RELAY_SVC and seeds a catch all policy for the policy relay.
perf_setup_mode() {
  MODE="$1"
  case "$MODE" in
    classic) RELAY_SVC="relay" ;;
    policy)
      RELAY_SVC="relay-policy"
      mkdir -p ./macpolicy
      printf '* @default\n' > ./macpolicy/policy.txt
      ;;
    *) echo "usage: mode must be classic or policy, got: $MODE" >&2; exit 2 ;;
  esac

  export_relay_profile
}

# perf_build builds the perfdhcp image (it sits behind a compose profile so up skips it).
perf_build() {
  docker compose build perfdhcp
}

# perf_run <out_file> <perfdhcp args...> runs perfdhcp once, tees output, returns its rc.
perf_run() {
  local out="$1"
  shift
  timeout 180 docker compose run --rm --no-deps perfdhcp "$@" 2>&1 | tee "$out"
  return "${PIPESTATUS[0]}"
}

# perf_field <file> <pattern> prints the last number on the first matching line.
perf_field() {
  awk -v p="$2" '$0 ~ p {print $NF; exit}' "$1"
}

perf_md_header() {
  printf '| Scenario | Sent | Received | Drops | Drop%% | Avg RTT |\n'
  printf '|---|---|---|---|---|---|\n'
}

# perf_md_row <label> <out_file> emits one Markdown row parsed from a perfdhcp report.
perf_md_row() {
  local label="$1" f="$2" sent recv drops avg pct="n/a"
  sent="$(perf_field "$f" 'sent packets:')"
  recv="$(perf_field "$f" 'received packets:')"
  drops="$(perf_field "$f" '^[[:space:]]*drops:')"
  # Avg delay line ends with the unit so take value and unit.
  avg="$(awk '/avg delay:/{print $(NF-1), $NF; exit}' "$f")"
  if [ -n "$sent" ] && [ -n "$drops" ] && [ "$sent" -gt 0 ] 2>/dev/null && [ "$drops" -ge 0 ] 2>/dev/null; then
    pct="$(awk -v d="$drops" -v s="$sent" 'BEGIN{printf "%.2f", 100*d/s}')"
  fi
  printf '| %s | %s | %s | %s | %s | %s |\n' \
    "$label" "${sent:-n/a}" "${recv:-n/a}" "${drops:-n/a}" "$pct" "${avg:-n/a}"
}
