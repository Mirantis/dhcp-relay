#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Reusable perfdhcp driver and report parser. Sourced by bench.sh.

# PERF_COMMON and the MODE/RELAY_SVC set by perf_setup_mode are read by the sourcing scripts.
# shellcheck disable=SC2034

# Shared client parameters for the benchmark.
#
# perfdhcp always emulates a relay (it sets giaddr and hops and sends from port 67) so our relay relays it onward.
# Both legs run through our relay. kea replies to source (see compose) and we forward to giaddr.
PERF_IFACE="${PERF_IFACE:-eth0}"
PERF_SERVER="${PERF_SERVER:-255.255.255.255}"
PERF_COMMON=(-b mac=02:00:ff:00:00:00 -B -W 5000000 -l "$PERF_IFACE" "$PERF_SERVER")

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

  if ! command -v export_relay_profile >/dev/null 2>&1; then
    echo "ERROR: export_relay_profile is not defined" >&2
    return 1
  fi
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
  local docker_rc="${PIPESTATUS[0]}" tee_rc="${PIPESTATUS[1]}"
  if [ "$tee_rc" -ne 0 ]; then
    echo "ERROR: failed to write output to $out" >&2
    return "$tee_rc"
  fi
  if [ "$docker_rc" -eq 124 ]; then
    echo "ERROR: perfdhcp timed out after 180s" >> "$out"
  fi
  return "$docker_rc"
}

# perf_field <file> <pattern> prints the last whitespace-delimited field on the first matching line.
perf_field() {
  awk -v p="$2" '$0 ~ p {print $NF; exit}' "$1"
}

# perf_drops <file> sums drops across both exchange stages so a loss in either DISCOVER-OFFER or REQUEST-ACK counts.
# The summary table and the gate share it so they never disagree on the drop count.
perf_drops() {
  awk '/^[[:space:]]*drops:/{s+=$NF} END{printf "%d", s+0}' "$1"
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
  drops="$(perf_drops "$f")"
  # Avg delay line ends with the unit so take value and unit.
  avg="$(awk '/avg delay:/{print $(NF-1), $NF; exit}' "$f")"
  if [ -n "$sent" ] && [ -n "$drops" ] \
    && [[ "$sent" =~ ^[0-9]+$ ]] && [[ "$drops" =~ ^[0-9]+$ ]] \
    && [ "$sent" -gt 0 ]; then
    pct="$(awk -v d="$drops" -v s="$sent" 'BEGIN{printf "%.2f", 100*d/s}')"
  else
    if [ -n "$sent" ] || [ -n "$drops" ]; then echo "WARN: non-numeric sent/drops in $f" >&2; fi
  fi
  printf '| %s | %s | %s | %s | %s | %s |\n' \
    "$label" "${sent:-n/a}" "${recv:-n/a}" "${drops:-n/a}" "$pct" "${avg:-n/a}"
}
