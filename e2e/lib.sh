#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Shared helpers sourced by the phase scripts after they set RELAY_SVC.

# MAC_* and helpers below are used by the phase scripts that source this file.
# shellcheck disable=SC2034

set -euo pipefail

# Pinned client MACs mirrored by the client services in compose.yaml.
MAC_ALLOWED="02:00:00:00:00:01"   # relayed in both phases (default action)
MAC_BLOCKED="02:00:00:00:00:02"   # forward @blackhole in the policy phase
MAC_UNLISTED="02:00:00:00:00:04"  # absent from the policy so denied by the fallback
MAC_REPLYDROP="02:00:00:00:00:05" # forwarded but its reply is dropped

# TEMP_FILES tracks mktemp outputs so EXIT cleanup removes them even if a phase aborts
# before reaching its own rm -f.
TEMP_FILES=()

# Relay service under test. Each phase sets it before sourcing.
RELAY_SVC="${RELAY_SVC:-relay}"

# export_relay_profile activates the compose profile so up, logs, and down all see the service.
export_relay_profile() {
  case "${RELAY_SVC}" in
    relay) export COMPOSE_PROFILES="classic" ;;
    relay-policy) export COMPOSE_PROFILES="policy" ;;
    *) echo "FAIL: unknown RELAY_SVC ${RELAY_SVC}"; exit 1 ;;
  esac
}

export_relay_profile

# relay_logs prints the relay logs with color codes stripped for grep.
relay_logs() {
  docker compose logs --no-color "${RELAY_SVC}"
}

# wait_log polls the relay log for a fixed string for up to 15s then fails.
wait_log() {
  local needle="$1" msg="$2" i
  for i in $(seq 1 30); do
    if grep -aqF -- "${needle}" <<<"$(relay_logs)"; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: ${msg}"
  exit 1
}

# wait_log_re is the regular expression variant of wait_log.
wait_log_re() {
  local pattern="$1" msg="$2" i
  for i in $(seq 1 30); do
    if grep -aqE -- "${pattern}" <<<"$(relay_logs)"; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: ${msg}"
  exit 1
}

# expect_lease runs the client once and requires it to get a lease.
expect_lease() {
  local svc="$1"

  docker compose run --rm --no-deps "${svc}" \
    -i eth0 -t 3 -T 2 -A 0 -q -n -f -s /bin/true \
    || { echo "FAIL: ${svc} did not get a lease"; exit 1; }
}

# expect_no_lease runs the client once and requires it to FAIL to get a lease.
expect_no_lease() {
  local svc="$1" msg="$2" rc=0

  docker compose run --rm --no-deps "${svc}" \
      -i eth0 -t 2 -T 2 -A 0 -q -n -f -s /bin/true || rc=$?

  # Exit codes >= 125 indicate Docker infrastructure failures, not "no lease".
  if [ "${rc}" -ge 125 ]; then
    echo "FAIL: ${svc} container did not run (rc=${rc})"
    exit 1
  fi

  if [ "${rc}" -eq 0 ]; then
    echo "FAIL: ${msg}"
    exit 1
  fi
}

# kea_cmd sends a JSON command to kea and prints the reply.
kea_cmd() {
  printf '%s' "$1" | docker compose exec -T kea socat -t5 - UNIX-CONNECT:/run/kea/kea4-ctrl-socket
}

# kea_ready waits up to 30s for the control socket to answer.
kea_ready() {
  command -v jq >/dev/null 2>&1 || { echo "FAIL: jq is required"; exit 1; }

  local i
  for i in $(seq 1 60); do
    kea_cmd '{"command":"version-get"}' 2>/dev/null | grep -Eq '"result":[[:space:]]*0' && return 0
    sleep 0.5
  done

  echo "FAIL: kea control socket never became ready"
  exit 1
}

kea_reset_stats() {
  kea_cmd '{"command":"statistic-reset-all"}' >/dev/null
}

# kea_stat prints an integer statistic (0 when absent, empty, or unreadable).
kea_stat() {
  local out
  # The || true and non numeric fallback map kea errors to 0. Pair assert_delta_zero with an unmitigated kea check so a missing value is not masked.
  out="$(kea_cmd "{\"command\":\"statistic-get\",\"arguments\":{\"name\":\"$1\"}}" 2>/dev/null \
    | jq -r --arg n "$1" '.arguments[$n][0][0] // 0' 2>/dev/null)" || true

  # Emit 0 for empty or non numeric output so arithmetic callers never see a blank.
  case "$out" in
    '' | *[!0-9]*) echo 0 ;;
    *) echo "$out" ;;
  esac
}

# lease_count prints the number of leases in subnet 1.
lease_count() {
  local out
  out="$(kea_cmd '{"command":"lease4-get-all","arguments":{"subnets":[1]}}' 2>/dev/null \
    | jq -r 'if .result == 0 then (.arguments.leases | length) else empty end' 2>/dev/null)" || true
  case "$out" in
    '' | *[!0-9]*) echo 0 ;;
    *) echo "$out" ;;
  esac
}

assert_stat_eq() {
  local name="$1" want="$2" msg="$3" got
  got="$(kea_stat "$name")"
  [ "$got" = "$want" ] || { echo "FAIL: ${msg} (${name}=${got} want ${want})"; exit 1; }
}

assert_lease_count() {
  local want="$1" msg="$2" got
  got="$(lease_count)"
  [ "$got" = "$want" ] || { echo "FAIL: ${msg} (leases=${got} want ${want})"; exit 1; }
}

# assert_delta_zero and assert_delta_pos compare a kea counter captured around a step.
assert_delta_zero() {
  [ "$1" = "$2" ] || { echo "FAIL: ${3} (delta $(($2 - $1)) want 0)"; exit 1; }
}

assert_delta_pos() {
  [ "$2" -gt "$1" ] || { echo "FAIL: ${3} (delta $(($2 - $1)) want positive)"; exit 1; }
}

assert_lease() {
  kea_cmd "{\"command\":\"lease4-get-by-hw-address\",\"arguments\":{\"hw-address\":\"$1\"}}" \
    | jq -e '.result == 0 and (.arguments.leases | length > 0)' >/dev/null \
    || { echo "FAIL: ${2} (no kea lease for $1)"; exit 1; }
}

assert_no_lease() {
  kea_cmd "{\"command\":\"lease4-get-by-hw-address\",\"arguments\":{\"hw-address\":\"$1\"}}" \
    | jq -e '.result == 3 or (.arguments.leases | length == 0)' >/dev/null \
    || { echo "FAIL: ${2} (kea has a lease for $1)"; exit 1; }
}

# circuit_id_hex prints the Agent Circuit ID sub option hex for an ifIndex (ASCII encoded).
circuit_id_hex() {
  local ascii_hex
  ascii_hex="$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n')"
  printf '01%02x%s' "${#1}" "$ascii_hex"
}

# assert_lease_opt82 checks the MAC lease carries Option 82 with the circuit ID for the ingress ifIndex the relay logged.
assert_lease_opt82() {
  local mac="$1" msg="$2" ifindex want got
  # -a so packet debug bytes in the log never make grep treat the stream as binary.
  # || true so a no-match pipeline does not trip errexit before the diagnostic below.
  ifindex="$(relay_logs | grep -aF "$mac" | grep -oE 'IfIndex=[0-9]+' | head -1 | cut -d= -f2 || true)"
  [ -n "$ifindex" ] || { echo "FAIL: ${msg} (no IfIndex logged for ${mac})"; exit 1; }
  want="$(circuit_id_hex "$ifindex")"
  got="$(kea_cmd "{\"command\":\"lease4-get-by-hw-address\",\"arguments\":{\"hw-address\":\"${mac}\"}}" \
    | jq -r '.arguments.leases[0]["user-context"] // {} | tostring' | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
  case "$got" in
    *"$want"*) : ;;
    *) echo "FAIL: ${msg} (circuit-id ${want} absent from user-context ${got})"; exit 1 ;;
  esac
}

# kea_report appends a Markdown snapshot of what kea observed to the CI job summary.
kea_report() {
  local title="$1" out="${GITHUB_STEP_SUMMARY:-/dev/stdout}" s
  {
    echo "### Kea view: ${title}"
    echo
    echo "| Metric | Value |"
    echo "|---|---|"
    for s in pkt4-received pkt4-discover-received pkt4-offer-sent \
             pkt4-request-received pkt4-ack-sent pkt4-nak-sent; do
      echo "| ${s} | $(kea_stat "$s") |"
    done
    echo "| leases | $(lease_count) |"
    echo
  } >> "$out"
}

# cleanup dumps the relay and kea logs then tears down the stack and volumes.
cleanup() {
  echo "=== relay logs (${RELAY_SVC}) ==="
  docker compose logs --no-color "${RELAY_SVC}" || true
  echo "=== kea logs ==="
  docker compose logs --no-color kea || true
  docker compose down -v --remove-orphans || true
  rm -rf ./macpolicy
  [ "${#TEMP_FILES[@]}" -gt 0 ] && rm -f "${TEMP_FILES[@]}" 2>/dev/null || true
}
