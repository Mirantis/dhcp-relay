#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Phase 2 of the e2e suite. Relay runs with the mac policy flag exercising policy decisions and hot reload.

set -euo pipefail

cd "$(dirname "$0")"

# Relay service that watches the policy file. See compose.yaml.
RELAY_SVC="relay-policy"
KEA_REPORT_TITLE="functional: MAC-policy relay (per-client decisions + hot reload)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source ./lib.sh

trap cleanup EXIT

echo "=== seeding the MAC policy (strict allow-list, no catch-all) ==="
mkdir -p ./macpolicy
cat > ./macpolicy/policy.txt <<EOF
# e2e MAC policy (phase 2)
${MAC_ALLOWED}                       # default action relays via kea
${MAC_BLOCKED} @blackhole            # forward dropped
${MAC_REPLYDROP} @default @blackhole # forward ok but reply dropped
# ${MAC_UNLISTED} absent so it hits the fallback blackhole
EOF

echo "=== bringing up the policy relay stack ==="
docker compose up --build -d kea relay-policy

# Wait for the relay to log its startup banner before running any client assertions.
relay_ready

# Wait for the kea control socket then zero its counters for this phase.
kea_ready
kea_reset_stats

echo "=== default action: ${MAC_ALLOWED} should get a lease ==="
expect_lease client
assert_lease "$MAC_ALLOWED" "kea holds no lease for the default-action client"

echo "=== forward blackhole: ${MAC_BLOCKED} must NOT get a lease and must NOT reach kea ==="
discover_before="$(kea_stat pkt4-discover-received)"
expect_no_lease client-denied "relay leased to a forward-blackholed client"
wait_log "${MAC_BLOCKED} (blackhole)" \
  "relay did not log dropping the forward-blackholed client"
assert_no_lease "$MAC_BLOCKED" "kea leased a forward-blackholed client"
assert_delta_zero "$discover_before" "$(kea_stat pkt4-discover-received)" \
  "a forward-blackholed DISCOVER still reached kea"

echo "=== strict allow-list: unlisted ${MAC_UNLISTED} must NOT get a lease and must NOT reach kea ==="
discover_before="$(kea_stat pkt4-discover-received)"
expect_no_lease client-unlisted "relay leased to a client absent from the allow-list"
wait_log "${MAC_UNLISTED} (blackhole)" \
  "relay did not default-deny the unlisted client"
assert_no_lease "$MAC_UNLISTED" "kea leased a client absent from the allow-list"
assert_delta_zero "$discover_before" "$(kea_stat pkt4-discover-received)" \
  "an unlisted DISCOVER still reached kea"

echo "=== reverse path: ${MAC_REPLYDROP} is forwarded to kea but its reply is dropped ==="
discover_before="$(kea_stat pkt4-discover-received)"
offer_before="$(kea_stat pkt4-offer-sent)"
expect_no_lease client-reply-drop "relay delivered a reply it was told to blackhole"
wait_log "${MAC_REPLYDROP} (reply blackhole)" \
  "relay did not log dropping the reply on the reverse path"
# Proves the forward path worked and separates a reply drop from a forward drop.
assert_delta_pos "$discover_before" "$(kea_stat pkt4-discover-received)" \
  "the forwarded DISCOVER never reached kea (forward path broken, not just the reply)"
assert_delta_pos "$offer_before" "$(kea_stat pkt4-offer-sent)" \
  "kea never offered for the reply-dropped client"

echo "=== hot reload: switch the policy to '* @default' via an atomic rename ==="
cat > ./macpolicy/policy.txt.new <<EOF
# e2e MAC policy (reloaded) relays everyone via the catch all
* @default
EOF
mv ./macpolicy/policy.txt.new ./macpolicy/policy.txt

# Poll interval is 1s. Confirm the reload by its logged default fallback.
wait_log 'default action: default' \
  "relay never reloaded the policy after the file changed"

echo "=== post-reload: previously blackholed ${MAC_BLOCKED} should now get a lease ==="
expect_lease client-denied
assert_lease "$MAC_BLOCKED" "kea holds no lease for the client after the policy reload"

echo "=== Option 61 policy tag: a reply action survives a reply that omits Option 61 ==="
# kea runs with echo client id off so replies carry no Option 61. The relay reapplies the reply blackhole from the Option 82 tag. udhcpc sends a default client id of 0x01 plus the client MAC.
clientid="01$(printf '%s' "$MAC_UNLISTED" | tr -d ':')"
cat > ./macpolicy/policy.txt.new <<EOF
# Option 61 (client id) keyed reply drop plus a catch all relaying everyone else.
0x${clientid} @default @blackhole
* @default
EOF
mv ./macpolicy/policy.txt.new ./macpolicy/policy.txt

wait_log_re '1 entries, default action: default' \
  "relay never reloaded the Option 61 policy"

echo "=== Option 61 control: a catch-all client still gets its reply ==="
expect_lease client
assert_lease "$MAC_ALLOWED" "catch-all client lost its reply under the Option 61 policy"

echo "=== Option 61 tag: ${MAC_UNLISTED} is forwarded but its reply is dropped via the tag ==="
discover_before="$(kea_stat pkt4-discover-received)"
offer_before="$(kea_stat pkt4-offer-sent)"
expect_no_lease client-unlisted "Option 61 keyed reply delivered (Option 82 policy tag not honored)"
# The forward must have reached kea proving this is a reply drop not a forward drop.
assert_delta_pos "$discover_before" "$(kea_stat pkt4-discover-received)" \
  "the Option 61 client's DISCOVER never reached kea (forward broken, not the reply)"
assert_delta_pos "$offer_before" "$(kea_stat pkt4-offer-sent)" \
  "kea never offered for the Option 61 client"

echo "=== mac policy e2e: success ==="
