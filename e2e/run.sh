#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

set -euo pipefail

cd "$(dirname "$0")"

cleanup() {
  echo "=== relay logs ==="
  docker compose logs --no-color relay || true
  echo "=== kea logs ==="
  docker compose logs --no-color kea || true
  docker compose down -v --remove-orphans
}
trap cleanup EXIT

echo "=== bringing stack up ==="
docker compose up --build -d kea relay

sleep 3

echo "=== negative case: direct broadcast on server-net must NOT get a lease ==="
if docker compose run --rm --no-deps client-direct \
    -i eth0 -t 2 -T 2 -A 0 -q -n -f -s /bin/true; then
  echo "FAIL: Kea handed out a lease to a non-relayed client"
  exit 1
fi

echo "=== probing through the relay ==="
# busybox udhcpc emulates a real DHCP client (hops=0, broadcast DISCOVER):
#   -i eth0    interface to use.
#   -t 3       attempt up to 3 times.
#   -T 2       wait 2s between attempts.
#   -A 0       no delay between attempt cycles.
#   -q         exit after the lease is acquired.
#   -n         exit non-zero if no lease (CI hard-fail).
#   -f         foreground (stream logs back to the host).
#   -s /bin/true   skip the default interface-configure script.
docker compose run --rm --no-deps client \
  -i eth0 -t 3 -T 2 -A 0 -q -n -f -s /bin/true

echo "=== asserting traffic went through the relay ==="
sleep 3
if ! docker compose logs --no-color relay | grep -q 'Option 82 -> Sub-option'; then
  echo "FAIL: relay never injected Option 82 — DHCP traffic bypassed the relay"
  exit 1
fi
if ! docker compose logs --no-color relay | grep -qE '<-- 0x[0-9a-f]+: DHCP-(OFFER|ACK)'; then
  echo "FAIL: relay never wrote an OFFER/ACK back to the client interface"
  exit 1
fi

echo "=== success ==="
