#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# Drives a release. busybox udhcpc only sends a RELEASE on signal, not on -q exit, so run it in
# the background with release-on-exit, wait for the lease, then SIGTERM so it releases on the way out.
rm -f /tmp/bound

udhcpc -i eth0 -f -R -s /release.sh &
pid=$!

i=0
while [ ! -f /tmp/bound ] && [ "$i" -lt 60 ]; do
  sleep 0.5
  i=$((i + 1))
done

if [ ! -f /tmp/bound ]; then
  echo "run-release: client never obtained a lease" >&2
  kill "$pid" 2>/dev/null
  exit 1
fi

# Let the lease settle then trigger the release on exit.
sleep 1
kill -TERM "$pid"
wait "$pid"
