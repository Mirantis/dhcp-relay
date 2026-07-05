#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

# busybox udhcpc hook for the release client. On bound it applies the lease and adds a host
# route to the DHCP server via the relay so the unicast RELEASE reaches the relay, then marks
# ready so the runner can trigger the release.
case "$1" in
  bound|renew)
    ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
    [ -n "$serverid" ] && route add -host "$serverid" gw 192.168.50.2
    : > /tmp/bound
    ;;
esac
