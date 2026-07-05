# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""The -giaddr override forces the relayed giaddr on the unnumbered path."""

from harness import MAC_ALLOWED, bring_up, log, seed_linkmap

GIADDR = ["relay-unnumbered-giaddr", "relay-unnumbered-giaddr-init"]


def test_giaddr_override():
    seed_linkmap("* 192.168.50.0/24\n")
    with bring_up("relay-unnumbered-giaddr", GIADDR, "", init_service="relay-unnumbered-giaddr-init") as s:
        log("relay forwards under the -giaddr override, not the auto-derived address")
        s.expect_lease("client")
        s.wait_log("Relaying under giaddr=203.0.113.1", "relay did not use the -giaddr override")

        # kea still leases via Link Selection despite a giaddr the relay does not own.
        s.assert_lease(MAC_ALLOWED, "kea holds no lease under the giaddr override")
