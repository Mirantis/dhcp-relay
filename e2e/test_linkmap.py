# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Link-map NIC selector. A name glob resolves the subnet and a non-match with no catch-all drops."""

from harness import MAC_ALLOWED, UNNUMBERED_SERVICES, bring_up, log, seed_linkmap


def test_linkmap_name_selector_matches():
    # Key the map on the ingress NIC name via a glob rather than the catch-all.
    seed_linkmap("name=eth* 192.168.50.0/24\n")
    with bring_up("relay-unnumbered", UNNUMBERED_SERVICES, "", init_service="relay-unnumbered-init") as s:
        log("ingress NIC matched by name glob relays via Link Selection")
        s.expect_lease("client")
        s.wait_log("Option 82 -> Sub-option: Type=5", "relay did not emit Link Selection for the name-matched NIC")
        s.assert_lease(MAC_ALLOWED, "kea holds no lease for the name-matched ingress")


def test_linkmap_no_match_drops():
    # A selector that matches no NIC and no catch-all leaves the unnumbered ingress unresolved.
    seed_linkmap("name=zzzz9 10.0.0.0/8\n")
    with bring_up("relay-unnumbered", UNNUMBERED_SERVICES, "", init_service="relay-unnumbered-init") as s:
        log("unmatched ingress NIC with no catch-all is dropped")
        s.expect_no_lease("client", "relay leased despite no matching link-map entry")
        s.wait_log("no link-map entry", "relay did not log the missing link-map entry for the ingress NIC")
