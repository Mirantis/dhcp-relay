# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Link-map robustness. An empty map drops every ingress; a malformed reload keeps the previous map."""

from harness import MAC_ALLOWED, UNNUMBERED_SERVICES, bring_up, log, seed_linkmap

UNNUMBERED = UNNUMBERED_SERVICES


def test_linkmap_empty_drops():
    seed_linkmap("# empty link map, no entries\n")
    with bring_up("relay-unnumbered", UNNUMBERED, "", init_service="relay-unnumbered-init") as s:
        log("empty link map warns and drops every unnumbered ingress")
        s.wait_log(
            "no entries: every unnumbered ingress request will be dropped", "relay did not warn on the empty link map"
        )
        s.expect_no_lease("client", "relay leased despite an empty link map")


def test_linkmap_reload_robustness():
    seed_linkmap("* 192.168.50.0/24\n")
    with bring_up("relay-unnumbered", UNNUMBERED, "", init_service="relay-unnumbered-init") as s:
        log("baseline catch-all relays")
        s.expect_lease("client")

        log("malformed link map is rejected and the previous one kept")
        seed_linkmap("this is not a valid link map line\n")
        s.wait_log("link map: reload failed, keeping previous", "relay accepted a malformed link map")

        s.expect_lease("client")
        s.assert_lease(MAC_ALLOWED, "relay dropped the previous link map after a bad reload")
