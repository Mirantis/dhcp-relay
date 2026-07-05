# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""A numbered ingress with two IPv4s relays one copy per address."""

from harness import bring_up, log

MULTIHOMED = ["relay-multihomed", "relay-multihomed-init"]


def test_multihomed_relays_per_address():
    with bring_up(
        "relay-multihomed",
        MULTIHOMED,
        "",
        init_service="relay-multihomed-init",
        init_ready="added second client-net IPv4",
    ) as s:
        log("a client is relayed once per interface address")
        s.expect_lease("client")
        s.wait_log("Relaying under giaddr=192.168.50.2", "relay did not relay under the primary address")
        s.wait_log("Relaying under giaddr=192.168.50.5", "relay did not relay under the second address")
