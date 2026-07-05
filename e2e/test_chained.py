# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Chained relay. perfdhcp emulates an upstream relay (hops>0, its own giaddr) so the relay takes
the already-relayed forward path and forwards the reply back to that giaddr. A low -max-hops trips
the loop-drop."""

from harness import PERF_COMMON, bring_up, log

# A tiny perfdhcp run over the shared client parameters. perfdhcp sets giaddr and hops so every
# packet is already-relayed.
PERF = ["-4", "-r", "5", "-R", "5", "-n", "5", *PERF_COMMON]


def test_chained_relay_forwards_reply():
    with bring_up("relay", ["relay"], "") as s:
        s.compose.build("perfdhcp")
        log("perfdhcp drives the already-relayed forward path")
        s.compose.run("perfdhcp", *PERF, timeout=120)

        s.wait_log("Forwarding DHCPv4-DISCOVER relayed message", "relay did not take the already-relayed forward path")
        # A reply to a client-subnet address on port 67 is a reply forwarded to the upstream relay giaddr,
        # not a local delivery to the client on port 68.
        s.wait_log_re(
            r"DHCP-(OFFER|ACK) \[\d+\], Src=\S+, Dst=192\.168\.50\.\d+:67",
            "relay did not forward the reply to the upstream relay giaddr",
        )


def test_hops_max_drops():
    with bring_up("relay-maxhops", ["relay-maxhops"], "") as s:
        s.compose.build("perfdhcp")
        log("-max-hops 1 drops perfdhcp's already-relayed request")
        s.compose.run("perfdhcp", *PERF, timeout=120)

        s.wait_log_re(r"hop count \d+ reaches maximum 1", "relay did not drop the over-limit relayed request")
