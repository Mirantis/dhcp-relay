# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""A client that sets the broadcast flag gets its reply on the broadcast path."""

from harness import bring_up, log


def test_broadcast_flag_reply():
    with bring_up("relay", ["relay"], "") as s:
        log("client sets the broadcast flag (-B) so the relay broadcasts the reply")
        rc, out = s.compose.run(
            "client", "-i", "eth0", "-B", "-t", "3", "-T", "2", "-A", "0", "-q", "-n", "-f", "-s", "/bin/true"
        )
        if rc != 0:
            raise AssertionError(f"broadcast client did not get a lease (rc={rc})\n{out}")

        # The broadcast reply path sends to 255.255.255.255:68, the unicast path to the client IP.
        s.wait_log_re(
            r"DHCP-(OFFER|ACK) \[\d+\].*Dst=255\.255\.255\.255:68",
            "relay did not broadcast the reply for a broadcast-flag client",
        )
