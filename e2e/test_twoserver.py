# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Per-client forward. A policy server action sends one client to a second DHCP server."""

from harness import bring_up, log, seed_policy


def test_per_client_server_forward():
    # 02:00:00:00:00:01 -> kea2 (10.99.0.4); everyone else -> the default server (kea, 10.99.0.3).
    seed_policy("02:00:00:00:00:01 10.99.0.4\n* @default\n")
    with bring_up("relay-twoserver", ["kea2", "relay-twoserver"], "") as s:
        log("the policy-selected client is forwarded to the second server")
        s.expect_lease("client")
        s.wait_log_re(
            r"DHCP-DISCOVER \[\d+\], Src=\S+, Dst=10\.99\.0\.4:67",
            "relay did not forward the selected client to kea2",
        )

        log("a default client still goes to the primary server")
        s.expect_lease("client-denied")
        s.wait_log_re(
            r"DHCP-DISCOVER \[\d+\], Src=\S+, Dst=10\.99\.0\.3:67",
            "relay did not forward the default client to the primary server",
        )
