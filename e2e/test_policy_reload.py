# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Hot-reload robustness. A malformed policy is rejected and the previous one kept."""

from harness import MAC_ALLOWED, MAC_BLOCKED, bring_up, log, seed_policy


def test_policy_reload_robustness():
    # Own fresh relay-policy on a permissive baseline so the log starts clean for unambiguous waits.
    seed_policy("* @default\n")
    with bring_up("relay-policy", ["relay-policy"], "") as s:
        log("baseline: the catch-all relays every client")
        s.expect_lease("client")
        s.assert_lease(MAC_ALLOWED, "baseline catch-all did not lease")

        log("malformed policy must be rejected and the previous one kept")
        seed_policy("!!! not a valid identifier @@@\n")
        s.wait_log(
            "reload failed, keeping previous", "relay accepted a malformed policy instead of keeping the previous"
        )

        # The retained catch-all still relays a fresh client.
        s.expect_lease("client-denied")
        s.assert_lease(MAC_BLOCKED, "relay dropped the previous policy after a bad reload")

        log("a valid reload recovers and applies the new strict allow-list")
        seed_policy(f"{MAC_ALLOWED} @default\n")
        s.wait_log_re(r"1 entries, default action: blackhole", "relay never applied the recovered strict policy")
        s.expect_no_lease("client-denied", "recovered strict allow-list still relayed an unlisted client")
