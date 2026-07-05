# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Phase 2. Relay runs with the MAC policy exercising per-client decisions and hot reload."""

from harness import MAC_ALLOWED, MAC_BLOCKED, MAC_REPLYDROP, MAC_UNLISTED, log, seed_policy


def test_mac_policy(policy_stack):
    s = policy_stack

    log(f"default action: {MAC_ALLOWED} should get a lease")
    s.expect_lease("client")
    s.assert_lease(MAC_ALLOWED, "kea holds no lease for the default-action client")

    log(f"forward blackhole: {MAC_BLOCKED} must NOT get a lease and must NOT reach kea")
    discover_before = s.kea_stat("pkt4-discover-received")
    s.expect_no_lease("client-denied", "relay leased to a forward-blackholed client")
    s.wait_log(f"{MAC_BLOCKED} (blackhole)", "relay did not log dropping the forward-blackholed client")
    s.assert_no_lease(MAC_BLOCKED, "kea leased a forward-blackholed client")
    assert s.kea_stat("pkt4-discover-received") == discover_before, "a forward-blackholed DISCOVER still reached kea"

    log(f"strict allow-list: unlisted {MAC_UNLISTED} must NOT get a lease and must NOT reach kea")
    discover_before = s.kea_stat("pkt4-discover-received")
    s.expect_no_lease("client-unlisted", "relay leased to a client absent from the allow-list")
    s.wait_log(f"{MAC_UNLISTED} (blackhole)", "relay did not default-deny the unlisted client")
    s.assert_no_lease(MAC_UNLISTED, "kea leased a client absent from the allow-list")
    assert s.kea_stat("pkt4-discover-received") == discover_before, "an unlisted DISCOVER still reached kea"

    log(f"reverse path: {MAC_REPLYDROP} is forwarded to kea but its reply is dropped")
    discover_before = s.kea_stat("pkt4-discover-received")
    offer_before = s.kea_stat("pkt4-offer-sent")
    s.expect_no_lease("client-reply-drop", "relay delivered a reply it was told to blackhole")
    s.wait_log(f"{MAC_REPLYDROP} (reply blackhole)", "relay did not log dropping the reply on the reverse path")
    # The forward path worked, separating a reply drop from a forward drop.
    assert s.kea_stat("pkt4-discover-received") > discover_before, "the forwarded DISCOVER never reached kea"
    assert s.kea_stat("pkt4-offer-sent") > offer_before, "kea never offered for the reply-dropped client"

    log("hot reload: switch the policy to '* @default' via an atomic rename")
    seed_policy("# e2e MAC policy (reloaded) relays everyone via the catch all\n* @default\n")
    s.wait_log("default action: default", "relay never reloaded the policy after the file changed")

    log(f"post-reload: previously blackholed {MAC_BLOCKED} should now get a lease")
    s.expect_lease("client-denied")
    s.assert_lease(MAC_BLOCKED, "kea holds no lease for the client after the policy reload")

    log("Option 61 policy tag: a reply action survives a reply that omits Option 61")
    # udhcpc sends a default client id of 0x01 plus the client MAC.
    clientid = "01" + MAC_UNLISTED.replace(":", "")
    seed_policy(
        "# Option 61 (client id) keyed reply drop plus a catch all relaying everyone else.\n"
        f"0x{clientid} @default @blackhole\n"
        "* @default\n"
    )
    s.wait_log_re(r"1 entries, default action: default", "relay never reloaded the Option 61 policy")

    log("Option 61 control: a catch-all client still gets its reply")
    s.expect_lease("client")
    s.assert_lease(MAC_ALLOWED, "catch-all client lost its reply under the Option 61 policy")

    log(f"Option 61 tag: {MAC_UNLISTED} is forwarded but its reply is dropped via the tag")
    discover_before = s.kea_stat("pkt4-discover-received")
    offer_before = s.kea_stat("pkt4-offer-sent")
    s.expect_no_lease("client-unlisted", "Option 61 keyed reply delivered (Option 82 policy tag not honored)")
    assert s.kea_stat("pkt4-discover-received") > discover_before, "the Option 61 client's DISCOVER never reached kea"
    assert s.kea_stat("pkt4-offer-sent") > offer_before, "kea never offered for the Option 61 client"
