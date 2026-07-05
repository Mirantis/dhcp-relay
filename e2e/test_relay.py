# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Phase 1. Classic relay with no MAC policy so every client is relayed."""

from harness import MAC_ALLOWED, MAC_BLOCKED, log


def test_classic_relay(classic_stack):
    s = classic_stack

    log("negative control: a non-relayed client on server-net must NOT get a lease")
    s.expect_no_lease("client-direct", "kea handed a lease to a non-relayed client")

    log(f"happy path: relayed client {MAC_ALLOWED} should get a lease")
    # busybox udhcpc emulates a real client with hops 0 and a broadcast DISCOVER.
    s.expect_lease("client")

    log("asserting the exchange actually went through the relay")
    s.wait_log("Option 82 -> Sub-option", "relay never injected Option 82, traffic bypassed the relay")
    s.wait_log_re(r"<-- 0x[0-9a-f]+: DHCP-(OFFER|ACK)", "relay never wrote an OFFER/ACK back to the client interface")

    log("kea ground truth: the relayed client holds a lease with the ingress Option 82")
    s.assert_lease(MAC_ALLOWED, "kea holds no lease for the relayed client")
    s.assert_lease_opt82(MAC_ALLOWED, "relay did not store the ingress Option 82 in the lease")

    log(f"statelessness: a second distinct client {MAC_BLOCKED} should also get a lease")
    s.expect_lease("client-denied")
    s.assert_lease(MAC_BLOCKED, "kea holds no lease for the second relayed client")
    s.assert_lease_count(2, "kea lease table does not hold exactly the two relayed clients")
