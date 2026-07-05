# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Phase 3. The client NIC is unnumbered so relaying uses the link map and RFC 3527 Link Selection."""

from harness import MAC_ALLOWED, log


def test_unnumbered_relay(unnumbered_stack):
    s = unnumbered_stack

    log(f"happy path: a client on the unnumbered segment {MAC_ALLOWED} should still get a lease")
    s.expect_lease("client")

    log("asserting the request went through the relay on the unnumbered path")
    s.wait_log("Option 82 -> Sub-option", "relay never injected Option 82, traffic bypassed the relay")
    # Type=5 is the RFC 3527 Link Selection sub-option, emitted only on the unnumbered giaddr path. It
    # guards against a false pass where the relay came up numbered (for example if the flush did not take).
    s.wait_log(
        "Option 82 -> Sub-option: Type=5",
        "relay did not emit the Link Selection sub-option, the unnumbered path was not exercised",
    )
    s.wait_log_re(r"<-- 0x[0-9a-f]+: DHCP-(OFFER|ACK)", "relay never wrote an OFFER/ACK back to the client interface")

    log("kea ground truth: the client holds exactly one lease in the mapped subnet")
    s.assert_lease(MAC_ALLOWED, "kea holds no lease for the client on the unnumbered segment")
    s.assert_lease_count(1, "kea lease table does not hold exactly the one client")
