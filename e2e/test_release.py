# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""DHCPRELEASE round-trip. The client applies its lease and a host route so the unicast
RELEASE it sends on quit traverses the relay and frees the lease in kea."""

from harness import bring_up, log


def test_dhcp_release():
    with bring_up("relay", ["relay"], "") as s:
        log("release client obtains a lease through the relay then releases on SIGTERM")
        # The runner backgrounds udhcpc with release-on-exit, waits for the lease, then SIGTERMs it.
        rc, out = s.compose.run("client-release", timeout=120)
        if rc != 0:
            raise AssertionError(f"release client did not run cleanly (rc={rc})\n{out}")

        log("relay relays the unicast RELEASE and kea frees the lease")
        s.wait_log("DHCP-RELEASE", "relay never relayed the client RELEASE")
        # Kea keeps a released lease in an expired state rather than removing it, so assert kea's
        # own release log rather than the lease disappearing.
        s.wait_service_log("kea", "was released properly", "kea did not free the released lease")
