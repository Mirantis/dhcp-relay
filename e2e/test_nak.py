# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""NAK relay path. A crafted out-of-subnet REQUEST makes authoritative kea NAK, and the relay
relays the DHCPNAK back to the client."""

from harness import bring_up, log


def test_nak_relayed():
    with bring_up("relay", ["relay"], "") as s:
        log("crafted INIT-REBOOT REQUEST for an out-of-subnet address forces a NAK")
        rc, out = s.compose.run("nak-client", timeout=60)
        if rc != 0:
            raise AssertionError(f"nak-client did not run cleanly (rc={rc})\n{out}")

        log("kea NAKs and the relay relays the DHCPNAK back")
        s.wait_service_log("kea", "DHCPNAK", "kea did not send a NAK for the out-of-subnet request")
        s.wait_log("DHCP-NAK", "relay never relayed the DHCPNAK")
