#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

"""Broadcast a crafted INIT-REBOOT DHCPREQUEST for an out-of-subnet address so the relay picks it
up and an authoritative kea answers with a DHCPNAK. No scapy, just a raw BOOTP/DHCP payload."""

import socket
import struct
import time

MAC = bytes.fromhex("020000000007")
XID = 0x4E414B00  # "NAK\0"
REQUESTED_IP = "10.0.0.99"  # outside the relayed subnet so kea must NAK
MAGIC_COOKIE = 0x63825363
BROADCAST_FLAG = 0x8000  # ask for a broadcast reply so the NAK comes back to a client with no IP


def build_request() -> bytes:
    chaddr = MAC + b"\x00" * 10
    pkt = struct.pack("!BBBB", 1, 1, 6, 0)  # op=BOOTREQUEST, htype=ethernet, hlen=6, hops=0
    pkt += struct.pack("!I", XID)
    pkt += struct.pack("!HH", 0, BROADCAST_FLAG)  # secs, flags
    pkt += socket.inet_aton("0.0.0.0") * 4  # ciaddr, yiaddr, siaddr, giaddr
    pkt += chaddr
    pkt += b"\x00" * 64  # sname
    pkt += b"\x00" * 128  # file
    pkt += struct.pack("!I", MAGIC_COOKIE)
    pkt += bytes([53, 1, 3])  # option 53 message type = REQUEST
    pkt += bytes([50, 4]) + socket.inet_aton(REQUESTED_IP)  # option 50 requested IP
    pkt += bytes([61, 7, 1]) + MAC  # option 61 client id (type 1 plus the MAC)
    pkt += bytes([255])  # end
    return pkt


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 68))

    packet = build_request()
    for _ in range(5):
        sock.sendto(packet, ("255.255.255.255", 67))
        time.sleep(0.5)


if __name__ == "__main__":
    main()
