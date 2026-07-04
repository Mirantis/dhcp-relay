// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package specs

// https://en.wikipedia.org/wiki/User_Datagram_Protocol
const (
	UDPFieldSizeSourcePort      = 16
	UDPFieldSizeDestinationPort = 16
	UDPFieldSizeLength          = 16
	UDPFieldSizeChecksum        = 16

	UDPHeaderSizeBits = UDPFieldSizeSourcePort + UDPFieldSizeDestinationPort + UDPFieldSizeLength + UDPFieldSizeChecksum
)
