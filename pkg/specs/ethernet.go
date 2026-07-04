// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package specs

// https://en.wikipedia.org/wiki/Ethernet_frame
const (
	EthernetFieldSizeDestinationMACAddress = 48
	EthernetFieldSizeSourceMACAddress      = 48
	EthernetFieldSizeEtherType             = 16

	EthernetHeaderSizeBits = EthernetFieldSizeDestinationMACAddress + EthernetFieldSizeSourceMACAddress + EthernetFieldSizeEtherType
)

// Field-size constants are in bits. EthernetMACLengthBytes is in bytes.
const (
	EthernetCommonMTU      = 1500
	EthernetMACLengthBytes = 6
)
