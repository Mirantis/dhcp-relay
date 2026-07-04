// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package bytecode

import (
	"code.local/dhcp-relay/pkg/specs"
)

const ( // field offsets in bits, BPF consumers divide by 8 for byte addressing
	EthernetFieldOffsetEtherType = specs.EthernetHeaderSizeBits - specs.EthernetFieldSizeEtherType

	IPv4FieldOffsetFlags = specs.IPv4FieldSizeVersion + specs.IPv4FieldSizeIHL +
		specs.IPv4FieldSizeDSC + specs.IPv4FieldSizeECN + specs.IPv4FieldSizeTotalLength +
		specs.IPv4FieldSizeIdentification
	IPv4FieldOffsetProtocol = IPv4FieldOffsetFlags + specs.IPv4FieldSizeFlags +
		specs.IPv4FieldSizeFragmentOffset + specs.IPv4FieldSizeTTL

	// UDPFieldOffsetDestinationPort is the byte offset from the IP header start to the UDP destination port field.
	// BPF_IND adds the IP header length from X register so this is Ethernet header bytes plus the UDP source port bytes.
	UDPFieldOffsetDestinationPort = specs.EthernetHeaderSizeBits/8 + specs.UDPFieldSizeSourcePort/8
)

const ( // field masks
	IPv4FieldBitMaskVersion = 0xF0 // Upper 4 bits mask
	IPv4FieldBitMaskIHL     = 0x0F // Lower 4 bits mask
)
