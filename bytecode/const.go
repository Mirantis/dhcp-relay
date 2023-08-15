package bytecode

import (
	"code.local/dhcp-relay/specs"
)

const ( // field offsets
	EthernetFieldOffsetEtherType = specs.EthernetHeaderLength - specs.EthernetFieldSizeEtherType

	IPv4FieldOffsetFlags = specs.IPv4FieldSizeVersion + specs.IPv4FieldSizeIHL +
		specs.IPv4FieldSizeDSC + specs.IPv4FieldSizeECN + specs.IPv4FieldSizeTotalLength +
		specs.IPv4FieldSizeIdentification
	IPv4FieldOffsetProtocol = IPv4FieldOffsetFlags + specs.IPv4FieldSizeFlags +
		specs.IPv4FieldSizeFragmentOffset + specs.IPv4FieldSizeTTL

	UDPFieldOffsetDestinationPort = specs.UDPFieldSizeSourcePort
)

const ( // field masks
	IPv4FieldBitMaskIHL = 0x0F // Lower 4 bits mask
)
