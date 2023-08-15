package dhcp

import (
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/specs"
)

func IsUnicast(layerDHCPv4 *layers.DHCPv4) bool {
	return layerDHCPv4.Flags&specs.DHCPv4BroadcastFlag == 0
}

func SetUnicast(layerDHCPv4 *layers.DHCPv4) {
	layerDHCPv4.Flags &= ^uint16(specs.DHCPv4BroadcastFlag)
}

func IsBroadcast(layerDHCPv4 *layers.DHCPv4) bool {
	return layerDHCPv4.Flags&specs.DHCPv4BroadcastFlag == specs.DHCPv4BroadcastFlag
}

func SetBroadcast(layerDHCPv4 *layers.DHCPv4) {
	layerDHCPv4.Flags |= specs.DHCPv4BroadcastFlag
}
