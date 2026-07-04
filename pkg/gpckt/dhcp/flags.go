// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp

import (
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/specs"
)

func IsUnicast(layerDHCPv4 *layers.DHCPv4) bool {
	if layerDHCPv4 == nil {
		return false
	}

	return layerDHCPv4.Flags&specs.DHCPv4BroadcastFlag == 0
}

func SetUnicast(layerDHCPv4 *layers.DHCPv4) {
	if layerDHCPv4 == nil {
		return
	}

	layerDHCPv4.Flags &^= uint16(specs.DHCPv4BroadcastFlag)
}

func IsBroadcast(layerDHCPv4 *layers.DHCPv4) bool {
	if layerDHCPv4 == nil {
		return false
	}

	return layerDHCPv4.Flags&specs.DHCPv4BroadcastFlag == specs.DHCPv4BroadcastFlag
}

func SetBroadcast(layerDHCPv4 *layers.DHCPv4) {
	if layerDHCPv4 == nil {
		return
	}

	layerDHCPv4.Flags |= specs.DHCPv4BroadcastFlag
}
