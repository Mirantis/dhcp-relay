package main

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/specs"
)

func ValidateLayers(layerEthernet *layers.Ethernet, layerIPv4 *layers.IPv4, layerUDP *layers.UDP, layerDHCPv4 *layers.DHCPv4, mtu uint16) error {
	if layerEthernet == nil {
		return fmt.Errorf("invalid Ethernet layer data")
	}

	if layerIPv4 == nil {
		return fmt.Errorf("invalid IPv4 layer data")
	}

	if layerIPv4.Flags&layers.IPv4MoreFragments != 0 && layerIPv4.FragOffset > 0 {
		return fmt.Errorf("IPv4 header indicates that packet is fragmented")
	}

	if layerIPv4.IHL > specs.IPv4FieldIHLValueThresholdForOptionsFieldPresence {
		return fmt.Errorf("IPv4 header has variable-sized Options field")
	}

	if layerIPv4.SrcIP == nil || layerIPv4.SrcIP.To4() == nil {
		return fmt.Errorf("source IP is not valid IPv4")
	}

	if layerIPv4.SrcIP.IsMulticast() || layerIPv4.SrcIP.IsLinkLocalMulticast() {
		return fmt.Errorf("source IP is Multicast IPv4")
	}

	if layerIPv4.DstIP == nil || layerIPv4.DstIP.To4() == nil {
		return fmt.Errorf("destination IP is not valid IPv4")
	}

	if layerIPv4.DstIP.IsMulticast() || layerIPv4.DstIP.IsLinkLocalMulticast() {
		return fmt.Errorf("destination IP is Multicast IPv4")
	}

	if layerUDP == nil {
		return fmt.Errorf("invalid UDP layer data")
	}

	if layerUDP.DstPort != specs.DHCPv4ServerPort {
		return fmt.Errorf("unexpected UDP Destination port: %d", layerUDP.DstPort)
	}

	if layerDHCPv4 == nil {
		return fmt.Errorf("invalid DHCPv4 layer data")
	}

	if layerDHCPv4.HardwareType != layers.LinkTypeEthernet {
		return fmt.Errorf("unexpected HardwareType in DHCPv4 message: %s", layerDHCPv4.HardwareType)
	}

	if layerDHCPv4.HardwareLen != specs.EthernetMACLength {
		return fmt.Errorf("unexpected size of HardwareLen in DHCPv4 message: %d", layerDHCPv4.HardwareLen)
	}

	if layerDHCPv4.Len() < specs.DHCPv4MinMessageSize || layerDHCPv4.Len() > mtu {
		return fmt.Errorf("unexpected size of DHCPv4 message: %d", layerDHCPv4.Len())
	}

	return nil
}
