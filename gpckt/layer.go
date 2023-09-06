package gpckt

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func GetEthernet(packet gopacket.Packet) *layers.Ethernet {
	l := packet.Layer(layers.LayerTypeEthernet)
	if l == nil {
		return nil
	}

	layerEthernet, ok := l.(*layers.Ethernet)
	if !ok {
		return nil
	}

	return layerEthernet
}

func GetIPv4(packet gopacket.Packet) *layers.IPv4 {
	l := packet.Layer(layers.LayerTypeIPv4)
	if l == nil {
		return nil
	}

	layerIPv4, ok := l.(*layers.IPv4)
	if !ok {
		return nil
	}

	return layerIPv4
}

func GetUDP(packet gopacket.Packet) *layers.UDP {
	l := packet.Layer(layers.LayerTypeUDP)
	if l == nil {
		return nil
	}

	layerUDP, ok := l.(*layers.UDP)
	if !ok {
		return nil
	}

	return layerUDP
}

func GetDHCPv4(packet gopacket.Packet) *layers.DHCPv4 {
	l := packet.Layer(layers.LayerTypeDHCPv4)
	if l == nil {
		return nil
	}

	layerDHCPv4, ok := l.(*layers.DHCPv4)
	if !ok {
		return nil
	}

	return layerDHCPv4
}

func CopyDHCPv4(layerDHCPv4 *layers.DHCPv4) (*layers.DHCPv4, error) {
	out := new(layers.DHCPv4)

	if err := out.DecodeFromBytes(layerDHCPv4.Contents, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("copy error: %w", err)
	}

	return out, nil
}
