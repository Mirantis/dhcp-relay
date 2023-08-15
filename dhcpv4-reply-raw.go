package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/gpckt/dhcp"
	"code.local/dhcp-relay/sockets"
	"code.local/dhcp-relay/specs"
)

func HandleDHCPv4GenericReplyRaw(
	cfg *HandleOptions,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
) error {
	srcIP := layerDHCPv4.RelayAgentIP.To4()
	if srcIP == nil || srcIP.IsLoopback() || srcIP.Equal(net.IPv4zero) || srcIP.Equal(net.IPv4bcast) {
		return fmt.Errorf("invalid Relay Agent address value")
	}

	opt82 := dhcp.GetRelayAgentInformationOption(layerDHCPv4)
	if !dhcp.IsOption(opt82) {
		return fmt.Errorf("no Relay Agent Information")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)
	if len(subOpts) == 0 {
		return fmt.Errorf("no Relay Agent Information")
	}

	for _, el := range subOpts {
		cl.Debugf("Option 82 -> Sub-option: Type=%d, Len=%d, Data=[% x], ASCII=%s",
			el.Type, el.Length, el.Data, strconv.QuoteToASCII(string(el.Data)))
	}

	ifIndex := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...)
	if ifIndex == 0 {
		return fmt.Errorf("invalid Agent Circuit ID sub-option value")
	}

	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return fmt.Errorf("invalid interface data in Agent Circuit ID for IfIndex=%d: %w", ifIndex, err)
	}

	layerEthernet := &layers.Ethernet{
		SrcMAC:       ifi.HardwareAddr,
		DstMAC:       layerDHCPv4.ClientHWAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	layerIPv4 := &layers.IPv4{
		Version:  specs.IPv4Version,
		Id:       GenerateRandomIPv4ID(),
		Flags:    layers.IPv4DontFragment,
		TTL:      cfg.ReplyTTL,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP.To4(),
		DstIP:    layerDHCPv4.YourClientIP.To4(),
	}

	layerUDP := &layers.UDP{
		SrcPort: specs.DHCPv4ServerPort,
		DstPort: specs.DHCPv4ClientPort,
	}

	err = layerUDP.SetNetworkLayerForChecksum(layerIPv4)
	if err != nil {
		return fmt.Errorf("layer crafting error: %w", err)
	}

	if layerDHCPv4.RelayHops > 0 {
		layerDHCPv4.RelayHops--
	}

	if layerDHCPv4.RelayHops == 0 {
		dhcp.DeleteRelayAgentInformationOption(layerDHCPv4)
		layerDHCPv4.RelayAgentIP = nil
	}

	dhcp.SetUnicast(layerDHCPv4)

	buffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(
		buffer, gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		layerEthernet, layerIPv4, layerUDP, layerDHCPv4,
	)
	if err != nil {
		return fmt.Errorf("layer encoding error: %w", err)
	}

	rs := new(sockets.Raw)

	err = rs.Create(sockets.Htons(unix.ETH_P_ALL))
	if err != nil {
		return fmt.Errorf("socket create error: %w", err)
	}
	defer rs.Close()

	err = rs.AttachBPF([]unix.SockFilter{
		{Code: unix.BPF_RET | unix.BPF_K, K: 0}, // filter ALL
	})
	if err != nil {
		return fmt.Errorf("socket attach BPF error: %w", err)
	}

	n, err := rs.Send(ifi.Index, ifi.HardwareAddr, sockets.Htons(unix.ETH_P_ALL), buffer.Bytes())
	if err != nil {
		return fmt.Errorf("socket write error: %w", err)
	}

	cl.Debugf("Sent %d bytes of data to socket\n", n)

	cl.Infof("%s 0x%x: DHCP-%s [%d], IfIndex=%d, Src=%s, Dst=%s\n",
		logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), ifIndex,
		net.JoinHostPort(
			srcIP.To4().String(), strconv.Itoa(specs.DHCPv4ServerPort),
		),
		net.JoinHostPort(
			layerDHCPv4.YourClientIP.To4().String(), strconv.Itoa(specs.DHCPv4ClientPort),
		),
	)

	return nil
}
