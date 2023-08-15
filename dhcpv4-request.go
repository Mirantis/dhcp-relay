package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/gpckt/dhcp"
	"code.local/dhcp-relay/specs"
)

func sendDHCPv4ToServer(
	cfg *HandleOptions,
	buf []byte,
) (laddr, raddr net.Addr, err error) {
	var to *net.UDPAddr

	to, err = net.ResolveUDPAddr("udp4",
		net.JoinHostPort(
			cfg.DHCPServerAddress,
			strconv.Itoa(specs.DHCPv4ServerPort),
		),
	)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // pass error unwrapped
	}

	pconn := ipv4.NewPacketConn(cfg.PacketConn)

	err = pconn.SetBPF([]bpf.RawInstruction{
		{Op: unix.BPF_RET | unix.BPF_K, Jt: 0, Jf: 0, K: 0}, // filter ALL
	})
	if err != nil {
		return pconn.LocalAddr(), to, err
	}

	n, err := pconn.WriteTo(buf, nil, to)
	if err != nil {
		return pconn.LocalAddr(), to, err
	}

	cl.Debugf("Sent %d bytes of data to socket\n", n)

	return pconn.LocalAddr(), to, nil
}

func HandleDHCPv4GenericRequest(
	cfg *HandleOptions,
	ifIndex int,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
) error {
	addrs := GetInterfaceGlobalUnicastAddrs4(ifIndex)
	if len(addrs) == 0 {
		return fmt.Errorf("no IPv4 addresses on IfIndex=%d", ifIndex)
	}

	subOpt1 := dhcp.CreateAgentCircuitIDSubOption(ifIndex)
	if !dhcp.IsOption(subOpt1) {
		return fmt.Errorf("invalid Agent Circuit ID sub-option for IfIndex=%d", ifIndex)
	}

	cl.Debugf("Option 82 -> Sub-option: Type=%d, Len=%d, Data=[% x], ASCII=%s",
		subOpt1.Type, subOpt1.Length, subOpt1.Data, strconv.QuoteToASCII(string(subOpt1.Data)))

	dhcp.SetRelayAgentInformationOption(layerDHCPv4, subOpt1)

	dhcp.SetUnicast(layerDHCPv4)
	layerDHCPv4.RelayHops++

	for _, addr := range addrs {
		layerDHCPv4.RelayAgentIP = addr.IP

		buffer := gopacket.NewSerializeBuffer()

		err := gopacket.SerializeLayers(
			buffer, gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			},
			layerDHCPv4,
		)
		if err != nil {
			return fmt.Errorf("layer encoding error: %w", err)
		}

		if laddr, raddr, err := sendDHCPv4ToServer(cfg, buffer.Bytes()); err != nil {
			cl.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
		} else {
			cl.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
				logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)
		}
	}

	return nil
}

func ForwardDHCPv4RelayedRequest(
	cfg *HandleOptions,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
) error {
	dhcp.SetUnicast(layerDHCPv4)

	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(
		buffer, gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		layerDHCPv4,
	)
	if err != nil {
		return fmt.Errorf("layer encoding error: %w", err)
	}

	if laddr, raddr, err := sendDHCPv4ToServer(cfg, buffer.Bytes()); err != nil {
		cl.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
	} else {
		cl.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
			logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)
	}

	return nil
}
