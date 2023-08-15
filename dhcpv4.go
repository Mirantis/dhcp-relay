package main

import (
	"net"
	"strconv"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/gpckt/dhcp"
)

type HandleOptions struct {
	PacketConn        net.PacketConn
	DHCPServerAddress string
	ReplyTTL          uint8
}

func HandleDHCPv4(
	cfg *HandleOptions,
	sall *unix.SockaddrLinklayer,
	layerEthernet *layers.Ethernet,
	layerIPv4 *layers.IPv4,
	layerUDP *layers.UDP,
	layerDHCPv4 *layers.DHCPv4,
) {
	dhcpMessageType := dhcp.GetMessageType(layerDHCPv4)
	if dhcpMessageType == "" {
		cl.Debugf("Discarding DHCPv4-%s relayed message: invalid type\n",
			layerDHCPv4.Operation)

		return
	}

	layerDHCPv4.Options = dhcp.DeleteSplitOptions(layerDHCPv4.Options...)

	funcDataInLog := func() {
		cl.Infof("%s 0x%x: DHCP-%s [%d], IfIndex=%d, Src=%s(%s), Dst=%s(%s)\n",
			logDataInPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), sall.Ifindex,
			net.JoinHostPort(layerIPv4.SrcIP.String(), strconv.Itoa(int(layerUDP.SrcPort))), layerEthernet.SrcMAC,
			net.JoinHostPort(layerIPv4.DstIP.String(), strconv.Itoa(int(layerUDP.DstPort))), layerEthernet.DstMAC,
		)
	}

	switch layerDHCPv4.Operation {
	case layers.DHCPOpRequest:
		funcDataInLog()

		if layerDHCPv4.RelayHops > 0 {
			cl.Debugf("Forwarding DHCPv4-%s relayed message: Xid=0x%x\n",
				dhcpMessageType, layerDHCPv4)

			if err := ForwardDHCPv4RelayedRequest(cfg, dhcpMessageType, layerDHCPv4); err != nil {
				cl.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
					dhcpMessageType, err)
			}

			return
		}

		if err := HandleDHCPv4GenericRequest(cfg, sall.Ifindex, dhcpMessageType, layerDHCPv4); err != nil {
			cl.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
				dhcpMessageType, err)
		}
	case layers.DHCPOpReply:
		if layerDHCPv4.RelayHops != 1 {
			cl.Debugf("Discarding DHCPv4-%s relayed message: unexpected hops count\n",
				dhcpMessageType)

			return
		}

		funcDataInLog()

		if err := HandleDHCPv4GenericReplyRaw(cfg, dhcpMessageType, layerDHCPv4); err != nil {
			cl.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
				dhcpMessageType, err)
		}
	}
}
