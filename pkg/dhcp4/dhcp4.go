// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"net"
	"strconv"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
)

type HandleOptions struct {
	Logger            *logger.Config
	PacketConn        net.PacketConn
	DHCPServerAddress string
	ReplyTTL          uint8
}

func Handle(
	cfg *HandleOptions,
	sall *unix.SockaddrLinklayer,
	layerEthernet *layers.Ethernet,
	layerIPv4 *layers.IPv4,
	layerUDP *layers.UDP,
	layerDHCPv4 *layers.DHCPv4,
) {
	dhcpMessageType := dhcp.GetMessageType(layerDHCPv4)
	if dhcpMessageType == "" {
		cfg.Logger.Debugf("Discarding DHCPv4-%s relayed message: invalid type\n",
			layerDHCPv4.Operation)

		return
	}

	layerDHCPv4.Options = dhcp.DeleteSplitOptions(layerDHCPv4.Options...)

	funcDataInLog := func() {
		cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], IfIndex=%d, Src=%s(%s), Dst=%s(%s)\n",
			logDataInPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), sall.Ifindex,
			net.JoinHostPort(layerIPv4.SrcIP.String(), strconv.Itoa(int(layerUDP.SrcPort))), layerEthernet.SrcMAC,
			net.JoinHostPort(layerIPv4.DstIP.String(), strconv.Itoa(int(layerUDP.DstPort))), layerEthernet.DstMAC,
		)
	}

	switch layerDHCPv4.Operation {
	case layers.DHCPOpRequest:
		funcDataInLog()

		if layerDHCPv4.RelayHops > 0 {
			cfg.Logger.Debugf("Forwarding DHCPv4-%s relayed message: Xid=0x%x\n",
				dhcpMessageType, layerDHCPv4)

			if err := ForwardRelayedRequest(cfg, dhcpMessageType, layerDHCPv4); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
					dhcpMessageType, err)
			}

			return
		}

		if err := HandleGenericRequest(cfg, sall.Ifindex, dhcpMessageType, layerDHCPv4); err != nil {
			cfg.Logger.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
				dhcpMessageType, err)
		}
	case layers.DHCPOpReply:
		if layerDHCPv4.RelayHops != 1 {
			cfg.Logger.Debugf("Discarding DHCPv4-%s relayed message: unexpected hops count\n",
				dhcpMessageType)

			return
		}

		funcDataInLog()

		bootFileName := dhcp.GetBootFileName(layerDHCPv4)
		if bootFileName != "" {
			cfg.Logger.Debugf("Boot File Name: %s\n", bootFileName)
		}

		switch {
		case dhcp.IsUnicast(layerDHCPv4):
			if err := HandleGenericReply(cfg, dhcpMessageType, layerDHCPv4, UnicastReply); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s unicast relayed message: %v\n",
					dhcpMessageType, err)
			}
		case dhcp.IsBroadcast(layerDHCPv4):
			if err := HandleGenericReply(cfg, dhcpMessageType, layerDHCPv4, BroadcastReply); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s broadcast relayed message: %v\n",
					dhcpMessageType, err)
			}
		}
	}
}
