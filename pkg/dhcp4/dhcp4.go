// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"net"
	"runtime/debug"
	"strconv"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
)

// HandleOptions is the process wide relay configuration shared by every handler goroutine. It is read only during handling.
type HandleOptions struct {
	Logger              *logger.Config
	PacketConn          net.PacketConn
	ReplyInterfaceCache *InterfaceCache
	DHCPServerAddress   string
	// BroadcastReplyL2Unicast keeps the client MAC as L2 destination for a broadcast reply instead of the Ethernet broadcast address.
	BroadcastReplyL2Unicast bool
	ReplyTTL                uint8
}

// Decision is the per packet policy outcome threaded into Handle beside the shared config. Its zero value is the default relay behavior.
type Decision struct {
	// ServerAddress overrides the upstream for this packet. Empty keeps HandleOptions.DHCPServerAddress.
	ServerAddress string
	// PolicyTag is the matched policy key embedded in Option 82 on the request so the reply path can reapply the action.
	PolicyTag []byte
	// ReplyNICMatch selects the reverse path NICs. Nil keeps the Option 82 ingress NIC.
	ReplyNICMatch func(name, macStr string) bool
	// ReplySubOpts is the Option 82 sub options already decoded on the policy path. Nil makes HandleGenericReply decode them.
	ReplySubOpts []layers.DHCPOption
	// DropReply drops the reply on the reverse path.
	DropReply bool
}

func Handle(
	cfg *HandleOptions,
	dec *Decision,
	sall *unix.SockaddrLinklayer,
	layerEthernet *layers.Ethernet,
	layerIPv4 *layers.IPv4,
	layerUDP *layers.UDP,
	layerDHCPv4 *layers.DHCPv4,
) {
	// A packet with no matched policy handles with the zero decision so the rest of the function never nil checks it.
	if dec == nil {
		dec = &Decision{}
	}

	// A panic while handling one packet is logged with a stack so only this packet is lost.
	defer func() {
		if r := recover(); r != nil {
			cfg.Logger.Errorf("Recovered DHCPv4 handler panic: Xid=0x%x, client %s: %v\n%s",
				layerDHCPv4.Xid, layerDHCPv4.ClientHWAddr, r, debug.Stack())
		}
	}()

	dhcpMessageType := dhcp.GetMessageType(layerDHCPv4)
	if dhcpMessageType == "" {
		cfg.Logger.Debugf("Discarding DHCPv4-%s relayed message: invalid type\n",
			layerDHCPv4.Operation)

		return
	}

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

			if err := ForwardRelayedRequest(cfg, dec, dhcpMessageType, layerDHCPv4); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
					dhcpMessageType, err)
			}

			return
		}

		if err := HandleGenericRequest(cfg, dec, sall.Ifindex, dhcpMessageType, layerDHCPv4); err != nil {
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
			if err := HandleGenericReply(cfg, dec, dhcpMessageType, layerDHCPv4, UnicastReply); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s unicast relayed message: %v\n",
					dhcpMessageType, err)
			}
		case dhcp.IsBroadcast(layerDHCPv4):
			if err := HandleGenericReply(cfg, dec, dhcpMessageType, layerDHCPv4, BroadcastReply); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s broadcast relayed message: %v\n",
					dhcpMessageType, err)
			}
		}
	}
}
