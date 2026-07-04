// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4

import (
	"context"
	"net"
	"runtime/debug"
	"strconv"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
)

// LinkSubnetLookup resolves the client subnet for an ingress NIC by name and MAC. A *linkmap.Map satisfies it.
type LinkSubnetLookup interface {
	Lookup(name, mac string) (net.IP, bool)
}

// HandleOptions is the process wide relay configuration shared by every handler goroutine. It is read only during handling.
type HandleOptions struct {
	Logger              *logger.Config
	PacketConn          net.PacketConn
	ReplyInterfaceCache *InterfaceCache
	// LinkMap resolves the client subnet for an unnumbered ingress NIC. Nil disables unnumbered ingress support.
	LinkMap           LinkSubnetLookup
	DHCPServerAddress string
	// Giaddr overrides the auto derived server facing giaddr used for an unnumbered ingress. Nil auto derives it.
	Giaddr net.IP
	// MaxHops bounds the relay hop count so a packet at or above it is discarded per RFC 2131.
	MaxHops uint8
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
	ctx context.Context,
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
			if cfg != nil && cfg.Logger != nil {
				cfg.Logger.Errorf("Recovered DHCPv4 handler panic: %v\n%s", r, debug.Stack())
			}
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
				dhcpMessageType, layerDHCPv4.Xid)

			if err := ForwardRelayedRequest(cfg, dec, dhcpMessageType, layerDHCPv4); err != nil {
				cfg.Logger.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
					dhcpMessageType, err)
			}

			return
		}

		if err := HandleGenericRequest(ctx, cfg, dec, sall.Ifindex, dhcpMessageType, layerDHCPv4); err != nil {
			cfg.Logger.Errorf("Error handling DHCPv4-%s relayed message: %v\n",
				dhcpMessageType, err)
		}
	case layers.DHCPOpReply:
		// A reply carries the hop count of the request it answers. Accept one hop up to the maximum so a chained
		// relay reply still routes and drop anything outside that range as malformed or looped.
		if layerDHCPv4.RelayHops < 1 || layerDHCPv4.RelayHops > cfg.MaxHops {
			cfg.Logger.Debugf("Discarding DHCPv4-%s relayed message: unexpected hops count\n",
				dhcpMessageType)

			return
		}

		funcDataInLog()

		// A reply blackhole applies whether the reply is delivered locally or forwarded so honor it before the split.
		if dec.DropReply {
			cfg.Logger.Debugf("Dropping DHCPv4-%s reply: client %s (reply blackhole)\n",
				dhcpMessageType, layerDHCPv4.ClientHWAddr)

			return
		}

		bootFileName := dhcp.GetBootFileName(layerDHCPv4)
		if bootFileName != "" {
			cfg.Logger.Debugf("Boot File Name: %s\n", bootFileName)
		}

		// A reply whose giaddr is not ours belongs to a downstream relay so forward it there. GiaddrIsLocal also
		// counts a configured -giaddr as ours so a reply echoing it is delivered locally.
		if !cfg.GiaddrIsLocal(layerDHCPv4.RelayAgentIP) {
			if err := ForwardRelayedReply(cfg, layerDHCPv4, dhcpMessageType); err != nil {
				cfg.Logger.Warnf("Error forwarding DHCPv4-%s reply to relay agent: %v\n",
					dhcpMessageType, err)
			}

			return
		}

		switch {
		case dhcp.IsUnicast(layerDHCPv4):
			// A reply the relay cannot route back (for example no Option 82) is recoverable and not a relay
			// fault. Warn rather than error.
			if err := HandleGenericReply(cfg, dec, dhcpMessageType, layerDHCPv4, UnicastReply); err != nil {
				cfg.Logger.Warnf("Error handling DHCPv4-%s unicast relayed message: %v\n",
					dhcpMessageType, err)
			}
		case dhcp.IsBroadcast(layerDHCPv4):
			if err := HandleGenericReply(cfg, dec, dhcpMessageType, layerDHCPv4, BroadcastReply); err != nil {
				cfg.Logger.Warnf("Error handling DHCPv4-%s broadcast relayed message: %v\n",
					dhcpMessageType, err)
			}
		default:
			cfg.Logger.Debugf("Discarding DHCPv4-%s reply: unsupported flags=0x%x\n",
				dhcpMessageType, layerDHCPv4.Flags)
		}
	default:
		cfg.Logger.Debugf("Discarding DHCPv4-%s message: unsupported operation=%s\n",
			dhcpMessageType, layerDHCPv4.Operation)
	}
}
