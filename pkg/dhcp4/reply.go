// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/sockets"
	"code.local/dhcp-relay/pkg/specs"
)

// HandleGenericReply crafts a relayed DHCPv4 reply and sends it to the client, or drops it when DropReply is set.
func HandleGenericReply(
	cfg *HandleOptions,
	dec *Decision,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
	replyType uint8,
) error {
	if dec == nil {
		dec = &Decision{}
	}

	if dec.DropReply {
		cfg.Logger.Debugf("Dropping DHCPv4-%s reply: client %s (reply blackhole)\n",
			dhcpMessageType, layerDHCPv4.ClientHWAddr)

		return nil
	}

	// A reply needs the relay's own Relay Agent address as its source.
	srcIP := layerDHCPv4.RelayAgentIP.To4()
	if srcIP == nil || srcIP.IsLoopback() || srcIP.Equal(net.IPv4zero) || srcIP.Equal(net.IPv4bcast) {
		return errors.New("invalid Relay Agent address value")
	}

	// Reuse the sub options the policy path already decoded. Decode here for the no policy path.
	subOpts := dec.ReplySubOpts
	if subOpts == nil {
		opt82 := dhcp.GetRelayAgentInformationOption(layerDHCPv4)
		if !dhcp.IsOption(opt82) {
			return errors.New("no Relay Agent Information")
		}

		subOpts = dhcp.DecodeRelayAgentInformationOption(opt82)
	}

	if len(subOpts) == 0 {
		return errors.New("no Relay Agent Information")
	}

	for _, el := range subOpts {
		cfg.Logger.Debugf("Option 82 -> Sub-option: Type=%d, Len=%d, Data=[% x], ASCII=%s",
			el.Type, el.Length, el.Data, strconv.QuoteToASCII(string(el.Data)))
	}

	ifIndex := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...)
	if ifIndex == 0 {
		return errors.New("invalid Agent Circuit ID sub-option value")
	}

	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return fmt.Errorf("invalid interface data in Agent Circuit ID for IfIndex=%d: %w", ifIndex, err)
	}

	layerIPv4 := &layers.IPv4{
		Version:  specs.IPv4Version,
		Id:       GenerateRandomIPv4ID(),
		Flags:    layers.IPv4DontFragment,
		TTL:      cfg.ReplyTTL,
		Protocol: layers.IPProtocolUDP,
	}

	layerUDP := &layers.UDP{
		SrcPort: specs.DHCPv4ServerPort,
		DstPort: specs.DHCPv4ClientPort,
	}

	err = layerUDP.SetNetworkLayerForChecksum(layerIPv4)
	if err != nil {
		return fmt.Errorf("layer crafting error: %w", err)
	}

	// Decrement hops. At zero this is the last hop so strip Option 82 and RelayAgentIP.
	if layerDHCPv4.RelayHops > 0 {
		layerDHCPv4.RelayHops--
	}

	if layerDHCPv4.RelayHops == 0 {
		dhcp.DeleteRelayAgentInformationOption(layerDHCPv4)
		layerDHCPv4.RelayAgentIP = nil
	}

	dstMAC, err := ReplyAddressing(replyType, srcIP, layerDHCPv4, layerIPv4, cfg.BroadcastReplyL2Unicast)
	if err != nil {
		return fmt.Errorf("reply addressing error: %w", err)
	}

	targets := ReplyTargets(cfg, dec.ReplyNICMatch, ifi, layerDHCPv4.ClientHWAddr)

	// One raw socket is created here and reused for every copy.
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

	// One copy per NIC. A send error on one does not stop the others.
	errs := make([]error, 0, len(targets))

	for _, nic := range targets {
		// A unicast copy out a non ingress NIC is sourced from an address on that NIC.
		if replyType == UnicastReply {
			layerIPv4.SrcIP = srcIP

			if nic.Index != ifi.Index {
				addrs := GetInterfaceGlobalUnicastAddrs4(nic.Index)
				if len(addrs) == 0 {
					errs = append(errs, fmt.Errorf("%s: no IPv4 address for a unicast reply copy", nic.Name))

					continue
				}

				layerIPv4.SrcIP = BestUnicastSrc(addrs, layerDHCPv4.YourClientIP)
			}
		}

		if err := SendReply(cfg, rs, nic, dstMAC, dhcpMessageType, layerDHCPv4, layerIPv4, layerUDP); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", nic.Name, err))
		}
	}

	return errors.Join(errs...)
}

// ReplyAddressing applies unicast or broadcast addressing for a reply to the IPv4 layer and returns the Ethernet destination.
func ReplyAddressing(
	replyType uint8,
	srcIP net.IP,
	layerDHCPv4 *layers.DHCPv4,
	layerIPv4 *layers.IPv4,
	broadcastL2Unicast bool,
) (net.HardwareAddr, error) {
	dstMAC := layerDHCPv4.ClientHWAddr

	switch replyType {
	case UnicastReply:
		layerIPv4.SrcIP = srcIP.To4()

		// A DHCPINFORM ACK leaves yiaddr zero and puts the client address in ciaddr.
		dstIP := layerDHCPv4.YourClientIP.To4()
		if dstIP.IsUnspecified() {
			dstIP = layerDHCPv4.ClientIP.To4()
		}

		layerIPv4.DstIP = dstIP

		dhcp.SetUnicast(layerDHCPv4)
	case BroadcastReply:
		layerIPv4.SrcIP = net.IPv4zero
		layerIPv4.DstIP = net.IPv4bcast

		// RFC 2131 sends a broadcast reply to the Ethernet broadcast address. Legacy mode keeps the client MAC.
		if !broadcastL2Unicast {
			dstMAC = layers.EthernetBroadcast
		}

		dhcp.SetBroadcast(layerDHCPv4)
	default:
		// Fail fast on unknown reply types instead of sending a malformed packet.
		return nil, fmt.Errorf("unsupported reply type: %d", replyType)
	}

	return dstMAC, nil
}

// SendReply serializes and writes the reply frame out of nic with dstMAC as the Ethernet destination.
func SendReply(
	cfg *HandleOptions,
	rs *sockets.Raw,
	nic net.Interface,
	dstMAC net.HardwareAddr,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
	layerIPv4 *layers.IPv4,
	layerUDP *layers.UDP,
) error {
	layerEthernet := &layers.Ethernet{
		SrcMAC:       nic.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(
		buffer, gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		layerEthernet, layerIPv4, layerUDP, layerDHCPv4,
	)
	if err != nil {
		return fmt.Errorf("layer encoding error: %w", err)
	}

	n, err := rs.Send(nic.Index, nic.HardwareAddr, sockets.Htons(unix.ETH_P_ALL), buffer.Bytes())
	if err != nil {
		return fmt.Errorf("socket write error: %w", err)
	}

	cfg.Logger.Debugf("Sent %d bytes of data to socket\n", n)

	cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], IfIndex=%d, Src=%s, Dst=%s\n",
		logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), nic.Index,
		net.JoinHostPort(layerIPv4.SrcIP.String(), strconv.Itoa(specs.DHCPv4ServerPort)),
		net.JoinHostPort(layerIPv4.DstIP.String(), strconv.Itoa(specs.DHCPv4ClientPort)),
	)

	return nil
}

// ReplyTargets returns the NICs a reply goes out of, defaulting to the ingress NIC alone.
func ReplyTargets(
	cfg *HandleOptions,
	match func(name, macStr string) bool,
	ingress *net.Interface,
	client net.HardwareAddr,
) []net.Interface {
	targets := []net.Interface{*ingress}

	if match == nil {
		return targets
	}

	if cfg.ReplyInterfaceCache == nil {
		cfg.Logger.Errorf("Reply NIC match for client %s has no interface cache, using ingress %s\n",
			client, ingress.Name)

		return targets
	}

	ifaces, err := cfg.ReplyInterfaceCache.Interfaces()

	// A refetch error still returns a usable stale snapshot so match on that instead of collapsing to ingress.
	if err != nil && len(ifaces) > 0 {
		cfg.Logger.Errorf("Reply NIC enumeration for client %s degraded to a stale snapshot: %v\n",
			client, err)
	}

	if len(ifaces) == 0 {
		cfg.Logger.Errorf("Reply NIC enumeration failed for client %s, using ingress %s: %v\n",
			client, ingress.Name, err)

		return targets
	}

	matched := SelectReplyInterfaces(match, ifaces)
	if len(matched) == 0 {
		cfg.Logger.Errorf("Reply NIC match selected no live interface for client %s: using ingress %s\n",
			client, ingress.Name)

		return targets
	}

	// A match that leaves out the ingress NIC starves the client segment so the operator sees that intent in the log.
	if !slices.ContainsFunc(matched, func(ni net.Interface) bool { return ni.Index == ingress.Index }) {
		cfg.Logger.Warnf("Reply NIC match for client %s does not include the ingress %s\n",
			client, ingress.Name)
	}

	return matched
}

// SelectReplyInterfaces returns the up NICs that match accepts. A nil match returns nothing.
func SelectReplyInterfaces(match func(name, macStr string) bool, ifaces []net.Interface) []net.Interface {
	if match == nil {
		return nil
	}

	matched := make([]net.Interface, 0, len(ifaces))

	for _, ni := range ifaces {
		// Skip NICs that cannot carry an Ethernet reply (down or no hardware address).
		if ni.Flags&net.FlagUp == 0 || len(ni.HardwareAddr) == 0 {
			continue
		}

		if match(ni.Name, ni.HardwareAddr.String()) {
			matched = append(matched, ni)
		}
	}

	return matched
}
