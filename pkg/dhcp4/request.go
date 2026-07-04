// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/specs"
)

// serverDialTimeout bounds the per-request route probe used to auto derive a giaddr for an unnumbered ingress.
const serverDialTimeout = 5 * time.Second

// EffectiveServerAddress returns the per packet upstream override when set otherwise the process default.
func EffectiveServerAddress(cfg *HandleOptions, dec *Decision) string {
	if dec != nil && dec.ServerAddress != "" {
		return dec.ServerAddress
	}

	return cfg.DHCPServerAddress
}

func SendToServer(
	cfg *HandleOptions,
	serverAddr string,
	buf []byte,
) (laddr, raddr net.Addr, err error) {
	var to *net.UDPAddr

	to, err = net.ResolveUDPAddr("udp4",
		net.JoinHostPort(
			serverAddr,
			strconv.Itoa(specs.DHCPv4ServerPort),
		),
	)
	if err != nil {
		return nil, nil, err
	}

	pconn := ipv4.NewPacketConn(cfg.PacketConn)

	n, err := pconn.WriteTo(buf, nil, to)
	if err != nil {
		return pconn.LocalAddr(), to, err
	}

	cfg.Logger.Debugf("Sent %d bytes of data to socket\n", n)

	return pconn.LocalAddr(), to, nil
}

// ServerFacingAddr returns the local global unicast IPv4 the kernel routes to serverAddr for use as an
// unnumbered ingress giaddr. The context bounds the lookup and a non global unicast source is rejected.
func ServerFacingAddr(ctx context.Context, serverAddr string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, serverDialTimeout)
	defer cancel()

	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "udp4",
		net.JoinHostPort(serverAddr, strconv.Itoa(specs.DHCPv4ServerPort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || !IsGlobalUnicastIPv4(local.IP) {
		return nil, fmt.Errorf("no global unicast IPv4 route to server %s", serverAddr)
	}

	return local.IP.To4(), nil
}

// ResolveGiaddr resolves an ingress NIC to its giaddr(s). A numbered ingress returns its interface addresses.
// An unnumbered ingress returns the override or auto derived giaddr plus the link map subnet in one lookup.
func ResolveGiaddr(
	ctx context.Context,
	cfg *HandleOptions,
	dec *Decision,
	ifIndex int,
) (addrs []net.IPNet, override, linkSubnet net.IP, err error) {
	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("interface address lookup error for IfIndex=%d: %w", ifIndex, err)
	}

	addrs, err = InterfaceGlobalUnicastAddrs4(ifi)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("interface address lookup error for IfIndex=%d: %w", ifIndex, err)
	}

	if len(addrs) > 0 {
		return addrs, nil, nil, nil
	}

	// Unnumbered ingress. Without a link map the server cannot be told which subnet the client sits on.
	if cfg.LinkMap == nil {
		return nil, nil, nil, fmt.Errorf("no IPv4 addresses on IfIndex=%d", ifIndex)
	}

	subnet, ok := cfg.LinkMap.Lookup(ifi.Name, ifi.HardwareAddr.String())
	if !ok {
		return nil, nil, nil, fmt.Errorf("no IPv4 on IfIndex=%d (%s) and no link-map entry", ifIndex, ifi.Name)
	}

	giaddr := cfg.Giaddr
	if giaddr == nil {
		giaddr, err = ServerFacingAddr(ctx, EffectiveServerAddress(cfg, dec))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("giaddr auto-derive for IfIndex=%d: %w", ifIndex, err)
		}
	}

	return nil, giaddr, subnet, nil
}

func HandleGenericRequest(
	ctx context.Context,
	cfg *HandleOptions,
	dec *Decision,
	ifIndex int,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
) error {
	// An explicit hop bound guards against a future caller bypassing the RelayHops==0 dispatch in dhcp4.go.
	if layerDHCPv4.RelayHops >= cfg.MaxHops {
		return fmt.Errorf("hop count %d reaches maximum %d for IfIndex=%d", layerDHCPv4.RelayHops, cfg.MaxHops, ifIndex)
	}

	addrs, override, linkSubnet, err := ResolveGiaddr(ctx, cfg, dec, ifIndex)
	if err != nil {
		return err
	}

	subOpt1 := dhcp.CreateAgentCircuitIDSubOption(uint32(ifIndex)) //nolint:gosec // ifIndex is a positive Linux ifindex.
	if !dhcp.IsOption(subOpt1) {
		return fmt.Errorf("invalid Agent Circuit ID sub-option for IfIndex=%d", ifIndex)
	}

	cfg.Logger.Debugf("Option 82 -> Sub-option: Type=%d, Len=%d, Data=[% x], ASCII=%s",
		subOpt1.Type, subOpt1.Length, subOpt1.Data, strconv.QuoteToASCII(string(subOpt1.Data)))

	// Routing sub-options the server and reply path need. Link Selection is added only for an unnumbered ingress.
	routing := []layers.DHCPOption{subOpt1}
	if linkSubnet != nil {
		routing = append(routing, dhcp.CreateLinkSelectionSubOption(linkSubnet))
	}

	// The policy tag is optional so drop it when it pushes Option 82 past the limit and keep the routing sub-options.
	full := routing
	if dec != nil && len(dec.PolicyTag) > 0 {
		full = append(append([]layers.DHCPOption{}, routing...), dhcp.CreatePolicyTagSubOption(dec.PolicyTag))
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(full...)
	if !dhcp.IsOption(opt82) {
		cfg.Logger.Debugf("Policy tag too large for Option 82, relaying without it\n")
		opt82 = dhcp.EncodeRelayAgentInformationOption(routing...)
	}
	if !dhcp.IsOption(opt82) {
		return fmt.Errorf("could not encode Option 82 for IfIndex=%d", ifIndex)
	}

	dhcp.SetOption(layerDHCPv4, opt82)

	layerDHCPv4.RelayHops++

	serverAddr := EffectiveServerAddress(cfg, dec)

	// send relays one copy under giaddr. A serialize error aborts the request, a send error is logged and the
	// remaining copies still go out.
	send := func(giaddr net.IP) error {
		layerDHCPv4.RelayAgentIP = giaddr

		buffer := gopacket.NewSerializeBuffer()

		if err := gopacket.SerializeLayers(
			buffer, gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			},
			layerDHCPv4,
		); err != nil {
			return fmt.Errorf("layer encoding error: %w", err)
		}

		if laddr, raddr, err := SendToServer(cfg, serverAddr, buffer.Bytes()); err != nil {
			cfg.Logger.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
		} else {
			cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
				logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)
		}

		return nil
	}

	// An unnumbered ingress relays under one override giaddr. A numbered ingress relays once per interface address.
	if override != nil {
		return send(override)
	}

	for _, addr := range addrs {
		if err := send(addr.IP); err != nil {
			return err
		}
	}

	return nil
}

func ForwardRelayedRequest(
	cfg *HandleOptions,
	dec *Decision,
	dhcpMessageType string,
	layerDHCPv4 *layers.DHCPv4,
) error {
	// A relayed request is at least one hop in. Drop it at the configured maximum so loops cannot cycle forever.
	if layerDHCPv4.RelayHops >= cfg.MaxHops {
		return fmt.Errorf("hop count %d reaches maximum %d", layerDHCPv4.RelayHops, cfg.MaxHops)
	}

	// Count this relay hop per RFC 2131 so a forwarding loop grows the count and reaches the maximum.
	layerDHCPv4.RelayHops++

	if err := RelayToServer(cfg, EffectiveServerAddress(cfg, dec), dhcpMessageType, layerDHCPv4); err != nil {
		cfg.Logger.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
	}

	return nil
}

// RelayToServer serializes the DHCPv4 layer and sends it to dst on the server port then logs the send.
func RelayToServer(cfg *HandleOptions, dst, dhcpMessageType string, layerDHCPv4 *layers.DHCPv4) error {
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

	laddr, raddr, err := SendToServer(cfg, dst, buffer.Bytes())
	if err != nil {
		return err
	}

	cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
		logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)

	return nil
}
