// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/specs"
)

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

	cfg.Logger.Debugf("Sent %d bytes of data to socket\n", n)

	return pconn.LocalAddr(), to, nil
}

func HandleGenericRequest(
	cfg *HandleOptions,
	dec *Decision,
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

	cfg.Logger.Debugf("Option 82 -> Sub-option: Type=%d, Len=%d, Data=[% x], ASCII=%s",
		subOpt1.Type, subOpt1.Length, subOpt1.Data, strconv.QuoteToASCII(string(subOpt1.Data)))

	subOpts := []layers.DHCPOption{subOpt1}

	// Embed the matched policy key so the reply path can reapply the action. Skip it when it cannot fit Option 82 next to the circuit id.
	if dec != nil && len(dec.PolicyTag) > 0 {
		subOpts = append(subOpts, dhcp.CreatePolicyTagSubOption(dec.PolicyTag))
	}

	// Encode once. When the tag pushes Option 82 past the limit relay with the circuit id alone so the reply still routes by ingress NIC.
	opt82 := dhcp.EncodeRelayAgentInformationOption(subOpts...)
	if dhcp.IsOption(opt82) {
		dhcp.SetOption(layerDHCPv4, opt82)
	} else {
		cfg.Logger.Debugf("Policy tag too large for Option 82, relaying without it\n")
		dhcp.SetRelayAgentInformationOption(layerDHCPv4, subOpt1)
	}

	layerDHCPv4.RelayHops++

	serverAddr := EffectiveServerAddress(cfg, dec)

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

		if laddr, raddr, err := SendToServer(cfg, serverAddr, buffer.Bytes()); err != nil {
			cfg.Logger.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
		} else {
			cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
				logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)
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

	if laddr, raddr, err := SendToServer(cfg, EffectiveServerAddress(cfg, dec), buffer.Bytes()); err != nil {
		cfg.Logger.Errorf("Error sending DHCPv4 relayed message: %v\n", err)
	} else {
		cfg.Logger.Infof("%s 0x%x: DHCP-%s [%d], Src=%s, Dst=%s\n",
			logDataOutPrefix, layerDHCPv4.Xid, dhcpMessageType, layerDHCPv4.Len(), laddr, raddr)
	}

	return nil
}
