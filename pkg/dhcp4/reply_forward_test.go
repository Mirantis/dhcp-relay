// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/specs"
)

// firstGlobalIPv4 returns a global unicast IPv4 configured on a usable interface.
func firstGlobalIPv4(t *testing.T) net.IP {
	t.Helper()

	ifi, err := net.InterfaceByIndex(findUsableIfIndex(t))
	if err != nil {
		t.Skipf("InterfaceByIndex: %v", err)
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		t.Skipf("Addrs: %v", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
			return ipnet.IP.To4()
		}
	}

	t.Skip("no global IPv4 address on the usable interface")

	return nil
}

// minimalReply builds the smallest valid DHCPv4 reply layer for testing the reverse path.
func minimalReply(giaddr net.IP) *layers.DHCPv4 {
	return &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareLen:  6,
		Xid:          0x0000abcd,
		RelayHops:    1,
		RelayAgentIP: giaddr,
		YourClientIP: net.IPv4(192, 168, 50, 10),
		ClientHWAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
}

// TestForwardRelayedReplyForwards checks a reply is forwarded verbatim to its giaddr on the server port.
func TestForwardRelayedReplyForwards(t *testing.T) {
	giaddr := firstGlobalIPv4(t)

	rcv, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", net.JoinHostPort(giaddr.String(), "67"))
	if err != nil {
		t.Skipf("bind %s:67 failed (%v), skipping test that needs the DHCPv4 server port", giaddr, err)
	}
	defer rcv.Close()

	sender, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("ListenPacket sender: %v", err)
	}
	defer sender.Close()

	cfg := &dhcp4.HandleOptions{
		Logger:     logger.NewWithoutDatetime(),
		PacketConn: sender,
		MaxHops:    specs.DHCPv4MaxHops,
	}

	if err := dhcp4.ForwardRelayedReply(cfg, minimalReply(giaddr), "OFFER"); err != nil {
		t.Fatalf("ForwardRelayedReply: %v", err)
	}

	decoded := decodeDHCPv4(t, readFromListener(t, rcv))

	if decoded.Operation != layers.DHCPOpReply {
		t.Errorf("Operation = %v, want reply", decoded.Operation)
	}

	if decoded.Xid != 0x0000abcd {
		t.Errorf("Xid = 0x%x, want 0xabcd", decoded.Xid)
	}

	if decoded.RelayAgentIP.To4() == nil || !decoded.RelayAgentIP.To4().Equal(giaddr) {
		t.Errorf("RelayAgentIP = %s, want it forwarded verbatim as %s", decoded.RelayAgentIP, giaddr)
	}

	// The return path counts this hop so a re-ingested reply drains toward the minimum and cannot loop.
	if decoded.RelayHops != 0 {
		t.Errorf("RelayHops = %d, want it decremented to 0 on the return path", decoded.RelayHops)
	}
}

// TestForwardRelayedReplyHopFloor checks a reply below the minimum hop count errors rather than underflowing.
func TestForwardRelayedReplyHopFloor(t *testing.T) {
	sender, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("ListenPacket sender: %v", err)
	}
	defer sender.Close()

	cfg := &dhcp4.HandleOptions{
		Logger:     logger.NewWithoutDatetime(),
		PacketConn: sender,
		MaxHops:    specs.DHCPv4MaxHops,
	}

	reply := minimalReply(net.IPv4(192, 168, 50, 1))
	reply.RelayHops = 0

	if err := dhcp4.ForwardRelayedReply(cfg, reply, "OFFER"); err == nil ||
		!strings.Contains(err.Error(), "below minimum") {
		t.Errorf("error = %v, want it to contain \"below minimum\"", err)
	}
}

// TestForwardRelayedReplyInvalidGiaddr checks an unusable giaddr surfaces a clear error rather than sending.
func TestForwardRelayedReplyInvalidGiaddr(t *testing.T) {
	sender, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("ListenPacket sender: %v", err)
	}
	defer sender.Close()

	cfg := &dhcp4.HandleOptions{
		Logger:     logger.NewWithoutDatetime(),
		PacketConn: sender,
		MaxHops:    specs.DHCPv4MaxHops,
	}

	for name, giaddr := range map[string]net.IP{
		"unspecified": net.IPv4zero,
		"nil":         nil,
		"loopback":    net.IPv4(127, 0, 0, 1),
		"broadcast":   net.IPv4bcast,
	} {
		t.Run(name, func(t *testing.T) {
			err := dhcp4.ForwardRelayedReply(cfg, minimalReply(giaddr), "OFFER")
			if err == nil || !strings.Contains(err.Error(), "invalid Relay Agent address") {
				t.Errorf("error = %v, want it to contain \"invalid Relay Agent address\"", err)
			}
		})
	}
}

// TestIsRelayLocalAddr checks the local address discriminator used to split deliver from forward.
func TestIsRelayLocalAddr(t *testing.T) {
	if dhcp4.IsRelayLocalAddr(net.IPv4zero) {
		t.Error("the unspecified address must not be reported as local")
	}

	if dhcp4.IsRelayLocalAddr(nil) {
		t.Error("a nil address must not be reported as local")
	}

	// A global unicast IPv4 on a real interface is what a giaddr we set looks like so it must match.
	if !dhcp4.IsRelayLocalAddr(firstGlobalIPv4(t)) {
		t.Error("a global unicast address on a local interface must be reported as local")
	}

	// Loopback is never a valid giaddr so it must not alias one of our addresses.
	if dhcp4.IsRelayLocalAddr(net.IPv4(127, 0, 0, 1)) {
		t.Error("a loopback address must not be reported as local")
	}

	// TEST-NET-3 (RFC 5737) is reserved for documentation and will not be configured locally.
	if dhcp4.IsRelayLocalAddr(net.IPv4(203, 0, 113, 200)) {
		t.Error("a documentation range address must not be reported as local")
	}
}

// TestIsRelayLocalAddrMatchesRequestGiaddr locks the single relay invariant. Every address the request path can
// place in giaddr must be seen as local on the reply path so the reply is delivered to the client not forwarded.
func TestIsRelayLocalAddrMatchesRequestGiaddr(t *testing.T) {
	ifIndex := findUsableIfIndex(t)

	addrs, err := dhcp4.GetInterfaceGlobalUnicastAddrs4(ifIndex)
	if err != nil {
		t.Fatalf("GetInterfaceGlobalUnicastAddrs4: %v", err)
	}
	if len(addrs) == 0 {
		t.Skip("no global unicast IPv4 on the usable interface")
	}

	// The request path sources giaddr from this exact set so the reply path must classify all of it as local.
	for _, a := range addrs {
		if !dhcp4.IsRelayLocalAddr(a.IP) {
			t.Errorf("giaddr %s from the request path must be classified local, else a single relay reply forwards and is lost", a.IP)
		}
	}
}
