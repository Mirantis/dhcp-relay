// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/specs"
)

// readFromListener reads one packet from a UDP listener with a short deadline.
func readFromListener(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom listener: %v", err)
	}

	return buf[:n]
}

// decodeDHCPv4 parses raw DHCPv4 bytes into a layer so the test can inspect them.
func decodeDHCPv4(t *testing.T, data []byte) *layers.DHCPv4 {
	t.Helper()

	decoded := &layers.DHCPv4{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDHCPv4, decoded)
	var decodedTypes []gopacket.LayerType
	if err := parser.DecodeLayers(data, &decodedTypes); err != nil {
		t.Fatalf("DecodeLayers: %v", err)
	}

	return decoded
}

// findUsableIfIndex returns the first up non loopback interface with a global IPv4.
func findUsableIfIndex(t *testing.T) int {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("net.Interfaces: %v", err)
	}

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
				return ifi.Index
			}
		}
	}

	t.Skip("no suitable interface with a global IPv4 address")

	return 0
}

// listenServer binds the receiver on port 67 at 127.0.0.1 where SendToServer writes. Needs CAP_NET_BIND_SERVICE.
func listenServer(t *testing.T) net.PacketConn {
	t.Helper()

	conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:67")
	if err != nil {
		t.Skipf("bind 127.0.0.1:67 failed (%v), skipping test that needs the DHCPv4 server port", err)
	}

	return conn
}

// newSenderCfg builds a HandleOptions whose PacketConn is a fresh sender socket.
func newSenderCfg(t *testing.T) *dhcp4.HandleOptions {
	t.Helper()

	conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sender: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &dhcp4.HandleOptions{
		Logger:            logger.NewWithoutDatetime(),
		PacketConn:        conn,
		DHCPServerAddress: "127.0.0.1",
		MaxHops:           specs.DHCPv4MaxHops,
	}
}

// minimalDiscover builds the smallest valid DHCPv4 request layer for testing.
func minimalDiscover() *layers.DHCPv4 {
	return &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareLen:  6,
		Xid:          0x12345678,
		ClientHWAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
}

// TestHandleGenericRequestNoAddrs checks an invalid IfIndex surfaces a clear error.
func TestHandleGenericRequestNoAddrs(t *testing.T) {
	conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	cfg := &dhcp4.HandleOptions{
		Logger:            logger.NewWithoutDatetime(),
		PacketConn:        conn,
		DHCPServerAddress: "127.0.0.1",
		MaxHops:           specs.DHCPv4MaxHops,
	}

	err = dhcp4.HandleGenericRequest(t.Context(), cfg, nil, 999999, "DISCOVER", minimalDiscover())
	if err == nil {
		t.Fatal("expected an error for an IfIndex with no IPv4 addresses, got nil")
	}

	if !strings.Contains(err.Error(), "no IPv4 addresses") && !strings.Contains(err.Error(), "interface address lookup error") {
		t.Errorf("error = %q, want it to contain \"no IPv4 addresses\" or \"interface address lookup error\"", err.Error())
	}
}

// TestHandleGenericRequestInjectsOption82 verifies the relay adds Option 82 and bumps RelayHops.
func TestHandleGenericRequestInjectsOption82(t *testing.T) {
	ifIndex := findUsableIfIndex(t)

	cfg := newSenderCfg(t)
	rcv := listenServer(t)
	defer rcv.Close()

	layerDHCPv4 := minimalDiscover()
	if err := dhcp4.HandleGenericRequest(t.Context(), cfg, nil, ifIndex, "DISCOVER", layerDHCPv4); err != nil {
		t.Fatalf("HandleGenericRequest: %v", err)
	}

	received := readFromListener(t, rcv)
	decoded := decodeDHCPv4(t, received)

	opt82 := dhcp.GetRelayAgentInformationOption(decoded)
	if !dhcp.IsOption(opt82) {
		t.Fatal("expected Option 82 to be set on the relayed packet")
	}

	if decoded.RelayHops != 1 {
		t.Errorf("RelayHops = %d, want 1", decoded.RelayHops)
	}

	if decoded.RelayAgentIP.To4() == nil || decoded.RelayAgentIP.IsUnspecified() {
		t.Errorf("RelayAgentIP = %s, want a non zero IPv4", decoded.RelayAgentIP)
	}
}

// TestHandleGenericRequestPolicyTag checks the policy tag sub option rides inside Option 82.
func TestHandleGenericRequestPolicyTag(t *testing.T) {
	ifIndex := findUsableIfIndex(t)

	cfg := newSenderCfg(t)
	rcv := listenServer(t)
	defer rcv.Close()

	dec := &dhcp4.Decision{PolicyTag: []byte{0xaa, 0xbb}}

	layerDHCPv4 := minimalDiscover()
	if err := dhcp4.HandleGenericRequest(t.Context(), cfg, dec, ifIndex, "DISCOVER", layerDHCPv4); err != nil {
		t.Fatalf("HandleGenericRequest: %v", err)
	}

	received := readFromListener(t, rcv)
	decoded := decodeDHCPv4(t, received)

	opt82 := dhcp.GetRelayAgentInformationOption(decoded)
	if !dhcp.IsOption(opt82) {
		t.Fatal("expected Option 82 to be set on the relayed packet")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)
	if subOpts == nil {
		t.Fatal("failed to decode Option 82 sub options")
	}

	if dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...) == 0 {
		t.Error("expected the Agent Circuit ID sub option to be present")
	}

	tag := dhcp.ExtractPolicyTagSubOptionData(subOpts...)
	if tag == nil {
		t.Fatal("expected the policy tag sub option to be present")
	}

	if !bytesEqual(tag, []byte{0xaa, 0xbb}) {
		t.Errorf("policy tag = %x, want aabb", tag)
	}
}

// TestForwardRelayedRequest checks a relayed request is forwarded verbatim to the server.
func TestForwardRelayedRequest(t *testing.T) {
	cfg := newSenderCfg(t)
	rcv := listenServer(t)
	defer rcv.Close()

	layerDHCPv4 := minimalDiscover()
	layerDHCPv4.RelayHops = 1

	if err := dhcp4.ForwardRelayedRequest(cfg, nil, "REQUEST", layerDHCPv4); err != nil {
		t.Fatalf("ForwardRelayedRequest: %v", err)
	}

	received := readFromListener(t, rcv)
	if len(received) == 0 {
		t.Fatal("expected non empty bytes from the listener")
	}

	decoded := decodeDHCPv4(t, received)
	if decoded.Xid != layerDHCPv4.Xid {
		t.Errorf("decoded Xid = 0x%x, want 0x%x", decoded.Xid, layerDHCPv4.Xid)
	}
}

// TestForwardRelayedRequestHopsExceeded checks a relayed request at the hop maximum is discarded.
func TestForwardRelayedRequestHopsExceeded(t *testing.T) {
	cfg := newSenderCfg(t)

	layerDHCPv4 := minimalDiscover()
	layerDHCPv4.RelayHops = specs.DHCPv4MaxHops

	err := dhcp4.ForwardRelayedRequest(cfg, nil, "REQUEST", layerDHCPv4)
	if err == nil {
		t.Fatal("expected an error for hop count at maximum, got nil")
	}

	if !strings.Contains(err.Error(), "hop count") {
		t.Errorf("error = %q, want it to contain \"hop count\"", err.Error())
	}
}

// bytesEqual avoids pulling in the bytes package just for one comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
