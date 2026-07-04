// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"net"
	"testing"

	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/gpckt/dhcp"
)

// stubLinkMap is a fixed LinkSubnetLookup for the unnumbered ingress tests.
type stubLinkMap struct {
	subnet net.IP
}

func (s stubLinkMap) Lookup(_, _ string) (net.IP, bool) {
	return s.subnet, s.subnet != nil
}

// loopbackIfIndex returns a loopback ifIndex. Loopback has no global unicast IPv4 so the relay treats it as unnumbered.
func loopbackIfIndex(t *testing.T) int {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("net.Interfaces: %v", err)
	}

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Index
		}
	}

	t.Skip("no loopback interface")

	return 0
}

func TestServerFacingAddr(t *testing.T) {
	// A global unicast target routes via a global unicast source, which is a valid giaddr.
	server := firstGlobalIPv4(t)

	ip, err := dhcp4.ServerFacingAddr(t.Context(), server.String())
	if err != nil {
		t.Fatalf("ServerFacingAddr: %v", err)
	}

	if ip.To4() == nil || !ip.IsGlobalUnicast() {
		t.Errorf("ServerFacingAddr = %v, want a global unicast IPv4", ip)
	}

	// A loopback target yields a loopback source, which is not a deliverable giaddr and must be rejected.
	if _, err := dhcp4.ServerFacingAddr(t.Context(), "127.0.0.1"); err == nil {
		t.Error("ServerFacingAddr(127.0.0.1) = nil error, want a non global unicast rejection")
	}
}

// TestHandleGenericRequestUnnumberedLinkSelection drives the unnumbered ingress path over the loopback ifIndex. It
// checks the relay auto-derives a giaddr and adds the RFC 3527 Link Selection sub option beside the circuit id.
func TestHandleGenericRequestUnnumberedLinkSelection(t *testing.T) {
	ifIndex := loopbackIfIndex(t)

	cfg := newSenderCfg(t)
	cfg.LinkMap = stubLinkMap{subnet: net.IPv4(192, 168, 50, 0).To4()}

	rcv := listenServer(t)
	defer rcv.Close()

	if err := dhcp4.HandleGenericRequest(t.Context(), cfg, nil, ifIndex, "DISCOVER", minimalDiscover()); err != nil {
		t.Fatalf("HandleGenericRequest: %v", err)
	}

	decoded := decodeDHCPv4(t, readFromListener(t, rcv))

	// giaddr must be auto-derived to a real IPv4, not left unset.
	if decoded.RelayAgentIP.To4() == nil || decoded.RelayAgentIP.To4().Equal(net.IPv4zero.To4()) {
		t.Errorf("giaddr = %s, want an auto-derived server-facing IPv4", decoded.RelayAgentIP)
	}

	opt82 := dhcp.GetRelayAgentInformationOption(decoded)
	if !dhcp.IsOption(opt82) {
		t.Fatal("expected Option 82 on the relayed packet")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)

	subnet := dhcp.ExtractLinkSelectionSubOptionData(subOpts...)
	if subnet == nil || !subnet.Equal(net.IPv4(192, 168, 50, 0).To4()) {
		t.Errorf("Link Selection subnet = %v, want 192.168.50.0", subnet)
	}

	if dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...) != ifIndex {
		t.Errorf("Agent Circuit ID = %d, want ingress ifIndex %d",
			dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...), ifIndex)
	}
}

// TestHandleGenericRequestUnnumberedNoLinkMap checks an unnumbered ingress without a link map fails clearly.
func TestHandleGenericRequestUnnumberedNoLinkMap(t *testing.T) {
	ifIndex := loopbackIfIndex(t)

	cfg := newSenderCfg(t) // no LinkMap set

	err := dhcp4.HandleGenericRequest(t.Context(), cfg, nil, ifIndex, "DISCOVER", minimalDiscover())
	if err == nil {
		t.Fatal("expected an error for an unnumbered ingress with no link map, got nil")
	}
}
