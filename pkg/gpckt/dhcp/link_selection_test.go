// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp_test

import (
	"net"
	"testing"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
)

// TestLinkSelectionSubOptionRoundTrip encodes the Link Selection sub option into Option 82 then decodes it back.
func TestLinkSelectionSubOptionRoundTrip(t *testing.T) {
	subnet := net.IPv4(192, 168, 50, 0)

	sub := dhcp.CreateLinkSelectionSubOption(subnet)
	if !dhcp.IsOption(sub) {
		t.Fatal("CreateLinkSelectionSubOption returned a zero option for a valid IPv4 subnet")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(dhcp.CreateAgentCircuitIDSubOption(3), sub)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	decoded := dhcp.DecodeRelayAgentInformationOption(opt82)

	got := dhcp.ExtractLinkSelectionSubOptionData(decoded...)
	if got == nil || !got.Equal(subnet.To4()) {
		t.Errorf("ExtractLinkSelectionSubOptionData = %v, want %s", got, subnet)
	}

	// The circuit id must survive alongside the Link Selection sub option.
	if ifIndex := dhcp.ExtractAgentCircuitIDSubOptionData(decoded...); ifIndex != 3 {
		t.Errorf("Agent Circuit ID = %d, want 3", ifIndex)
	}
}

// TestLinkSelectionSubOptionRejectsNonIPv4 checks a non IPv4 value yields a zero option rather than bad bytes.
func TestLinkSelectionSubOptionRejectsNonIPv4(t *testing.T) {
	if dhcp.IsOption(dhcp.CreateLinkSelectionSubOption(net.ParseIP("2001:db8::1"))) {
		t.Error("CreateLinkSelectionSubOption accepted an IPv6 address")
	}

	if dhcp.ExtractLinkSelectionSubOptionData() != nil {
		t.Error("ExtractLinkSelectionSubOptionData returned non-nil for no options")
	}
}
