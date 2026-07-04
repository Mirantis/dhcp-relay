// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp_test

import (
	"bytes"
	"testing"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/specs"
)

// TestPolicyTagRoundTrip confirms the policy tag and Agent Circuit ID both survive an encode then decode of Option 82.
func TestPolicyTagRoundTrip(t *testing.T) {
	const ifIndex = 7

	tag := []byte{0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	circuit := dhcp.CreateAgentCircuitIDSubOption(ifIndex)

	tagOpt := dhcp.CreatePolicyTagSubOption(tag)
	if !dhcp.IsOption(tagOpt) {
		t.Fatal("CreatePolicyTagSubOption returned a zero option")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(circuit, tagOpt)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)

	if got := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...); got != ifIndex {
		t.Errorf("Agent Circuit ID = %d, want %d", got, ifIndex)
	}

	if got := dhcp.ExtractPolicyTagSubOptionData(subOpts...); !bytes.Equal(got, tag) {
		t.Errorf("policy tag = % x, want % x", got, tag)
	}
}

// TestExtractPolicyTagAbsent returns nil when Option 82 carries no policy tag.
func TestExtractPolicyTagAbsent(t *testing.T) {
	circuit := dhcp.CreateAgentCircuitIDSubOption(3)
	subOpts := dhcp.DecodeRelayAgentInformationOption(dhcp.EncodeRelayAgentInformationOption(circuit))

	if got := dhcp.ExtractPolicyTagSubOptionData(subOpts...); got != nil {
		t.Errorf("policy tag = % x, want nil", got)
	}
}

// TestCreatePolicyTagSubOptionRejects yields a zero option for an empty or oversized tag.
func TestCreatePolicyTagSubOptionRejects(t *testing.T) {
	if dhcp.IsOption(dhcp.CreatePolicyTagSubOption(nil)) {
		t.Error("empty tag must produce a zero option")
	}

	// The last size also covers a length byte wrap of a 256 byte tag.
	for _, size := range []int{specs.DHCPv4MaxSubOptionSize + 1, specs.DHCPv4MaxSubOptionSize + 2, specs.DHCPv4MaxSubOptionSize + 3} {
		if dhcp.IsOption(dhcp.CreatePolicyTagSubOption(make([]byte, size))) {
			t.Errorf("a %d byte tag must produce a zero option", size)
		}
	}
}

// TestPolicyTagMaxSizeRoundTrip encodes the largest allowed tag alone which fills the Option 82 budget exactly.
func TestPolicyTagMaxSizeRoundTrip(t *testing.T) {
	tag := bytes.Repeat([]byte{0xab}, specs.DHCPv4MaxSubOptionSize)

	tagOpt := dhcp.CreatePolicyTagSubOption(tag)
	if !dhcp.IsOption(tagOpt) {
		t.Fatal("CreatePolicyTagSubOption rejected the largest allowed tag")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(tagOpt)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption rejected the largest allowed tag")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)
	if got := dhcp.ExtractPolicyTagSubOptionData(subOpts...); !bytes.Equal(got, tag) {
		t.Errorf("policy tag = % x, want % x", got, tag)
	}
}

// TestCreatePolicyTagSubOptionCopiesTag keeps the option immune to later caller writes.
func TestCreatePolicyTagSubOptionCopiesTag(t *testing.T) {
	tag := []byte{1, 2, 3}

	opt := dhcp.CreatePolicyTagSubOption(tag)

	tag[0] = 9

	if !bytes.Equal(opt.Data, []byte{1, 2, 3}) {
		t.Errorf("option data = % x, want the original 01 02 03", opt.Data)
	}
}
