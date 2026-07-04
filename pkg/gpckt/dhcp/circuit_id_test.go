// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp_test

import (
	"strconv"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
)

// TestAgentCircuitIDRoundTrip confirms the Agent Circuit ID ifIndex survives encode then decode.
func TestAgentCircuitIDRoundTrip(t *testing.T) {
	const ifIndex = 7

	circuit := dhcp.CreateAgentCircuitIDSubOption(ifIndex)
	if !dhcp.IsOption(circuit) {
		t.Fatal("CreateAgentCircuitIDSubOption returned a zero option")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(circuit)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)

	if got := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...); got != ifIndex {
		t.Errorf("Agent Circuit ID = %d, want %d", got, ifIndex)
	}
}

// TestAgentCircuitIDZero confirms a zero ifIndex yields a valid option and round trips to zero.
func TestAgentCircuitIDZero(t *testing.T) {
	circuit := dhcp.CreateAgentCircuitIDSubOption(0)
	if !dhcp.IsOption(circuit) {
		t.Fatal("CreateAgentCircuitIDSubOption(0) returned a zero option")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(circuit)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)

	if got := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...); got != 0 {
		t.Errorf("Agent Circuit ID = %d, want 0", got)
	}
}

// TestAgentCircuitIDLargeValue confirms the max uint32 ifIndex round trips via strconv.Itoa.
func TestAgentCircuitIDLargeValue(t *testing.T) {
	const ifIndex = 4294967295

	circuit := dhcp.CreateAgentCircuitIDSubOption(ifIndex)
	if !dhcp.IsOption(circuit) {
		t.Fatal("CreateAgentCircuitIDSubOption returned a zero option")
	}

	opt82 := dhcp.EncodeRelayAgentInformationOption(circuit)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	subOpts := dhcp.DecodeRelayAgentInformationOption(opt82)

	if got := dhcp.ExtractAgentCircuitIDSubOptionData(subOpts...); got != ifIndex {
		t.Errorf("Agent Circuit ID = %d, want %d", got, ifIndex)
	}

	if string(circuit.Data) != strconv.Itoa(ifIndex) {
		t.Errorf("circuit data = %q, want %q", circuit.Data, strconv.Itoa(ifIndex))
	}
}

// TestDecodeRelayAgentInformationOptionMalformed confirms a truncated Option 82 body is rejected as nil.
func TestDecodeRelayAgentInformationOptionMalformed(t *testing.T) {
	malformed := layers.DHCPOption{
		Type:   layers.DHCPOpt(82),
		Length: 1,
		Data:   []byte{0x01},
	}

	if got := dhcp.DecodeRelayAgentInformationOption(malformed); got != nil {
		t.Errorf("DecodeRelayAgentInformationOption = %v, want nil", got)
	}
}

// TestDecodeRelayAgentInformationOptionTrailingGarbage confirms a truncated trailer rejects the whole option.
func TestDecodeRelayAgentInformationOptionTrailingGarbage(t *testing.T) {
	const ifIndex = 9

	circuit := dhcp.CreateAgentCircuitIDSubOption(ifIndex)

	opt82 := dhcp.EncodeRelayAgentInformationOption(circuit)
	if !dhcp.IsOption(opt82) {
		t.Fatal("EncodeRelayAgentInformationOption returned a zero option")
	}

	trailers := map[string][]byte{
		"truncated header":     {0x01},       // a lone type byte with no length
		"length overruns body": {0xE0, 0x05}, // declares 5 data bytes but none follow
	}

	for name, trailer := range trailers {
		t.Run(name, func(t *testing.T) {
			garbled := opt82
			garbled.Data = append(append([]byte(nil), opt82.Data...), trailer...)

			if got := dhcp.DecodeRelayAgentInformationOption(garbled); got != nil {
				t.Errorf("DecodeRelayAgentInformationOption = %v, want nil for a truncated trailer", got)
			}
		})
	}
}

// TestEncodeRelayAgentInformationOptionEmpty confirms no sub options yields a zero option since empty data gives Length 0.
func TestEncodeRelayAgentInformationOptionEmpty(t *testing.T) {
	opt82 := dhcp.EncodeRelayAgentInformationOption()
	if dhcp.IsOption(opt82) {
		t.Error("EncodeRelayAgentInformationOption with no sub options must return a zero option")
	}
}

// TestEncodeRelayAgentInformationOptionZeroSubOption confirms a zero sub option aborts the encode and yields a zero option.
func TestEncodeRelayAgentInformationOptionZeroSubOption(t *testing.T) {
	zero := layers.DHCPOption{}

	opt82 := dhcp.EncodeRelayAgentInformationOption(zero)
	if dhcp.IsOption(opt82) {
		t.Error("EncodeRelayAgentInformationOption must reject a zero sub option")
	}
}
