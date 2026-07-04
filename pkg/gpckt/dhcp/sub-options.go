// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp

import (
	"strconv"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/specs"
)

const (
	AgentCircuitIDSubOption layers.DHCPOpt = 1
	// PolicyTagSubOption carries the matched policy key so the reply path can reapply the same action.
	PolicyTagSubOption layers.DHCPOpt = 224
)

const (
	// MaxAgentCircuitIDSize is the widest Agent Circuit ID payload the decimal form of a uint32 interface index.
	MaxAgentCircuitIDSize = 10

	// MaxPolicyTagSize is the largest policy tag that always fits Option 82 beside a maximal Agent Circuit ID sub option.
	MaxPolicyTagSize = specs.DHCPv4MaxOptionSize -
		2*(specs.DHCPv4OptionTypeSize+specs.DHCPv4OptionLengthSize) - MaxAgentCircuitIDSize
)

func CreateAgentCircuitIDSubOption(value int) layers.DHCPOption {
	data := []byte(strconv.Itoa(value))

	return layers.DHCPOption{
		Type:   AgentCircuitIDSubOption,
		Length: byte(len(data)), //nolint:gosec // strconv.Itoa of an int produces at most ~20 bytes.
		Data:   data,
	}
}

func ExtractAgentCircuitIDSubOptionData(options ...layers.DHCPOption) int {
	for _, opt := range options {
		if opt.Type != AgentCircuitIDSubOption {
			continue
		}

		val, err := strconv.Atoi(string(opt.Data))
		if err != nil {
			return 0
		}

		return val
	}

	return 0
}

// CreatePolicyTagSubOption wraps a matched policy key as a sub option with its own copy, returning zero when tag is empty or too large.
func CreatePolicyTagSubOption(tag []byte) layers.DHCPOption {
	if len(tag) == 0 || len(tag) > specs.DHCPv4MaxSubOptionSize {
		return layers.DHCPOption{}
	}

	return layers.DHCPOption{
		Type:   PolicyTagSubOption,
		Length: byte(len(tag)), //nolint:gosec // len(tag) bounded to DHCPv4MaxSubOptionSize above.
		Data:   append([]byte(nil), tag...),
	}
}

// ExtractPolicyTagSubOptionData returns the policy tag bytes or nil when absent.
func ExtractPolicyTagSubOptionData(options ...layers.DHCPOption) []byte {
	for _, opt := range options {
		if opt.Type == PolicyTagSubOption {
			return opt.Data
		}
	}

	return nil
}
