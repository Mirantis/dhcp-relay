// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp

import (
	"net"
	"strconv"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/specs"
)

const (
	AgentCircuitIDSubOption layers.DHCPOpt = 1
	// LinkSelectionSubOption (RFC 3527) carries the client subnet so the server picks a pool from it not from giaddr.
	LinkSelectionSubOption layers.DHCPOpt = 5
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

func CreateAgentCircuitIDSubOption(value uint32) layers.DHCPOption {
	data := []byte(strconv.FormatUint(uint64(value), 10))

	return layers.DHCPOption{
		Type:   AgentCircuitIDSubOption,
		Length: byte(len(data)), //nolint:gosec // a uint32 renders to at most 10 digits.
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

// CreateLinkSelectionSubOption wraps an IPv4 subnet address as the RFC 3527 sub option, returning zero for a non IPv4 value.
func CreateLinkSelectionSubOption(subnet net.IP) layers.DHCPOption {
	v4 := subnet.To4()
	if v4 == nil {
		return layers.DHCPOption{}
	}

	return layers.DHCPOption{
		Type:   LinkSelectionSubOption,
		Length: net.IPv4len,
		Data:   append([]byte(nil), v4...),
	}
}

// ExtractLinkSelectionSubOptionData returns the IPv4 subnet from the RFC 3527 sub option or nil when absent or malformed.
func ExtractLinkSelectionSubOptionData(options ...layers.DHCPOption) net.IP {
	for _, opt := range options {
		if opt.Type == LinkSelectionSubOption && len(opt.Data) == net.IPv4len {
			return net.IP(append([]byte(nil), opt.Data...))
		}
	}

	return nil
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

// ExtractPolicyTagSubOptionData returns a copy of the policy tag bytes or nil when absent.
func ExtractPolicyTagSubOptionData(options ...layers.DHCPOption) []byte {
	for _, opt := range options {
		if opt.Type == PolicyTagSubOption {
			return append([]byte(nil), opt.Data...)
		}
	}

	return nil
}
