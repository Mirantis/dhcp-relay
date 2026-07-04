// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

// Package relay applies per client MAC policy decisions to DHCPv4 packet handling on the relay hot path.
package relay

import (
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/macpolicy"
)

// PolicyForPacket returns the per packet Decision and whether to drop the packet.
func PolicyForPacket(
	policy *macpolicy.Map,
	layerDHCPv4 *layers.DHCPv4,
) (*dhcp4.Decision, bool) {
	var clientID []byte
	if opt := dhcp.GetOption(layerDHCPv4, layers.DHCPOptClientID); dhcp.IsOption(opt) {
		clientID = opt.Data
	}

	if layerDHCPv4.Operation == layers.DHCPOpReply {
		action, subOpts := LookupReplyAction(policy, layerDHCPv4, clientID)

		// A client denied on the forward path must not receive forged or rogue server replies either.
		if action.Kind == macpolicy.ActionBlackhole {
			return nil, true
		}

		dec := ReplyConfig(action)
		// Hand the decoded sub options to the reply path so it does not decode Option 82 a second time.
		dec.ReplySubOpts = subOpts

		return dec, false
	}

	action, key := policy.LookupID(clientID, layerDHCPv4.ClientHWAddr)
	if action.Kind == macpolicy.ActionBlackhole {
		return nil, true
	}

	return RequestConfig(action, key), false
}

// LookupReplyAction picks the per client reply Action, preferring the Option 82 tag then falling back to Option 61 and chaddr.
// It also returns the decoded Option 82 sub options so the caller can pass them to the reply path and avoid a second decode.
func LookupReplyAction(policy *macpolicy.Map, layerDHCPv4 *layers.DHCPv4, clientID []byte) (macpolicy.Action, []layers.DHCPOption) {
	var subOpts []layers.DHCPOption
	if opt82 := dhcp.GetRelayAgentInformationOption(layerDHCPv4); dhcp.IsOption(opt82) {
		subOpts = dhcp.DecodeRelayAgentInformationOption(opt82)
	}

	return lookupReplyActionFromSubOpts(policy, layerDHCPv4, clientID, subOpts), subOpts
}

// lookupReplyActionFromSubOpts picks the reply Action from already decoded Option 82 sub options so the caller decodes once.
func lookupReplyActionFromSubOpts(
	policy *macpolicy.Map,
	layerDHCPv4 *layers.DHCPv4,
	clientID []byte,
	subOpts []layers.DHCPOption,
) macpolicy.Action {
	// Always check chaddr/clientID first so a forged Option 82 tag cannot bypass a blackhole.
	base := policy.Lookup(clientID, layerDHCPv4.ClientHWAddr)
	if base.Kind == macpolicy.ActionBlackhole {
		return base
	}

	if tag := dhcp.ExtractPolicyTagSubOptionData(subOpts...); len(tag) > 0 {
		// A tag matching no entry is stale after a reload or came from a foreign relay.
		if action, id := policy.LookupID(tag); id != nil {
			return action
		}
	}

	return base
}

// RequestConfig returns the Decision for a request, overriding the upstream for a server action and tagging with the key.
func RequestConfig(action macpolicy.Action, key []byte) *dhcp4.Decision {
	dec := &dhcp4.Decision{PolicyTag: key}

	if action.Kind == macpolicy.ActionServer {
		dec.ServerAddress = action.Server
	}

	return dec
}

// ReplyConfig returns the Decision for a reply, threading the reverse path action and otherwise leaving the default ingress reply.
func ReplyConfig(action macpolicy.Action) *dhcp4.Decision {
	dec := &dhcp4.Decision{}

	switch action.Reply.Kind {
	case macpolicy.ReplyBlackhole:
		dec.DropReply = true
	case macpolicy.ReplyMatch:
		dec.ReplyNICMatch = action.Reply.Match
	case macpolicy.ReplyIngress:
		// Ingress is the default reply path so nothing is overridden.
	}

	return dec
}
