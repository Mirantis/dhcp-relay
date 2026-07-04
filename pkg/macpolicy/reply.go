// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package macpolicy

import (
	"fmt"
	"strings"

	"code.local/dhcp-relay/pkg/cfgmatch"
)

// ReplyActionKind selects where a matched client's replies are sent.
type ReplyActionKind uint8

const (
	// ReplyIngress sends the reply out the Option 82 ingress NIC. It is the zero value.
	ReplyIngress ReplyActionKind = iota
	// ReplyBlackhole drops the reply.
	ReplyBlackhole
	// ReplyMatch sends a copy out every NIC that the embedded Selector accepts.
	ReplyMatch
)

// ReplyAction is the reverse path decision for one client. The embedded Selector applies only when Kind is ReplyMatch.
type ReplyAction struct {
	cfgmatch.Selector
	Kind ReplyActionKind
}

// ParseReplyAction interprets the optional reply field. Empty or "@default" keeps the ingress NIC, "@blackhole" drops, "*" matches all.
func ParseReplyAction(token string) (ReplyAction, error) {
	switch token {
	case "", ActionDefaultKeyword:
		return ReplyAction{Kind: ReplyIngress}, nil
	case ActionBlackholeKeyword:
		return ReplyAction{Kind: ReplyBlackhole}, nil
	}

	// Reject an unknown reserved keyword instead of treating it as a selector term.
	if strings.HasPrefix(token, ActionPrefix) {
		return ReplyAction{}, fmt.Errorf("unknown reply action %q", token)
	}

	sel, err := cfgmatch.ParseSelector(token)
	if err != nil {
		return ReplyAction{}, err
	}

	return ReplyAction{Selector: sel, Kind: ReplyMatch}, nil
}
