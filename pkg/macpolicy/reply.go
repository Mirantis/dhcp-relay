// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Reply term prefixes. A reply field is comma separated terms selecting NICs by interface name or MAC.
const (
	ReplyDimName = "name="
	ReplyDimMAC  = "mac="
)

// ReplyActionKind selects where a matched client's replies are sent.
type ReplyActionKind uint8

const (
	// ReplyIngress sends the reply out the Option 82 ingress NIC. It is the zero value.
	ReplyIngress ReplyActionKind = iota
	// ReplyBlackhole drops the reply.
	ReplyBlackhole
	// ReplyMatch sends a copy out every NIC that Match accepts.
	ReplyMatch
)

// ReplyAction is the reverse path decision for one client. The glob fields and All apply only when Kind is ReplyMatch.
type ReplyAction struct {
	NameGlobs []string
	MACGlobs  []string
	All       bool
	Kind      ReplyActionKind
}

// Match reports whether the NIC with this name and MAC should get a reply copy (only for ReplyMatch).
func (r ReplyAction) Match(name, mac string) bool {
	if r.All {
		return true
	}

	for _, g := range r.NameGlobs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}

	for _, g := range r.MACGlobs {
		if ok, _ := filepath.Match(g, mac); ok {
			return true
		}
	}

	return false
}

// ParseReplyAction interprets the optional reply field. Empty or "@default" keeps the ingress NIC, "@blackhole" drops, "*" matches all.
func ParseReplyAction(token string) (ReplyAction, error) {
	switch token {
	case "", ActionDefaultKeyword:
		return ReplyAction{Kind: ReplyIngress}, nil
	case ActionBlackholeKeyword:
		return ReplyAction{Kind: ReplyBlackhole}, nil
	case CatchAllKey:
		return ReplyAction{Kind: ReplyMatch, All: true}, nil
	}

	// Reject an unknown reserved keyword instead of treating it as a term.
	if strings.HasPrefix(token, ActionPrefix) {
		return ReplyAction{}, fmt.Errorf("unknown reply action %q", token)
	}

	r := ReplyAction{Kind: ReplyMatch}

	for _, term := range strings.Split(token, ",") {
		switch {
		case strings.HasPrefix(term, ReplyDimName):
			glob := term[len(ReplyDimName):]
			if err := ValidateGlob(glob); err != nil {
				return ReplyAction{}, err
			}

			r.NameGlobs = append(r.NameGlobs, glob)
		case strings.HasPrefix(term, ReplyDimMAC):
			// Lowercase so the glob matches the lowercase aa:bb form used at match time.
			glob := strings.ToLower(term[len(ReplyDimMAC):])
			if err := ValidateGlob(glob); err != nil {
				return ReplyAction{}, err
			}

			r.MACGlobs = append(r.MACGlobs, glob)
		default:
			return ReplyAction{}, fmt.Errorf("invalid reply term %q (want name=, mac=, *, @default, or @blackhole)", term)
		}
	}

	return r, nil
}

// ValidateGlob errors when glob is empty or not a valid filepath.Match pattern, checked once at parse time.
func ValidateGlob(glob string) error {
	if glob == "" {
		return errors.New("empty glob")
	}

	if _, err := filepath.Match(glob, ""); err != nil {
		return fmt.Errorf("invalid glob %q: %w", glob, err)
	}

	return nil
}
