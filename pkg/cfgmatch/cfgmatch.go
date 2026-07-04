// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

// Package cfgmatch holds the NIC glob selector and config-line tokenizer shared by the relay's file-backed
// config maps (the MAC policy reply field and the link map), so both parse and match a NIC the same way.
package cfgmatch

import (
	"fmt"
	"strings"

	"code.local/dhcp-relay/pkg/glob"
)

// File syntax tokens shared by callers that build or validate these files.
const (
	CommentPrefix = "#"
	CatchAllKey   = "*"
	NameDim       = "name="
	MACDim        = "mac="
)

// Selector matches a NIC by name or MAC globs, or every NIC when All is set.
type Selector struct {
	NameGlobs []string
	MACGlobs  []string
	All       bool
}

// Match reports whether the NIC with this name and MAC satisfies the selector.
func (s Selector) Match(name, mac string) bool {
	if s.All {
		return true
	}

	mac = strings.ToLower(mac)

	// A malformed glob cannot match. ParseSelector rejects these at load so a match error is a non match.
	for _, g := range s.NameGlobs {
		if glob.Match(g, name) {
			return true
		}
	}

	for _, g := range s.MACGlobs {
		if glob.Match(g, mac) {
			return true
		}
	}

	return false
}

// ParseSelector parses "*" or comma separated name= and mac= glob terms into a Selector.
func ParseSelector(token string) (Selector, error) {
	if token == CatchAllKey {
		return Selector{All: true}, nil
	}

	var s Selector

	for _, term := range strings.Split(token, ",") {
		switch {
		case strings.HasPrefix(term, NameDim):
			g := term[len(NameDim):]
			if err := glob.Validate(g); err != nil {
				return Selector{}, err
			}

			s.NameGlobs = append(s.NameGlobs, g)
		case strings.HasPrefix(term, MACDim):
			// Lowercase so the glob matches the lowercase aa:bb form used at match time.
			g := strings.ToLower(term[len(MACDim):])
			if err := glob.Validate(g); err != nil {
				return Selector{}, err
			}

			s.MACGlobs = append(s.MACGlobs, g)
		default:
			return Selector{}, fmt.Errorf("invalid selector term %q (want name=, mac=, or *)", term)
		}
	}

	return s, nil
}

// Fields splits a config line into whitespace fields, dropping a trailing comment that starts at a "#" token.
func Fields(line string) []string {
	fields := strings.Fields(line)

	for i, f := range fields {
		if strings.HasPrefix(f, CommentPrefix) {
			return fields[:i]
		}
	}

	return fields
}
