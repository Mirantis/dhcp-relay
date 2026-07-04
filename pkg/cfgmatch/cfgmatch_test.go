// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package cfgmatch_test

import (
	"strings"
	"testing"

	"code.local/dhcp-relay/pkg/cfgmatch"
)

func TestParseSelector(t *testing.T) {
	all, err := cfgmatch.ParseSelector("*")
	if err != nil || !all.All {
		t.Fatalf(`ParseSelector("*") = %+v, %v; want All=true`, all, err)
	}

	sel, err := cfgmatch.ParseSelector("name=eth0,mac=AA:BB:*")
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}

	if len(sel.NameGlobs) != 1 || sel.NameGlobs[0] != "eth0" {
		t.Errorf("NameGlobs = %v, want [eth0]", sel.NameGlobs)
	}

	// mac globs are lowercased at parse so they match the lowercase NIC MAC form.
	if len(sel.MACGlobs) != 1 || sel.MACGlobs[0] != "aa:bb:*" {
		t.Errorf("MACGlobs = %v, want [aa:bb:*]", sel.MACGlobs)
	}

	// Name globs stay case sensitive and repeated same-dimension terms accumulate rather than overwrite.
	multi, err := cfgmatch.ParseSelector("name=Eth0,name=br*")
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}

	if len(multi.NameGlobs) != 2 || multi.NameGlobs[0] != "Eth0" || multi.NameGlobs[1] != "br*" {
		t.Errorf("NameGlobs = %v, want [Eth0 br*]", multi.NameGlobs)
	}

	// Unknown term prefix and malformed globs (including a bad class hidden past a star) must error at parse.
	for _, bad := range []string{"bogus", "name=", "name=eth*[a", "mac=aa:*[b"} {
		if _, err := cfgmatch.ParseSelector(bad); err == nil {
			t.Errorf("ParseSelector(%q) = nil error, want error", bad)
		}
	}
}

func TestSelectorMatch(t *testing.T) {
	cases := []struct {
		name string
		nic  string
		mac  string
		sel  cfgmatch.Selector
		want bool
	}{
		{"all", "anything", "aa:bb:cc:dd:ee:ff", cfgmatch.Selector{All: true}, true},
		{"name glob hit", "eth0", "x", cfgmatch.Selector{NameGlobs: []string{"eth*"}}, true},
		{"name glob miss", "br0", "x", cfgmatch.Selector{NameGlobs: []string{"eth*"}}, false},
		{"mac case insensitive", "x", "AA:BB:CC:DD:EE:FF", cfgmatch.Selector{MACGlobs: []string{"aa:bb:*"}}, true},
		{"empty selector matches nothing", "eth0", "aa:bb:cc:dd:ee:ff", cfgmatch.Selector{}, false},
		{"malformed name glob is a non match", "eth0", "x", cfgmatch.Selector{NameGlobs: []string{"eth*[a"}}, false},
		{"malformed mac glob is a non match", "x", "aa:bb:cc:dd:ee:ff", cfgmatch.Selector{MACGlobs: []string{"aa:*[b"}}, false},
		{"mac hit after name miss", "br0", "aa:bb", cfgmatch.Selector{NameGlobs: []string{"eth*"}, MACGlobs: []string{"aa:*"}}, true},
	}

	for _, c := range cases {
		if got := c.sel.Match(c.nic, c.mac); got != c.want {
			t.Errorf("%s: Match(%q, %q) = %v, want %v", c.name, c.nic, c.mac, got, c.want)
		}
	}
}

func TestFields(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"name=eth0 192.168.50.0/24", "name=eth0,192.168.50.0/24"},
		{"name=eth0 192.168.50.0/24 # trailing comment", "name=eth0,192.168.50.0/24"},
		{"# whole line comment", ""},
		{"   ", ""},
		{"a b#c d", "a,b#c,d"}, // a # inside a field stays literal, only a #-prefixed field starts a comment
	}

	for _, c := range cases {
		if got := strings.Join(cfgmatch.Fields(c.in), ","); got != c.want {
			t.Errorf("Fields(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
