// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package glob_test

import (
	"testing"

	"code.local/dhcp-relay/pkg/glob"
)

func TestValidate(t *testing.T) {
	for _, p := range []string{"eth0", "eth*", "eth?", "br-lan*", "aa:bb:*", "[ab]c", "*"} {
		if err := glob.Validate(p); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", p, err)
		}
	}

	// The empty glob and any malformed class must be rejected, including one hidden past a star that a probe
	// against the empty string alone would miss.
	for _, p := range []string{"", "[", "[a-", "eth*[a", "aa:*[b"} {
		if err := glob.Validate(p); err == nil {
			t.Errorf("Validate(%q) = nil, want error", p)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		s       string
		want    bool
	}{
		{"eth*", "eth0", true},
		{"eth*", "br0", false},
		{"*", "anything", true},
		{"eth?", "eth0", true},
		{"eth?", "eth10", false},
		// A malformed pattern is a non match rather than a panic.
		{"eth*[a", "eth0", false},
	}

	for _, c := range cases {
		if got := glob.Match(c.pattern, c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}
