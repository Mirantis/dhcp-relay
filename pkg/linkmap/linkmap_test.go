// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package linkmap_test

import (
	"strings"
	"testing"

	"code.local/dhcp-relay/pkg/linkmap"
)

func TestParseAndLookup(t *testing.T) {
	const content = `
# ingress NIC selector -> client subnet
name=eth0        192.168.50.0/24
name=br-lan*     10.10.0.0/24
mac=02:00:00:*   172.16.0.0/24
*                192.168.0.0/24   # fallback
`

	tbl, _, err := linkmap.Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := []struct {
		name string
		mac  string
		want string
	}{
		{"eth0", "aa:bb:cc:dd:ee:ff", "192.168.50.0"},    // exact name
		{"br-lan5", "aa:bb:cc:dd:ee:ff", "10.10.0.0"},    // name glob
		{"eth9", "02:00:00:11:22:33", "172.16.0.0"},      // mac glob, before the fallback
		{"whatever", "ff:ff:ff:ff:ff:ff", "192.168.0.0"}, // catch-all
	}

	for _, c := range cases {
		got, ok := tbl.Lookup(c.name, c.mac)
		if !ok {
			t.Errorf("Lookup(%q, %q) = _, false; want %s", c.name, c.mac, c.want)

			continue
		}

		if got.String() != c.want {
			t.Errorf("Lookup(%q, %q) = %s; want %s", c.name, c.mac, got, c.want)
		}
	}
}

func TestLookupNoMatch(t *testing.T) {
	tbl, _, err := linkmap.Parse(strings.NewReader("name=eth0 192.168.50.0/24\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, ok := tbl.Lookup("eth1", "aa:bb:cc:dd:ee:ff"); ok {
		t.Error("Lookup(eth1) matched, want no match without a catch-all")
	}
}

func TestParseErrors(t *testing.T) {
	for _, content := range []string{
		"name=eth0\n",                       // missing subnet
		"name=eth0 192.168.50.0/24 extra\n", // too many fields
		"name=eth0 notacidr\n",              // not a CIDR
		"name=eth0 ::1/128\n",               // not IPv4
		"bogus=eth0 192.168.50.0/24\n",      // unknown selector term
		"name=eth*[a 192.168.50.0/24\n",     // malformed glob
	} {
		if _, _, err := linkmap.Parse(strings.NewReader(content)); err == nil {
			t.Errorf("Parse(%q) = nil error, want error", content)
		}
	}
}
