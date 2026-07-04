// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy_test

import (
	"strings"
	"testing"

	"code.local/dhcp-relay/pkg/macpolicy"
)

// replyOf returns the reply action parsed from a line whose reply field is replyField.
func replyOf(t *testing.T, replyField string) macpolicy.ReplyAction {
	t.Helper()

	table, _, err := macpolicy.Parse(strings.NewReader("02:00:00:00:00:01 @default " + replyField + "\n"))
	if err != nil {
		t.Fatalf("Parse with reply %q: %v", replyField, err)
	}

	return table.Lookup(mustParseMAC(t, "02:00:00:00:00:01")).Reply
}

func TestReplyActionKind(t *testing.T) {
	tests := []struct {
		field string
		want  macpolicy.ReplyActionKind
	}{
		{"", macpolicy.ReplyIngress},
		{"@default", macpolicy.ReplyIngress},
		{"@blackhole", macpolicy.ReplyBlackhole},
		{"*", macpolicy.ReplyMatch},
		{"name=eth*", macpolicy.ReplyMatch},
		{"mac=02:00:*", macpolicy.ReplyMatch},
	}

	for _, tc := range tests {
		if got := replyOf(t, tc.field).Kind; got != tc.want {
			t.Errorf("reply %q kind = %d, want %d", tc.field, got, tc.want)
		}
	}
}

func TestReplyActionMatch(t *testing.T) {
	tests := []struct {
		field string
		name  string
		mac   string
		want  bool
	}{
		{"*", "anything", "aa:bb:cc:dd:ee:ff", true},
		{"name=eth*", "eth0", "aa:bb:cc:dd:ee:ff", true},
		{"name=eth*", "br0", "aa:bb:cc:dd:ee:ff", false},
		{"mac=02:00:*", "x", "02:00:00:00:00:01", true},
		{"mac=02:00:*", "x", "aa:bb:cc:dd:ee:ff", false},
		// An uppercase glob matches the lowercase NIC MAC form.
		{"mac=AA:BB:*", "x", "aa:bb:cc:dd:ee:ff", true},
		{"name=eth0,mac=02:*", "br0", "02:00:00:00:00:09", true},
		{"name=eth0,mac=02:*", "br0", "aa:bb:cc:dd:ee:ff", false},
	}

	for _, tc := range tests {
		if got := replyOf(t, tc.field).Match(tc.name, tc.mac); got != tc.want {
			t.Errorf("reply %q Match(%q, %q) = %v, want %v", tc.field, tc.name, tc.mac, got, tc.want)
		}
	}
}

func TestReplyActionErrors(t *testing.T) {
	for _, field := range []string{"@bogus", "name=", "name=[", "eth0", "foo=bar"} {
		if _, _, err := macpolicy.Parse(strings.NewReader("02:00:00:00:00:01 @default " + field + "\n")); err == nil {
			t.Errorf("Parse with reply %q must fail", field)
		}
	}
}

func TestParseInlineComments(t *testing.T) {
	const content = `
aa:bb:cc:dd:ee:ff @default name=eth* # trailing comment is stripped
11:22:33:44:55:66 @default name=br#0 # literal '#' stays inside the glob
`

	table, _, err := macpolicy.Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// The trailing comment is dropped so the reply glob is exactly eth*.
	if r := table.Lookup(mustParseMAC(t, "aa:bb:cc:dd:ee:ff")).Reply; !r.Match("eth0", "x") {
		t.Errorf("name=eth* should match eth0, got %+v", r)
	}

	// The '#' inside the glob is preserved so it matches br#0 and not br.
	r := table.Lookup(mustParseMAC(t, "11:22:33:44:55:66")).Reply
	if !r.Match("br#0", "x") {
		t.Error("name=br#0 should match br#0")
	}

	if r.Match("br", "x") {
		t.Error("name=br#0 must not match br")
	}
}
