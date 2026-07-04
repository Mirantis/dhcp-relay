// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package macpolicy_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/macpolicy"
)

const (
	reloadTimeout = 2 * time.Second
	pollInterval  = 10 * time.Millisecond
	testInterval  = 20 * time.Millisecond
)

// writePolicyFile writes content to a fresh temp file and returns its path.
func writePolicyFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.txt")

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	return path
}

// replaceFile atomically swaps the file at path via a rename in the same directory.
func replaceFile(t *testing.T, path, content string) {
	t.Helper()

	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename temp file: %v", err)
	}
}

func mustParseMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()

	hwAddr, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", s, err)
	}

	return hwAddr
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}

	return b
}

func newPolicy(t *testing.T, content string) *macpolicy.Map {
	t.Helper()

	m, err := macpolicy.New(writePolicyFile(t, content), testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = m.Close() })

	return m
}

// newErr returns the error from loading the given policy content.
func newErr(t *testing.T, content string) error {
	t.Helper()

	_, err := macpolicy.New(writePolicyFile(t, content), testInterval, logger.NewWithoutDatetime())

	return err
}

func assertAction(t *testing.T, got macpolicy.Action, kind macpolicy.ActionKind, server string) {
	t.Helper()

	if got.Kind != kind || got.Server != server {
		t.Errorf("got %+v, want {Kind:%d Server:%q}", got, kind, server)
	}
}

// eventually polls cond until it returns true or the timeout elapses.
func eventually(cond func() bool, timeout, interval time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(interval)
	}

	return cond()
}

func TestLookupActions(t *testing.T) {
	const content = `
# policy
02:00:00:00:00:01              # bare MAC means default action
02:00:00:00:00:03  10.0.0.5    # server action
02:00:00:00:00:04  @default    # explicit default keyword
02:00:00:00:00:05  @blackhole  # blackhole action

02:00:00:00:00:07  1.1.1.1     # duplicated below
02:00:00:00:00:07  2.2.2.2     # last entry wins
`

	m := newPolicy(t, content)

	tests := []struct {
		name       string
		mac        string
		wantServer string
		wantKind   macpolicy.ActionKind
	}{
		{"bare is default", "02:00:00:00:00:01", "", macpolicy.ActionDefault},
		{"server override", "02:00:00:00:00:03", "10.0.0.5", macpolicy.ActionServer},
		{"default keyword", "02:00:00:00:00:04", "", macpolicy.ActionDefault},
		{"blackhole keyword", "02:00:00:00:00:05", "", macpolicy.ActionBlackhole},
		{"duplicate last wins", "02:00:00:00:00:07", "2.2.2.2", macpolicy.ActionServer},
		// With no fallback an unmatched client is dropped.
		{"unmatched without catch all", "02:00:00:00:00:09", "", macpolicy.ActionBlackhole},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertAction(t, m.Lookup(mustParseMAC(t, tc.mac)), tc.wantKind, tc.wantServer)
		})
	}
}

func TestCatchAllDefault(t *testing.T) {
	m := newPolicy(t, "02:00:00:00:00:01 @blackhole\n* @default\n")

	// Explicit entry wins over the fallback.
	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:01")), macpolicy.ActionBlackhole, "")
	// Unmatched falls through to the fallback.
	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:09")), macpolicy.ActionDefault, "")
}

func TestCatchAllServer(t *testing.T) {
	m := newPolicy(t, "* 10.9.9.9\n")

	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:09")), macpolicy.ActionServer, "10.9.9.9")
}

func TestCatchAllBlackhole(t *testing.T) {
	m := newPolicy(t, "02:00:00:00:00:01\n* @blackhole\n")

	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:01")), macpolicy.ActionDefault, "")
	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:09")), macpolicy.ActionBlackhole, "")
}

func TestUppercaseFileEntry(t *testing.T) {
	m := newPolicy(t, "AA:BB:CC:DD:EE:FF @default\n")

	assertAction(t, m.Lookup(mustParseMAC(t, "aa:bb:cc:dd:ee:ff")), macpolicy.ActionDefault, "")
}

func TestEmptyFileDropsAll(t *testing.T) {
	m := newPolicy(t, "# only comments\n\n")

	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:01")), macpolicy.ActionBlackhole, "")
}

func TestLookupUnmatched(t *testing.T) {
	m := newPolicy(t, "02:00:00:00:00:01\n")

	// An identifier with no entry (and no fallback) is blackholed. A nil id is skipped.
	assertAction(t, m.Lookup(mustParseMAC(t, "00:11:22:33:44:55:66:77")), macpolicy.ActionBlackhole, "")
	assertAction(t, m.Lookup(nil), macpolicy.ActionBlackhole, "")
}

func TestNewInvalidLineFails(t *testing.T) {
	if newErr(t, "not-a-mac\n") == nil {
		t.Error("New must fail on an invalid MAC")
	}

	if newErr(t, "aa:bb:cc:dd:ee:ff 1.1.1.1 extra\n") == nil {
		t.Error("New must fail on a line with too many fields")
	}
}

func TestNewMissingFileFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.txt")

	if _, err := macpolicy.New(missing, testInterval, logger.NewWithoutDatetime()); err == nil {
		t.Error("New must fail when the file does not exist")
	}
}

func TestNewAcceptsResolvableServer(t *testing.T) {
	// localhost resolves via /etc/hosts so no network is needed. newPolicy closes the watcher before the temp dir is removed.
	newPolicy(t, "02:00:00:00:00:01 localhost\n")
}

func TestNewRejectsUnresolvableServer(t *testing.T) {
	// The .invalid TLD (RFC 6761) never resolves. New fails before starting the poller so there is nothing to close.
	if newErr(t, "02:00:00:00:00:01 nonexistent.invalid\n") == nil {
		t.Error("New must reject a server value that is neither a valid IP nor resolvable")
	}
}

func TestLookupClientID(t *testing.T) {
	// A hex key matches the client's Option 61 identifier.
	m := newPolicy(t, "0x01aabbccddeeff @blackhole\n")

	clientID := mustHex(t, "01aabbccddeeff")
	chaddr := mustParseMAC(t, "aa:bb:cc:dd:ee:ff")

	assertAction(t, m.Lookup(clientID, chaddr), macpolicy.ActionBlackhole, "")
}

func TestLookupChaddrFallback(t *testing.T) {
	// With no Option 61 match the chaddr is tried next.
	m := newPolicy(t, "aa:bb:cc:dd:ee:ff @blackhole\n")

	other := mustHex(t, "deadbeef")
	chaddr := mustParseMAC(t, "aa:bb:cc:dd:ee:ff")

	assertAction(t, m.Lookup(other, chaddr), macpolicy.ActionBlackhole, "")
}

func TestLookupClientIDWinsOverChaddr(t *testing.T) {
	// Option 61 is checked before the chaddr.
	m := newPolicy(t, "0x0a0b0c @blackhole\naa:bb:cc:dd:ee:ff @default\n")

	clientID := mustHex(t, "0a0b0c")
	chaddr := mustParseMAC(t, "aa:bb:cc:dd:ee:ff")

	assertAction(t, m.Lookup(clientID, chaddr), macpolicy.ActionBlackhole, "")
	// Without the Option 61 the chaddr entry applies.
	assertAction(t, m.Lookup(nil, chaddr), macpolicy.ActionDefault, "")
}

func TestNewRejectsBadSyntax(t *testing.T) {
	for _, content := range []string{
		"02:00:00:00:00:01 @bogus\n",         // unknown @ action
		"0xZZ @default\n",                    // invalid hex identifier
		"0x123 @default\n",                   // odd length hex
		"00:11:22:33:44:55:66:77 @default\n", // EUI-64 is not a 6 byte MAC
		// Hex id too long for the Option 82 policy tag.
		"0x" + strings.Repeat("aa", dhcp.MaxPolicyTagSize+1) + " @default\n",
	} {
		if newErr(t, content) == nil {
			t.Errorf("New must fail on %q", content)
		}
	}
}

// TestParseIdentifierLengthCap bounds a hex key by the Option 82 policy tag limit.
func TestParseIdentifierLengthCap(t *testing.T) {
	maxKey := "0x" + strings.Repeat("aa", dhcp.MaxPolicyTagSize)

	id, err := macpolicy.ParseIdentifier(maxKey)
	if err != nil || len(id) != dhcp.MaxPolicyTagSize {
		t.Errorf("ParseIdentifier(%d bytes) = (%d bytes, %v), want the full id and nil",
			dhcp.MaxPolicyTagSize, len(id), err)
	}

	if _, err := macpolicy.ParseIdentifier(maxKey + "aa"); err == nil {
		t.Errorf("ParseIdentifier must reject a %d byte identifier", dhcp.MaxPolicyTagSize+1)
	}
}

// hasWarning reports whether any warning contains substr.
func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}

	return false
}

// TestParseDuplicateWarnings asserts Parse reports duplicate keys and keeps the last entry for both the catch all and a plain identifier.
func TestParseDuplicateWarnings(t *testing.T) {
	table, warnings, err := macpolicy.Parse(strings.NewReader("* @default\n* @blackhole\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// A blackhole catch all with no entries also warns 'no relayable entries', so match the duplicate warning
	// among the warnings rather than assuming it is the only one.
	if !hasWarning(warnings, "duplicate") {
		t.Errorf("warnings = %q, want a duplicate catch all warning", warnings)
	}

	// The last catch all wins as the fallback.
	assertAction(t, table.Lookup(mustParseMAC(t, "02:00:00:00:00:09")), macpolicy.ActionBlackhole, "")

	_, warnings, err = macpolicy.Parse(strings.NewReader("02:00:00:00:00:08 1.1.1.1\n02:00:00:00:00:08 2.2.2.2\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(warnings) != 1 || !strings.Contains(warnings[0], "duplicate identifier") {
		t.Errorf("warnings = %q, want one duplicate identifier warning", warnings)
	}
}

// TestValidateServerNilSeen covers the exported helper with a nil seen set.
func TestValidateServerNilSeen(t *testing.T) {
	// A literal IP validates without DNS and must not panic on the nil map write.
	err := macpolicy.ValidateServer(macpolicy.Action{Kind: macpolicy.ActionServer, Server: "192.0.2.1"}, nil)
	if err != nil {
		t.Errorf("ValidateServer(literal IP, nil) = %v, want nil", err)
	}

	if err := macpolicy.ValidateServer(macpolicy.Action{Kind: macpolicy.ActionDefault}, nil); err != nil {
		t.Errorf("ValidateServer(non server, nil) = %v, want nil", err)
	}
}

// TestValidateServerContextCanceled checks the caller context reaches the resolver so Close can abort a validation stuck on a slow lookup.
func TestValidateServerContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	a := macpolicy.Action{Kind: macpolicy.ActionServer, Server: "unresolvable.invalid"}
	if err := macpolicy.ValidateServerContext(ctx, a, nil); err == nil {
		t.Fatal("a canceled context must fail host name validation")
	}
}

func TestLookupID(t *testing.T) {
	m := newPolicy(t, "0x0a0b0c @blackhole\naa:bb:cc:dd:ee:ff @default\n")

	clientID := mustHex(t, "0a0b0c")
	chaddr := mustParseMAC(t, "aa:bb:cc:dd:ee:ff")

	// An Option 61 match returns the clientID bytes as the matched key.
	if a, key := m.LookupID(clientID, chaddr); a.Kind != macpolicy.ActionBlackhole || !bytes.Equal(key, clientID) {
		t.Errorf("LookupID by clientID = (%d, % x), want (blackhole, % x)", a.Kind, key, clientID)
	}

	// A chaddr match returns the chaddr bytes as the matched key.
	if a, key := m.LookupID(nil, chaddr); a.Kind != macpolicy.ActionDefault || !bytes.Equal(key, chaddr) {
		t.Errorf("LookupID by chaddr = (%d, % x), want (default, % x)", a.Kind, key, chaddr)
	}

	// No match returns the fallback and a nil key.
	if a, key := m.LookupID(mustParseMAC(t, "02:00:00:00:00:09")); a.Kind != macpolicy.ActionBlackhole || key != nil {
		t.Errorf("LookupID unmatched = (%d, % x), want (blackhole, nil)", a.Kind, key)
	}
}
