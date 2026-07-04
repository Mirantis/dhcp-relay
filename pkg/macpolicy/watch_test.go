// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy_test

import (
	"os"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/macpolicy"
)

const settleDelay = 200 * time.Millisecond

func TestReloadChangesAction(t *testing.T) {
	other := mustParseMAC(t, "02:00:00:00:00:09")

	path := writePolicyFile(t, "02:00:00:00:00:01\n")

	m, err := macpolicy.New(path, testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// No fallback yet so an unlisted client is blackholed.
	assertAction(t, m.Lookup(other), macpolicy.ActionBlackhole, "")

	// Add a permissive fallback and wait for the poller to reload.
	replaceFile(t, path, "02:00:00:00:00:01\n* @default\n")

	reloaded := eventually(func() bool {
		return m.Lookup(other).Kind == macpolicy.ActionDefault
	}, reloadTimeout, pollInterval)

	if !reloaded {
		t.Fatal("poll reload did not apply the '*' fallback")
	}

	// The explicit entry must survive the rebuild.
	assertAction(t, m.Lookup(mustParseMAC(t, "02:00:00:00:00:01")), macpolicy.ActionDefault, "")
}

func TestReloadErrorKeepsPrevious(t *testing.T) {
	macA := mustParseMAC(t, "02:00:00:00:00:01")
	macB := mustParseMAC(t, "02:00:00:00:00:02")

	path := writePolicyFile(t, "02:00:00:00:00:01\n")

	m, err := macpolicy.New(path, testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// First a valid reload so we know the watcher is live. macB gains a server.
	replaceFile(t, path, "02:00:00:00:00:01\n02:00:00:00:00:02 10.0.0.7\n")

	live := eventually(func() bool {
		a := m.Lookup(macB)

		return a.Kind == macpolicy.ActionServer && a.Server == "10.0.0.7"
	}, reloadTimeout, pollInterval)

	if !live {
		t.Fatal("watcher never applied the first (valid) reload")
	}

	// Now an invalid file. The reload must fail and the previous snapshot stays.
	replaceFile(t, path, "this is not valid\n")

	time.Sleep(settleDelay)

	assertAction(t, m.Lookup(macA), macpolicy.ActionDefault, "")
	assertAction(t, m.Lookup(macB), macpolicy.ActionServer, "10.0.0.7")
}

// TestDeleteDuringWatchKeepsPrevious removes the watched file and expects the stat failure to keep the previous policy.
func TestDeleteDuringWatchKeepsPrevious(t *testing.T) {
	mac := mustParseMAC(t, "02:00:00:00:00:01")

	path := writePolicyFile(t, "02:00:00:00:00:01 @blackhole\n")

	m, err := macpolicy.New(path, testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove policy: %v", err)
	}

	// Give the poller ticks with the file missing. The previous snapshot must survive.
	time.Sleep(settleDelay)
	assertAction(t, m.Lookup(mac), macpolicy.ActionBlackhole, "")

	// A recreated file is a new inode so the next poll picks it up.
	replaceFile(t, path, "02:00:00:00:00:01 @default\n")

	recovered := eventually(func() bool {
		return m.Lookup(mac).Kind == macpolicy.ActionDefault
	}, reloadTimeout, pollInterval)

	if !recovered {
		t.Fatal("watcher never recovered after the file reappeared")
	}
}
