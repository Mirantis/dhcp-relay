// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/dhcp4"
)

const cacheExpiryWait = 5 * time.Millisecond

// sameBacking reports whether two enumerations share one backing array meaning the cached snapshot was reused.
func sameBacking(t *testing.T, a, b []net.Interface) bool {
	t.Helper()

	if len(a) == 0 || len(b) == 0 {
		t.Skip("no network interfaces to compare")
	}

	return &a[0] == &b[0]
}

// SameInterfaces reports whether two enumerations describe the same interfaces regardless of backing array.
func SameInterfaces(t *testing.T, a, b []net.Interface) bool {
	t.Helper()

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].Index != b[i].Index {
			return false
		}
	}

	return true
}

// TestInterfaceCacheReusesSnapshot checks a second call within the TTL returns equivalent data instead of enumerating again.
func TestInterfaceCacheReusesSnapshot(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Hour)

	a, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	b, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	if !SameInterfaces(t, a, b) {
		t.Error("a call within the TTL must return the cached snapshot")
	}
	if sameBacking(t, a, b) {
		t.Error("a call within the TTL must return a defensive copy")
	}
}

// TestInterfaceCacheDisabled checks a non positive TTL enumerates on every call.
func TestInterfaceCacheDisabled(t *testing.T) {
	c := dhcp4.NewInterfaceCache(0)

	a, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	b, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	if sameBacking(t, a, b) {
		t.Error("a non positive TTL must enumerate on every call")
	}
}

// TestInterfaceCacheExpiry checks an expired snapshot is refetched.
func TestInterfaceCacheExpiry(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Millisecond)

	a, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	time.Sleep(cacheExpiryWait)

	b, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}

	if !SameInterfaces(t, a, b) {
		t.Error("an expired snapshot must be refetched with equivalent data")
	}
	if sameBacking(t, a, b) {
		t.Error("an expired snapshot must return a different backing array")
	}
}

// TestInterfaceCacheConcurrent hammers one cache from many goroutines so the race detector can observe the snapshot swap.
func TestInterfaceCacheConcurrent(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Millisecond)

	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			for range 50 {
				if _, err := c.Interfaces(); err != nil {
					t.Errorf("Interfaces: %v", err)

					return
				}
			}
		})
	}

	wg.Wait()
}
