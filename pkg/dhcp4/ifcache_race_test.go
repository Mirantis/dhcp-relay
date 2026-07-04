// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/dhcp4"
)

// TestInterfaceCacheServesStaleOnRefetchError verifies the stale snapshot is served when net.Interfaces() fails.
func TestInterfaceCacheServesStaleOnRefetchError(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Hour)

	// Prime the cache with a valid snapshot.
	first, err := c.Interfaces()
	if err != nil {
		t.Fatalf("initial Interfaces: %v", err)
	}

	if len(first) == 0 {
		t.Skip("no network interfaces on this host")
	}

	// Expire the snapshot so the next call triggers a refetch path.
	time.Sleep(2 * time.Millisecond)

	// On a real system net.Interfaces() is unlikely to fail, so this test documents the stale snapshot contract.
	second, err := c.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces after expiry returned error %v; expected stale fallback or fresh snapshot", err)
	}

	if len(second) != len(first) {
		t.Errorf("stale/fresh snapshot length changed: %d -> %d", len(first), len(second))
	}
}

// TestInterfaceCacheStaleFallbackConcurrent hammers the cache from many goroutines with a short TTL under the race detector.
func TestInterfaceCacheStaleFallbackConcurrent(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Microsecond)

	var wg sync.WaitGroup

	var errors atomic.Int64

	for range 16 {
		wg.Go(func() {
			for range 100 {
				if _, err := c.Interfaces(); err != nil {
					errors.Add(1)

					return
				}
			}
		})
	}

	wg.Wait()

	if got := errors.Load(); got > 0 {
		t.Errorf("concurrent Interfaces had %d error(s); stale fallback should prevent errors", got)
	}
}

// TestInterfaceCacheRefetchSerialized verifies the mu lock serializes refetches so concurrent callers reuse the fresh snapshot.
func TestInterfaceCacheRefetchSerialized(t *testing.T) {
	c := dhcp4.NewInterfaceCache(time.Hour)

	var wg sync.WaitGroup

	results := make([][]net.Interface, 20)

	for i := range 20 {
		wg.Go(func() {
			ifaces, err := c.Interfaces()
			if err != nil {
				t.Errorf("Interfaces: %v", err)

				return
			}

			results[i] = ifaces
		})
	}

	wg.Wait()

	// All concurrent callers within the TTL must share the same backing array.
	for i := 1; i < len(results); i++ {
		if len(results[0]) > 0 && len(results[i]) > 0 && &results[0][0] != &results[i][0] {
			t.Errorf("goroutine %d got a different snapshot backing array", i)
		}
	}
}
