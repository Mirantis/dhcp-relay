// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy_test

import (
	"sync"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/macpolicy"
)

// TestConcurrentLookupVsReload hammers the atomic pointer swap with concurrent readers and a single writer.
func TestConcurrentLookupVsReload(t *testing.T) {
	mac := mustParseMAC(t, "02:00:00:00:00:01")

	path := writePolicyFile(t, "02:00:00:00:00:01 @default\n")

	m, err := macpolicy.New(path, testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	var wg sync.WaitGroup

	stop := make(chan struct{})

	// Readers continuously Lookup while the poller swaps snapshots.
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}

				a := m.Lookup(mac)
				if a.Kind != macpolicy.ActionDefault && a.Kind != macpolicy.ActionBlackhole {
					t.Errorf("Lookup returned unexpected kind %d", a.Kind)
					return
				}
			}
		})
	}

	// Single writer alternates file content so Reload swaps fresh Tables. Only one goroutine touches the file.
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}

			replaceFile(t, path, "02:00:00:00:00:01 @blackhole\n")
			time.Sleep(testInterval * 2)
			replaceFile(t, path, "02:00:00:00:00:01 @default\n")
			time.Sleep(testInterval * 2)
		}
	})

	// Let the poller settle.
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestConcurrentValidateContext tests ValidateContext is safe to call from multiple goroutines since the seen map is per call not shared.
func TestConcurrentValidateContext(t *testing.T) {
	const content = "02:00:00:00:00:01 127.0.0.1\n02:00:00:00:00:02 127.0.0.1\n* @default\n"

	path := writePolicyFile(t, content)

	m, err := macpolicy.New(path, testInterval, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	var wg sync.WaitGroup

	for range 16 {
		wg.Go(func() {
			for range 10 {
				if err := m.Reload(); err != nil {
					t.Errorf("concurrent Reload: %v", err)
					return
				}
			}
		})
	}

	wg.Wait()
}
