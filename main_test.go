// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package main

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitForHandlersCompletes drains a burst of quick handlers within the grace period.
func TestWaitForHandlersCompletes(t *testing.T) {
	var wg sync.WaitGroup

	var inFlight atomic.Int64

	const n = 50

	for range n {
		wg.Go(func() {
			inFlight.Add(1)
			defer inFlight.Add(-1)

			time.Sleep(5 * time.Millisecond)
		})
	}

	forceQuit := make(chan os.Signal, 1)

	if got := waitForHandlers(&wg, forceQuit, shutdownGracePeriod); got != drainCompleted {
		t.Errorf("waitForHandlers = %v, want drainCompleted", got)
	}

	if got := inFlight.Load(); got != 0 {
		t.Errorf("inFlight = %d after drain, want 0", got)
	}
}

// TestWaitForHandlersGracePeriodExpiry returns drainTimedOut when a handler outlives the grace period.
func TestWaitForHandlersGracePeriodExpiry(t *testing.T) {
	var wg sync.WaitGroup

	handlerDone := make(chan struct{})

	wg.Go(func() { <-handlerDone })

	forceQuit := make(chan os.Signal, 1)

	if got := waitForHandlers(&wg, forceQuit, 20*time.Millisecond); got != drainTimedOut {
		t.Errorf("waitForHandlers = %v, want drainTimedOut", got)
	}

	// Release the handler so the test goroutine does not leak.
	close(handlerDone)
	wg.Wait()
}

// TestWaitForHandlersForced returns drainForced when a second signal arrives before the handlers drain.
func TestWaitForHandlersForced(t *testing.T) {
	var wg sync.WaitGroup

	handlerDone := make(chan struct{})

	wg.Go(func() { <-handlerDone })

	forceQuit := make(chan os.Signal, 1)
	forceQuit <- os.Interrupt

	if got := waitForHandlers(&wg, forceQuit, time.Hour); got != drainForced {
		t.Errorf("waitForHandlers = %v, want drainForced", got)
	}

	// Release the handler so the test goroutine does not leak.
	close(handlerDone)
	wg.Wait()
}
