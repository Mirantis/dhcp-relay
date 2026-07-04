// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package debug_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/goleak"

	"code.local/dhcp-relay/pkg/debug"
	"code.local/dhcp-relay/pkg/logger"
)

const (
	readyAttempts = 50
	readyDelay    = 10 * time.Millisecond
)

// TestMain runs the package tests under goleak so the Serve goroutine is reported as a leak unless Shutdown stops it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// newTestClient returns a client without keep alives so no idle connection goroutine lingers for goleak.
func newTestClient(t *testing.T) *http.Client {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)

	return client
}

// waitReachable polls the metrics endpoint until the server accepts and returns the status code or 0 when attempts run out.
func waitReachable(t *testing.T, client *http.Client, addr string) int {
	t.Helper()

	url := "http://" + addr + "/debug/metrics"

	for range readyAttempts {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(readyDelay)

			continue
		}

		status := resp.StatusCode

		_ = resp.Body.Close()

		return status
	}

	return 0
}

// TestServeStartsAndStops binds the debug server then checks an endpoint and shuts it down so goleak confirms the Serve goroutine exited.
func TestServeStartsAndStops(t *testing.T) {
	srv := debug.Serve("127.0.0.1:0", logger.NewWithoutDatetime())
	if srv == nil {
		t.Fatal("Serve returned nil")
	}

	status := waitReachable(t, newTestClient(t), srv.Addr)
	if status == 0 {
		t.Fatalf("debug server never became reachable at %s", srv.Addr)
	}

	if status != http.StatusOK {
		t.Errorf("GET /debug/metrics = %d, want %d", status, http.StatusOK)
	}

	ctx, cancel := context.WithTimeout(t.Context(), debug.ServerShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestServeEmptyAddrReturnsNil keeps the debug server disabled without an address.
func TestServeEmptyAddrReturnsNil(t *testing.T) {
	if srv := debug.Serve("", logger.NewWithoutDatetime()); srv != nil {
		t.Errorf("Serve with an empty addr = %v, want nil", srv)
	}
}

// TestServeBindFailureReturnsNil returns nil when the address is already bound. No goroutine starts so goleak stays clean.
func TestServeBindFailureReturnsNil(t *testing.T) {
	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if srv := debug.Serve(ln.Addr().String(), logger.NewWithoutDatetime()); srv != nil {
		t.Errorf("Serve(%s) = %v, want nil on a bound address", ln.Addr(), srv)
	}
}

// TestShutdownNilServer accepts the nil a disabled or failed Serve returns.
func TestShutdownNilServer(t *testing.T) {
	debug.Shutdown(nil, logger.NewWithoutDatetime())
}

// TestShutdownStopsServer covers the package level Shutdown helper end to end via goleak.
func TestShutdownStopsServer(t *testing.T) {
	cl := logger.NewWithoutDatetime()

	srv := debug.Serve("127.0.0.1:0", cl)
	if srv == nil {
		t.Fatal("Serve returned nil")
	}

	if waitReachable(t, newTestClient(t), srv.Addr) == 0 {
		t.Fatalf("debug server never became reachable at %s", srv.Addr)
	}

	debug.Shutdown(srv, cl)
}
