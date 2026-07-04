// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package debug

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/metrics"
	"sync"
	"time"

	_ "expvar"
	_ "net/http/pprof" //nolint:gosec // G108: profiling is opt-in via CLI flag.

	"code.local/dhcp-relay/pkg/logger"
)

/*
	Available server endpoints.

	Profiling and tracing (auto-registered by net/http/pprof):
		- /debug/pprof/                  (index listing all sub-profiles, with descriptions)
		- /debug/pprof/cmdline
		- /debug/pprof/profile           (CPU profile, ?seconds=N)
		- /debug/pprof/symbol
		- /debug/pprof/trace             (execution trace, ?seconds=N)
		- /debug/pprof/heap              (delta with ?seconds=N)
		- /debug/pprof/allocs            (delta with ?seconds=N)
		- /debug/pprof/goroutine         (delta with ?seconds=N; debug=2 dumps full stacks)
		- /debug/pprof/block             (requires runtime.SetBlockProfileRate)
		- /debug/pprof/mutex             (requires runtime.SetMutexProfileFraction)
		- /debug/pprof/threadcreate
		- /debug/pprof/goroutineleak     (only when built with GOEXPERIMENT=goroutineleakprofile)

	Variables and metrics:
		- /debug/vars                    (expvar — published variables in JSON)
		- /debug/metrics                 (runtime/metrics — all supported metrics in plain text)
*/

const ServerReadHeaderTimeout = 5 * time.Second

// ServerShutdownTimeout bounds the graceful Shutdown of the debug server.
const ServerShutdownTimeout = 5 * time.Second

// registerMetrics guards the one time route registration so Serve is safe to call more than once.
var registerMetrics sync.Once

// Serve binds addr and serves the debug HTTP server in a background goroutine, returning the server or nil.
func Serve(addr string, cl *logger.Config) *http.Server {
	if addr == "" {
		return nil
	}

	registerMetrics.Do(func() {
		http.HandleFunc("/debug/metrics", RuntimeMetricsHandler)
	})

	var lc net.ListenConfig

	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		cl.Errorf("Failed to start `/debug` web server: %s", err)

		return nil
	}

	server := &http.Server{
		Addr:              ln.Addr().String(),
		ReadHeaderTimeout: ServerReadHeaderTimeout,
	}

	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cl.Errorf("`/debug` web server stopped: %s", err)
		}
	}()

	return server
}

// Shutdown gracefully stops a server returned by Serve within ServerShutdownTimeout. A nil server does nothing.
func Shutdown(server *http.Server, cl *logger.Config) {
	if server == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		cl.Warnf("Error shutting down `/debug` web server: %s", err)
	}
}

func RuntimeMetricsHandler(w http.ResponseWriter, _ *http.Request) {
	descs := metrics.All()

	samples := make([]metrics.Sample, len(descs))
	for i, d := range descs {
		samples[i].Name = d.Name
	}

	metrics.Read(samples)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	for i, s := range samples {
		switch s.Value.Kind() {
		case metrics.KindUint64:
			fmt.Fprintf(w, "%s %d\n", s.Name, s.Value.Uint64())
		case metrics.KindFloat64:
			fmt.Fprintf(w, "%s %f\n", s.Name, s.Value.Float64())
		case metrics.KindFloat64Histogram:
			h := s.Value.Float64Histogram()
			fmt.Fprintf(w, "%s histogram buckets=%d\n", s.Name, len(h.Buckets))
		case metrics.KindBad:
			fmt.Fprintf(w, "%s unsupported (%s)\n", s.Name, descs[i].Description)
		default:
			fmt.Fprintf(w, "%s unsupported (unknown kind %d)\n", s.Name, s.Value.Kind())
		}
	}
}
