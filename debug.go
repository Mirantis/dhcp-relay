// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package main

import (
	"fmt"
	"net/http"
	"runtime/metrics"
	"time"

	_ "expvar"
	_ "net/http/pprof" //nolint:gosec // G108: profiling is opt-in via CLI flag.
)

/*
	Available server endpoints:

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

const defaultServerReadHeaderTimeout = 5 * time.Second

func debug(addr string) {
	if addr == "" {
		return
	}

	http.HandleFunc("/debug/metrics", runtimeMetricsHandler)

	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: defaultServerReadHeaderTimeout,
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			cl.Errorf("Failed to start `/debug` web server: %s", err)
		}
	}()
}

func runtimeMetricsHandler(w http.ResponseWriter, _ *http.Request) {
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
		}
	}
}
