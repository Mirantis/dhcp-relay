package main

import (
	_ "expvar"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // profiling is enabled via CLI flag
	"time"
)

/*
	Available server endpoints:
		- /debug/pprof
		- /debug/pprof/cmdline
		- /debug/pprof/profile
		- /debug/pprof/symbol
		- /debug/pprof/trace
		- /debug/vars
*/

const defaultServerReadHeaderTimeout = 5 * time.Second

func debug(addr string) {
	if addr == "" {
		return
	}

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
