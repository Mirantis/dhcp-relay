// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"net"
	"testing"
	"time"

	"code.local/dhcp-relay/pkg/dhcp4"
)

// BenchmarkInterfaceCacheDisabled measures the cost of enumerating NICs on every call with no caching.
func BenchmarkInterfaceCacheDisabled(b *testing.B) {
	c := dhcp4.NewInterfaceCache(0)

	b.ResetTimer()

	for range b.N {
		if _, err := c.Interfaces(); err != nil {
			b.Fatalf("Interfaces: %v", err)
		}
	}
}

// BenchmarkInterfaceCacheHit measures the cost of a cached lookup within the TTL.
func BenchmarkInterfaceCacheHit(b *testing.B) {
	c := dhcp4.NewInterfaceCache(time.Hour)

	b.ResetTimer()

	for range b.N {
		if _, err := c.Interfaces(); err != nil {
			b.Fatalf("Interfaces: %v", err)
		}
	}
}

// BenchmarkInterfaceCache1s measures the cost with a 1 second TTL simulating the default reply path.
func BenchmarkInterfaceCache1s(b *testing.B) {
	c := dhcp4.NewInterfaceCache(time.Second)

	b.ResetTimer()

	for range b.N {
		if _, err := c.Interfaces(); err != nil {
			b.Fatalf("Interfaces: %v", err)
		}
	}
}

// BenchmarkInterfaceCacheDefault measures the cost with the production default TTL.
func BenchmarkInterfaceCacheDefault(b *testing.B) {
	c := dhcp4.NewInterfaceCache(dhcp4.DefaultInterfaceCacheTTL)

	b.ResetTimer()

	for range b.N {
		if _, err := c.Interfaces(); err != nil {
			b.Fatalf("Interfaces: %v", err)
		}
	}
}

// BenchmarkNetInterfacesDirect measures the cost of a direct net.Interfaces call as a baseline.
func BenchmarkNetInterfacesDirect(b *testing.B) {
	for range b.N {
		if _, err := net.Interfaces(); err != nil {
			b.Fatalf("net.Interfaces: %v", err)
		}
	}
}
