// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterfaceCacheTTL is how long a NIC enumeration is served before a refetch. A non positive TTL disables caching.
const DefaultInterfaceCacheTTL = 1 * time.Second

// interfaceSnapshot is one immutable enumeration result with its fetch time.
type interfaceSnapshot struct {
	fetched time.Time
	ifaces  []net.Interface
}

// InterfaceCache caches net.Interfaces so the reply NIC match avoids a full RTNETLINK dump per packet.
type InterfaceCache struct {
	snap atomic.Pointer[interfaceSnapshot]
	// mu serializes the refetch so concurrent expired readers dump RTNETLINK once.
	mu  sync.Mutex
	ttl time.Duration
}

// NewInterfaceCache returns a cache holding each enumeration for ttl. Non positive ttl disables caching.
func NewInterfaceCache(ttl time.Duration) *InterfaceCache {
	return &InterfaceCache{ttl: ttl}
}

// Interfaces returns the cached enumeration or refetches an expired one. A stale snapshot is served on refetch error.
func (c *InterfaceCache) Interfaces() ([]net.Interface, error) {
	if s := c.snap.Load(); s != nil && time.Since(s.fetched) < c.ttl {
		return s.ifaces, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Another caller may have refreshed while this one waited for the lock.
	if s := c.snap.Load(); s != nil && time.Since(s.fetched) < c.ttl {
		return s.ifaces, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		// With caching enabled serve a stale snapshot so a transient netlink error does not collapse reply routing to ingress only.
		if c.ttl > 0 {
			if s := c.snap.Load(); s != nil {
				return s.ifaces, err
			}
		}

		return nil, err
	}

	c.snap.Store(&interfaceSnapshot{fetched: time.Now(), ifaces: ifaces})

	return ifaces, nil
}
