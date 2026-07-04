// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4

import (
	"net"
)

// IsGlobalUnicastIPv4 reports whether ip is a global unicast IPv4 address. It is the single predicate for a usable
// giaddr so interface enumeration, the reply locality check, and the -giaddr validation all accept the same set.
func IsGlobalUnicastIPv4(ip net.IP) bool {
	return ip.To4() != nil && ip.IsGlobalUnicast()
}

func GetInterfaceGlobalUnicastAddrs4(ifIndex int) ([]net.IPNet, error) {
	if ifIndex == 0 {
		return nil, nil
	}

	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil, err
	}

	return InterfaceGlobalUnicastAddrs4(ifi)
}

// InterfaceGlobalUnicastAddrs4 returns the global unicast IPv4 addresses configured on ifi. It is the single
// predicate the request path shares so a caller that already holds an interface reuses it without a second lookup.
func InterfaceGlobalUnicastAddrs4(ifi *net.Interface) ([]net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}

	out := make([]net.IPNet, 0, len(addrs))

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			continue
		case *net.IPNet:
			if v == nil || !IsGlobalUnicastIPv4(v.IP) {
				continue
			}

			out = append(out, *v)
		}
	}

	return out, nil
}

// IsRelayLocalAddr reports whether ip is a global unicast IPv4 on any interface of this host. The reply path uses
// GiaddrIsLocal (which also honors a configured -giaddr) to decide local delivery. Loopback and link-local never match.
func IsRelayLocalAddr(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || v4.IsUnspecified() {
		return false
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		// Reuse the To4 result for the global unicast check and the address compare.
		a4 := ipnet.IP.To4()
		if a4 == nil || !ipnet.IP.IsGlobalUnicast() {
			continue
		}

		if a4.Equal(v4) {
			return true
		}
	}

	return false
}

// GiaddrIsLocal reports whether a reply giaddr should be delivered locally rather than forwarded. It holds for an
// address on this host or the configured -giaddr override the host may not itself carry.
func (cfg *HandleOptions) GiaddrIsLocal(ip net.IP) bool {
	return IsRelayLocalAddr(ip) || (cfg.Giaddr != nil && cfg.Giaddr.Equal(ip))
}

// BestUnicastSrc returns the address containing yiaddr or the first address as a fallback. It returns nil for an empty addrs.
// The caller must ensure addrs contains only IPv4 addresses, otherwise the fallback returns nil for an IPv6-only entry.
func BestUnicastSrc(addrs []net.IPNet, yiaddr net.IP) net.IP {
	if len(addrs) == 0 {
		return nil
	}

	// If yiaddr is unset (nil or 0-length), skip subnet matching and fall back to the first available address.
	yi4 := yiaddr.To4()
	if len(yiaddr) != 0 && yi4 != nil {
		for _, a := range addrs {
			if a.IP.To4() != nil && a.Contains(yi4) {
				return a.IP.To4()
			}
		}
	}

	return addrs[0].IP.To4()
}
