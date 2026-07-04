// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4

import (
	"net"
)

func GetInterfaceGlobalUnicastAddrs4(ifIndex int) []net.IPNet {
	if ifIndex == 0 {
		return nil
	}

	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}

	out := make([]net.IPNet, 0, len(addrs))

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			continue
		case *net.IPNet:
			if v == nil || v.IP == nil || !v.IP.IsGlobalUnicast() || v.IP.To4() == nil {
				continue
			}

			out = append(out, *v)
		}
	}

	return out
}

// BestUnicastSrc returns the address containing yiaddr or the first address as a fallback. It returns nil for an empty addrs.
func BestUnicastSrc(addrs []net.IPNet, yiaddr net.IP) net.IP {
	if len(addrs) == 0 {
		return nil
	}

	yi4 := yiaddr.To4()
	if yi4 != nil {
		for _, a := range addrs {
			if a.IP.To4() != nil && a.Contains(yi4) {
				return a.IP.To4()
			}
		}
	}

	return addrs[0].IP.To4()
}
