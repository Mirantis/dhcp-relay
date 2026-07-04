// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp4_test

import (
	"net"
	"testing"

	"code.local/dhcp-relay/pkg/dhcp4"
)

// TestBestUnicastSrc checks BestUnicastSrc selects the address whose subnet contains yiaddr.
func TestBestUnicastSrc(t *testing.T) {
	v4net := func(a, b, c, d byte, mask net.IPMask) net.IPNet {
		return net.IPNet{IP: net.IPv4(a, b, c, d), Mask: mask}
	}

	mask24 := net.CIDRMask(24, 32)
	mask8 := net.CIDRMask(8, 32)

	tests := []struct {
		name   string
		addrs  []net.IPNet
		yiaddr net.IP
		want   net.IP
	}{
		{
			name: "matching subnet selected",
			addrs: []net.IPNet{
				v4net(192, 168, 1, 1, mask24),
				v4net(10, 0, 0, 1, mask8),
			},
			yiaddr: net.IPv4(192, 168, 1, 50),
			want:   net.IPv4(192, 168, 1, 1),
		},
		{
			name: "no matching subnet falls back to addrs[0]",
			addrs: []net.IPNet{
				v4net(10, 0, 0, 1, mask8),
			},
			yiaddr: net.IPv4(192, 168, 1, 50),
			want:   net.IPv4(10, 0, 0, 1),
		},
		{
			name: "picks the matching one not just the first",
			addrs: []net.IPNet{
				v4net(10, 0, 0, 1, mask8),
				v4net(172, 16, 0, 1, net.CIDRMask(16, 32)),
				v4net(192, 168, 1, 1, mask24),
			},
			yiaddr: net.IPv4(192, 168, 1, 77),
			want:   net.IPv4(192, 168, 1, 1),
		},
		{
			name: "IPv6 yiaddr falls back to addrs[0]",
			addrs: []net.IPNet{
				v4net(10, 0, 0, 1, mask8),
				v4net(192, 168, 1, 1, mask24),
			},
			yiaddr: net.ParseIP("2001:db8::1"),
			want:   net.IPv4(10, 0, 0, 1),
		},
		{
			name: "single address returns that address",
			addrs: []net.IPNet{
				v4net(192, 168, 1, 1, mask24),
			},
			yiaddr: net.IPv4(192, 168, 1, 5),
			want:   net.IPv4(192, 168, 1, 1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dhcp4.BestUnicastSrc(tc.addrs, tc.yiaddr)
			if !got.Equal(tc.want) {
				t.Errorf("BestUnicastSrc(%v, %v) = %s, want %s", tc.addrs, tc.yiaddr, got, tc.want)
			}
		})
	}
}

// TestGetInterfaceGlobalUnicastAddrs4 checks GetInterfaceGlobalUnicastAddrs4 returns nil for an invalid index.
func TestGetInterfaceGlobalUnicastAddrs4(t *testing.T) {
	t.Run("ifIndex 0 returns nil", func(t *testing.T) {
		if got := dhcp4.GetInterfaceGlobalUnicastAddrs4(0); got != nil {
			t.Errorf("GetInterfaceGlobalUnicastAddrs4(0) = %v, want nil", got)
		}
	})

	t.Run("invalid large ifIndex returns nil", func(t *testing.T) {
		if got := dhcp4.GetInterfaceGlobalUnicastAddrs4(999999); got != nil {
			t.Errorf("GetInterfaceGlobalUnicastAddrs4(999999) = %v, want nil", got)
		}
	})
}
