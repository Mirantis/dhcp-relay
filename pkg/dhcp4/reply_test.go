// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4_test

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
)

func TestSelectReplyInterfaces(t *testing.T) {
	mac := func(s string) net.HardwareAddr {
		hw, err := net.ParseMAC(s)
		if err != nil {
			t.Fatalf("parse MAC %q: %v", s, err)
		}

		return hw
	}

	eth0 := net.Interface{Name: "eth0", HardwareAddr: mac("02:00:00:00:00:01"), Flags: net.FlagUp}
	eth1 := net.Interface{Name: "eth1", HardwareAddr: mac("02:00:00:00:00:02"), Flags: net.FlagUp}
	down := net.Interface{Name: "eth2", HardwareAddr: mac("02:00:00:00:00:03")} // not up
	noHW := net.Interface{Name: "lo", Flags: net.FlagUp}                        // no hardware address
	ifaces := []net.Interface{eth0, eth1, down, noHW}

	names := func(ifs []net.Interface) []string {
		out := make([]string, len(ifs))
		for i, ni := range ifs {
			out[i] = ni.Name
		}

		return out
	}

	tests := []struct {
		name  string
		match func(name, macStr string) bool
		want  []string
	}{
		{"nil match selects nothing", nil, []string{}},
		{"match by name", func(name, _ string) bool { return name == "eth1" }, []string{"eth1"}},
		{"no match selects nothing", func(_, _ string) bool { return false }, []string{}},
		{"match all skips down and no HW NICs", func(_, _ string) bool { return true }, []string{"eth0", "eth1"}},
	}

	for _, tc := range tests {
		got := names(dhcp4.SelectReplyInterfaces(tc.match, ifaces))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestReplyAddressing locks the RFC 2131 link layer addressing for broadcast and unicast replies.
func TestReplyAddressing(t *testing.T) {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	yiaddr := net.IPv4(192, 0, 2, 50)
	srcIP := net.IPv4(192, 0, 2, 1)

	layerDHCPv4 := &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: yiaddr}
	layerIPv4 := &layers.IPv4{}

	dst, err := dhcp4.ReplyAddressing(dhcp4.UnicastReply, srcIP, layerDHCPv4, layerIPv4, false)
	if err != nil {
		t.Fatalf("unicast ReplyAddressing error: %v", err)
	}
	if !bytes.Equal(dst, clientMAC) {
		t.Errorf("unicast dst MAC = %s, want the client MAC %s", dst, clientMAC)
	}

	if !layerIPv4.SrcIP.Equal(srcIP) || !layerIPv4.DstIP.Equal(yiaddr) {
		t.Errorf("unicast IPs = %s > %s, want %s > %s", layerIPv4.SrcIP, layerIPv4.DstIP, srcIP, yiaddr)
	}

	if dhcp.IsBroadcast(layerDHCPv4) {
		t.Error("a unicast reply must not carry the broadcast flag")
	}

	layerDHCPv4 = &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: yiaddr}
	layerIPv4 = &layers.IPv4{}

	dst, err = dhcp4.ReplyAddressing(dhcp4.BroadcastReply, srcIP, layerDHCPv4, layerIPv4, false)
	if err != nil {
		t.Fatalf("broadcast ReplyAddressing error: %v", err)
	}
	if !bytes.Equal(dst, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("broadcast dst MAC = %s, want ff:ff:ff:ff:ff:ff", dst)
	}

	if !layerIPv4.SrcIP.Equal(net.IPv4zero) || !layerIPv4.DstIP.Equal(net.IPv4bcast) {
		t.Errorf("broadcast IPs = %s > %s, want 0.0.0.0 > 255.255.255.255", layerIPv4.SrcIP, layerIPv4.DstIP)
	}

	if !dhcp.IsBroadcast(layerDHCPv4) {
		t.Error("a broadcast reply must carry the broadcast flag")
	}
}

// TestReplyAddressingInvalidType checks that an unknown reply type returns an error and nil MAC.
func TestReplyAddressingInvalidType(t *testing.T) {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	yiaddr := net.IPv4(192, 0, 2, 50)
	srcIP := net.IPv4(192, 0, 2, 1)

	layerDHCPv4 := &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: yiaddr}
	layerIPv4 := &layers.IPv4{}

	dst, err := dhcp4.ReplyAddressing(99, srcIP, layerDHCPv4, layerIPv4, false)
	if err == nil {
		t.Fatal("expected an error for an unsupported reply type, got nil")
	}
	if dst != nil {
		t.Errorf("expected nil hardware address, got %s", dst)
	}
}

// TestReplyAddressingBroadcastL2Unicast checks the legacy toggle where a broadcast reply keeps the client MAC at L2.
func TestReplyAddressingBroadcastL2Unicast(t *testing.T) {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	yiaddr := net.IPv4(192, 0, 2, 50)
	srcIP := net.IPv4(192, 0, 2, 1)

	layerDHCPv4 := &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: yiaddr}
	layerIPv4 := &layers.IPv4{}

	dst, err := dhcp4.ReplyAddressing(dhcp4.BroadcastReply, srcIP, layerDHCPv4, layerIPv4, true)
	if err != nil {
		t.Fatalf("broadcast ReplyAddressing error: %v", err)
	}

	if !bytes.Equal(dst, clientMAC) {
		t.Errorf("legacy broadcast dst MAC = %s, want the client MAC %s", dst, clientMAC)
	}

	// The IP layer and the broadcast flag stay broadcast. Only the L2 destination changes.
	if !layerIPv4.SrcIP.Equal(net.IPv4zero) || !layerIPv4.DstIP.Equal(net.IPv4bcast) {
		t.Errorf("legacy broadcast IPs = %s > %s, want 0.0.0.0 > 255.255.255.255", layerIPv4.SrcIP, layerIPv4.DstIP)
	}

	if !dhcp.IsBroadcast(layerDHCPv4) {
		t.Error("a broadcast reply must carry the broadcast flag even in legacy L2 unicast mode")
	}
}

// TestReplyAddressingUnicastFallsBackToCiaddr checks that a unicast reply with yiaddr zero uses ciaddr as DstIP.
// This covers a DHCPINFORM ACK where the client address is in ciaddr and yiaddr is 0.0.0.0.
func TestReplyAddressingUnicastFallsBackToCiaddr(t *testing.T) {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	ciaddr := net.IPv4(10, 0, 0, 5)
	srcIP := net.IPv4(192, 0, 2, 1)

	layerDHCPv4 := &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: net.IPv4zero, ClientIP: ciaddr}
	layerIPv4 := &layers.IPv4{}

	dst, err := dhcp4.ReplyAddressing(dhcp4.UnicastReply, srcIP, layerDHCPv4, layerIPv4, false)
	if err != nil {
		t.Fatalf("unicast ReplyAddressing error: %v", err)
	}

	if !bytes.Equal(dst, clientMAC) {
		t.Errorf("unicast dst MAC = %s, want the client MAC %s", dst, clientMAC)
	}

	if !layerIPv4.DstIP.Equal(ciaddr) {
		t.Errorf("unicast DstIP = %s, want ciaddr %s", layerIPv4.DstIP, ciaddr)
	}

	if !layerIPv4.SrcIP.Equal(srcIP) {
		t.Errorf("unicast SrcIP = %s, want %s", layerIPv4.SrcIP, srcIP)
	}

	if dhcp.IsBroadcast(layerDHCPv4) {
		t.Error("a unicast reply must not carry the broadcast flag")
	}
}

// TestReplyAddressingUnicastPrefersYiaddr checks that yiaddr takes priority over ciaddr when both are set.
func TestReplyAddressingUnicastPrefersYiaddr(t *testing.T) {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	yiaddr := net.IPv4(192, 0, 2, 50)
	ciaddr := net.IPv4(10, 0, 0, 5)
	srcIP := net.IPv4(192, 0, 2, 1)

	layerDHCPv4 := &layers.DHCPv4{ClientHWAddr: clientMAC, YourClientIP: yiaddr, ClientIP: ciaddr}
	layerIPv4 := &layers.IPv4{}

	_, err := dhcp4.ReplyAddressing(dhcp4.UnicastReply, srcIP, layerDHCPv4, layerIPv4, false)
	if err != nil {
		t.Fatalf("unicast ReplyAddressing error: %v", err)
	}

	if !layerIPv4.DstIP.Equal(yiaddr) {
		t.Errorf("unicast DstIP = %s, want yiaddr %s not ciaddr %s", layerIPv4.DstIP, yiaddr, ciaddr)
	}
}

// TestReplyTargetsIngressOnly verifies that with ReplyNICMatch nil the reply goes only out the ingress NIC.
func TestReplyTargetsIngressOnly(t *testing.T) {
	cl := logger.NewWithoutDatetime()
	cfg := &dhcp4.HandleOptions{Logger: cl}

	ingress := &net.Interface{Index: 7, Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}}

	targets := dhcp4.ReplyTargets(cfg, nil, ingress, ingress.HardwareAddr)
	if len(targets) != 1 {
		t.Fatalf("expected exactly 1 target, got %d", len(targets))
	}

	if targets[0].Index != ingress.Index {
		t.Errorf("target index = %d, want ingress %d", targets[0].Index, ingress.Index)
	}
	if targets[0].Name != ingress.Name {
		t.Errorf("target name = %q, want ingress %q", targets[0].Name, ingress.Name)
	}
}
