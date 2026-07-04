// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package relay_test

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/macpolicy"
	"code.local/dhcp-relay/pkg/relay"
)

// testPolicy loads a policy from content with a poll interval long enough that the poller never fires.
func testPolicy(t *testing.T, content string) *macpolicy.Map {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	m, err := macpolicy.New(path, time.Hour, logger.NewWithoutDatetime())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = m.Close() })

	return m
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}

	return b
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()

	hw, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", s, err)
	}

	return hw
}

// replyWithTag builds a reply layer carrying the policy tag in Option 82 but no Option 61.
func replyWithTag(tag []byte, chaddr net.HardwareAddr) *layers.DHCPv4 {
	layer := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: chaddr}

	dhcp.SetRelayAgentInformationOption(layer,
		dhcp.CreateAgentCircuitIDSubOption(7), dhcp.CreatePolicyTagSubOption(tag))

	return layer
}

// RequestWithClientID builds a request layer carrying clientID as Option 61.
func RequestWithClientID(clientID []byte, chaddr net.HardwareAddr) *layers.DHCPv4 {
	layer := &layers.DHCPv4{Operation: layers.DHCPOpRequest, ClientHWAddr: chaddr}

	dhcp.SetOption(layer, layers.NewDHCPOption(layers.DHCPOptClientID, clientID))

	return layer
}

// TestPolicyForPacketReplyUsesTag is the core of the fix. An Option 61 keyed reply action is reapplied from the Option 82 tag.
func TestPolicyForPacketReplyUsesTag(t *testing.T) {
	clientID := mustHex(t, "01aabbccddeeff")
	m := testPolicy(t, "0x01aabbccddeeff @default @blackhole\n* @default\n")

	// chaddr is unrelated to the policy and there is no Option 61, so only the tag can select the reply blackhole.
	reply := replyWithTag(clientID, mustMAC(t, "02:00:00:00:00:09"))

	got, drop := relay.PolicyForPacket(m, reply)
	if drop {
		t.Fatal("a reply must not be dropped at the forward gate")
	}

	if !got.DropReply {
		t.Error("the policy tag should have selected the reply blackhole (DropReply=true)")
	}
}

// TestPolicyForPacketReplyFallsBackWithoutTag covers a reply that carries no tag and falls back to matching by chaddr.
func TestPolicyForPacketReplyFallsBackWithoutTag(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @default @blackhole\n* @default\n")

	// No Option 82 and no Option 61, only chaddr. The chaddr entry must still apply.
	dropped := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: mustMAC(t, "aa:bb:cc:dd:ee:ff")}
	if got, _ := relay.PolicyForPacket(m, dropped); !got.DropReply {
		t.Error("fallback chaddr match should select DropReply=true")
	}

	// A chaddr with no entry falls through to the catch all and is delivered.
	relayed := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: mustMAC(t, "02:00:00:00:00:09")}
	if got, _ := relay.PolicyForPacket(m, relayed); got.DropReply {
		t.Error("unmatched reply should fall through to the catch-all, not drop")
	}
}

// TestPolicyForPacketReplyStaleTagFallsBack covers a stale tag matching no entry, falling back to chaddr.
func TestPolicyForPacketReplyStaleTagFallsBack(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @default @blackhole\n* @default\n")

	reply := replyWithTag(mustHex(t, "01deadbeef"), mustMAC(t, "aa:bb:cc:dd:ee:ff"))

	got, drop := relay.PolicyForPacket(m, reply)
	if drop {
		t.Fatal("a reply must not be dropped at the forward gate")
	}

	if !got.DropReply {
		t.Error("a stale tag should fall back to the chaddr entry (DropReply=true)")
	}
}

// TestPolicyForPacketReplyForwardBlackholeDrops checks a forward blackholed client does not receive forged or rogue replies.
func TestPolicyForPacketReplyForwardBlackholeDrops(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @blackhole\n* @default\n")

	reply := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: mustMAC(t, "aa:bb:cc:dd:ee:ff")}
	if _, drop := relay.PolicyForPacket(m, reply); !drop {
		t.Error("a forward @blackhole client's reply must be dropped")
	}
}

// TestPolicyForPacketReplyStrictAllowListDrops checks a reply from a client absent from a strict allow list is dropped.
func TestPolicyForPacketReplyStrictAllowListDrops(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @default\n")

	reply := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: mustMAC(t, "02:00:00:00:00:09")}
	if _, drop := relay.PolicyForPacket(m, reply); !drop {
		t.Error("a reply from a client absent from a strict allow-list must be dropped")
	}
}

// TestPolicyForPacketRequestTagsAndForwards checks a request matched by Option 61 gets the per client upstream and policy tag.
func TestPolicyForPacketRequestTagsAndForwards(t *testing.T) {
	clientID := mustHex(t, "01aabbccddeeff")
	m := testPolicy(t, "0x01aabbccddeeff 10.0.0.5\n")

	req := RequestWithClientID(clientID, mustMAC(t, "02:00:00:00:00:09"))

	got, drop := relay.PolicyForPacket(m, req)
	if drop {
		t.Fatal("a server action must not drop the request")
	}

	if got.ServerAddress != "10.0.0.5" {
		t.Errorf("ServerAddress = %q, want 10.0.0.5", got.ServerAddress)
	}

	if !bytes.Equal(got.PolicyTag, clientID) {
		t.Errorf("PolicyTag = % x, want % x", got.PolicyTag, clientID)
	}
}

// TestPolicyForPacketRequestBlackholeDrops drops a forward blackholed request.
func TestPolicyForPacketRequestBlackholeDrops(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @blackhole\n")

	req := &layers.DHCPv4{Operation: layers.DHCPOpRequest, ClientHWAddr: mustMAC(t, "aa:bb:cc:dd:ee:ff")}
	if _, drop := relay.PolicyForPacket(m, req); !drop {
		t.Error("a forward blackhole must drop the request")
	}
}

// TestPolicyForPacketReplyNICMatch threads a reply NIC match action so the reply egresses only the named NICs.
func TestPolicyForPacketReplyNICMatch(t *testing.T) {
	mac := mustMAC(t, "0a:0b:0c:0d:0e:0f")
	m := testPolicy(t, "0a:0b:0c:0d:0e:0f @default name=eth0\n")

	got, drop := relay.PolicyForPacket(m, replyWithTag(mac, mac))
	if drop {
		t.Fatal("a reply must not be dropped at the forward gate")
	}

	if got.ReplyNICMatch == nil {
		t.Fatal("ReplyNICMatch = nil, want the policy match function")
	}

	if !got.ReplyNICMatch("eth0", "") {
		t.Error("ReplyNICMatch(eth0) = false, want true")
	}

	if got.ReplyNICMatch("br0", "") {
		t.Error("ReplyNICMatch(br0) = true, want false")
	}
}

// TestPolicyForPacketReplyMatchAll covers the flood form where every NIC matches.
func TestPolicyForPacketReplyMatchAll(t *testing.T) {
	mac := mustMAC(t, "0a:0b:0c:0d:0e:1f")
	m := testPolicy(t, "0a:0b:0c:0d:0e:1f @default *\n")

	got, _ := relay.PolicyForPacket(m, replyWithTag(mac, mac))
	if got.ReplyNICMatch == nil {
		t.Fatal("ReplyNICMatch = nil, want the policy match function")
	}

	if !got.ReplyNICMatch("anything", "aa:bb:cc:dd:ee:00") {
		t.Error("ReplyNICMatch must match any NIC for the flood form")
	}
}

// TestPolicyForPacketRequestDefaultKeepsUpstream checks a default action keeps the CLI upstream while still tagging the request.
func TestPolicyForPacketRequestDefaultKeepsUpstream(t *testing.T) {
	clientID := mustHex(t, "01a1b2c3d4e5f6")
	m := testPolicy(t, "0x01a1b2c3d4e5f6 @default\n")

	req := RequestWithClientID(clientID, mustMAC(t, "02:00:00:00:00:0a"))

	got, drop := relay.PolicyForPacket(m, req)
	if drop {
		t.Fatal("a default action must not drop the request")
	}

	if got.ServerAddress != "" {
		t.Errorf("ServerAddress = %q, want empty so the CLI upstream is kept", got.ServerAddress)
	}

	if !bytes.Equal(got.PolicyTag, clientID) {
		t.Errorf("PolicyTag = % x, want % x", got.PolicyTag, clientID)
	}
}

// TestRequestConfigServer overrides the upstream and tags with the matched key.
func TestRequestConfigServer(t *testing.T) {
	action := macpolicy.Action{Kind: macpolicy.ActionServer, Server: "10.0.0.5"}
	key := []byte{1, 2, 3}

	got := relay.RequestConfig(action, key)

	if got.ServerAddress != "10.0.0.5" {
		t.Errorf("ServerAddress = %q, want 10.0.0.5", got.ServerAddress)
	}

	if !bytes.Equal(got.PolicyTag, key) {
		t.Errorf("PolicyTag = % x, want % x", got.PolicyTag, key)
	}
}

// TestRequestConfigDefault keeps the upstream but still tags with the key.
func TestRequestConfigDefault(t *testing.T) {
	action := macpolicy.Action{Kind: macpolicy.ActionDefault}
	key := []byte{0xaa}

	got := relay.RequestConfig(action, key)

	if got.ServerAddress != "" {
		t.Errorf("ServerAddress = %q, want empty so the CLI upstream is kept", got.ServerAddress)
	}

	if !bytes.Equal(got.PolicyTag, key) {
		t.Errorf("PolicyTag = % x, want % x", got.PolicyTag, key)
	}
}

// TestRequestConfigNoKey yields a zero decision when there is no key to tag and the upstream is unchanged.
func TestRequestConfigNoKey(t *testing.T) {
	action := macpolicy.Action{Kind: macpolicy.ActionDefault}

	got := relay.RequestConfig(action, nil)

	if got.ServerAddress != "" || len(got.PolicyTag) != 0 {
		t.Errorf("default action with no key should yield a zero decision, got %+v", got)
	}
}

// TestReplyConfigBlackhole threads a reply blackhole as DropReply.
func TestReplyConfigBlackhole(t *testing.T) {
	action := macpolicy.Action{Reply: macpolicy.ReplyAction{Kind: macpolicy.ReplyBlackhole}}

	got := relay.ReplyConfig(action)

	if !got.DropReply {
		t.Error("DropReply = false, want true for a reply blackhole")
	}
}

// TestReplyConfigMatch threads the policy match function into ReplyNICMatch.
func TestReplyConfigMatch(t *testing.T) {
	reply := macpolicy.ReplyAction{Kind: macpolicy.ReplyMatch, NameGlobs: []string{"eth0"}}
	action := macpolicy.Action{Reply: reply}

	got := relay.ReplyConfig(action)

	if got.ReplyNICMatch == nil {
		t.Fatal("ReplyNICMatch = nil, want the policy match function")
	}

	if !got.ReplyNICMatch("eth0", "") {
		t.Error("ReplyNICMatch(eth0) = false, want true")
	}

	if got.ReplyNICMatch("br0", "") {
		t.Error("ReplyNICMatch(br0) = true, want false")
	}
}

// TestReplyConfigIngress yields a zero decision for the default ingress reply.
func TestReplyConfigIngress(t *testing.T) {
	action := macpolicy.Action{Reply: macpolicy.ReplyAction{Kind: macpolicy.ReplyIngress}}

	got := relay.ReplyConfig(action)

	if got.DropReply || got.ReplyNICMatch != nil {
		t.Errorf("an ingress reply should yield a zero decision, got %+v", got)
	}
}

// TestLookupReplyActionWithTag selects the reply action from an Option 82 policy tag.
func TestLookupReplyActionWithTag(t *testing.T) {
	clientID := mustHex(t, "01aabbccddeeff")
	m := testPolicy(t, "0x01aabbccddeeff @default @blackhole\n* @default\n")

	reply := replyWithTag(clientID, mustMAC(t, "02:00:00:00:00:09"))

	got, _ := relay.LookupReplyAction(m, reply, nil)
	if got.Reply.Kind != macpolicy.ReplyBlackhole {
		t.Errorf("Reply.Kind = %v, want ReplyBlackhole", got.Reply.Kind)
	}
}

// TestLookupReplyActionFallbackToChaddr matches a reply by chaddr when no tag is present.
func TestLookupReplyActionFallbackToChaddr(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @default @blackhole\n* @default\n")

	reply := &layers.DHCPv4{Operation: layers.DHCPOpReply, ClientHWAddr: mustMAC(t, "aa:bb:cc:dd:ee:ff")}

	got, _ := relay.LookupReplyAction(m, reply, nil)
	if got.Reply.Kind != macpolicy.ReplyBlackhole {
		t.Errorf("Reply.Kind = %v, want ReplyBlackhole", got.Reply.Kind)
	}
}

// TestLookupReplyActionStaleTagFallback falls back to chaddr when the tag matches no entry.
func TestLookupReplyActionStaleTagFallback(t *testing.T) {
	m := testPolicy(t, "aa:bb:cc:dd:ee:ff @default @blackhole\n* @default\n")

	reply := replyWithTag(mustHex(t, "01deadbeef"), mustMAC(t, "aa:bb:cc:dd:ee:ff"))

	got, _ := relay.LookupReplyAction(m, reply, nil)
	if got.Reply.Kind != macpolicy.ReplyBlackhole {
		t.Errorf("Reply.Kind = %v, want ReplyBlackhole from the chaddr fallback", got.Reply.Kind)
	}
}
