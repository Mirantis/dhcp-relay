// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp4

const (
	logDataInPrefix  = "-->"
	logDataOutPrefix = "<--"
)

type ReplyType uint8

const (
	// UnicastReply means the DHCPv4 broadcast flag is clear, so the reply is unicast to ciaddr per RFC 2131.
	UnicastReply ReplyType = 0
	// BroadcastReply means the DHCPv4 broadcast flag is set, so the reply is broadcast per RFC 2131.
	BroadcastReply ReplyType = 1
)
