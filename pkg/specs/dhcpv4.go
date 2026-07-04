// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package specs

const (
	DHCPv4ServerPort = 67
	DHCPv4ClientPort = 68

	// DHCPv4MinMessageSize is the min DHCP message (UDP payload) length per RFC 2131, 236 BOOTP fields plus 4 cookie plus 4 min options.
	DHCPv4MinMessageSize = 244
	// DHCPv4MaxMessageSize is the max DHCP message size (548) from RFC 791/RFC 2131 min IP datagram 576 less 28 IP+UDP header octets.
	DHCPv4MaxMessageSize = 548

	// DHCPv4MaxHops is the maximum hop count a relay forwards per RFC 2131. A relay discards a request at or above this value.
	DHCPv4MaxHops = 16
)

const (
	DHCPv4BroadcastFlag = 0x8000
)

const (
	// DHCPv4MaxOptionSize is the max option data length, the Length field per RFC 2132, excluding Type and Length header bytes.
	DHCPv4MaxOptionSize = 255

	DHCPv4OptionTypeSize   = 1
	DHCPv4OptionLengthSize = 1

	// DHCPv4MaxSubOptionSize is the largest sub option payload that fits inside a container option.
	DHCPv4MaxSubOptionSize = DHCPv4MaxOptionSize - DHCPv4OptionTypeSize - DHCPv4OptionLengthSize
)
