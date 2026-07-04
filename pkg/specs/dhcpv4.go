// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package specs

const (
	DHCPv4ServerPort = 67
	DHCPv4ClientPort = 68

	DHCPv4MinMessageSize = 244
	DHCPv4MaxMessageSize = 576
)

const (
	DHCPv4BroadcastFlag = 0x8000
)

const (
	DHCPv4MaxOptionSize = 255

	DHCPv4OptionTypeSize   = 1
	DHCPv4OptionLengthSize = 1

	// DHCPv4MaxSubOptionSize is the largest sub option payload that fits inside a container option.
	DHCPv4MaxSubOptionSize = DHCPv4MaxOptionSize - DHCPv4OptionTypeSize - DHCPv4OptionLengthSize
)
