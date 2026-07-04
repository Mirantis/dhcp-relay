// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package specs

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4
const (
	IPv4FieldSizeVersion        = 4
	IPv4FieldSizeIHL            = 4
	IPv4FieldSizeDSC            = 6
	IPv4FieldSizeECN            = 2
	IPv4FieldSizeTotalLength    = 16
	IPv4FieldSizeIdentification = 16
	IPv4FieldSizeFlags          = 3
	IPv4FieldSizeFragmentOffset = 13
	IPv4FieldSizeTTL            = 8
	IPv4FieldSizeProtocol       = 8
	IPv4FieldSizeChecksum       = 16
	IPv4FieldSizeSourceIP       = 32
	IPv4FieldSizeDestinationIP  = 32

	IPv4HeaderSizeBits = IPv4FieldSizeVersion + IPv4FieldSizeIHL + IPv4FieldSizeDSC + IPv4FieldSizeECN + IPv4FieldSizeTotalLength +
		IPv4FieldSizeIdentification + IPv4FieldSizeFlags + IPv4FieldSizeFragmentOffset + IPv4FieldSizeTTL + IPv4FieldSizeProtocol +
		IPv4FieldSizeChecksum + IPv4FieldSizeSourceIP + IPv4FieldSizeDestinationIP

	// IPv4FieldIHLValueMinHeaderNoOptions is the IHL for the min IPv4 header with no Options, present iff IHL exceeds this.
	IPv4FieldIHLValueMinHeaderNoOptions = 5
)

const (
	IPv4Version = 4
	DefaultTTL  = 64
)
