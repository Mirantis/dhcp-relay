// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package sockets_test

import (
	"encoding/binary"
	"testing"

	"code.local/dhcp-relay/pkg/sockets"
)

// isLittleEndian reports host byte order by reading a known byte layout in native order.
func isLittleEndian() bool {
	return binary.NativeEndian.Uint16([]byte{0x01, 0x00}) == 1
}

func TestHtons(t *testing.T) {
	tests := []struct {
		input uint16
	}{
		{0x0000},
		{0xFFFF},
		{0xFF00},
		{0x00FF},
		{0x1234},
	}

	littleEndian := isLittleEndian()

	for _, tt := range tests {
		got := sockets.Htons(tt.input)

		var want uint16
		if littleEndian {
			want = (tt.input << 8) | (tt.input >> 8)
		} else {
			want = tt.input
		}

		if got != want {
			t.Errorf("Htons(0x%04X) = 0x%04X, want 0x%04X", tt.input, got, want)
		}
	}
}

func TestHtonsRoundTrip(t *testing.T) {
	tests := []struct {
		input uint16
	}{
		{0x0000},
		{0xFFFF},
		{0xFF00},
		{0x00FF},
		{0x1234},
	}

	for _, tt := range tests {
		got := sockets.Htons(sockets.Htons(tt.input))
		if got != tt.input {
			t.Errorf("Htons(Htons(0x%04X)) = 0x%04X, want 0x%04X", tt.input, got, tt.input)
		}
	}
}
