// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package sockets

import (
	"encoding/binary"
)

// Htons converts a 16-bit integer from host byte order to network byte order.
// On little-endian hosts (amd64, arm64) this byte-swaps; on big-endian hosts
// it is a no-op — which is what "network byte order" means.
func Htons(i uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], i)

	return binary.NativeEndian.Uint16(b[:])
}
