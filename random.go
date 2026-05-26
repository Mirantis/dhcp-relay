// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package main

import (
	"crypto/rand"
	"encoding/binary"
)

func GenerateRandomIPv4ID() uint16 {
	var b [2]byte

	if _, err := rand.Read(b[:]); err != nil {
		return GenerateRandomIPv4ID()
	}

	return binary.BigEndian.Uint16(b[:])
}
