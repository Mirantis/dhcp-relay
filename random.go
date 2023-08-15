package main

import (
	"crypto/rand"
	"encoding/binary"
	"unsafe"
)

func GenerateRandomIPv4ID() uint16 {
	b := make([]byte, unsafe.Sizeof(uint16(0))) //nolint:makezero // C-style for bytes slices is fine here

	_, err := rand.Read(b)
	if err != nil {
		return GenerateRandomIPv4ID()
	}

	return binary.BigEndian.Uint16(b)
}
