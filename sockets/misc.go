package sockets

import (
	"encoding/binary"
	"unsafe"
)

func Htons(i uint16) uint16 {
	bytes := make([]byte, unsafe.Sizeof(uint16(0))) //nolint:makezero // C-style for bytes slices is fine here
	binary.BigEndian.PutUint16(bytes, i)

	return binary.LittleEndian.Uint16(bytes)
}
