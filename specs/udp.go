package specs

// https://en.wikipedia.org/wiki/User_Datagram_Protocol
const (
	UDPFieldSizeSourcePort      = 16
	UDPFieldSizeDestinationPort = 16
	UDPFieldSizeLength          = 16
	UDPFieldSizeChecksum        = 16

	UDPHeaderSize = UDPFieldSizeSourcePort + UDPFieldSizeDestinationPort + UDPFieldSizeLength + UDPFieldSizeChecksum
)
