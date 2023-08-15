package specs

// https://en.wikipedia.org/wiki/Ethernet_frame
const (
	EthernetFieldSizeDestinationMACAddress = 48
	EthernetFieldSizeSourceMACAddress      = 48
	EthernetFieldSizeEtherType             = 16

	EthernetHeaderLength = EthernetFieldSizeDestinationMACAddress + EthernetFieldSizeSourceMACAddress + EthernetFieldSizeEtherType
)

const (
	EthernetCommonMTU = 1500
	EthernetMACLength = 6
)
