package dhcp

import (
	"bytes"

	"github.com/gopacket/gopacket/layers"
)

func GetBootFileName(layerDHCPv4 *layers.DHCPv4) string {
	if len(layerDHCPv4.File) == 0 {
		return ""
	}

	return string(bytes.TrimSpace(layerDHCPv4.File))
}
