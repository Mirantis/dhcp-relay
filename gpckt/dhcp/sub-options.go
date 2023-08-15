package dhcp

import (
	"strconv"

	"github.com/gopacket/gopacket/layers"
)

const (
	AgentCircuitIDSubOption layers.DHCPOpt = 1
)

func CreateAgentCircuitIDSubOption(value int) layers.DHCPOption {
	data := []byte(strconv.Itoa(value))

	return layers.DHCPOption{
		Type:   AgentCircuitIDSubOption,
		Length: byte(len(data)),
		Data:   data,
	}
}

func ExtractAgentCircuitIDSubOptionData(options ...layers.DHCPOption) int {
	for _, opt := range options {
		if opt.Type != AgentCircuitIDSubOption {
			continue
		}

		val, err := strconv.Atoi(string(opt.Data))
		if err != nil {
			return 0
		}

		return val
	}

	return 0
}
