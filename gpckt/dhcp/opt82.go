package dhcp

import (
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/specs"
)

const (
	RelayAgentInformation layers.DHCPOpt = 82
)

func GetRelayAgentInformationOption(layerDHCPv4 *layers.DHCPv4) layers.DHCPOption {
	opt82 := GetOption(layerDHCPv4, RelayAgentInformation)
	if !IsOption(opt82) {
		return layers.DHCPOption{}
	}

	if len(opt82.Data) == 0 || opt82.Length < 1 {
		return layers.DHCPOption{}
	}

	return opt82
}

func DeleteRelayAgentInformationOption(layerDHCPv4 *layers.DHCPv4) {
	DeleteOption(layerDHCPv4, RelayAgentInformation)
}

func SetRelayAgentInformationOption(layerDHCPv4 *layers.DHCPv4, subOptions ...layers.DHCPOption) {
	opt82 := EncodeRelayAgentInformationOption(subOptions...)
	SetOption(layerDHCPv4, opt82)
}

func EncodeRelayAgentInformationOption(subOptions ...layers.DHCPOption) layers.DHCPOption {
	data := make([]byte, 0)

	for _, subOption := range subOptions {
		if subOption.Length == 0 {
			return layers.DHCPOption{}
		}

		data = append(data, byte(subOption.Type), subOption.Length)
		data = append(data, subOption.Data...)
	}

	if len(data) > specs.DHCPv4MaxOptionSize {
		return layers.DHCPOption{}
	}

	return layers.NewDHCPOption(RelayAgentInformation, data)
}

func DecodeRelayAgentInformationOption(option layers.DHCPOption) []layers.DHCPOption {
	data := option.Data
	subOptions := make([]layers.DHCPOption, 0)
	headerSize := specs.DHCPv4OptionTypeSize + specs.DHCPv4OptionLengthSize

	for len(data) > 0 {
		if len(data) < headerSize {
			return nil
		}

		length := int(data[specs.DHCPv4OptionTypeSize])
		if len(data) < headerSize+length {
			return nil
		}

		subOptions = append(subOptions, layers.DHCPOption{
			Type:   layers.DHCPOpt(data[0]),
			Length: data[specs.DHCPv4OptionTypeSize],
			Data:   data[headerSize : headerSize+length],
		})

		data = data[headerSize+length:]
	}

	return subOptions
}
