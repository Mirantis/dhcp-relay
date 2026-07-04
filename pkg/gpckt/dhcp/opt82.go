// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp

import (
	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/specs"
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

// SetRelayAgentInformationOption encodes sub options into Option 82 on the layer, skipping sets that cannot encode.
func SetRelayAgentInformationOption(layerDHCPv4 *layers.DHCPv4, subOptions ...layers.DHCPOption) {
	opt82 := EncodeRelayAgentInformationOption(subOptions...)
	if !IsOption(opt82) {
		return
	}

	SetOption(layerDHCPv4, opt82)
}

// EncodeRelayAgentInformationOption packs sub options into one Option 82 and returns zero for a zero sub option or oversize set.
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
	headerSize := specs.DHCPv4OptionTypeSize + specs.DHCPv4OptionLengthSize

	var subOptions []layers.DHCPOption

	for len(data) > 0 {
		// Reject the whole option on a truncated trailer so a corrupt Option 82 never yields a partial parse the reply path would trust.
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
