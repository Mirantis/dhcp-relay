package dhcp

import (
	"sort"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// RFC 3396: "...the encoding agent MUST either use this algorithm or not send the option at all."
// https://www.rfc-editor.org/rfc/rfc3396.html (Encoding Long Options in the DHCPv4)
func DeleteSplitOptions(options ...layers.DHCPOption) []layers.DHCPOption {
	optionCount := make(map[byte]int, len(options))

	for _, option := range options {
		if option.Type == layers.DHCPOptPad || option.Type == layers.DHCPOptEnd {
			continue
		}

		optionCount[byte(option.Type)]++
	}

	i := 0

	for _, option := range options {
		if option.Type == layers.DHCPOptPad || optionCount[byte(option.Type)] != 1 {
			continue
		}

		options[i] = option
		i++

		if option.Type == layers.DHCPOptEnd {
			break
		}
	}

	return options[:i]
}

func IsOption(option layers.DHCPOption) bool {
	return option.Length > 0
}

func GetOption(layerDHCPv4 *layers.DHCPv4, optionType layers.DHCPOpt) layers.DHCPOption {
	var specificOption layers.DHCPOption

	for _, opt := range layerDHCPv4.Options {
		if opt.Type == optionType {
			specificOption = opt

			break
		}
	}

	return specificOption
}

func DeleteOption(layerDHCPv4 *layers.DHCPv4, optionType layers.DHCPOpt) {
	for k, opt := range layerDHCPv4.Options {
		if opt.Type == optionType {
			layerDHCPv4.Options = append(layerDHCPv4.Options[:k], layerDHCPv4.Options[k+1:]...)

			return
		}
	}
}

func SetOption(layerDHCPv4 *layers.DHCPv4, newOption layers.DHCPOption) {
	for i, opt := range layerDHCPv4.Options {
		if opt.Type == newOption.Type {
			layerDHCPv4.Options[i] = newOption

			return
		}
	}

	layerDHCPv4.Options = append(layerDHCPv4.Options, newOption)

	sort.Slice(layerDHCPv4.Options, func(i, j int) bool {
		return layerDHCPv4.Options[i].Type < layerDHCPv4.Options[j].Type
	})
}

func GetMessageType(layerDHCPv4 *layers.DHCPv4) string {
	opt53 := GetOption(layerDHCPv4, layers.DHCPOptMessageType)
	if !IsOption(opt53) || len(opt53.Data) == 0 || opt53.Length != 1 {
		return ""
	}

	val := layers.DHCPMsgType(opt53.Data[0])

	if val <= layers.DHCPMsgTypeUnspecified || val > layers.DHCPMsgTypeInform {
		return ""
	}

	return strings.ToUpper(val.String())
}
