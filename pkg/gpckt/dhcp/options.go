// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package dhcp

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// RFC 3396: "...the encoding agent MUST either use this algorithm or not send the option at all."
// https://www.rfc-editor.org/rfc/rfc3396.html (Encoding Long Options in the DHCPv4)
// DeleteSplitOptions filters RFC 3396 split options in place mutating the backing array and returning a sub slice of it.
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
		if option.Type == layers.DHCPOptEnd {
			options[i] = option
			i++

			break
		}

		if option.Type == layers.DHCPOptPad || optionCount[byte(option.Type)] != 1 {
			continue
		}

		options[i] = option
		i++
	}

	return options[:i]
}

func IsOption(option layers.DHCPOption) bool {
	return option.Length > 0
}

func GetOption(layerDHCPv4 *layers.DHCPv4, optionType layers.DHCPOpt) layers.DHCPOption {
	for _, opt := range layerDHCPv4.Options {
		if opt.Type == optionType {
			return opt
		}
	}

	return layers.DHCPOption{}
}

func DeleteOption(layerDHCPv4 *layers.DHCPv4, optionType layers.DHCPOpt) {
	layerDHCPv4.Options = slices.DeleteFunc(layerDHCPv4.Options, func(opt layers.DHCPOption) bool {
		return opt.Type == optionType
	})
}

func SetOption(layerDHCPv4 *layers.DHCPv4, newOption layers.DHCPOption) {
	// Remove every RFC 3396 split fragment of this type before appending the unified replacement.
	layerDHCPv4.Options = slices.DeleteFunc(layerDHCPv4.Options, func(opt layers.DHCPOption) bool {
		return opt.Type == newOption.Type
	})

	layerDHCPv4.Options = append(layerDHCPv4.Options, newOption)

	slices.SortFunc(layerDHCPv4.Options, func(a, b layers.DHCPOption) int {
		return cmp.Compare(a.Type, b.Type)
	})
}

func GetMessageType(layerDHCPv4 *layers.DHCPv4) string {
	opt53 := GetOption(layerDHCPv4, layers.DHCPOptMessageType)
	if !IsOption(opt53) || len(opt53.Data) == 0 || opt53.Length != 1 {
		return ""
	}

	val := layers.DHCPMsgType(opt53.Data[0])

	switch val {
	case layers.DHCPMsgTypeDiscover, layers.DHCPMsgTypeOffer, layers.DHCPMsgTypeRequest,
		layers.DHCPMsgTypeDecline, layers.DHCPMsgTypeAck, layers.DHCPMsgTypeNak,
		layers.DHCPMsgTypeRelease, layers.DHCPMsgTypeInform:
	default:
		return ""
	}

	return strings.ToUpper(val.String())
}
