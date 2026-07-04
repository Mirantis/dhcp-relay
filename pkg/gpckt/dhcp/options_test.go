// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package dhcp_test

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
)

// TestDeleteSplitOptions is table driven over the RFC 3396 de duplicate filter.
func TestDeleteSplitOptions(t *testing.T) {
	opt1 := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})
	opt2 := layers.NewDHCPOption(layers.DHCPOptRouter, []byte{192, 168, 1, 1})
	pad := layers.DHCPOption{Type: layers.DHCPOptPad}
	end := layers.DHCPOption{Type: layers.DHCPOptEnd}

	tests := []struct {
		name string
		in   []layers.DHCPOption
		want []layers.DHCPOption
	}{
		{
			name: "no duplicates end dropped",
			in:   []layers.DHCPOption{opt1, opt2, end},
			want: []layers.DHCPOption{opt1, opt2},
		},
		{
			name: "duplicates merged",
			in:   []layers.DHCPOption{opt1, opt1, opt2},
			want: []layers.DHCPOption{opt2},
		},
		{
			name: "pad skipped end dropped",
			in:   []layers.DHCPOption{pad, opt1, pad, end},
			want: []layers.DHCPOption{opt1},
		},
		{
			name: "multiple duplicates",
			in:   []layers.DHCPOption{opt1, opt1, opt2, opt2, end},
			want: []layers.DHCPOption{},
		},
		{
			name: "empty input",
			in:   nil,
			want: []layers.DHCPOption{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make([]layers.DHCPOption, len(tt.in))
			copy(in, tt.in)

			got := dhcp.DeleteSplitOptions(in...)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeleteSplitOptions = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsOption is true only when Length is positive.
func TestIsOption(t *testing.T) {
	if dhcp.IsOption(layers.DHCPOption{}) {
		t.Error("zero option must not be an option")
	}

	if !dhcp.IsOption(layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})) {
		t.Error("option with data must be an option")
	}
}

// TestGetOption returns the matching option or a zero option.
func TestGetOption(t *testing.T) {
	mask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})
	layer := &layers.DHCPv4{Options: []layers.DHCPOption{mask}}

	if got := dhcp.GetOption(layer, layers.DHCPOptSubnetMask); !reflect.DeepEqual(got, mask) {
		t.Errorf("GetOption existing = %v, want %v", got, mask)
	}

	if got := dhcp.GetOption(layer, layers.DHCPOptRouter); dhcp.IsOption(got) {
		t.Errorf("GetOption missing = %v, want zero option", got)
	}
}

// TestSetOption adds then replaces and keeps options sorted by type.
func TestSetOption(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		layer := &layers.DHCPv4{}
		mask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})

		dhcp.SetOption(layer, mask)

		if len(layer.Options) != 1 || !reflect.DeepEqual(layer.Options[0], mask) {
			t.Fatalf("options = %v, want [%v]", layer.Options, mask)
		}
	})

	t.Run("replace", func(t *testing.T) {
		mask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{mask}}

		newMask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 0, 0})
		dhcp.SetOption(layer, newMask)

		if len(layer.Options) != 1 || !reflect.DeepEqual(layer.Options[0], newMask) {
			t.Fatalf("options = %v, want [%v]", layer.Options, newMask)
		}
	})

	t.Run("sorted", func(t *testing.T) {
		router := layers.NewDHCPOption(layers.DHCPOptRouter, []byte{192, 168, 1, 1})
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{router}}

		mask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})
		dhcp.SetOption(layer, mask)

		want := layers.DHCPOptions{mask, router}
		if !reflect.DeepEqual(layer.Options, want) {
			t.Errorf("options = %v, want %v", layer.Options, want)
		}
	})
}

// TestDeleteOption removes the option and ignores a missing type.
func TestDeleteOption(t *testing.T) {
	mask := layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0})
	router := layers.NewDHCPOption(layers.DHCPOptRouter, []byte{192, 168, 1, 1})

	t.Run("remove", func(t *testing.T) {
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{mask, router}}

		dhcp.DeleteOption(layer, layers.DHCPOptSubnetMask)

		if len(layer.Options) != 1 || layer.Options[0].Type != layers.DHCPOptRouter {
			t.Fatalf("options = %v, want [%v]", layer.Options, router)
		}
	})

	t.Run("missing no op", func(t *testing.T) {
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{mask}}

		dhcp.DeleteOption(layer, layers.DHCPOptRouter)

		if !reflect.DeepEqual(layer.Options, layers.DHCPOptions{mask}) {
			t.Errorf("options = %v, want unchanged", layer.Options)
		}
	})
}

// TestGetMessageType maps opt 53 to its upper case name.
func TestGetMessageType(t *testing.T) {
	t.Run("discover", func(t *testing.T) {
		opt53 := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)})
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{opt53}}

		if got := dhcp.GetMessageType(layer); got != "DISCOVER" {
			t.Errorf("GetMessageType = %q, want %q", got, "DISCOVER")
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		opt53 := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{0})
		layer := &layers.DHCPv4{Options: []layers.DHCPOption{opt53}}

		if got := dhcp.GetMessageType(layer); got != "" {
			t.Errorf("GetMessageType = %q, want %q", got, "")
		}
	})

	t.Run("missing opt 53", func(t *testing.T) {
		layer := &layers.DHCPv4{}

		if got := dhcp.GetMessageType(layer); got != "" {
			t.Errorf("GetMessageType = %q, want %q", got, "")
		}
	})
}

// TestUnicastBroadcastFlags toggles the broadcast bit of the Flags field.
func TestUnicastBroadcastFlags(t *testing.T) {
	layer := &layers.DHCPv4{}

	if !dhcp.IsUnicast(layer) {
		t.Error("fresh Flags must read as unicast")
	}
	if dhcp.IsBroadcast(layer) {
		t.Error("fresh Flags must not read as broadcast")
	}

	dhcp.SetBroadcast(layer)

	if !dhcp.IsBroadcast(layer) {
		t.Error("after SetBroadcast the layer must read as broadcast")
	}
	if dhcp.IsUnicast(layer) {
		t.Error("after SetBroadcast the layer must not read as unicast")
	}

	dhcp.SetUnicast(layer)

	if !dhcp.IsUnicast(layer) {
		t.Error("after SetUnicast the layer must read as unicast")
	}
	if dhcp.IsBroadcast(layer) {
		t.Error("after SetUnicast the layer must not read as broadcast")
	}
}

// TestGetBootFileName trims and returns the File field.
func TestGetBootFileName(t *testing.T) {
	t.Run("named", func(t *testing.T) {
		layer := &layers.DHCPv4{File: []byte("pxelinux.0")}

		if got := dhcp.GetBootFileName(layer); got != "pxelinux.0" {
			t.Errorf("GetBootFileName = %q, want %q", got, "pxelinux.0")
		}
	})

	t.Run("empty", func(t *testing.T) {
		layer := &layers.DHCPv4{}

		if got := dhcp.GetBootFileName(layer); got != "" {
			t.Errorf("GetBootFileName = %q, want %q", got, "")
		}
	})

	t.Run("whitespace only", func(t *testing.T) {
		layer := &layers.DHCPv4{File: []byte("   ")}

		if got := dhcp.GetBootFileName(layer); got != "" {
			t.Errorf("GetBootFileName = %q, want %q", got, "")
		}
	})
}
