package main

import (
	"net"
)

func GetInterfaceGlobalUnicastAddrs4(ifIndex int) []net.IPNet {
	if ifIndex == 0 {
		return nil
	}

	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}

	out := make([]net.IPNet, 0, len(addrs))

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			continue
		case *net.IPNet:
			if v == nil || v.IP == nil || !v.IP.IsGlobalUnicast() || v.IP.To4() == nil {
				continue
			}

			out = append(out, *v)
		}
	}

	return out
}
