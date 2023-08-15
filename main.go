//go:build linux && amd64
// +build linux,amd64

package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/bytecode"
	"code.local/dhcp-relay/gpckt"
	"code.local/dhcp-relay/logger"
	"code.local/dhcp-relay/sockets"
	"code.local/dhcp-relay/specs"
	"code.local/dhcp-relay/version"
)

// Note: This code requires CAP_NET_RAW capability.

func main() {
	flag.StringVar(&flagUpstreamDHCPServerAddr,
		"dhcp-server-address", "", "Address of upstream DHCPv4 server.")
	flag.BoolVar(&flagLogWithoutDatetime,
		"log-no-datetime", false, "Log without datetime prefix (systemd).")
	flag.Uint64Var(&flagReplyTTL,
		"reply-ttl", 1, "Custom TTL for DHCPv4 replies.")
	flag.Uint64Var(&flagMTU,
		"mtu", specs.EthernetCommonMTU, "Set MTU value for ingress traffic filter.")

	flag.BoolVar(&flagDebug,
		"debug", false, "Enable debug mode.")
	flag.StringVar(&flagDebugServerAddr,
		"debug-server", "localhost:8080", "Debug web server address.")

	flag.Usage = func() {
		_, err := fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s (version: %s):\n",
			os.Args[0], version.VCS(vcsAbbRevisionNum))
		if err != nil {
			panic(err)
		}

		flag.PrintDefaults()
	}

	flag.Parse()

	if flagLogWithoutDatetime {
		cl = logger.NewWithoutDatetime()
	} else {
		cl = logger.NewWithDatetime()
	}

	if flagDebug {
		cl.EnableVerbose()
		debug(flagDebugServerAddr)
	} else {
		cl.DisableVerbose()
	}

	if flagUpstreamDHCPServerAddr == "" {
		cl.Fatalf("Upstream DHCPv4 server value must be specified.\n")
	}

	if flagReplyTTL < 1 || flagReplyTTL > math.MaxUint8 {
		cl.Fatalf("Reply TTL must be in range of 1...%d.\n", math.MaxUint8)
	}

	if flagMTU < specs.DHCPv4MinMessageSize || flagMTU > math.MaxUint16 {
		cl.Fatalf("MTU must be in range of %d...%d.\n", specs.DHCPv4MinMessageSize, math.MaxUint16)
	}

	cl.Infof("DHCPv4-Relay version: %s\n", version.VCS(vcsAbbRevisionNum))
	cl.Debugf("DEBUG LOG IS ENABLED.\n")

	rs := new(sockets.Raw)

	err := rs.Create(sockets.Htons(unix.ETH_P_IP))
	if err != nil {
		cl.Fatalf("Error creating socket: %v\n", err)
	}

	defer func(rs *sockets.Raw) {
		err = rs.Close()
		if err != nil {
			cl.Warnf("Error closing socket: %v\n", err)
		}
	}(rs)

	bpfBytecode := bytecode.GetBPFSockFilterForDHCPv4Messages(uint32(flagMTU))
	cl.Debugf("BPF bytecode: %+v\n", bpfBytecode)

	err = rs.AttachBPF(bpfBytecode)
	if err != nil {
		cl.Errorf("Error attaching BPF to socket: %v\n", err)

		return
	}

	pconn, err := sockets.ListenPacketConn4("udp4", net.IPv4zero, specs.DHCPv4ServerPort)
	if err != nil {
		cl.Errorf("Error binding to UDP4 socket: %v\n", err)

		return
	}
	defer pconn.Close()

	cfg := &HandleOptions{
		PacketConn:        pconn,
		DHCPServerAddress: flagUpstreamDHCPServerAddr,
		ReplyTTL:          uint8(flagReplyTTL),
	}

	for {
		buf := make([]byte, int(flagMTU)) //nolint:makezero // C-style for bytes slices is fine here

		n, sall, err := rs.Receive(buf)
		if err != nil {
			cl.Errorf("Error reading from socket: %v\n", err)

			continue
		}

		cl.Debugf("Received %d bytes of data from socket\n", n)

		if sall.Ifindex < 1 {
			cl.Debugf("Invalid IfIndex value: %d\n", sall.Ifindex)

			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Default)
		layerEthernet := gpckt.GetEthernet(packet)
		layerIPv4 := gpckt.GetIPv4(packet)
		layerUDP := gpckt.GetUDP(packet)
		layerDHCPv4 := gpckt.GetDHCPv4(packet)

		err = ValidateLayers(layerEthernet, layerIPv4, layerUDP, layerDHCPv4, uint16(flagMTU))
		if err != nil {
			cl.Debugf("Packet validation error: %s\n", err)

			continue
		}

		go HandleDHCPv4(cfg, sall, layerEthernet, layerIPv4, layerUDP, layerDHCPv4)
	}
}
