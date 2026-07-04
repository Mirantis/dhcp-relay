// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	rtdebug "runtime/debug"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/bytecode"
	"code.local/dhcp-relay/pkg/debug"
	"code.local/dhcp-relay/pkg/dhcp4"
	"code.local/dhcp-relay/pkg/filewatch"
	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/linkmap"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/macpolicy"
	"code.local/dhcp-relay/pkg/relay"
	"code.local/dhcp-relay/pkg/sockets"
	"code.local/dhcp-relay/pkg/specs"
	"code.local/dhcp-relay/pkg/version"
)

const (
	vcsAbbRevisionNum = 8

	// Expected layer chain depth Ethernet then IPv4 then UDP then DHCPv4.
	dhcpLayerChainDepth = 4

	// ShutdownGracePeriod bounds how long main waits for in flight handler goroutines on shutdown.
	shutdownGracePeriod = 5 * time.Second

	// DefaultMaxHandlers caps concurrent DHCPv4 handler goroutines so a flood cannot exhaust fds and memory.
	DefaultMaxHandlers = 65535
)

var (
	flagUpstreamDHCPServerAddr string
	flagMACPolicy              string
	flagMACPolicyInterval      time.Duration

	flagLinkMap         string
	flagLinkMapInterval time.Duration
	flagGiaddr          string

	flagLogWithoutDatetime bool
	flagReplyTTL           uint64
	flagMTU                uint64

	flagDebug           bool
	flagDebugServerAddr string

	flagVerifyChecksums bool

	flagBroadcastReplyL2Unicast bool
	flagReplyNICCacheTTL        time.Duration

	flagMaxHandlers uint64

	flagMaxHops uint64

	flagVersion bool

	cl *logger.Config

	// HandlersWG tracks in flight dhcp4.Handle goroutines so shutdown can wait for replies instead of killing them mid send.
	handlersWG  sync.WaitGroup
	handlersSem chan struct{}
)

// This project requires CAP_NET_RAW capability.

func main() {
	flag.StringVar(&flagUpstreamDHCPServerAddr,
		"dhcp-server-address", "", "Address of upstream DHCPv4 server.")
	flag.StringVar(&flagMACPolicy,
		"mac-policy", "", "Path to the MAC policy file. Empty disables the policy.")
	flag.DurationVar(&flagMACPolicyInterval,
		"mac-policy-interval", filewatch.DefaultPollInterval, "Poll interval for reloading the MAC policy file.")
	flag.StringVar(&flagLinkMap,
		"link-map", "", "Path to the ingress NIC to subnet link map for unnumbered relay interfaces. Empty disables it.")
	flag.DurationVar(&flagLinkMapInterval,
		"link-map-interval", filewatch.DefaultPollInterval, "Poll interval for reloading the link map file.")
	flag.StringVar(&flagGiaddr,
		"giaddr", "", "Override the giaddr for an unnumbered ingress. Empty auto-derives the server-facing address.")
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

	flag.BoolVar(&flagVerifyChecksums,
		"verify-checksums", false, "Verify IPv4 and UDP checksums on received packets.")

	flag.BoolVar(&flagBroadcastReplyL2Unicast,
		"broadcast-reply-l2-unicast", false,
		"Send broadcast-flag DHCPv4 replies to the client unicast MAC at layer 2 "+
			"instead of the Ethernet broadcast address (RFC 2131 default).")

	flag.DurationVar(&flagReplyNICCacheTTL,
		"reply-nic-cache-ttl", dhcp4.DefaultInterfaceCacheTTL,
		"How long the reply NIC list is cached before refresh (zero or negative disables caching).")

	flag.BoolVar(&flagVersion,
		"version", false, "Print binary version and exit.")

	flag.Uint64Var(&flagMaxHandlers,
		"max-handlers", DefaultMaxHandlers, "Maximum concurrent DHCPv4 handler goroutines. Excess packets are dropped.")

	flag.Uint64Var(&flagMaxHops,
		"max-hops", specs.DHCPv4MaxHops, "Maximum DHCPv4 relay hop count. Packets at or above this value are dropped.")

	flag.Usage = func() {
		//nolint:gosec // G705: writing to stderr, not an untrusted sink.
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

	if flagVersion {
		cl.Infof("DHCPv4-Relay version: %s\n", version.VCS(vcsAbbRevisionNum))

		os.Exit(0)
	}

	if flagDebug {
		cl.EnableVerbose()

		if srv := debug.Serve(flagDebugServerAddr, cl); srv != nil {
			defer debug.Shutdown(srv, cl)
		}
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

	if flagMaxHandlers < 1 || flagMaxHandlers > math.MaxInt32 {
		cl.Fatalf("Max handlers must be in range of 1...%d.\n", math.MaxInt32)
	}

	if flagMaxHops < 1 || flagMaxHops > math.MaxUint8 {
		cl.Fatalf("Max hops must be in range of 1...%d.\n", math.MaxUint8)
	}

	var giaddr net.IP

	if flagGiaddr != "" {
		giaddr = net.ParseIP(flagGiaddr).To4()
		// Require global unicast so the reply path recognizes the echoed giaddr as locally deliverable. A
		// loopback, link-local, or multicast giaddr would make the server reply route away from the client.
		if !dhcp4.IsGlobalUnicastIPv4(giaddr) {
			cl.Fatalf("giaddr must be a global unicast IPv4 address, got %q.\n", flagGiaddr)
		}
	}

	if flagGiaddr != "" && flagLinkMap == "" {
		cl.Warnf("-giaddr has no effect without -link-map (a numbered ingress uses its own address as giaddr)\n")
	}

	cl.Infof("DHCPv4-Relay version: %s\n", version.VCS(vcsAbbRevisionNum))
	cl.Debugf("DEBUG LOG IS ENABLED.\n")

	var policy *macpolicy.Map

	if flagMACPolicy != "" {
		m, err := macpolicy.New(flagMACPolicy, flagMACPolicyInterval, cl)
		if err != nil {
			cl.Fatalf("Error loading MAC policy: %v\n", err)
		}

		policy = m

		defer m.Close()
	}

	var links *linkmap.Map

	if flagLinkMap != "" {
		lm, err := linkmap.New(flagLinkMap, flagLinkMapInterval, cl)
		if err != nil {
			cl.Fatalf("Error loading link map: %v\n", err)
		}

		links = lm

		defer lm.Close()
	}

	// A shutdown signal must run the deferred cleanup above so the process is not killed with it pending.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer stop()

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

	bpfBytecode := bytecode.GetBPFSockFilterForDHCPv4Messages(uint32(flagMTU)) //nolint:gosec // flagMTU bounded <= MaxUint16 above
	cl.Debugf("BPF bytecode: %+v\n", bpfBytecode)

	err = rs.AttachBPF(bpfBytecode)
	if err != nil {
		cl.Errorf("Error attaching BPF to socket: %v\n", err)

		return
	}

	pconn, err := sockets.ListenPacketConn4(ctx, "udp4", net.IPv4zero, specs.DHCPv4ServerPort)
	if err != nil {
		cl.Errorf("Error binding to UDP4 socket: %v\n", err)

		return
	}

	// A drop all BPF on the send only UDP socket guarantees nothing can ever be read from it.
	ppconn := ipv4.NewPacketConn(pconn)
	if err := ppconn.SetBPF([]bpf.RawInstruction{
		{Op: unix.BPF_RET | unix.BPF_K, Jt: 0, Jf: 0, K: 0}, // filter ALL
	}); err != nil {
		cl.Errorf("Error attaching BPF to UDP4 socket: %v\n", err)

		return
	}
	cfg := &dhcp4.HandleOptions{
		Logger:                  cl,
		PacketConn:              pconn,
		ReplyInterfaceCache:     dhcp4.NewInterfaceCache(flagReplyNICCacheTTL),
		Giaddr:                  giaddr,
		DHCPServerAddress:       flagUpstreamDHCPServerAddr,
		MaxHops:                 uint8(flagMaxHops), //nolint:gosec // flagMaxHops bounded <= MaxUint8 above
		BroadcastReplyL2Unicast: flagBroadcastReplyL2Unicast,
		ReplyTTL:                uint8(flagReplyTTL), //nolint:gosec // flagReplyTTL bounded <= MaxUint8 above
	}

	// Assign only a live map so the LinkSubnetLookup interface stays nil when no link map is configured.
	if links != nil {
		cfg.LinkMap = links
	}

	// An expired read deadline wakes the blocked Receive so the loop can observe the context and return.
	stopWake := context.AfterFunc(ctx, func() { _ = rs.SetReadDeadline(time.Now()) })
	defer stopWake()

	handlersSem = make(chan struct{}, int(flagMaxHandlers)) //nolint:gosec // flagMaxHandlers bounded <= MaxInt32 above

	for {
		//nolint:makezero,gosec // C-style byte buffer; flagMTU bounded <= MaxUint16 above.
		buf := make([]byte, int(flagMTU))

		n, sall, err := rs.Receive(buf)
		if err != nil {
			if ctx.Err() != nil {
				cl.Infof("Shutdown signal received, exiting.\n")

				// A second signal during the drain forces an immediate exit. Registered now so it only sees the next signal.
				forceQuit := make(chan os.Signal, 1)
				signal.Notify(forceQuit, os.Interrupt, unix.SIGTERM)
				stop() // stop the NotifyContext so only forceQuit receives signals during drain

				switch waitForHandlers(&handlersWG, forceQuit, shutdownGracePeriod) {
				case drainForced:
					cl.Warnf("Second shutdown signal received, exiting with handler(s) in flight\n")
				case drainTimedOut:
					cl.Warnf("Shutdown grace period expired, handler(s) still in flight\n")
				case drainCompleted:
					_ = pconn.Close()
				}

				return
			}

			cl.Errorf("Error reading from socket: %v\n", err)

			continue
		}

		cl.Debugf("Received %d bytes of data from socket\n", n)

		handlePacket(ctx, cl, cfg, policy, sall, buf[:n])
	}
}

// handlePacket decodes and validates one received frame then hands it to the DHCPv4 handler goroutine.
func handlePacket(
	ctx context.Context,
	cl *logger.Config,
	cfg *dhcp4.HandleOptions,
	policy *macpolicy.Map,
	sall *unix.SockaddrLinklayer,
	data []byte,
) {
	defer func() {
		if r := recover(); r != nil {
			cl.Errorf("Recovered DHCPv4 receive panic: IfIndex=%d: %v\n%s", sall.Ifindex, r, rtdebug.Stack())
		}
	}()

	if sall.Ifindex < 1 {
		cl.Debugf("Invalid IfIndex value: %d\n", sall.Ifindex)

		return
	}

	var (
		layerEthernet layers.Ethernet
		layerIPv4     layers.IPv4
		layerUDP      layers.UDP
		layerDHCPv4   layers.DHCPv4
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&layerEthernet, &layerIPv4, &layerUDP, &layerDHCPv4,
	)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, dhcpLayerChainDepth)

	err := parser.DecodeLayers(data, &decoded)
	if err != nil {
		cl.Debugf("Packet decode error: %s\n", err)

		return
	}

	if len(decoded) != dhcpLayerChainDepth || decoded[len(decoded)-1] != layers.LayerTypeDHCPv4 {
		cl.Debugf("Incomplete DHCPv4 layer chain: %v\n", decoded)

		return
	}

	err = dhcp4.ValidateLayers(
		dhcp4.ValidateOptions{
			MTU:             uint16(flagMTU), //nolint:gosec // flagMTU bounded <= MaxUint16 above.
			VerifyChecksums: flagVerifyChecksums,
		},
		&layerEthernet, &layerIPv4, &layerUDP, &layerDHCPv4,
	)
	if err != nil {
		cl.Debugf("Packet validation error: %s\n", err)

		return
	}

	// Drop RFC 3396 split options before the policy match so the policy decides on the same options the relay forwards
	layerDHCPv4.Options = dhcp.DeleteSplitOptions(layerDHCPv4.Options...)

	var dec *dhcp4.Decision

	if policy != nil {
		d, drop := relay.PolicyForPacket(policy, &layerDHCPv4)
		if drop {
			cl.Debugf("Dropping DHCPv4 message: client %s (blackhole)\n", layerDHCPv4.ClientHWAddr)

			return
		}

		dec = d
	}

	select {
	case handlersSem <- struct{}{}:
		handlersWG.Go(func() {
			defer func() { <-handlersSem }()
			// dhcp4.Handle recovers its own panic with package context, so the goroutine needs no second recover.
			dhcp4.Handle(ctx, cfg, dec, sall, &layerEthernet, &layerIPv4, &layerUDP, &layerDHCPv4)
		})
	default:
		cl.Warnf("Dropping DHCPv4 message from client %s handler pool full\n", layerDHCPv4.ClientHWAddr)
	}
}

// drainResult reports how waitForHandlers ended.
type drainResult int

const (
	drainCompleted drainResult = iota
	drainForced
	drainTimedOut
)

// waitForHandlers drains in flight handlers within grace returning early on forceQuit. It isolates the shutdown drain for testing.
// The wg.Wait goroutine blocks until wg reaches zero, callers returning without draining accept it leaks until process exit.
func waitForHandlers(wg *sync.WaitGroup, forceQuit <-chan os.Signal, grace time.Duration) drainResult {
	waitDone := make(chan struct{})

	go func() { wg.Wait(); close(waitDone) }()

	select {
	case <-waitDone:
		return drainCompleted
	case <-forceQuit:
		return drainForced
	case <-time.After(grace):
		return drainTimedOut
	}
}
