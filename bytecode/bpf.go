//nolint:gomnd // pregenerated BPF bytecode with static jump offsets
package bytecode

import (
	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/specs"
)

// Note that `tcpdump` generates BPF bytecode, which, by default, disregards the Options field in the IPv4 header implicitly.
// As such, it is necessary to add an explicit rule to exclude frames that contain a variable-sized Options field in the IPv4 header.
// The value of the IHL (Internet Header Length) field exceeding 5 indicates that there is a variable-sized Options field present in the IPv4 header.
// The following PCAP filter rule adds this check: `(not (ip[0] & 0x0F > 5))`.

// tcpdump -ddd 'ip and (not (ip[0] & 0x0F > 5)) and udp and (dst port 67) and (len >= 244) and (len <= 1500)' -s 1500.
func GetBPFSockFilterForDHCPv4Messages(mtu uint32) []unix.SockFilter {
	return []unix.SockFilter{
		// Load EtherType field from the ethernet header.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: EthernetFieldOffsetEtherType / 8},
		// If EtherType equals to IP (0x800), continue, else skip 14 instructions ahead.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 14, K: unix.ETH_P_IP},
		// Load the IP header length field from the IP header.
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: specs.EthernetHeaderLength / 8},
		// Keep only the lower 4 bits of the IP header length (which contains the actual length value).
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: IPv4FieldBitMaskIHL},
		// If IP header length is greater than 5 (which means IP options are present), skip 11 instructions ahead, else continue.
		{Code: unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K, Jt: 11, K: specs.IPv4FieldIHLValueThresholdForOptionsFieldPresence},
		// Load the Protocol field from the IP header.
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: (specs.EthernetHeaderLength + IPv4FieldOffsetProtocol) / 8},
		// If Protocol field equals to UDP (17), continue, else skip 9 instructions ahead.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 9, K: unix.IPPROTO_UDP},
		// Load the Flags field from the IP header.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: (specs.EthernetHeaderLength + IPv4FieldOffsetFlags) / 8},
		// If any fragment bit in Flags is set, skip 7 instructions ahead, else continue.
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 7, Jf: 0, K: unix.IP_OFFMASK},
		// Load the length of the IP header into X.
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: specs.EthernetHeaderLength / 8},
		// Load the Destination Port field from the UDP header.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: UDPFieldOffsetDestinationPort},
		// If Destination Port equals to DHCP Server Port (67), continue, else skip 4 instructions ahead.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: specs.DHCPv4ServerPort},
		// Load the total length of the packet.
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_LEN},
		// If total length is greater or equal to minimum DHCPv4 message size, continue, else skip 2 instructions ahead.
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 2, K: specs.DHCPv4MinMessageSize},
		// If total length is greater than common DHCPv4 message size, skip 1 instructions ahead, else continue.
		{Code: unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K, Jt: 1, K: mtu},
		// Return the common DHCPv4 message size. This tells the kernel how many bytes to keep.
		{Code: unix.BPF_RET | unix.BPF_K, K: mtu},
		// If none of the conditions are met, return 0. This tells the kernel to drop the packet.
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}
