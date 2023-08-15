# DHCPv4-Relay (opinionated Golang implementation).

This repository contains a DHCPv4 Relay agent written in Go (Golang). This relay agent listens for DHCPv4 requests and forwards them to the specified DHCPv4 server. The application is specially tailored to work in Kubernetes clusters using the `hostNetwork` container option but can also operate in any other Linux based environment.

### Features

- Listens to traffic on all interfaces without specifically binding to them.
- No restarts on interface changes.
- Supports forwarding to the DHCPv4 server via IP address or a dynamic DNS record (K8s Service).
- Uses BPF to filter out unrelated network traffic in kernel space.
- Minimalistic design with minimal configuration from CLI.
- On-demand runtime `pprof` endpoints availability for on-premises debugging.
- Requires only `CAP_NET_RAW` to operate.

### Non-features

- Support for DHCPv6 (DHCP for IPv6).
- Support for RFC3396 (split options).
- Explicit list of interfaces to bind to (upstream and/or downstream).
- Hot reloading for any CLI config options (obviously).
- Custom interface to range bindings via Link Selection sub-option.
- Full support for chained DHCPv4-Relay setups (point your relays directly to DHCP Server).

### Minimal operation expectations

- Linux kernel with AF_PACKET, BPF support.
- `CAP_NET_RAW`.
- Network connectivity to DHCPv4 server (and relayed clients).
- At least one Global unicast IPv4 address on the receiving network interface.
- Enough CPU/MEM resources for expected load footprint.

### Known Issues and Limitations

- No-op `PacketConn` listner on DHCPv4 Server port *(`Severity`: none)*.
- Some unrelated network traffic comes through to the application before BPF gets applied to the listening socket *(`Severity`: annoyance)*.
- Tested only on `linux,amd64` platform *(`Severity`: low)*.

### Additional Documentation & Resources

- [Dynamic Host Configuration Protocol basics](https://learn.microsoft.com/en-us/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics)
- [RFC2131: Dynamic Host Configuration Protoco](https://www.rfc-editor.org/rfc/rfc2131.html)l
- [RFC3046: DHCP Relay Agent Information Option](https://www.rfc-editor.org/rfc/rfc3046.html)
- [RFC3396: Encoding Long Options in the DHCPv4](https://www.rfc-editor.org/rfc/rfc3396.html)
- [RFC3527: Link Selection sub-option for the Relay Agent Information Option for DHCPv4](https://www.rfc-editor.org/rfc/rfc3527.html)
- [RFC5107: DHCP Server Identifier Override Suboption](https://www.rfc-editor.org/rfc/rfc5107.html)

### Contribution

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
