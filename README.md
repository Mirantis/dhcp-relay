# DHCPv4-Relay (opinionated Golang implementation).

This repository contains a DHCPv4 Relay agent written in Go (Golang). This relay agent listens for DHCPv4 requests and forwards them to the specified DHCPv4 server. The application is specially tailored to work in Kubernetes clusters using the `hostNetwork` container option but can also operate in any other Linux based environment.

### Features

- Listens to traffic on all interfaces without specifically binding to them.
- No restarts on interface changes.
- Supports forwarding to the DHCPv4 server via IP address or a dynamic DNS record (K8s Service).
- Optional per-client policy (match MAC or DHCP client-id; forward via the default or a specific upstream, or blackhole), with a `*` catch-all, reloaded automatically when the policy file changes.
- Replies honor the DHCP broadcast flag per RFC 2131: a broadcast-flag reply is sent to the Ethernet broadcast address, a unicast reply goes to the client's MAC and leased address. The `-broadcast-reply-l2-unicast` flag opts out, delivering broadcast-flag replies to the client's unicast MAC at layer 2 (the IP destination stays 255.255.255.255) for segments that drop or rate-limit broadcast frames.
- Graceful shutdown on SIGINT/SIGTERM: the receive loop exits and cleanup (policy poller, debug server, sockets) runs before the process ends.
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
- Tested on `linux/amd64` and `linux/arm64` platforms *(`Severity`: low)*.

### MAC policy

`-mac-policy <file>` applies a per-client policy (for example `-mac-policy /etc/dhcp-relay/policy.txt`). The file is polled every `-mac-policy-interval` (default 30s) and reloaded when its size, mtime, or inode changes. An in-place edit that changes none of those three is not detected until the next real change. Each line is `<key> [<action>] [<reply>]`. The `key` is a MAC, a `0x`-prefixed hex client identifier (DHCPv4 Option 61), or `*` (catch-all), matched against the client's Option 61 (preferred) then its `chaddr`. The `action` is `@default` (relay via `-dhcp-server-address`), `@blackhole` (drop), a server IP/hostname, or empty (same as `@default`). The optional `reply` field picks the outgoing NIC(s) for the client's replies: `@default` (or omitted) keeps the Option 82 ingress NIC, `@blackhole` drops the reply, `*` floods every up NIC (including the one facing the DHCP server, so prefer `name=`/`mac=` terms that select only client segments), and comma-separated `name=<glob>`/`mac=<glob>` terms match NICs by interface name or MAC, with `mac=` globs matched case-insensitively. Zero matches fall back to the ingress NIC and are logged, and a match that excludes the ingress NIC logs a warning since the requesting client's segment gets no copy. A unicast reply copy sent out a non-ingress NIC is sourced from that NIC's own IPv4 address (a matched NIC without one is skipped and reported). The NIC list used for matching is cached for 1 second by default; set `-reply-nic-cache-ttl` (a Go duration, e.g. `500ms`; zero or negative disables the cache) to change that:

```
# comments and blank lines ignored
aa:bb:cc:dd:ee:ff                          # relay via -dhcp-server-address, reply out the ingress NIC
0x01aabbccddeeff   10.0.0.5                # match Option 61, relay to a specific upstream
11:22:33:44:55:66  @default      name=eth* # reply out NICs named eth* (forward unchanged)
22:33:44:55:66:77  @blackhole              # drop the client
33:44:55:66:77:88  @default     @blackhole # forward, but drop the reply
*                  @default                # default for everyone else
```

A bare-MAC key must be a 6-byte Ethernet address; use the `0x` hex form for any other client identifier (the bytes must include the Option 61 type byte, e.g. `0x01` for Ethernet). A `0x` key is capped at 241 bytes so its policy tag always fits Option 82 next to the relay's circuit id sub-option. With no `*` line, unmatched clients are dropped (a strict allow-list). Server values must be a valid IP or a resolvable hostname. A malformed file, or an unresolvable server, is fatal at startup but only logged on reload (previous policy kept). Replace the file atomically (write a temporary file then rename it over the policy file) so the poller never reads a half-written file. If the file does change while a reload is reading it, that reload is discarded and retried on the next poll. A comment runs from a `#` that starts a line or follows whitespace, so trailing comments work and a literal `#` may appear inside a value such as an interface-name glob.

To apply the `reply` action the relay must re-identify the client when the server's reply comes back. It embeds the matched policy key in an Option 82 sub-option on the request, and since servers echo Option 82 back (RFC 3046) the relay reads the key off the reply and reapplies the same entry, even for `0x` Option 61 keys that the server does not echo itself. When the reply carries no usable tag (the request matched `*` so no key was embedded, the tag did not fit, or the tag no longer matches an entry after a reload), the relay falls back to matching the reply by its Option 61 then `chaddr`. A server that strips Option 82 entirely breaks reply delivery itself, not just the policy: the relay needs its own Agent Circuit ID sub-option to pick the egress NIC, so such replies are dropped and logged.

### Additional Documentation & Resources

- [Dynamic Host Configuration Protocol basics](https://learn.microsoft.com/en-us/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics)
- [RFC2131: Dynamic Host Configuration Protoco](https://www.rfc-editor.org/rfc/rfc2131.html)
- [RFC3046: DHCP Relay Agent Information Option](https://www.rfc-editor.org/rfc/rfc3046.html)
- [RFC3396: Encoding Long Options in the DHCPv4](https://www.rfc-editor.org/rfc/rfc3396.html)
- [RFC3527: Link Selection sub-option for the Relay Agent Information Option for DHCPv4](https://www.rfc-editor.org/rfc/rfc3527.html)
- [RFC5010: Relay Agent Flags Suboption](https://www.rfc-editor.org/rfc/rfc5010.html)
- [RFC5107: DHCP Server Identifier Override Suboption](https://www.rfc-editor.org/rfc/rfc5107.html)

### Contribution

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
