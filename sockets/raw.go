//nolint:wrapcheck // return all errors from `unix.*` unwrapped
package sockets

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type Raw struct {
	fd int
}

// Create socket with AF_PACKET, SOCK_RAW, and specified protocol.
// Example:
//   - sockets.Create(sockets.Htons(unix.ETH_P_ALL))
//   - sockets.Create(sockets.Htons(unix.ETH_P_IP))
//   - ...
func (r *Raw) Create(protocol uint16) error {
	var err error

	r.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(protocol))
	if err != nil {
		return err
	}

	unix.CloseOnExec(r.fd)

	return nil
}

func (r *Raw) Close() error {
	return unix.Close(r.fd)
}

func (r *Raw) Bind(ifIndex int, hwAddr net.HardwareAddr, protocol uint16) error {
	sa := &unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  ifIndex,
	}

	if hwAddr != nil {
		sa.Halen = uint8(len(hwAddr))
		copy(sa.Addr[:], hwAddr)
	}

	return unix.Bind(r.fd, sa)
}

func (r *Raw) AttachBPF(bytecode []unix.SockFilter) error {
	if len(bytecode) == 0 {
		return nil
	}

	fprog := unix.SockFprog{
		Len:    uint16(len(bytecode)),
		Filter: &bytecode[0],
	}

	return unix.SetsockoptSockFprog(r.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}

func (r *Raw) Receive(buf []byte) (int, *unix.SockaddrLinklayer, error) {
	n, sa, err := unix.Recvfrom(r.fd, buf, 0)

	sall, ok := sa.(*unix.SockaddrLinklayer)
	if !ok {
		return n, nil, fmt.Errorf("unexpected source")
	}

	if err != nil {
		return n, sall, err
	}

	return n, sall, nil
}

func (r *Raw) Send(ifIndex int, hwAddr net.HardwareAddr, protocol uint16, buf []byte) (int, error) {
	sa := &unix.SockaddrLinklayer{
		Ifindex:  ifIndex,
		Protocol: protocol,
	}

	if hwAddr != nil {
		sa.Halen = uint8(len(hwAddr))
		copy(sa.Addr[:], hwAddr)
	}

	err := unix.Sendto(r.fd, buf, 0, sa)
	if err != nil {
		return 0, err
	}

	return len(buf), nil
}
