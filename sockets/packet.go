//nolint:wrapcheck // return all errors from function wrappers unwrapped
package sockets

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func ControlReuseAddrAndPort(_, _ string, c syscall.RawConn) error {
	var opErr error

	f := func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if opErr != nil {
			return
		}

		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		if opErr != nil {
			return
		}
	}

	if err := c.Control(f); err != nil {
		return err
	}

	return opErr
}

func ListenPacketConn4(network string, addr net.IP, port uint16) (
	net.PacketConn, error,
) {
	lc := net.ListenConfig{
		Control: ControlReuseAddrAndPort, // Set SO_REUSEADDR, SO_REUSEPORT.
	}

	conn, err := lc.ListenPacket(
		context.Background(),
		network,
		net.JoinHostPort(
			addr.To4().String(),
			strconv.Itoa(int(port)),
		),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
