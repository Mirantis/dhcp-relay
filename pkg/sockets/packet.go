// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package sockets

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func ControlReuseAddrAndPort(_, _ string, c syscall.RawConn) error {
	var opErr error

	f := func(fd uintptr) {
		//nolint:gosec // FDs returned by the Go runtime fit in int on all supported platforms.
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if opErr != nil {
			return
		}

		//nolint:gosec // FDs returned by the Go runtime fit in int on all supported platforms.
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

func ListenPacketConn4(ctx context.Context, network string, addr net.IP, port uint16) (
	net.PacketConn, error,
) {
	if addr == nil {
		return nil, errors.New("addr must not be nil")
	}

	addr4 := addr.To4()
	if addr4 == nil {
		return nil, errors.New("addr must be a valid IPv4 address")
	}

	lc := net.ListenConfig{
		Control: ControlReuseAddrAndPort, // Set SO_REUSEADDR, SO_REUSEPORT.
	}

	conn, err := lc.ListenPacket(
		ctx,
		network,
		net.JoinHostPort(
			addr4.String(),
			strconv.Itoa(int(port)),
		),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
