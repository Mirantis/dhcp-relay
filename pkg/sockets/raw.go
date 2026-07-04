// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package sockets

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ErrNotInitialized is returned when a Raw method is called before Create succeeds.
var ErrNotInitialized = errors.New("socket not initialized")

// Raw wraps a nonblocking AF_PACKET socket in an os.File so blocking calls park on the Go runtime poller.
type Raw struct {
	f *os.File
}

// Create opens an AF_PACKET SOCK_RAW socket for the given protocol like Htons(ETH_P_ALL) or Htons(ETH_P_IP).
func (r *Raw) Create(protocol uint16) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return err
	}

	// Drop locally transmitted frames so the relay never re-ingests its own forwarded packets
	// through this socket. Kernels before 4.20 lack the option, treat ENOPROTOOPT as a no-op.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil &&
		!errors.Is(err, unix.ENOPROTOOPT) {
		_ = unix.Close(fd)

		return fmt.Errorf("set PACKET_IGNORE_OUTGOING: %w", err)
	}

	// A nonblocking descriptor makes os.NewFile register it with the runtime poller.
	if r.f != nil {
		_ = r.f.Close()
	}

	r.f = os.NewFile(uintptr(fd), "af-packet") //nolint:gosec // G115: kernel FDs are non negative and fit uintptr.

	return nil
}

func (r *Raw) Close() error {
	if r.f == nil {
		return ErrNotInitialized
	}

	return r.f.Close()
}

// SetReadDeadline wakes a Receive blocked past t. A zero t clears the deadline.
func (r *Raw) SetReadDeadline(t time.Time) error {
	if r.f == nil {
		return ErrNotInitialized
	}

	return r.f.SetReadDeadline(t)
}

// control runs f on the descriptor through the file's SyscallConn so the call cannot race a concurrent Close.
func (r *Raw) control(f func(fd int) error) error {
	if r.f == nil {
		return ErrNotInitialized
	}

	rc, err := r.f.SyscallConn()
	if err != nil {
		return err
	}

	var opErr error

	//nolint:gosec // G115: FDs returned by the Go runtime fit in int on all supported platforms.
	if err := rc.Control(func(fd uintptr) { opErr = f(int(fd)) }); err != nil {
		return err
	}

	return opErr
}

// setLinkLayerAddr copies hwAddr into sa and sets Halen, returning an error if the address exceeds the sockaddr capacity.
func setLinkLayerAddr(sa *unix.SockaddrLinklayer, hwAddr net.HardwareAddr) error {
	if hwAddr == nil {
		return nil
	}

	if len(hwAddr) > len(sa.Addr) {
		return fmt.Errorf("hardware address length %d exceeds sockaddr capacity %d", len(hwAddr), len(sa.Addr))
	}

	sa.Halen = uint8(len(hwAddr)) //nolint:gosec // validated to fit uint8 and sa.Addr above.
	copy(sa.Addr[:], hwAddr)

	return nil
}

func (r *Raw) Bind(ifIndex int, hwAddr net.HardwareAddr, protocol uint16) error {
	sa := &unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  ifIndex,
	}

	if err := setLinkLayerAddr(sa, hwAddr); err != nil {
		return err
	}

	return r.control(func(fd int) error { return unix.Bind(fd, sa) })
}

func (r *Raw) AttachBPF(bytecode []unix.SockFilter) error {
	if len(bytecode) == 0 {
		return nil
	}

	fprog := unix.SockFprog{
		Len:    uint16(len(bytecode)), //nolint:gosec // BPF programs are bounded by the kernel filter limit.
		Filter: &bytecode[0],
	}

	return r.control(func(fd int) error {
		return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
	})
}

// Receive blocks until one frame arrives and returns its length and link layer source.
func (r *Raw) Receive(buf []byte) (int, *unix.SockaddrLinklayer, error) {
	if r.f == nil {
		return 0, nil, ErrNotInitialized
	}

	rc, err := r.f.SyscallConn()
	if err != nil {
		return 0, nil, err
	}

	var (
		n    int
		sa   unix.Sockaddr
		rerr error
	)

	err = rc.Read(func(fd uintptr) bool {
		//nolint:gosec // G115: FDs returned by the Go runtime fit in int on all supported platforms.
		n, sa, rerr = unix.Recvfrom(int(fd), buf, 0)

		// On EAGAIN wait on the poller for readability and try again.
		return !errors.Is(rerr, unix.EAGAIN)
	})
	if err != nil {
		return 0, nil, err
	}

	if rerr != nil {
		return n, nil, rerr
	}

	sall, ok := sa.(*unix.SockaddrLinklayer)
	if !ok {
		return n, nil, errors.New("unexpected source")
	}

	return n, sall, nil
}

func (r *Raw) Send(ifIndex int, hwAddr net.HardwareAddr, protocol uint16, buf []byte) (int, error) {
	if r.f == nil {
		return 0, ErrNotInitialized
	}

	sa := &unix.SockaddrLinklayer{
		Ifindex:  ifIndex,
		Protocol: protocol,
	}

	if err := setLinkLayerAddr(sa, hwAddr); err != nil {
		return 0, err
	}

	rc, err := r.f.SyscallConn()
	if err != nil {
		return 0, err
	}

	var serr error

	err = rc.Write(func(fd uintptr) bool {
		//nolint:gosec // G115: FDs returned by the Go runtime fit in int on all supported platforms.
		serr = unix.Sendto(int(fd), buf, 0, sa)

		// On EAGAIN wait on the poller for writability and try again.
		return !errors.Is(serr, unix.EAGAIN)
	})
	if err != nil {
		return 0, err
	}

	if serr != nil {
		return 0, serr
	}

	return len(buf), nil
}
