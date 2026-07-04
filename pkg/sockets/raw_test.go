// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package sockets_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"code.local/dhcp-relay/pkg/sockets"
)

const (
	wakeDelay   = 100 * time.Millisecond
	wakeTimeout = 5 * time.Second
	recvBufSize = 2048
)

// TestRawReceiveDeadlineWake checks that an expired read deadline wakes a blocked Receive.
func TestRawReceiveDeadlineWake(t *testing.T) {
	rs := new(sockets.Raw)

	if err := rs.Create(sockets.Htons(unix.ETH_P_ALL)); err != nil {
		t.Skipf("Create needs CAP_NET_RAW: %v", err)
	}

	t.Cleanup(func() { _ = rs.Close() })

	// Drop every frame in kernel space so the socket stays quiet and Receive blocks.
	if err := rs.AttachBPF([]unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}); err != nil {
		t.Fatalf("AttachBPF: %v", err)
	}

	go func() {
		time.Sleep(wakeDelay)

		_ = rs.SetReadDeadline(time.Now())
	}()

	done := make(chan error, 1)

	go func() {
		_, _, err := rs.Receive(make([]byte, recvBufSize))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Receive = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(wakeTimeout):
		t.Fatal("Receive did not wake on the read deadline")
	}
}
