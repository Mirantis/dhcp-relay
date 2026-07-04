// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package relay_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs the package tests under goleak to catch leaked goroutines.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
