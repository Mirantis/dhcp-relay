// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs the package tests under goleak to catch a leaked goroutine such as a watch poller a test forgot to Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
