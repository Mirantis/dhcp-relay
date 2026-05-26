// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package main

import (
	"code.local/dhcp-relay/logger"
)

const (
	vcsAbbRevisionNum = 8
)

const (
	logDataInPrefix  = "-->"
	logDataOutPrefix = "<--"
)

var (
	flagUpstreamDHCPServerAddr string

	flagLogWithoutDatetime bool
	flagReplyTTL           uint64
	flagMTU                uint64

	flagDebug           bool
	flagDebugServerAddr string
)

var cl *logger.Config
