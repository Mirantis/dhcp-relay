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

//nolint:gochecknoglobals // CLI configuration flags
var (
	flagUpstreamDHCPServerAddr string

	flagLogWithoutDatetime bool
	flagReplyTTL           uint64
	flagMTU                uint64

	flagDebug           bool
	flagDebugServerAddr string
)

//nolint:gochecknoglobals // Logger
var (
	cl *logger.Config
)
