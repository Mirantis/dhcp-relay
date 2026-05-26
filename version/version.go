// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package version

import (
	"runtime/debug"
	"strings"
)

func VCS(abbRevisionNum uint8) string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	var (
		vcsRevision []rune // vcs.revision
		abbRevision string
		vcsModified string // vcs.modified
	)

	for _, el := range buildInfo.Settings {
		switch el.Key {
		case "vcs.revision":
			vcsRevision = []rune(el.Value)
		case "vcs.modified":
			vcsModified = el.Value
		default:
			continue
		}
	}

	if len(vcsRevision) <= int(abbRevisionNum) {
		abbRevision = string(vcsRevision)
	} else {
		abbRevision = string(vcsRevision[:abbRevisionNum])
	}

	var rev string

	if strings.EqualFold(vcsModified, "true") {
		rev = abbRevision + "-dirty"
	} else {
		rev = abbRevision
	}

	return rev
}
