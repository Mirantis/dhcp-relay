// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package version

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

const (
	baseVersion = "0.0.0"
	revPrefix   = "r"
)

func VCS(abbRevisionNum uint8) string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return baseVersion + "-unknown"
	}

	var (
		vcsRevision []rune
		vcsModified string
		vcsTime     string
	)

	for _, el := range buildInfo.Settings {
		switch el.Key {
		case "vcs.revision":
			vcsRevision = []rune(el.Value)
		case "vcs.modified":
			vcsModified = el.Value
		case "vcs.time":
			vcsTime = el.Value
		default:
			continue
		}
	}

	if strings.EqualFold(vcsModified, "true") {
		return baseVersion + "-dirty"
	}

	if len(vcsRevision) == 0 || vcsTime == "" {
		return baseVersion + "-unknown"
	}

	t, err := time.Parse(time.RFC3339, vcsTime)
	if err != nil {
		return baseVersion + "-unknown"
	}

	var abbRevision string
	if len(vcsRevision) <= int(abbRevisionNum) {
		abbRevision = string(vcsRevision)
	} else {
		abbRevision = string(vcsRevision[:abbRevisionNum])
	}

	secondsSinceMidnight := t.Hour()*3600 + t.Minute()*60 + t.Second()

	return fmt.Sprintf("%d.%d.%d-%d.%s%s",
		t.Year()%100, int(t.Month()), t.Day(), //nolint:mnd // last two digits of calendar year.
		secondsSinceMidnight,
		revPrefix, abbRevision,
	)
}
