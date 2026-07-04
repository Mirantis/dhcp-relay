// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

// Package linkmap maps an ingress NIC to the client subnet for RFC 3527 Link Selection so an unnumbered relay
// interface can still relay. It hot reloads the file through the shared filewatch watcher like the MAC policy.
package linkmap

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"time"

	"code.local/dhcp-relay/pkg/cfgmatch"
	"code.local/dhcp-relay/pkg/filewatch"
	"code.local/dhcp-relay/pkg/logger"
)

// numFields is the whitespace field count on a link map line.
const numFields = 2

// Entry pairs a NIC selector with the client subnet address emitted as the Link Selection sub option.
type Entry struct {
	Subnet net.IP
	Sel    cfgmatch.Selector
}

// Table is an immutable snapshot mapping an ingress NIC to its client subnet. The first matching entry wins.
type Table struct {
	entries []Entry
}

// Lookup returns the client subnet for the first entry whose selector matches the NIC, else nil and false.
func (t *Table) Lookup(name, mac string) (net.IP, bool) {
	for _, e := range t.entries {
		if e.Sel.Match(name, mac) {
			return e.Subnet, true
		}
	}

	return nil, false
}

// ParseSubnet accepts a CIDR and returns its network address for the Link Selection sub option.
func ParseSubnet(token string) (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(token)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", token, err)
	}

	v4 := ipnet.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("subnet %q is not IPv4", token)
	}

	return v4, nil
}

// Parse reads a link map from r into an immutable Table. Each non comment line is "<nic-selector> <subnet-cidr>".
func Parse(r io.Reader) (*Table, []string, error) {
	t := &Table{}

	scanner := bufio.NewScanner(r)

	for lineNum := 1; scanner.Scan(); lineNum++ {
		fields := cfgmatch.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		if len(fields) != numFields {
			return nil, nil, fmt.Errorf("line %d: expected '<nic-selector> <subnet-cidr>', got %d fields", lineNum, len(fields))
		}

		sel, err := cfgmatch.ParseSelector(fields[0])
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		subnet, err := ParseSubnet(fields[1])
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		t.entries = append(t.entries, Entry{Subnet: subnet, Sel: sel})
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read error: %w", err)
	}

	var warnings []string
	if len(t.entries) == 0 {
		warnings = append(warnings, "no entries: every unnumbered ingress request will be dropped")
	}

	return t, warnings, nil
}

// Map is a live link map backed by a file that filewatch reloads into a fresh Table on each change.
type Map struct {
	w *filewatch.Watcher[Table]
}

// New loads the link map once so a bad file fails fast then starts a poller. The caller must Close to stop it.
func New(path string, interval time.Duration, log *logger.Config) (*Map, error) {
	w, err := filewatch.New(filewatch.Config[Table]{
		Log:   log,
		Parse: Parse,
		Describe: func(t *Table) string {
			return fmt.Sprintf("%d entries", len(t.entries))
		},
		Path:     path,
		Name:     "link map",
		Interval: interval,
	})
	if err != nil {
		return nil, err
	}

	return &Map{w: w}, nil
}

// Lookup returns the client subnet for a NIC from the current snapshot, concurrency safe, nil before first load.
func (m *Map) Lookup(name, mac string) (net.IP, bool) {
	t := m.w.Snapshot()
	if t == nil {
		return nil, false
	}

	return t.Lookup(name, mac)
}

// Reload rereads the link map file and republishes it. Errors keep the previous snapshot.
func (m *Map) Reload() error {
	return m.w.Reload()
}

// Close stops the poller. Safe to call more than once.
func (m *Map) Close() error {
	return m.w.Close()
}
