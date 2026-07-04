// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

// Package glob validates and matches shell style patterns (filepath.Match) shared by the relay config maps.
package glob

import (
	"errors"
	"fmt"
	"path/filepath"
)

// Validate errors when pattern is empty or not a valid filepath.Match pattern, checked once at load time. It probes
// the empty string and the pattern itself so a bad class after a star is reached rather than slipping silently past.
func Validate(pattern string) error {
	if pattern == "" {
		return errors.New("empty glob")
	}

	if _, err := filepath.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid glob %q: %w", pattern, err)
	}

	if _, err := filepath.Match(pattern, pattern); err != nil {
		return fmt.Errorf("invalid glob %q: %w", pattern, err)
	}

	return nil
}

// Match reports whether s matches pattern. A malformed pattern (Validate rejects these at load) is a non match.
func Match(pattern, s string) bool {
	ok, _ := filepath.Match(pattern, s)

	return ok
}
