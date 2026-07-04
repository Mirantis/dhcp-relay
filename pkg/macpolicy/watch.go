// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

package macpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"code.local/dhcp-relay/pkg/logger"
)

// DefaultPollInterval is the poll period used when New gets a non positive interval.
const DefaultPollInterval = 30 * time.Second

// New loads the policy once so a bad file fails fast then starts a poller goroutine. The caller must Close to stop it.
func New(path string, interval time.Duration, log *logger.Config) (*Map, error) {
	abs, absErr := filepath.Abs(path)
	if absErr != nil {
		return nil, fmt.Errorf("resolve path %s: %w", path, absErr)
	}

	if interval <= 0 {
		interval = DefaultPollInterval
	}

	m := &Map{
		log:      log,
		path:     abs,
		interval: interval,
		done:     make(chan struct{}),
	}

	if err := m.Reload(); err != nil {
		return nil, err
	}

	m.wg.Add(1)
	go m.watch()

	return m, nil
}

// watch rechecks the file once per interval and returns when Close closes done.
func (m *Map) watch() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.poll()
		}
	}
}

// poll reloads the policy when the file differs from the last tick.
func (m *Map) poll() {
	info, err := os.Stat(m.path)
	if err != nil {
		m.log.Errorf("MAC policy: stat %s failed, keeping previous policy: %v\n", m.path, err)

		return
	}

	m.mu.Lock()
	last := m.lastInfo
	m.mu.Unlock()

	if last != nil && !FileChanged(last, info) {
		return
	}

	// Reload sets lastInfo only on success so a failed reload retries on the next tick.
	if err := m.Reload(); err != nil {
		m.log.Errorf("MAC policy: reload failed, keeping previous policy: %v\n", err)

		return
	}
}

// FileChanged reports whether two stats describe a different file by identity (os.SameFile) then size and mtime.
func FileChanged(a, b os.FileInfo) bool {
	return !os.SameFile(a, b) || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime())
}

// Close stops the poller and aborts any in flight validation DNS lookup then waits for the poller to return. Safe to call more than once.
func (m *Map) Close() error {
	m.closeOnce.Do(func() { close(m.done) })
	m.wg.Wait()

	return nil
}
