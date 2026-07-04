// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

// Package filewatch hot reloads a typed snapshot from a file. A poller swaps in a fresh snapshot on each change so
// readers always see one immutable value. It is shared by the config maps that back the relay policy and link map.
package filewatch

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"code.local/dhcp-relay/pkg/logger"
)

// DefaultPollInterval is the poll period used when New gets a non positive interval.
const DefaultPollInterval = 30 * time.Second

// Parser turns file contents into an immutable snapshot plus any non fatal warnings.
type Parser[T any] func(r io.Reader) (*T, []string, error)

// Validator checks a freshly parsed snapshot before it is published. The context is canceled on Close.
type Validator[T any] func(ctx context.Context, snap *T) error

// Config builds a Watcher. Parse is required. Validate and Describe are optional hooks.
type Config[T any] struct {
	Log      *logger.Config
	Parse    Parser[T]
	Validate Validator[T]
	Describe func(snap *T) string
	Path     string
	Name     string
	Interval time.Duration
}

// Watcher holds a hot reloaded snapshot of type T loaded from a file and refreshed by a poller.
type Watcher[T any] struct {
	snap     atomic.Pointer[T]
	log      *logger.Config
	parse    Parser[T]
	validate Validator[T]
	describe func(snap *T) string
	done     chan struct{}
	lastInfo os.FileInfo
	path     string
	name     string
	interval time.Duration
	// mu serializes Reload so lastInfo has a single writer.
	mu        sync.Mutex
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New loads the file once so a bad file fails fast then starts a poller goroutine. The caller must Close to stop it.
func New[T any](cfg Config[T]) (*Watcher[T], error) {
	if cfg.Parse == nil {
		return nil, fmt.Errorf("filewatch %s: Parse is required", cfg.Name)
	}

	if cfg.Log == nil {
		return nil, fmt.Errorf("filewatch %s: Log is required", cfg.Name)
	}

	abs, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve path %s: %w", cfg.Path, err)
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	w := &Watcher[T]{
		log:      cfg.Log,
		parse:    cfg.Parse,
		validate: cfg.Validate,
		describe: cfg.Describe,
		done:     make(chan struct{}),
		path:     abs,
		name:     cfg.Name,
		interval: interval,
	}

	if err := w.Reload(); err != nil {
		return nil, err
	}

	w.wg.Add(1)
	go w.watch()

	return w, nil
}

// Snapshot returns the current snapshot, concurrency safe, nil before the first successful load.
func (w *Watcher[T]) Snapshot() *T {
	return w.snap.Load()
}

// Reload reads and validates the file then atomically publishes the new snapshot. Errors keep the previous one.
func (w *Watcher[T]) Reload() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	//nolint:gosec // G304: the path is an operator supplied trusted CLI flag.
	f, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("open %s: %w", w.path, err)
	}
	defer f.Close()

	// Stat the open file so the change guard below and lastInfo describe the parsed bytes.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", w.path, err)
	}

	snap, warnings, err := w.parse(f)
	if err != nil {
		return err
	}

	// A parser that returns no error must return a snapshot. Storing nil would regress readers to the
	// before-first-load state and panic the describe hook, so reject it and keep the previous snapshot.
	if snap == nil {
		return fmt.Errorf("%s %s: parser returned a nil snapshot", w.name, w.path)
	}

	// Reject a file that changed while it was read so a torn in place write is never published. The poller retries.
	after, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", w.path, err)
	}

	if FileChanged(info, after) {
		return fmt.Errorf("%s %s changed during reload", w.name, w.path)
	}

	if w.validate != nil {
		ctx, cancel := w.CloseContext()
		defer cancel()

		if err := w.validate(ctx, snap); err != nil {
			return err
		}
	}

	for _, warn := range warnings {
		w.log.Warnf("%s: %s\n", w.name, warn)
	}

	w.snap.Store(snap)
	w.lastInfo = info

	if w.describe != nil {
		w.log.Infof("%s loaded from %s (%s)\n", w.name, w.path, w.describe(snap))
	} else {
		w.log.Infof("%s loaded from %s\n", w.name, w.path)
	}

	return nil
}

// CloseContext returns a context that Close cancels. The caller must call cancel to release the bridge goroutine.
func (w *Watcher[T]) CloseContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	if w.done == nil {
		return ctx, cancel
	}

	go func() {
		select {
		case <-w.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// watch rechecks the file once per interval and returns when Close closes done.
func (w *Watcher[T]) watch() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

// poll reloads the file when it differs from the last tick.
func (w *Watcher[T]) poll() {
	info, err := os.Stat(w.path)
	if err != nil {
		w.log.Errorf("%s: stat %s failed, keeping previous: %v\n", w.name, w.path, err)

		return
	}

	w.mu.Lock()
	last := w.lastInfo
	w.mu.Unlock()

	if last != nil && !FileChanged(last, info) {
		return
	}

	// Reload sets lastInfo only on success so a failed reload retries on the next tick.
	if err := w.Reload(); err != nil {
		w.log.Errorf("%s: reload failed, keeping previous: %v\n", w.name, err)

		return
	}
}

// FileChanged reports whether two stats describe a different file by identity (os.SameFile) then size and mtime.
func FileChanged(a, b os.FileInfo) bool {
	return !os.SameFile(a, b) || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime())
}

// Close stops the poller and cancels any in flight validation then waits for the poller to return. Safe to call twice.
func (w *Watcher[T]) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	w.wg.Wait()

	return nil
}
