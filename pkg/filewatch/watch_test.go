// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

//go:build linux

package filewatch_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"

	"code.local/dhcp-relay/pkg/filewatch"
	"code.local/dhcp-relay/pkg/logger"
)

// TestMain runs under goleak so a Watcher whose Close fails to stop its poller goroutine is caught.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type snap struct{}

func okParse(io.Reader) (*snap, []string, error) { return &snap{}, nil, nil }

func writeCfg(t *testing.T) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "cfg.txt")
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	return p
}

// TestNewRequiresParseAndLog checks the required hooks are validated at New rather than panicking on first use.
func TestNewRequiresParseAndLog(t *testing.T) {
	path := writeCfg(t)

	if _, err := filewatch.New(filewatch.Config[snap]{Path: path, Name: "t", Log: logger.NewWithoutDatetime()}); err == nil {
		t.Error("New with nil Parse = nil error, want error")
	}

	if _, err := filewatch.New(filewatch.Config[snap]{Path: path, Name: "t", Parse: okParse}); err == nil {
		t.Error("New with nil Log = nil error, want error")
	}
}

// TestNewRejectsNilSnapshot checks a parser that returns no error but a nil snapshot is rejected rather than stored.
func TestNewRejectsNilSnapshot(t *testing.T) {
	path := writeCfg(t)

	nilParse := func(io.Reader) (*snap, []string, error) { return nil, nil, nil }

	if _, err := filewatch.New(filewatch.Config[snap]{
		Path: path, Name: "t", Log: logger.NewWithoutDatetime(), Parse: nilParse,
	}); err == nil {
		t.Error("New with a nil-snapshot parser = nil error, want error")
	}
}

// TestNewReloadClose drives the success path. New publishes a snapshot and starts the poller then Close stops it.
// The goleak check in TestMain fails the run if Close leaks the poller goroutine.
func TestNewReloadClose(t *testing.T) {
	path := writeCfg(t)

	w, err := filewatch.New(filewatch.Config[snap]{
		Path: path, Name: "t", Log: logger.NewWithoutDatetime(), Parse: okParse,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if w.Snapshot() == nil {
		t.Fatal("Snapshot() = nil after a successful New")
	}

	if err := w.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close is idempotent.
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
