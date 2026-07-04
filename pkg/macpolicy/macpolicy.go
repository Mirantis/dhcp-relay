// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The dhcp-relay Authors

// Package macpolicy implements a hot reloadable per client policy for the DHCPv4 relay backed by an atomic Table pointer.
package macpolicy

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"code.local/dhcp-relay/pkg/gpckt/dhcp"
	"code.local/dhcp-relay/pkg/logger"
	"code.local/dhcp-relay/pkg/specs"
)

// Policy file syntax tokens shared with callers that build or validate files.
const (
	CommentPrefix = "#"
	CatchAllKey   = "*"
	// HexPrefix marks a hex client identifier such as "0x01aabbcc". Any other key is a MAC.
	HexPrefix = "0x"
	// ActionPrefix introduces a reserved keyword. No host name begins with it.
	ActionPrefix           = "@"
	ActionDefaultKeyword   = "@default"
	ActionBlackholeKeyword = "@blackhole"
)

// Whitespace separated field columns on a policy line. Only the key is required.
const (
	fieldKey    = 0
	fieldAction = 1
	fieldReply  = 2
	maxFields   = 3
)

// dnsLookupTimeout bounds the resolver call used to validate a host name server.
const dnsLookupTimeout = 5 * time.Second

// ActionKind is the forward path decision for a matched client.
type ActionKind uint8

const (
	// ActionBlackhole drops the request. As the zero value it denies by default.
	ActionBlackhole ActionKind = iota
	// ActionDefault relays via the CLI default server.
	ActionDefault
	// ActionServer relays via the per entry host in Action.Server.
	ActionServer
)

// Action is the full policy decision for one client. Server is set only when Kind is ActionServer. Reply is the reverse path decision.
type Action struct {
	Server string
	Reply  ReplyAction
	Kind   ActionKind
}

// String renders the forward action for logs. It does not describe Reply.
func (a Action) String() string {
	switch a.Kind {
	case ActionServer:
		return "server " + a.Server
	case ActionDefault:
		return "default"
	case ActionBlackhole:
		return "blackhole"
	default:
		return "unknown"
	}
}

// Table is an immutable snapshot of a parsed policy mapping a client identifier to an Action with a fallback for unmatched clients.
type Table struct {
	entries  map[string]Action
	fallback Action
}

// LookupID returns the Action for the first non empty identifier with an entry plus the matched identifier, else the fallback and nil.
func (t *Table) LookupID(ids ...[]byte) (Action, []byte) {
	for _, id := range ids {
		if len(id) == 0 {
			continue
		}

		if a, found := t.entries[string(id)]; found {
			return a, id
		}
	}

	return t.fallback, nil
}

// Lookup returns the Action for the first non empty identifier with an entry, else the fallback ("*" or ActionBlackhole).
func (t *Table) Lookup(ids ...[]byte) Action {
	a, _ := t.LookupID(ids...)

	return a
}

// serverSet is a set of server values already validated so each is resolved once.
type serverSet = map[string]struct{}

// Validate returns an error for the first server that is neither a literal IP nor a resolvable host name, each resolved once per call.
func (t *Table) Validate() error {
	return t.ValidateContext(context.Background())
}

// ValidateContext is Validate with a caller supplied context so a shutdown can abort an in flight DNS lookup.
func (t *Table) ValidateContext(ctx context.Context) error {
	seen := make(serverSet)

	for _, a := range t.entries {
		if err := ValidateServerContext(ctx, a, seen); err != nil {
			return err
		}
	}

	return ValidateServerContext(ctx, t.fallback, seen)
}

// ValidateServer checks that an Action's server is a literal IP or resolvable host.
func ValidateServer(a Action, seen serverSet) error {
	return ValidateServerContext(context.Background(), a, seen)
}

// ValidateServerContext is ValidateServer with a caller context so shutdown can abort an in flight DNS lookup bounded by dnsLookupTimeout.
func ValidateServerContext(ctx context.Context, a Action, seen serverSet) error {
	if a.Kind != ActionServer {
		return nil
	}

	if seen == nil {
		seen = make(serverSet)
	}

	if _, ok := seen[a.Server]; ok {
		return nil
	}

	if net.ParseIP(a.Server) != nil {
		seen[a.Server] = struct{}{}

		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	if _, err := net.DefaultResolver.LookupHost(ctx, a.Server); err != nil {
		return fmt.Errorf("server %q is not a valid IP or resolvable host: %w", a.Server, err)
	}

	// Record the resolved value so one pass resolves each server once.
	seen[a.Server] = struct{}{}

	return nil
}

// Map is a live policy backed by a file. A poller swaps in a fresh Table on each file change so Lookup always sees one snapshot.
type Map struct {
	snap     atomic.Pointer[Table]
	log      *logger.Config
	done     chan struct{}
	lastInfo os.FileInfo
	path     string
	interval time.Duration
	// mu serializes Reload so lastInfo has a single writer.
	mu        sync.Mutex
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// LookupID returns the Action and matched identifier from the current snapshot, concurrency safe.
func (m *Map) LookupID(ids ...[]byte) (Action, []byte) {
	t := m.snap.Load()
	if t == nil {
		return Action{}, nil
	}

	return t.LookupID(ids...)
}

// Lookup returns the Action for a client from the current snapshot, concurrency safe, returning zero before first load.
func (m *Map) Lookup(ids ...[]byte) Action {
	a, _ := m.LookupID(ids...)

	return a
}

// Reload reads and validates the file then atomically publishes the new Table. Errors keep the previous snapshot.
func (m *Map) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	//nolint:gosec // G304: the policy path is an operator supplied trusted CLI flag.
	f, err := os.Open(m.path)
	if err != nil {
		return fmt.Errorf("open %s: %w", m.path, err)
	}
	defer f.Close()

	// Stat the open file so the change guard below and lastInfo describe the parsed bytes.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", m.path, err)
	}

	t, warnings, err := Parse(f)
	if err != nil {
		return err
	}

	// Reject a file that changed while it was being read so a torn in place write is never published. The poller retries on the next tick.
	after, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", m.path, err)
	}

	if FileChanged(info, after) {
		return fmt.Errorf("policy %s changed during reload", m.path)
	}

	// Revalidate servers so one that stopped resolving fails the reload. The context lets Close abort a lookup still in flight.
	ctx, cancel := m.CloseContext()
	defer cancel()

	if err := t.ValidateContext(ctx); err != nil {
		return err
	}

	for _, w := range warnings {
		m.log.Warnf("MAC policy: %s\n", w)
	}

	m.snap.Store(t)
	m.lastInfo = info

	if len(t.entries) == 0 && t.fallback.Kind == ActionBlackhole {
		m.log.Warnf("MAC policy %s has no relayable entries: every DHCPv4 message will be dropped\n", m.path)
	}

	m.log.Infof("MAC policy loaded from %s (%d entries, default action: %s)\n", m.path, len(t.entries), t.fallback)

	return nil
}

// CloseContext returns a context that Close cancels. The caller must call cancel to release the bridge goroutine.
func (m *Map) CloseContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	if m.done == nil {
		return ctx, cancel
	}

	go func() {
		select {
		case <-m.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// ParseAction interprets the optional forward action token. Empty or "@default" relays via CLI server, "@blackhole" drops.
func ParseAction(token string) (Action, error) {
	switch token {
	case "", ActionDefaultKeyword:
		return Action{Kind: ActionDefault}, nil
	case ActionBlackholeKeyword:
		return Action{Kind: ActionBlackhole}, nil
	default:
		if strings.HasPrefix(token, ActionPrefix) {
			return Action{}, fmt.Errorf("unknown action %q", token)
		}

		return Action{Kind: ActionServer, Server: token}, nil
	}
}

// ParseIdentifier decodes a policy key into raw identifier bytes. A HexPrefix key is raw hex (an Option 61 client id).
func ParseIdentifier(token string) ([]byte, error) {
	if strings.HasPrefix(token, HexPrefix) {
		id, err := hex.DecodeString(token[len(HexPrefix):])
		if err != nil {
			return nil, fmt.Errorf("invalid hex identifier %q: %w", token, err)
		}

		if len(id) == 0 {
			return nil, fmt.Errorf("empty hex identifier %q", token)
		}

		if len(id) > dhcp.MaxPolicyTagSize {
			return nil, fmt.Errorf("hex identifier %q is %d bytes, at most %d fits the Option 82 policy tag",
				token, len(id), dhcp.MaxPolicyTagSize)
		}

		return id, nil
	}

	id, err := net.ParseMAC(token)
	if err != nil {
		return nil, fmt.Errorf("invalid identifier %q: %w", token, err)
	}

	// The relay only handles 6 byte Ethernet addresses. Reject longer forms such as EUI64 that net.ParseMAC accepts.
	if len(id) != specs.EthernetMACLength {
		return nil, fmt.Errorf("identifier %q must be a 6 byte MAC (use the %s prefix for other client ids)", token, HexPrefix)
	}

	return id, nil
}

// Parse reads a policy from r into an immutable Table. Each non comment line is "<key> [action] [reply]".
func Parse(r io.Reader) (*Table, []string, error) {
	t := &Table{entries: make(map[string]Action)}

	var warnings []string

	sawCatchAll := false

	scanner := bufio.NewScanner(r)

	for lineNum := 1; scanner.Scan(); lineNum++ {
		fields := strings.Fields(scanner.Text())

		// A field starting with "#" begins a comment so "#" stays literal inside a value.
		for i, f := range fields {
			if strings.HasPrefix(f, CommentPrefix) {
				fields = fields[:i]

				break
			}
		}

		if len(fields) == 0 {
			continue
		}

		if len(fields) > maxFields {
			return nil, nil, fmt.Errorf("line %d: expected '<key> [action] [reply]', got %d fields", lineNum, len(fields))
		}

		// Action and reply are optional.
		var actionToken, replyToken string

		if len(fields) > fieldAction {
			actionToken = fields[fieldAction]
		}

		if len(fields) > fieldReply {
			replyToken = fields[fieldReply]
		}

		action, err := ParseAction(actionToken)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		action.Reply, err = ParseReplyAction(replyToken)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		key := fields[fieldKey]

		// The catch all becomes the fallback not a map entry.
		if key == CatchAllKey {
			if sawCatchAll {
				warnings = append(warnings, fmt.Sprintf("line %d: duplicate %q entry, last one wins", lineNum, CatchAllKey))
			}

			t.fallback = action
			sawCatchAll = true

			continue
		}

		id, err := ParseIdentifier(key)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		// Key by raw bytes so Lookup can compare directly against packet bytes.
		k := string(id)

		if _, dup := t.entries[k]; dup {
			warnings = append(warnings, fmt.Sprintf("line %d: duplicate identifier %s, last entry wins", lineNum, key))
		}

		t.entries[k] = action
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read error: %w", err)
	}

	return t, warnings, nil
}
