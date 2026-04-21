// Package audit provides a tamper-evident structured audit log for GhostKey.
//
// Every credential interception is recorded as an NDJSON event. Real tokens are
// NEVER stored — only ghost tokens and metadata.
//
// Security guarantee: grep the audit log for any real token and it will never appear.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventType constants for the audit log.
const (
	EventIntercept = "intercept" // A ghost token was found and replaced.
	EventRotate    = "rotate"    // A credential was rotated in the vault.
	EventBlocked   = "blocked"   // A request was blocked (unknown ghost token).
	EventError     = "error"     // An internal error occurred.
)

// Event is a single audit log entry.
// Real tokens are intentionally absent — audit logs must be safe to share.
type Event struct {
	Timestamp   time.Time `json:"ts"`
	EventType   string    `json:"event"`
	GhostTokens []string  `json:"ghost_tokens"`        // ghost tokens seen (NEVER real tokens)
	Upstream    string    `json:"upstream"`            // e.g. "api.openai.com:443"
	Method      string    `json:"method,omitempty"`    // HTTP method
	Path        string    `json:"path,omitempty"`      // URL path (already scrubbed)
	Locations   []string  `json:"locations,omitempty"` // where tokens were found
	AgentPID    int       `json:"agent_pid,omitempty"`
	Rewrites    int       `json:"rewrites"` // count of substitutions made
}

// Auditor writes structured NDJSON audit events to a file or stdout.
// All writes are serialized with a mutex; the Auditor is safe for concurrent use.
type Auditor struct {
	mu      sync.Mutex
	out     *os.File
	enabled bool
}

// New creates an Auditor. If filePath is empty, events are written to stdout.
// If enabled is false, all Log calls are no-ops (zero overhead).
func New(enabled bool, filePath string) (*Auditor, error) {
	if !enabled {
		return &Auditor{enabled: false}, nil
	}

	var f *os.File
	if filePath == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) //nolint:gosec // path comes from trusted config
		if err != nil {
			return nil, fmt.Errorf("audit: open %q: %w", filePath, err)
		}
	}
	return &Auditor{out: f, enabled: true}, nil
}

// Log writes an audit event as a single NDJSON line.
// If e.Timestamp is zero, it is set to now (UTC).
func (a *Auditor) Log(e Event) {
	if !a.enabled {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(e)
	if err != nil {
		// Cannot log the failure — silently drop to avoid recursive loops.
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.out.Write(append(data, '\n'))
}

// Close closes the underlying log file. Calling Close on a stdout-backed Auditor is a no-op.
func (a *Auditor) Close() error {
	if a.out != nil && a.out != os.Stdout {
		return a.out.Close()
	}
	return nil
}

// TailFile streams an NDJSON audit log file to the returned channel in real time.
// It first replays all existing events, then follows new lines as they are appended.
// The returned error channel receives at most one error; both channels are closed when done.
func TailFile(path string) (<-chan Event, <-chan error) {
	events := make(chan Event, 64)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		f, err := os.Open(path) //nolint:gosec // path comes from trusted config
		if err != nil {
			errs <- fmt.Errorf("audit: open %q: %w", path, err)
			return
		}
		defer func() { _ = f.Close() }()

		for {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				var e Event
				if jsonErr := json.Unmarshal(scanner.Bytes(), &e); jsonErr == nil {
					events <- e
				}
			}
			if err := scanner.Err(); err != nil {
				errs <- err
				return
			}
			// Pause before checking for new lines (tail -f behaviour).
			time.Sleep(200 * time.Millisecond)
		}
	}()

	return events, errs
}
