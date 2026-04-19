// Package vault stores the mapping from ghost tokens to real credentials.
// It supports hot-reload so the proxy never needs to restart when credentials rotate.
//
// Ghost token format: GHOST::<identifier>
// where identifier is [a-zA-Z0-9_-]+. Examples:
//   - GHOST::openai-prod
//   - GHOST::github-ci
//   - GHOST::aws-dev
//
// The GHOST:: prefix is intentionally distinctive — no real API ever generates it,
// making false positives impossible.
package vault

import (
	"fmt"
	"regexp"
	"sync"
)

// ghostTokenRE validates the GHOST:: token format.
var ghostTokenRE = regexp.MustCompile(`^GHOST::[a-zA-Z0-9_-]+$`)

// GhostTokenScanRE matches GHOST:: tokens anywhere in a string (used by intercept layer).
var GhostTokenScanRE = regexp.MustCompile(`GHOST::[a-zA-Z0-9_-]+`)

// Vault stores the mapping from ghost tokens to real credentials.
// Implementations must be safe for concurrent use.
type Vault interface {
	// Resolve returns the real credential for a ghost token.
	// Returns ("", false) if the ghost token is not registered.
	Resolve(ghostToken string) (realToken string, ok bool)

	// Register adds or updates a ghost→real mapping at runtime.
	Register(ghostToken, realToken string)

	// Revoke removes a ghost token mapping.
	Revoke(ghostToken string)

	// ListGhosts returns all registered ghost tokens. Real tokens are NEVER returned.
	ListGhosts() []string
}

// ValidateGhostToken returns an error if token does not match the GHOST:: format.
func ValidateGhostToken(token string) error {
	if !ghostTokenRE.MatchString(token) {
		return fmt.Errorf("vault: invalid ghost token %q — must match GHOST::[a-zA-Z0-9_-]+", token)
	}
	return nil
}

// MemoryVault is a thread-safe in-memory implementation of Vault.
type MemoryVault struct {
	mu       sync.RWMutex
	mappings map[string]string // ghost → real
}

// NewMemoryVault creates an empty MemoryVault.
func NewMemoryVault() *MemoryVault {
	return &MemoryVault{mappings: make(map[string]string)}
}

// NewMemoryVaultFromMap creates a MemoryVault pre-loaded with the given mappings.
func NewMemoryVaultFromMap(m map[string]string) *MemoryVault {
	v := &MemoryVault{mappings: make(map[string]string, len(m))}
	for k, val := range m {
		v.mappings[k] = val
	}
	return v
}

// Resolve returns the real credential for a ghost token.
func (m *MemoryVault) Resolve(ghostToken string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	real, ok := m.mappings[ghostToken]
	return real, ok
}

// Register adds or updates a ghost→real mapping.
func (m *MemoryVault) Register(ghostToken, realToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mappings[ghostToken] = realToken
}

// Revoke removes a ghost token mapping.
func (m *MemoryVault) Revoke(ghostToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mappings, ghostToken)
}

// ListGhosts returns all registered ghost tokens. Real tokens are never returned.
func (m *MemoryVault) ListGhosts() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ghosts := make([]string, 0, len(m.mappings))
	for ghost := range m.mappings {
		ghosts = append(ghosts, ghost)
	}
	return ghosts
}
