package vault

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestMemoryVaultRoundTrip(t *testing.T) {
	v := NewMemoryVault()
	v.Register("GHOST::test", "real-secret")
	real, ok := v.Resolve("GHOST::test")
	if !ok {
		t.Fatal("expected to resolve GHOST::test")
	}
	if real != "real-secret" {
		t.Errorf("got %q, want %q", real, "real-secret")
	}
}

func TestMemoryVaultRevoke(t *testing.T) {
	v := NewMemoryVault()
	v.Register("GHOST::test", "real-secret")
	v.Revoke("GHOST::test")
	_, ok := v.Resolve("GHOST::test")
	if ok {
		t.Error("resolved revoked token")
	}
}

func TestMemoryVaultListGhosts(t *testing.T) {
	v := NewMemoryVault()
	v.Register("GHOST::a", "real-a")
	v.Register("GHOST::b", "real-b")
	ghosts := v.ListGhosts()
	if len(ghosts) != 2 {
		t.Errorf("expected 2 ghosts, got %d", len(ghosts))
	}
}

func TestMemoryVaultConcurrent(t *testing.T) {
	v := NewMemoryVault()
	v.Register("GHOST::concurrent", "real")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v.Resolve("GHOST::concurrent")
			v.ListGhosts()
		}()
	}
	wg.Wait()
}

func TestFileVaultLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	content := `
mappings:
  "GHOST::openai": "sk-real-openai"
  "GHOST::github": "ghp-real-github"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	logger := zap.NewNop()
	fv, err := NewFileVault(path, false, logger)
	if err != nil {
		t.Fatalf("NewFileVault: %v", err)
	}

	real, ok := fv.Resolve("GHOST::openai")
	if !ok {
		t.Fatal("expected to resolve GHOST::openai")
	}
	if real != "sk-real-openai" {
		t.Errorf("got %q", real)
	}
}

func TestFileVaultHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	initial := `mappings:
  "GHOST::key": "initial-value"
`
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	logger := zap.NewNop()
	fv, err := NewFileVault(path, true, logger)
	if err != nil {
		t.Fatalf("NewFileVault: %v", err)
	}
	defer fv.Close()

	real, ok := fv.Resolve("GHOST::key")
	if !ok || real != "initial-value" {
		t.Fatalf("initial value wrong: %q %v", real, ok)
	}

	// Update the file
	updated := `mappings:
  "GHOST::key": "rotated-value"
`
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}

	// Wait for hot-reload (fsnotify is async)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		real, ok = fv.Resolve("GHOST::key")
		if ok && real == "rotated-value" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("hot-reload did not happen within 3s; got %q %v", real, ok)
}

func TestValidateGhostToken(t *testing.T) {
	valid := []string{"GHOST::openai-prod", "GHOST::a", "GHOST::foo_bar-123"}
	for _, tok := range valid {
		if err := ValidateGhostToken(tok); err != nil {
			t.Errorf("%q should be valid: %v", tok, err)
		}
	}
	invalid := []string{"ghost::lower", "GHOST::", "GHOST::has space", "sk-real-key", ""}
	for _, tok := range invalid {
		if err := ValidateGhostToken(tok); err == nil {
			t.Errorf("%q should be invalid", tok)
		}
	}
}
