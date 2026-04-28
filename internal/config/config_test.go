package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if cfg.Proxy.ListenAddr != "127.0.0.1:9876" {
		t.Errorf("default listen_addr: got %q", cfg.Proxy.ListenAddr)
	}
	if cfg.Proxy.ReadTimeout != 30 {
		t.Errorf("default read_timeout: got %d", cfg.Proxy.ReadTimeout)
	}
	if cfg.Audit.Format != "json" {
		t.Errorf("default audit format: got %q", cfg.Audit.Format)
	}
}

func TestLoadFromFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ghostkey.yaml")
	content := `
proxy:
  listen_addr: "127.0.0.1:7777"
audit:
  enabled: false
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load from file: %v", err)
	}
	if cfg.Proxy.ListenAddr != "127.0.0.1:7777" {
		t.Errorf("listen_addr from file: got %q", cfg.Proxy.ListenAddr)
	}
	if cfg.Audit.Enabled {
		t.Error("audit should be disabled")
	}
}

func TestLoadResolvesRelativePathsFromConfigDir(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ghostkey.yaml")
	content := `
vault:
  backend: file
  file_path: "./secrets.yaml"
audit:
  file_path: "./ghostkey-audit.ndjson"
ca:
  cert_file: "./ca.crt"
  key_file: "./ca.key"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with relative paths: %v", err)
	}

	if got, want := cfg.Vault.FilePath, filepath.Join(tmp, "secrets.yaml"); got != want {
		t.Fatalf("vault.file_path = %q, want %q", got, want)
	}
	if got, want := cfg.Audit.FilePath, filepath.Join(tmp, "ghostkey-audit.ndjson"); got != want {
		t.Fatalf("audit.file_path = %q, want %q", got, want)
	}
	if got, want := cfg.CA.CertFile, filepath.Join(tmp, "ca.crt"); got != want {
		t.Fatalf("ca.cert_file = %q, want %q", got, want)
	}
	if got, want := cfg.CA.KeyFile, filepath.Join(tmp, "ca.key"); got != want {
		t.Fatalf("ca.key_file = %q, want %q", got, want)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("GHOSTKEY_PROXY_LISTEN_ADDR", "127.0.0.1:5555")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.Proxy.ListenAddr != "127.0.0.1:5555" {
		t.Errorf("env override: got %q, want 127.0.0.1:5555", cfg.Proxy.ListenAddr)
	}
}
