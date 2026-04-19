// Package config handles loading and validation of GhostKey configuration.
// Config sources are merged in priority order: YAML file → environment variables → built-in defaults.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level GhostKey configuration.
type Config struct {
	Proxy ProxyConfig `yaml:"proxy" mapstructure:"proxy"`
	Vault VaultConfig `yaml:"vault" mapstructure:"vault"`
	Audit AuditConfig `yaml:"audit" mapstructure:"audit"`
	CA    CAConfig    `yaml:"ca"    mapstructure:"ca"`
}

// ProxyConfig configures the HTTP/HTTPS proxy listener.
type ProxyConfig struct {
	ListenAddr   string `yaml:"listen_addr"   mapstructure:"listen_addr"`
	ReadTimeout  int    `yaml:"read_timeout"  mapstructure:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout" mapstructure:"write_timeout"`
}

// VaultConfig configures the credential backend.
type VaultConfig struct {
	// Backend selects the credential store: "file", "env", or "hashicorp".
	Backend string `yaml:"backend" mapstructure:"backend"`

	// FilePath is the YAML secrets file for the "file" backend.
	FilePath  string `yaml:"file_path"  mapstructure:"file_path"`
	WatchFile bool   `yaml:"watch_file" mapstructure:"watch_file"`

	// Mappings are inline ghost→real mappings (alternative to file backend).
	Mappings map[string]string `yaml:"mappings" mapstructure:"mappings"`

	// HashiCorp Vault backend configuration.
	HashicorpAddr  string `yaml:"hashicorp_addr"  mapstructure:"hashicorp_addr"`
	HashicorpToken string `yaml:"hashicorp_token" mapstructure:"hashicorp_token"`
	HashicorpPath  string `yaml:"hashicorp_path"  mapstructure:"hashicorp_path"`
}

// AuditConfig configures the tamper-evident audit logger.
type AuditConfig struct {
	Enabled  bool   `yaml:"enabled"   mapstructure:"enabled"`
	FilePath string `yaml:"file_path" mapstructure:"file_path"`
	// Format is "json" (NDJSON) or "text".
	Format string `yaml:"format" mapstructure:"format"`
}

// CAConfig configures the TLS certificate authority used for MITM interception.
// If both CertFile and KeyFile are empty, GhostKey auto-generates a CA on first run
// and saves it to ~/.ghostkey/ca.{crt,key}.
type CAConfig struct {
	CertFile string `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile  string `yaml:"key_file"  mapstructure:"key_file"`
}

// Load reads configuration from cfgFile (if non-empty) with environment variable
// overrides. Environment variables use the GHOSTKEY_ prefix, e.g.:
//
//	GHOSTKEY_PROXY_LISTEN_ADDR=127.0.0.1:9876
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Built-in defaults
	v.SetDefault("proxy.listen_addr", "127.0.0.1:9876")
	v.SetDefault("proxy.read_timeout", 30)
	v.SetDefault("proxy.write_timeout", 30)
	v.SetDefault("vault.backend", "file")
	v.SetDefault("vault.watch_file", true)
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.format", "json")

	// File-based config
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("ghostkey")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.ghostkey")
	}

	// Environment variable overrides (GHOSTKEY_PROXY_LISTEN_ADDR → proxy.listen_addr)
	v.SetEnvPrefix("GHOSTKEY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional when relying on env vars / defaults
		if cfgFile != "" {
			return nil, fmt.Errorf("config: read %q: %w", cfgFile, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}
