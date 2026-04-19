// GhostKey — credential firewall for AI agents.
// Agents send the ghost. Servers get the key.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/yourusername/ghostkey/internal/audit"
	"github.com/yourusername/ghostkey/internal/config"
	"github.com/yourusername/ghostkey/internal/proxy"
	"github.com/yourusername/ghostkey/internal/vault"
)

// Version is injected by the build system via -ldflags.
var Version = "v0.1.3"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ghostkey",
		Short: "Credential firewall for AI agents",
		Long:  "GhostKey ensures AI agents never possess real credentials.\nAgents send the ghost. Servers get the key.",
	}
	root.AddCommand(
		startCmd(),
		caCmd(),
		vaultCmd(),
		auditCmd(),
		checkCmd(),
		versionCmd(),
	)
	return root
}

// ----------------------------------------------------------------------------
// ghostkey start
// ----------------------------------------------------------------------------

func startCmd() *cobra.Command {
	var cfgFile string
	var listenAddr string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the GhostKey proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			if listenAddr != "" {
				cfg.Proxy.ListenAddr = listenAddr
			}

			logger, err := buildLogger(verbose)
			if err != nil {
				return fmt.Errorf("logger: %w", err)
			}
			defer logger.Sync() //nolint:errcheck

			// Build vault
			v, closeFn, err := buildVault(cfg, logger)
			if err != nil {
				return err
			}
			defer closeFn()

			// Build CA manager
			ca, err := proxy.NewCAManager(cfg.CA.CertFile, cfg.CA.KeyFile)
			if err != nil {
				return fmt.Errorf("CA: %w", err)
			}

			// Build auditor
			a, err := audit.New(cfg.Audit.Enabled, cfg.Audit.FilePath)
			if err != nil {
				return err
			}
			defer a.Close()

			// Build and start proxy
			p := proxy.New(cfg, v, ca, a, logger)

			// Graceful shutdown on SIGINT / SIGTERM
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

			errCh := make(chan error, 1)
			go func() { errCh <- p.Start() }()

			select {
			case err := <-errCh:
				return err
			case <-quit:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return p.Shutdown(ctx)
			}
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file (default: ./ghostkey.yaml)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Override proxy listen address")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable debug logging")
	return cmd
}

// ----------------------------------------------------------------------------
// ghostkey ca
// ----------------------------------------------------------------------------

func caCmd() *cobra.Command {
	ca := &cobra.Command{
		Use:   "ca",
		Short: "Manage the GhostKey CA certificate",
	}
	ca.AddCommand(caInstallCmd(), caShowCmd(), caRegenCmd())
	return ca
}

func caInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the GhostKey CA into the system trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath, err := proxy.CACertPath()
			if err != nil {
				return err
			}
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return fmt.Errorf("CA cert not found at %s — run 'ghostkey start' once to generate it", certPath)
			}

			switch runtime.GOOS {
			case "darwin":
				fmt.Printf("Installing CA into macOS system keychain: %s\n", certPath)
				c := exec.Command("sudo", "security", "add-trusted-cert",
					"-d", "-r", "trustRoot",
					"-k", "/Library/Keychains/System.keychain",
					certPath)
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				return c.Run()
			case "linux":
				fmt.Printf("Installing CA on Linux: %s\n", certPath)
				if _, err := os.Stat("/etc/debian_version"); err == nil {
					dest := "/usr/local/share/ca-certificates/ghostkey.crt"
					data, err := os.ReadFile(certPath)
					if err != nil {
						return err
					}
					if err := os.WriteFile(dest, data, 0644); err != nil {
						return fmt.Errorf("write %s (try sudo): %w", dest, err)
					}
					return exec.Command("sudo", "update-ca-certificates").Run()
				}
				dest := "/etc/pki/ca-trust/source/anchors/ghostkey.crt"
				data, err := os.ReadFile(certPath)
				if err != nil {
					return err
				}
				if err := os.WriteFile(dest, data, 0644); err != nil {
					return fmt.Errorf("write %s (try sudo): %w", dest, err)
				}
				return exec.Command("sudo", "update-ca-trust").Run()
			default:
				return fmt.Errorf("automatic install not supported on %s — see 'ghostkey ca show'", runtime.GOOS)
			}
		},
	}
}

func caShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the CA certificate PEM to stdout",
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath, err := proxy.CACertPath()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(certPath)
			if err != nil {
				return fmt.Errorf("CA cert not found — run 'ghostkey start' once to generate it: %w", err)
			}
			fmt.Print(string(data))
			return nil
		},
	}
}

func caRegenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "regen",
		Short: "Regenerate the CA certificate (invalidates all cached leaf certs)",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			certPath := home + "/.ghostkey/ca.crt"
			keyPath := home + "/.ghostkey/ca.key"
			_ = os.Remove(certPath)
			_ = os.Remove(keyPath)
			_, err = proxy.NewCAManager("", "")
			if err != nil {
				return err
			}
			fmt.Println("CA regenerated. Run 'ghostkey ca install' to trust it again.")
			return nil
		},
	}
}

// ----------------------------------------------------------------------------
// ghostkey vault
// ----------------------------------------------------------------------------

func vaultCmd() *cobra.Command {
	var cfgFile string

	v := &cobra.Command{
		Use:   "vault",
		Short: "Manage ghost token mappings",
	}
	v.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file")
	v.AddCommand(
		vaultListCmd(&cfgFile),
		vaultAddCmd(&cfgFile),
		vaultRevokeCmd(&cfgFile),
	)
	return v
}

func vaultListCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered ghost tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgFile)
			if err != nil {
				return err
			}
			logger := zap.NewNop()
			v, closeFn, err := buildVault(cfg, logger)
			if err != nil {
				return err
			}
			defer closeFn()
			ghosts := v.ListGhosts()
			if len(ghosts) == 0 {
				fmt.Println("(no ghost tokens registered)")
				return nil
			}
			for _, g := range ghosts {
				fmt.Println(g)
			}
			return nil
		},
	}
}

func vaultAddCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "add <ghost-token> <real-token|-stdin>",
		Short: "Add a ghost→real mapping (use '-' to read real token from stdin)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ghost := args[0]
			if err := vault.ValidateGhostToken(ghost); err != nil {
				return err
			}

			var real string
			if args[1] == "-" {
				// Read real token from stdin — NEVER from CLI args (they appear in shell history).
				fmt.Fprint(os.Stderr, "Enter real token: ")
				scanner := bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					real = strings.TrimSpace(scanner.Text())
				}
				if real == "" {
					return fmt.Errorf("vault: real token cannot be empty")
				}
			} else {
				real = args[1]
			}

			cfg, err := config.Load(*cfgFile)
			if err != nil {
				return err
			}

			// Write to secrets file if using file backend
			if cfg.Vault.Backend == "file" && cfg.Vault.FilePath != "" {
				return appendToSecretsFile(cfg.Vault.FilePath, ghost, real)
			}

			// In-memory only (printed as instructions for other backends)
			fmt.Printf("Added %s (write to your secrets source to persist)\n", ghost)
			return nil
		},
	}
}

func vaultRevokeCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <ghost-token>",
		Short: "Remove a ghost token mapping",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ghost := args[0]
			cfg, err := config.Load(*cfgFile)
			if err != nil {
				return err
			}
			logger := zap.NewNop()
			v, closeFn, err := buildVault(cfg, logger)
			if err != nil {
				return err
			}
			defer closeFn()
			v.Revoke(ghost)
			fmt.Printf("Revoked %s\n", ghost)
			return nil
		},
	}
}

// ----------------------------------------------------------------------------
// ghostkey audit
// ----------------------------------------------------------------------------

func auditCmd() *cobra.Command {
	a := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the audit log",
	}
	a.AddCommand(auditTailCmd(), auditStatsCmd())
	return a
}

func auditTailCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Stream audit events in real time",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			if cfg.Audit.FilePath == "" {
				return fmt.Errorf("audit.file_path is not configured")
			}
			events, errc := audit.TailFile(cfg.Audit.FilePath)
			for {
				select {
				case e, ok := <-events:
					if !ok {
						return nil
					}
					printAuditEvent(e)
				case err := <-errc:
					if err != nil {
						return err
					}
				}
			}
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")
	return cmd
}

func auditStatsCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print summary statistics from the audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			if cfg.Audit.FilePath == "" {
				return fmt.Errorf("audit.file_path is not configured")
			}
			events, errc := audit.TailFile(cfg.Audit.FilePath)
			total, intercepts, rotations := 0, 0, 0
			ghosts := make(map[string]int)
			for {
				select {
				case e, ok := <-events:
					if !ok {
						goto done
					}
					total++
					switch e.EventType {
					case audit.EventIntercept:
						intercepts++
					case audit.EventRotate:
						rotations++
					}
					for _, g := range e.GhostTokens {
						ghosts[g]++
					}
				case err := <-errc:
					if err != nil {
						return err
					}
					goto done
				}
			}
		done:
			fmt.Printf("Total events:     %d\n", total)
			fmt.Printf("Intercepts:       %d\n", intercepts)
			fmt.Printf("Rotations:        %d\n", rotations)
			fmt.Printf("Active ghosts:    %d\n", len(ghosts))
			for g, count := range ghosts {
				fmt.Printf("  %-40s  %d requests\n", g, count)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")
	return cmd
}

// ----------------------------------------------------------------------------
// ghostkey check
// ----------------------------------------------------------------------------

func checkCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Verify config, CA, and vault connectivity",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				fmt.Printf("✗ Config:  %v\n", err)
				return err
			}
			fmt.Printf("✓ Config:  loaded (listen: %s)\n", cfg.Proxy.ListenAddr)

			ca, err := proxy.NewCAManager(cfg.CA.CertFile, cfg.CA.KeyFile)
			if err != nil {
				fmt.Printf("✗ CA:      %v\n", err)
				return err
			}
			_ = ca
			fmt.Println("✓ CA:      ready")

			logger := zap.NewNop()
			v, closeFn, err := buildVault(cfg, logger)
			if err != nil {
				fmt.Printf("✗ Vault:   %v\n", err)
				return err
			}
			defer closeFn()
			fmt.Printf("✓ Vault:   %d ghost token(s) registered\n", len(v.ListGhosts()))
			return nil
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")
	return cmd
}

// ----------------------------------------------------------------------------
// ghostkey version
// ----------------------------------------------------------------------------

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ghostkey %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func buildLogger(verbose bool) (*zap.Logger, error) {
	if verbose {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

// buildVault constructs the appropriate Vault implementation from config.
// The returned closeFn should be deferred by the caller.
func buildVault(cfg *config.Config, logger *zap.Logger) (vault.Vault, func(), error) {
	noop := func() {}

	switch cfg.Vault.Backend {
	case "file":
		if cfg.Vault.FilePath == "" && len(cfg.Vault.Mappings) == 0 {
			return vault.NewMemoryVault(), noop, nil
		}
		if cfg.Vault.FilePath != "" {
			fv, err := vault.NewFileVault(cfg.Vault.FilePath, cfg.Vault.WatchFile, logger)
			if err != nil {
				return nil, noop, err
			}
			// Merge any inline mappings
			for g, r := range cfg.Vault.Mappings {
				fv.Register(g, r)
			}
			return fv, fv.Close, nil
		}
		// Inline mappings only
		return vault.NewMemoryVaultFromMap(cfg.Vault.Mappings), noop, nil

	case "env":
		return vault.NewEnvVault(cfg.Vault.Mappings), noop, nil

	default:
		// Fallback: inline mappings in memory
		return vault.NewMemoryVaultFromMap(cfg.Vault.Mappings), noop, nil
	}
}

// appendToSecretsFile merges a new ghost→real mapping into an existing secrets file.
func appendToSecretsFile(path, ghost, real string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("vault: read secrets file: %w", err)
	}
	content := string(data)
	if !strings.Contains(content, "mappings:") {
		content = "mappings:\n" + content
	}
	line := fmt.Sprintf("  %q: %q\n", ghost, real)
	content += line

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return fmt.Errorf("vault: write secrets file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vault: rename secrets file: %w", err)
	}
	fmt.Printf("Added %s to %s\n", ghost, path)
	return nil
}

func printAuditEvent(e audit.Event) {
	fmt.Printf("[%s] %-12s  %-30s  %s %s  rewrites=%d  tokens=%v\n",
		e.Timestamp.Format(time.RFC3339),
		e.EventType,
		e.Upstream,
		e.Method,
		e.Path,
		e.Rewrites,
		e.GhostTokens,
	)
}
