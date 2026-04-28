// GhostKey — credential firewall for AI agents.
// Agents send the ghost. Servers get the key.
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/jhaji2911/ghostkey/internal/audit"
	"github.com/jhaji2911/ghostkey/internal/config"
	"github.com/jhaji2911/ghostkey/internal/proxy"
	"github.com/jhaji2911/ghostkey/internal/vault"
)

// Version is injected by the build system via -ldflags.
var Version = "v0.1.4"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:              "ghostkey",
		Short:            "Credential firewall for AI agents",
		Long:             "GhostKey ensures AI agents never possess real credentials.\nAgents send the ghost. Servers get the key.",
		TraverseChildren: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			printIntro(cmd.CommandPath())
		},
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	root.AddCommand(
		initCmd(),
		startCmd(),
		wrapCmd(),
		caCmd(),
		vaultCmd(),
		auditCmd(),
		doctorCmd(),
		scanCmd(),
		serviceCmd(),
		checkCmd(),
		versionCmd(),
	)
	return root
}

type introFlavor struct {
	Label string
}

var introFlavors = []introFlavor{
	{Label: "Specter"},
	{Label: "Phantom"},
	{Label: "Poltergeist"},
	{Label: "Wisp"},
	{Label: "Mist"},
}

func printIntro(commandPath string) {
	ghost := `
   ▄▄▄▄▄▄▄
  █████████
  ██▀███▀██
  █████████
  ▀█▀ ▀ ▀█▀
`
	flavor := introFlavorFor(commandPath)
	fmt.Printf("\033[36m%s\033[0m", ghost)
	fmt.Printf("  \033[1;36mGhostKey\033[0m %s\n", Version)
	fmt.Printf("  %s mode: %s\n", flavor.Label, commandPath)
	fmt.Println("  Credential firewall for AI agents.")
	fmt.Println()
}

func introFlavorFor(commandPath string) introFlavor {
	h := fnv.New32a()
	_, _ = h.Write([]byte(commandPath))
	return introFlavors[h.Sum32()%uint32(len(introFlavors))]
}

const defaultConfigTemplate = `proxy:
  listen_addr: "127.0.0.1:9876"
  read_timeout: 30
  write_timeout: 30

vault:
  backend: file
  file_path: "./secrets.yaml"
  watch_file: true

audit:
  enabled: true
  file_path: "./ghostkey-audit.ndjson"
  format: json

ca:
  cert_file: ""
  key_file: ""
`

const defaultSecretsTemplate = `# secrets.yaml — keep this file out of git
mappings: {}
`

var providerEnvVars = map[string][]string{
	"openai":      {"OPENAI_API_KEY"},
	"anthropic":   {"ANTHROPIC_API_KEY"},
	"github":      {"GITHUB_TOKEN"},
	"huggingface": {"HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN"},
	"stripe":      {"STRIPE_API_KEY"},
}

type secretsFile struct {
	Mappings map[string]string `yaml:"mappings"`
}

// ----------------------------------------------------------------------------
// ghostkey init
// ----------------------------------------------------------------------------

func initCmd() *cobra.Command {
	var dir string
	var force bool
	var generateCA bool
	var projectMode bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Bootstrap GhostKey config, secrets, and safety defaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir, err := resolveInitDir(dir, projectMode)
			if err != nil {
				return err
			}
			absDir, err := filepath.Abs(targetDir)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(absDir, 0750); err != nil {
				return err
			}

			configPath := filepath.Join(absDir, "ghostkey.yaml")
			secretsPath := filepath.Join(absDir, "secrets.yaml")

			if err := writeBootstrapFile(configPath, defaultConfigTemplate, force); err != nil {
				return err
			}
			if err := writeBootstrapFile(secretsPath, defaultSecretsTemplate, force); err != nil {
				return err
			}
			if err := ensureGitignoreEntries(absDir, []string{"secrets.yaml", "ghostkey-audit.ndjson"}); err != nil {
				return err
			}
			if generateCA {
				if _, err := proxy.NewCAManager("", ""); err != nil {
					return fmt.Errorf("generate CA: %w", err)
				}
			}

			fmt.Printf("  ✓ Wrote %s\n", configPath)
			fmt.Printf("  ✓ Wrote %s\n", secretsPath)
			fmt.Printf("  ✓ Updated %s\n", filepath.Join(absDir, ".gitignore"))
			if generateCA {
				fmt.Println("  ✓ Generated local GhostKey CA")
			}
			fmt.Println()
			fmt.Println("  Next steps:")
			fmt.Printf("    ghostkey ca install\n")
			fmt.Printf("    ghostkey vault add -c %s GHOST::openai\n", configPath)
			fmt.Printf("    ghostkey start -c %s\n", configPath)
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Directory to initialize (default: ~/.ghostkey, or current directory with --project)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing ghostkey.yaml and secrets.yaml")
	cmd.Flags().BoolVar(&generateCA, "ca", true, "Generate the local GhostKey CA during init")
	cmd.Flags().BoolVar(&projectMode, "project", false, "Initialize GhostKey files in current project directory instead of ~/.ghostkey")
	return cmd
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

			// First-run experience: no vault entries yet
			if len(v.ListGhosts()) == 0 {
				fmt.Println("  First time running? Let's get you set up.")
				fmt.Println()
				fmt.Println("  1. Add a credential:")
				fmt.Println("     ghostkey vault add GHOST::openai")
				fmt.Println()
				fmt.Println("  2. Run your agent through GhostKey:")
				fmt.Println("     ghostkey wrap -- claude")
				fmt.Println("     ghostkey wrap -- python agent.py")
				fmt.Println()
				fmt.Println("  3. Check that everything's working:")
				fmt.Println("     ghostkey doctor")
				fmt.Println()
			}

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
			defer func() { _ = a.Close() }()

			// Build and start proxy
			p := proxy.New(cfg, v, ca, a, logger)

			fmt.Printf("  Listening on %s...\n\n", cfg.Proxy.ListenAddr)

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
	ca.AddCommand(caInstallCmd(), caUninstallCmd(), caShowCmd(), caRegenCmd())
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
				c := exec.Command("sudo", "security", "add-trusted-cert", //nolint:gosec // intentional: installs CA into system keychain
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
					data, err := os.ReadFile(certPath) //nolint:gosec // intentional: certPath is derived from user home directory
					if err != nil {
						return err
					}
					if err := os.WriteFile(dest, data, 0644); err != nil { //nolint:gosec // CA cert is public; world-readable is correct for trust anchors
						return fmt.Errorf("write %s (try sudo): %w", dest, err)
					}
					return exec.Command("sudo", "update-ca-certificates").Run() //nolint:gosec // intentional: runs system CA update tool
				}
				dest := "/etc/pki/ca-trust/source/anchors/ghostkey.crt"
				data, err := os.ReadFile(certPath) //nolint:gosec // intentional: certPath is derived from user home directory
				if err != nil {
					return err
				}
				if err := os.WriteFile(dest, data, 0644); err != nil { //nolint:gosec // CA cert is public; world-readable is correct for trust anchors
					return fmt.Errorf("write %s (try sudo): %w", dest, err)
				}
				return exec.Command("sudo", "update-ca-trust").Run() //nolint:gosec // intentional: runs system CA update tool
			default:
				return fmt.Errorf("automatic install not supported on %s — see 'ghostkey ca show'", runtime.GOOS)
			}
		},
	}
}

func caUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the GhostKey CA certificate from system trust store and disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			certPath := filepath.Join(home, ".ghostkey", "ca.crt")
			keyPath := filepath.Join(home, ".ghostkey", "ca.key")

			fmt.Println()
			fmt.Println("  Removing GhostKey CA certificate...")
			fmt.Println()

			// Remove from system trust store
			switch runtime.GOOS {
			case "darwin":
				c := exec.Command("sudo", "security", "delete-certificate",
					"-c", "GhostKey CA", "/Library/Keychains/System.keychain")
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				if err := c.Run(); err != nil {
					fmt.Printf("  ⚠ Could not remove from macOS keychain (may not be installed): %v\n", err)
				} else {
					fmt.Println("  ✓ Removed from macOS System Keychain")
				}
			case "linux":
				for _, p := range []string{
					"/usr/local/share/ca-certificates/ghostkey.crt",
					"/etc/pki/ca-trust/source/anchors/ghostkey.crt",
				} {
					if err := os.Remove(p); err == nil {
						_ = exec.Command("sudo", "update-ca-certificates").Run()
						_ = exec.Command("sudo", "update-ca-trust").Run()
						fmt.Println("  ✓ Removed from Linux CA trust store")
						break
					}
				}
			}

			// Delete cert and key files
			for _, p := range []string{certPath, keyPath} {
				if err := os.Remove(p); err == nil {
					fmt.Printf("  ✓ Deleted %s\n", p)
				}
			}

			fmt.Println()
			fmt.Println("  GhostKey's certificate has been fully removed from your system.")
			fmt.Println("  Your HTTPS traffic is no longer inspected by GhostKey.")
			fmt.Println()
			return nil
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
			data, err := os.ReadFile(certPath) //nolint:gosec // intentional: certPath is derived from user home directory
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
		Use:   "add [ghost-token]",
		Short: "Add a ghost→real mapping (interactive secure prompt, token never in shell history)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var ghost string
			if len(args) > 0 {
				ghost = args[0]
			} else {
				fmt.Print("\n  Enter ghost token name (e.g. GHOST::openai): ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("could not read input: %w", err)
				}
				ghost = strings.TrimSpace(input)
				if ghost == "" {
					return fmt.Errorf("ghost token cannot be empty")
				}
			}

			if !strings.HasPrefix(ghost, "GHOST::") {
				ghost = "GHOST::" + ghost
			}

			if err := vault.ValidateGhostToken(ghost); err != nil {
				return err
			}

			fmt.Printf("\n  Adding credential for %s\n\n", ghost)
			fmt.Printf("  Real token (hidden): ")
			real, err := readPassword()
			if err != nil {
				return fmt.Errorf("could not read token: %w", err)
			}
			fmt.Println()

			fmt.Printf("  Confirm token:       ")
			confirm, err := readPassword()
			if err != nil {
				return fmt.Errorf("could not read token: %w", err)
			}
			fmt.Println()

			if real != confirm {
				return fmt.Errorf("\n  ✗ tokens do not match")
			}
			if real == "" {
				return fmt.Errorf("vault: real token cannot be empty")
			}

			cfg, err := config.Load(*cfgFile)
			if err != nil {
				return err
			}

			// Write to secrets file if using file backend
			if cfg.Vault.Backend == "file" && cfg.Vault.FilePath != "" {
				if err := upsertSecretsFileMapping(cfg.Vault.FilePath, ghost, real); err != nil {
					return err
				}
			} else {
				fmt.Printf("  Added %s (write to your secrets source to persist)\n", ghost)
			}

			// Derive a friendly name for the export hint (strip "GHOST::" prefix, uppercase)
			name := strings.ToUpper(strings.TrimPrefix(ghost, "GHOST::"))
			fmt.Printf("\n  ✓ Saved. Use it like this:\n\n")
			fmt.Printf("    export %s_API_KEY=%s\n", name, ghost)
			fmt.Printf("    ghostkey wrap -- python agent.py\n\n")
			return nil
		},
	}
}

func vaultRevokeCmd(cfgFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke [ghost-token]",
		Short: "Remove a ghost token mapping",
		Args:  cobra.MaximumNArgs(1),
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

			var ghost string
			if len(args) > 0 {
				ghost = args[0]
			} else {
				ghosts := v.ListGhosts()
				if len(ghosts) == 0 {
					fmt.Println("  (no ghost tokens registered)")
					return nil
				}
				fmt.Println("\n  Registered ghost tokens:")
				for i, g := range ghosts {
					fmt.Printf("    [%d] %s\n", i+1, g)
				}
				fmt.Print("\n  Select token to revoke (number) or name: ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("could not read input: %w", err)
				}
				input = strings.TrimSpace(input)
				if input == "" {
					return nil // cancel
				}

				// check if numeric selection
				var selectedIndex int
				if n, err := fmt.Sscanf(input, "%d", &selectedIndex); err == nil && n == 1 {
					if selectedIndex >= 1 && selectedIndex <= len(ghosts) {
						ghost = ghosts[selectedIndex-1]
					} else {
						return fmt.Errorf("invalid selection")
					}
				} else {
					ghost = input
					if !strings.HasPrefix(ghost, "GHOST::") {
						ghost = "GHOST::" + ghost
					}
				}
			}

			if cfg.Vault.Backend == "file" && cfg.Vault.FilePath != "" {
				removed, err := removeSecretsFileMapping(cfg.Vault.FilePath, ghost)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Printf("No mapping found for %s in %s\n", ghost, cfg.Vault.FilePath)
					return nil
				}
				fmt.Printf("Revoked %s\n", ghost)
				return nil
			}

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
// ghostkey wrap
// ----------------------------------------------------------------------------

func wrapCmd() *cobra.Command {
	var port int
	var cfgFile string
	var envMappings []string
	var autoEnv bool
	cmd := &cobra.Command{
		Use:   "wrap -- <command> [args...]",
		Short: "Run a command with proxy env vars injected (agent never touches system proxy)",
		Long: `Run a command as a subprocess with GhostKey proxy env vars injected only for that process.
Does not touch system proxy settings. Does not affect other terminals.

Examples:
  ghostkey wrap -- claude
  ghostkey wrap -- python agent.py
  ghostkey wrap -- aider --model gpt-4o
  ghostkey wrap -- npx @anthropic-ai/claude-code`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: ghostkey wrap -- <command> [args...]")
			}

			proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)

			// Check proxy is reachable
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				return fmt.Errorf(
					"  ✗ Proxy is not running\n    GhostKey needs to be running before you can wrap commands.\n    Fix: ghostkey start\n    Or install as a service: ghostkey service install",
				)
			}
			_ = conn.Close()

			assignments := []string{
				"HTTPS_PROXY=" + proxyURL,
				"HTTP_PROXY=" + proxyURL,
				"https_proxy=" + proxyURL,
				"http_proxy=" + proxyURL,
				"NO_PROXY=localhost,127.0.0.1,::1",
				"no_proxy=localhost,127.0.0.1,::1",
			}

			existingEnv := envSliceToMap(os.Environ())
			if autoEnv || len(envMappings) > 0 {
				cfg, err := config.Load(cfgFile)
				if err == nil {
					logger := zap.NewNop()
					v, closeFn, vaultErr := buildVault(cfg, logger)
					if vaultErr == nil {
						defer closeFn()
						if autoEnv {
							assignments = append(assignments, inferGhostEnvAssignments(v.ListGhosts(), existingEnv)...)
						}
					}
				}
			}

			explicitAssignments, err := parseWrapEnvMappings(envMappings)
			if err != nil {
				return err
			}
			assignments = append(assignments, explicitAssignments...)

			proc := exec.Command(args[0], args[1:]...) //nolint:gosec // intentional: wraps arbitrary user command with proxy env vars
			proc.Env = mergeEnvAssignments(os.Environ(), assignments)
			proc.Stdin = os.Stdin
			proc.Stdout = os.Stdout
			proc.Stderr = os.Stderr
			return proc.Run()
		},
	}
	cmd.Flags().IntVar(&port, "port", 9876, "GhostKey proxy port")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file used to infer ghost-token env vars")
	cmd.Flags().StringArrayVar(&envMappings, "env", nil, "Explicit env assignment in KEY=GHOST::token form")
	cmd.Flags().BoolVar(&autoEnv, "auto-env", true, "Infer common provider env vars from configured ghost tokens")
	return cmd
}

// ----------------------------------------------------------------------------
// ghostkey doctor
// ----------------------------------------------------------------------------

func doctorCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check GhostKey installation and report any issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			issues := 0

			fmt.Println()
			fmt.Println("  Checking GhostKey installation...")
			fmt.Println()

			// Binary / version
			fmt.Printf("  [✓] Binary:       %s %s\n", os.Args[0], Version)

			// Config
			cfg, cfgErr := config.Load(cfgFile)
			if cfgErr != nil {
				fmt.Printf("  [✗] Config:       error — %v\n", cfgErr)
				issues++
			} else {
				cfgPath := cfgFile
				if cfgPath == "" {
					home, _ := os.UserHomeDir()
					cfgPath = filepath.Join(home, ".ghostkey", "ghostkey.yaml")
					if _, err := os.Stat(cfgPath); err != nil {
						cfgPath = "defaults"
					}
				}
				fmt.Printf("  [✓] Config:       %s\n", cfgPath)
			}

			// CA cert
			home, _ := os.UserHomeDir()
			certPath := filepath.Join(home, ".ghostkey", "ca.crt")
			if _, err := os.Stat(certPath); err != nil {
				fmt.Printf("  [✗] CA cert:      not found at %s\n", certPath)
				fmt.Printf("      Fix: ghostkey start  (auto-generates CA)\n")
				issues++
			} else {
				// Check expiry
				data, _ := os.ReadFile(certPath) //nolint:gosec // intentional: certPath is derived from user home directory
				expiry := parseCertExpiry(data)
				if expiry.IsZero() {
					fmt.Printf("  [✓] CA cert:      %s\n", certPath)
				} else if time.Until(expiry) < 30*24*time.Hour {
					fmt.Printf("  [⚠] CA cert:      %s (expires %s — renew soon)\n", certPath, expiry.Format("2006-01-02"))
					issues++
				} else {
					fmt.Printf("  [✓] CA cert:      %s (expires %s)\n", certPath, expiry.Format("2006-01-02"))
				}

				// Check if trusted
				trusted := isCATrusted(certPath)
				if trusted {
					fmt.Printf("  [✓] CA trusted:   System trust store\n")
				} else {
					fmt.Printf("  [✗] CA trusted:   NOT in system trust store\n")
					fmt.Printf("      Fix: ghostkey ca install\n")
					issues++
				}
			}

			// Proxy running
			listenAddr := "127.0.0.1:9876"
			if cfg != nil && cfg.Proxy.ListenAddr != "" {
				listenAddr = cfg.Proxy.ListenAddr
			}
			conn, dialErr := net.DialTimeout("tcp", listenAddr, time.Second)
			if dialErr != nil {
				fmt.Printf("  [✗] Proxy:        Not running on %s\n", listenAddr)
				fmt.Printf("      Fix: ghostkey start\n")
				fmt.Printf("      Or install as a service: ghostkey service install\n")
				issues++
			} else {
				_ = conn.Close()
				fmt.Printf("  [✓] Proxy:        Running on %s\n", listenAddr)
			}

			// Vault
			if cfg != nil {
				logger := zap.NewNop()
				v, closeFn, vaultErr := buildVault(cfg, logger)
				if vaultErr != nil {
					fmt.Printf("  [✗] Vault:        error — %v\n", vaultErr)
					issues++
				} else {
					defer closeFn()
					count := len(v.ListGhosts())
					fmt.Printf("  [✓] Vault:        %d credential(s) registered\n", count)
				}
			}

			// Service
			serviceRunning := isServiceInstalled()
			if serviceRunning {
				fmt.Printf("  [✓] Service:      Installed\n")
			} else {
				fmt.Printf("  [✗] Service:      Not registered — run: ghostkey service install\n")
				issues++
			}

			fmt.Println()
			if issues == 0 {
				fmt.Println("  All checks passed.")
			} else {
				fmt.Printf("  %d issue(s) found. Run the commands above to fix.\n", issues)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")
	return cmd
}

// parseCertExpiry reads a PEM certificate and returns its NotAfter time.
// parseCertExpiry reads a PEM certificate and returns its NotAfter time.
func parseCertExpiry(pemData []byte) time.Time {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}

// isCATrusted checks whether the ghostkey CA is in the system trust store.
func isCATrusted(certPath string) bool {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("security", "find-certificate", "-c", "GhostKey", "/Library/Keychains/System.keychain").Output()
		return err == nil && len(out) > 0
	case "linux":
		for _, p := range []string{
			"/usr/local/share/ca-certificates/ghostkey.crt",
			"/etc/pki/ca-trust/source/anchors/ghostkey.crt",
		} {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
	}
	return false
}

// isServiceInstalled checks if the GhostKey service is registered.
func isServiceInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", "sh.ghostkey.plist")
		_, err := os.Stat(plist)
		return err == nil
	case "linux":
		svc := filepath.Join(home, ".config", "systemd", "user", "ghostkey.service")
		_, err := os.Stat(svc)
		return err == nil
	}
	return false
}

// ----------------------------------------------------------------------------
// ghostkey scan
// ----------------------------------------------------------------------------

// credentialPattern defines a regex pattern for detecting a type of credential.
type credentialPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Ghost   string // suggested ghost token suffix
}

var credentialPatterns = []credentialPattern{
	{Name: "OpenAI API key", Pattern: regexp.MustCompile(`sk-proj-[a-zA-Z0-9_\-]{20,}`), Ghost: "openai"},
	{Name: "OpenAI API key (legacy)", Pattern: regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`), Ghost: "openai"},
	{Name: "Anthropic API key", Pattern: regexp.MustCompile(`sk-ant-api\d{2}-[a-zA-Z0-9\-_]{40,}`), Ghost: "anthropic"},
	{Name: "GitHub token", Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), Ghost: "github"},
	{Name: "GitHub Actions token", Pattern: regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), Ghost: "github-actions"},
	{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Ghost: "aws"},
	{Name: "Stripe secret key", Pattern: regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24}`), Ghost: "stripe"},
	{Name: "Stripe test key", Pattern: regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24}`), Ghost: "stripe-test"},
	{Name: "HuggingFace token", Pattern: regexp.MustCompile(`hf_[a-zA-Z0-9]{37}`), Ghost: "huggingface"},
}

type scanMatch struct {
	File    string
	Line    int
	Content string
	Pattern credentialPattern
	Ghost   string
}

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"__pycache__":  true,
	".cache":       true,
}

var skipExts = map[string]bool{
	".lock": true, ".sum": true, ".bin": true, ".exe": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".woff": true, ".ttf": true,
	".zip": true, ".tar": true, ".gz": true, ".br": true,
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory for exposed credentials that AI agents could exfiltrate",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}

			absPath, err := filepath.Abs(scanPath)
			if err != nil {
				return err
			}

			fmt.Printf("\n  Scanning for exposed credentials in %s...\n\n", absPath)

			var matches []scanMatch
			err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // skip unreadable
				}
				if info.IsDir() {
					if skipDirs[info.Name()] {
						return filepath.SkipDir
					}
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if skipExts[ext] {
					return nil
				}
				// Skip files larger than 1 MB
				if info.Size() > 1024*1024 {
					return nil
				}

				data, err := os.ReadFile(path) //nolint:gosec // intentional: path is from filepath.Walk output, not user input
				if err != nil {
					return nil
				}

				lines := strings.Split(string(data), "\n")
				for lineNum, line := range lines {
					// Skip lines that already have GHOST:: tokens
					if strings.Contains(line, "GHOST::") {
						continue
					}
					for _, pat := range credentialPatterns {
						if pat.Pattern.MatchString(line) {
							// Make relative path for display
							rel, _ := filepath.Rel(absPath, path)
							ghost := "GHOST::" + pat.Ghost
							matches = append(matches, scanMatch{
								File:    rel,
								Line:    lineNum + 1,
								Content: strings.TrimSpace(line),
								Pattern: pat,
								Ghost:   ghost,
							})
							break // one match per line
						}
					}
				}
				return nil
			})
			if err != nil {
				return err
			}

			if len(matches) == 0 {
				fmt.Println("  ✓ No exposed credentials found.")
				fmt.Println()
				return nil
			}

			fmt.Printf("  ⚠ Found %d exposed credential(s)\n\n", len(matches))
			for _, m := range matches {
				// Truncate long content for display
				content := m.Content
				if len(content) > 80 {
					content = content[:80] + "..."
				}
				fmt.Printf("  %s (line %d)\n", m.File, m.Line)
				fmt.Printf("    %s\n", content)
				fmt.Printf("    → Replace with: %s\n", suggestReplacement(m.Content, m.Pattern, m.Ghost))
				fmt.Printf("    → Then run: ghostkey vault add %s\n\n", m.Ghost)
			}

			fmt.Println("  ─────────────────────────────────────────────────────")
			fmt.Printf("  Any AI agent running in this directory has access to\n")
			fmt.Printf("  all %d of these real credentials.\n\n", len(matches))

			fmt.Printf("  Fix automatically? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))

			if answer != "y" && answer != "yes" {
				fmt.Println()
				return nil
			}

			fmt.Println()
			return applyFixes(absPath, matches)
		},
	}
	return cmd
}

// suggestReplacement replaces the matched token in the line with the ghost token.
func suggestReplacement(line string, pat credentialPattern, ghost string) string {
	return pat.Pattern.ReplaceAllString(line, ghost)
}

// applyFixes rewrites files replacing matched credentials with ghost tokens.
func applyFixes(basePath string, matches []scanMatch) error {
	// Group matches by file
	byFile := make(map[string][]scanMatch)
	for _, m := range matches {
		byFile[m.File] = append(byFile[m.File], m)
	}

	ghostsAdded := map[string]bool{}

	for relPath, fileMatches := range byFile {
		fullPath := filepath.Join(basePath, relPath)
		data, err := os.ReadFile(fullPath) //nolint:gosec // intentional: certPath is derived from user home directory
		if err != nil {
			fmt.Printf("  ✗ Could not read %s: %v\n", relPath, err)
			continue
		}

		content := string(data)
		for _, m := range fileMatches {
			content = m.Pattern.Pattern.ReplaceAllString(content, m.Ghost)
			ghostsAdded[m.Ghost] = true
		}

		if err := os.WriteFile(fullPath, []byte(content), 0600); err != nil { //nolint:gosec // path is constructed from Walk output, not user input
			fmt.Printf("  ✗ Could not write %s: %v\n", relPath, err)
			continue
		}
		fmt.Printf("  → Rewrote %s\n", relPath)
	}

	fmt.Println()
	for ghost := range ghostsAdded {
		fmt.Printf("  Run: ghostkey vault add %s\n", ghost)
	}

	fmt.Printf("\n  ✓ Done. Your agents now run with ghost tokens only.\n\n")
	return nil
}

// ----------------------------------------------------------------------------
// ghostkey service
// ----------------------------------------------------------------------------

func serviceCmd() *cobra.Command {
	svc := &cobra.Command{
		Use:   "service",
		Short: "Manage GhostKey as a system service (auto-start on login)",
	}
	svc.AddCommand(serviceInstallCmd(), serviceUninstallCmd(), serviceStatusCmd(), serviceLogsCmd())
	return svc
}

func serviceInstallCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register GhostKey as a system service (auto-starts on login)",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			binaryPath := os.Args[0]
			// Try to resolve full path if it's just a name
			if !filepath.IsAbs(binaryPath) {
				if abs, err := exec.LookPath(binaryPath); err == nil {
					binaryPath = abs
				}
			}

			configPath := cfgFile
			if configPath == "" {
				configPath = filepath.Join(home, ".ghostkey", "ghostkey.yaml")
			}
			logPath := filepath.Join(home, ".ghostkey", "ghostkey.log")

			switch runtime.GOOS {
			case "darwin":
				plistPath := filepath.Join(home, "Library", "LaunchAgents", "sh.ghostkey.plist")
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>sh.ghostkey</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + binaryPath + `</string>
    <string>start</string>
    <string>--config</string>
    <string>` + configPath + `</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>` + logPath + `</string>
  <key>StandardErrorPath</key><string>` + logPath + `</string>
</dict>
</plist>`
				if err := os.WriteFile(plistPath, []byte(plist), 0600); err != nil { //nolint:gosec // intentional: path is derived from user home directory
					return fmt.Errorf("could not write plist: %w", err)
				}
				_ = exec.Command("launchctl", "unload", plistPath).Run()                   //nolint:gosec // intentional: manages launchd service
				if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil { //nolint:gosec // intentional: manages launchd service
					return fmt.Errorf("launchctl load failed: %w", err)
				}
				fmt.Println("  ✓ Service registered (launchd) — starts automatically on login")

			case "linux":
				svcDir := filepath.Join(home, ".config", "systemd", "user")
				if err := os.MkdirAll(svcDir, 0750); err != nil {
					return err
				}
				unit := "[Unit]\nDescription=GhostKey credential proxy\nAfter=network.target\n\n" +
					"[Service]\nExecStart=" + binaryPath + " start --config " + configPath + "\n" +
					"Restart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
				svcPath := filepath.Join(svcDir, "ghostkey.service")
				if err := os.WriteFile(svcPath, []byte(unit), 0600); err != nil { //nolint:gosec // intentional: path is derived from user home directory
					return fmt.Errorf("could not write service file: %w", err)
				}
				_ = exec.Command("systemctl", "--user", "enable", "ghostkey").Run()
				_ = exec.Command("systemctl", "--user", "start", "ghostkey").Run()
				fmt.Println("  ✓ Service registered (systemd --user) — starts automatically on login")

			default:
				return fmt.Errorf("automatic service install not supported on %s", runtime.GOOS)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file path")
	return cmd
}

func serviceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the GhostKey service registration",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			switch runtime.GOOS {
			case "darwin":
				plistPath := filepath.Join(home, "Library", "LaunchAgents", "sh.ghostkey.plist")
				_ = exec.Command("launchctl", "unload", plistPath).Run() //nolint:gosec // intentional: manages launchd service
				if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
					return err
				}
				fmt.Println("  ✓ Service unregistered (launchd)")
			case "linux":
				svcPath := filepath.Join(home, ".config", "systemd", "user", "ghostkey.service")
				_ = exec.Command("systemctl", "--user", "stop", "ghostkey").Run()
				_ = exec.Command("systemctl", "--user", "disable", "ghostkey").Run()
				if err := os.Remove(svcPath); err != nil && !os.IsNotExist(err) {
					return err
				}
				fmt.Println("  ✓ Service unregistered (systemd --user)")
			default:
				return fmt.Errorf("service uninstall not supported on %s", runtime.GOOS)
			}
			return nil
		},
	}
}

func serviceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether GhostKey service is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch runtime.GOOS {
			case "darwin":
				out, err := exec.Command("launchctl", "list", "sh.ghostkey").Output()
				if err != nil {
					fmt.Println("  Service: not running (not loaded)")
					return nil
				}
				fmt.Printf("  Service: running\n%s\n", string(out))
			case "linux":
				out, err := exec.Command("systemctl", "--user", "status", "ghostkey").Output()
				if err != nil {
					fmt.Printf("  Service: %s\n", string(out))
					return nil
				}
				fmt.Print(string(out))
			default:
				fmt.Printf("  Service status not supported on %s\n", runtime.GOOS)
			}
			return nil
		},
	}
}

func serviceLogsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logs",
		Short: "Tail the GhostKey service log",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			logPath := filepath.Join(home, ".ghostkey", "ghostkey.log")

			var tailCmd *exec.Cmd
			switch runtime.GOOS {
			case "linux":
				// Try journalctl first
				if _, err := exec.LookPath("journalctl"); err == nil {
					tailCmd = exec.Command("journalctl", "--user", "-u", "ghostkey", "-f")
					tailCmd.Stdout = os.Stdout
					tailCmd.Stderr = os.Stderr
					return tailCmd.Run()
				}
				fallthrough
			default:
				tailCmd = exec.Command("tail", "-f", logPath) //nolint:gosec // intentional: logPath is derived from config
				tailCmd.Stdout = os.Stdout
				tailCmd.Stderr = os.Stderr
				return tailCmd.Run()
			}
		},
	}
}

// ----------------------------------------------------------------------------
// ghostkey version
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

func writeBootstrapFile(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func resolveInitDir(dir string, projectMode bool) (string, error) {
	if dir != "" {
		return dir, nil
	}
	if projectMode {
		return ".", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghostkey"), nil
}

func ensureGitignoreEntries(dir string, entries []string) error {
	path := filepath.Join(dir, ".gitignore")
	existingBytes, err := os.ReadFile(path) //nolint:gosec // path is derived from the working directory
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	existing := strings.Split(strings.ReplaceAll(string(existingBytes), "\r\n", "\n"), "\n")
	seen := make(map[string]bool, len(existing))
	for _, line := range existing {
		seen[strings.TrimSpace(line)] = true
	}
	for _, entry := range entries {
		if !seen[entry] {
			existing = append(existing, entry)
		}
	}

	content := strings.TrimSpace(strings.Join(existing, "\n"))
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func parseWrapEnvMappings(mappings []string) ([]string, error) {
	assignments := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		key, val, ok := strings.Cut(mapping, "=")
		if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("invalid --env %q: expected KEY=GHOST::token", mapping)
		}
		if err := vault.ValidateGhostToken(strings.TrimSpace(val)); err != nil {
			return nil, err
		}
		assignments = append(assignments, strings.TrimSpace(key)+"="+strings.TrimSpace(val))
	}
	return assignments, nil
}

func inferGhostEnvAssignments(ghosts []string, existing map[string]string) []string {
	if len(ghosts) == 0 {
		return nil
	}

	sortedGhosts := append([]string(nil), ghosts...)
	sort.Strings(sortedGhosts)

	assignments := make([]string, 0, len(sortedGhosts))
	assigned := make(map[string]bool)
	for _, ghost := range sortedGhosts {
		provider := inferProviderFromGhost(ghost)
		envVars := providerEnvVars[provider]
		for _, envVar := range envVars {
			if existing[envVar] != "" || assigned[envVar] {
				continue
			}
			assignments = append(assignments, envVar+"="+ghost)
			assigned[envVar] = true
			break
		}
	}
	return assignments
}

func inferProviderFromGhost(ghost string) string {
	name := strings.ToLower(strings.TrimPrefix(ghost, "GHOST::"))
	for _, sep := range []string{"-", "_"} {
		if idx := strings.Index(name, sep); idx > 0 {
			name = name[:idx]
			break
		}
	}
	return name
}

func envSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		key, val, ok := strings.Cut(kv, "=")
		if ok {
			out[key] = val
		}
	}
	return out
}

func mergeEnvAssignments(base, assignments []string) []string {
	merged := envSliceToMap(base)
	order := make([]string, 0, len(merged))
	seen := make(map[string]bool, len(merged))
	for _, kv := range base {
		key, _, ok := strings.Cut(kv, "=")
		if ok && !seen[key] {
			order = append(order, key)
			seen[key] = true
		}
	}
	for _, kv := range assignments {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if !seen[key] {
			order = append(order, key)
			seen[key] = true
		}
		merged[key] = val
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, key+"="+merged[key])
	}
	return out
}

func loadSecretsFile(path string) (*secretsFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from config or CLI-controlled workspace files
	if err != nil {
		if os.IsNotExist(err) {
			return &secretsFile{Mappings: map[string]string{}}, nil
		}
		return nil, fmt.Errorf("vault: read secrets file: %w", err)
	}
	var sf secretsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("vault: parse secrets file: %w", err)
	}
	if sf.Mappings == nil {
		sf.Mappings = map[string]string{}
	}
	return &sf, nil
}

func writeSecretsFile(path string, sf *secretsFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := yaml.Marshal(sf)
	if err != nil {
		return fmt.Errorf("vault: marshal secrets file: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { //nolint:gosec // tmp path is derived from config
		return fmt.Errorf("vault: write secrets file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("vault: rename secrets file: %w", err)
	}
	return nil
}

func upsertSecretsFileMapping(path, ghost, real string) error {
	sf, err := loadSecretsFile(path)
	if err != nil {
		return err
	}
	sf.Mappings[ghost] = real
	if err := writeSecretsFile(path, sf); err != nil {
		return err
	}
	fmt.Printf("Added %s to %s\n", ghost, path)
	return nil
}

func removeSecretsFileMapping(path, ghost string) (bool, error) {
	sf, err := loadSecretsFile(path)
	if err != nil {
		return false, err
	}
	if _, ok := sf.Mappings[ghost]; !ok {
		return false, nil
	}
	delete(sf.Mappings, ghost)
	if err := writeSecretsFile(path, sf); err != nil {
		return false, err
	}
	return true, nil
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

// readPassword reads a password from the terminal without echoing it.
// Falls back to plain stdin read if terminal is not available (e.g. in pipes/tests).
func readPassword() (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		return string(b), err
	}
	// Non-terminal fallback (piped input)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	return "", nil
}
