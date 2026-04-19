package vault

import (
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// secretsFile is the on-disk YAML structure for a secrets file.
type secretsFile struct {
	Mappings map[string]string `yaml:"mappings"`
}

// FileVault is a Vault backed by a YAML file with optional hot-reload via fsnotify.
//
// Hot-reload allows credential rotation without restarting the proxy: edit secrets.yaml
// and the in-memory map is updated atomically within milliseconds.
type FileVault struct {
	mu       sync.RWMutex
	mappings map[string]string
	path     string
	logger   *zap.Logger
	watcher  *fsnotify.Watcher
	done     chan struct{}
}

// NewFileVault creates a FileVault that reads from the given YAML file.
// If watch is true, the file is monitored for changes and auto-reloaded.
func NewFileVault(path string, watch bool, logger *zap.Logger) (*FileVault, error) {
	fv := &FileVault{
		path:   path,
		logger: logger,
		done:   make(chan struct{}),
	}
	if err := fv.reload(); err != nil {
		return nil, fmt.Errorf("vault: file backend: initial load: %w", err)
	}
	if watch {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, fmt.Errorf("vault: file backend: fsnotify: %w", err)
		}
		if err := w.Add(path); err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("vault: file backend: watch %q: %w", path, err)
		}
		fv.watcher = w
		go fv.watchLoop()
	}
	return fv, nil
}

// reload reads the secrets file and atomically replaces the in-memory map.
func (f *FileVault) reload() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("vault: read %q: %w", f.path, err)
	}
	var sf secretsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("vault: parse %q: %w", f.path, err)
	}
	if sf.Mappings == nil {
		sf.Mappings = make(map[string]string)
	}
	f.mu.Lock()
	f.mappings = sf.Mappings
	f.mu.Unlock()
	f.logger.Info("vault: credentials loaded",
		zap.String("file", f.path),
		zap.Int("count", len(sf.Mappings)),
	)
	return nil
}

func (f *FileVault) watchLoop() {
	defer f.watcher.Close()
	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				f.logger.Info("vault: secrets file changed, reloading",
					zap.String("file", f.path))
				if err := f.reload(); err != nil {
					f.logger.Error("vault: hot-reload failed", zap.Error(err))
				}
			}
		case err, ok := <-f.watcher.Errors:
			if !ok {
				return
			}
			f.logger.Error("vault: fsnotify error", zap.Error(err))
		case <-f.done:
			return
		}
	}
}

// Close stops the file watcher goroutine.
func (f *FileVault) Close() {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
}

// Resolve returns the real credential for a ghost token.
func (f *FileVault) Resolve(ghostToken string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	real, ok := f.mappings[ghostToken]
	return real, ok
}

// Register adds or updates a ghost→real mapping in memory.
// Note: this does NOT write back to the secrets file.
func (f *FileVault) Register(ghostToken, realToken string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mappings[ghostToken] = realToken
}

// Revoke removes a ghost token mapping from memory.
// Note: this does NOT write back to the secrets file.
func (f *FileVault) Revoke(ghostToken string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.mappings, ghostToken)
}

// ListGhosts returns all registered ghost tokens. Real tokens are never returned.
func (f *FileVault) ListGhosts() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ghosts := make([]string, 0, len(f.mappings))
	for ghost := range f.mappings {
		ghosts = append(ghosts, ghost)
	}
	return ghosts
}

// EnvVault resolves ghost tokens to real credentials stored in environment variables.
// Mappings in this vault map ghost tokens to environment variable NAMES (not values),
// e.g.: "GHOST::openai" → "OPENAI_API_KEY".
type EnvVault struct {
	mu       sync.RWMutex
	mappings map[string]string // ghost → env var name
}

// NewEnvVault creates an EnvVault with the provided ghost→envvar-name mappings.
func NewEnvVault(mappings map[string]string) *EnvVault {
	m := make(map[string]string, len(mappings))
	for k, v := range mappings {
		m[k] = v
	}
	return &EnvVault{mappings: m}
}

// Resolve looks up the env var name for the ghost token and returns its current value.
func (e *EnvVault) Resolve(ghostToken string) (string, bool) {
	e.mu.RLock()
	envVar, ok := e.mappings[ghostToken]
	e.mu.RUnlock()
	if !ok {
		return "", false
	}
	val := os.Getenv(envVar)
	if val == "" {
		return "", false
	}
	return val, true
}

// Register maps a ghost token to an environment variable name.
func (e *EnvVault) Register(ghostToken, envVarName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mappings[ghostToken] = envVarName
}

// Revoke removes a ghost token mapping.
func (e *EnvVault) Revoke(ghostToken string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.mappings, ghostToken)
}

// ListGhosts returns all registered ghost tokens.
func (e *EnvVault) ListGhosts() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ghosts := make([]string, 0, len(e.mappings))
	for ghost := range e.mappings {
		ghosts = append(ghosts, ghost)
	}
	return ghosts
}
