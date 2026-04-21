# Contributing to GhostKey

## Development Setup

```bash
git clone https://github.com/jhaji2911/GhostKey
cd GhostKey
go mod download
go build ./...
go test -race ./...
```

## Running Locally

```bash
make build
./bin/ghostkey start --verbose

# In another terminal:
./bin/ghostkey vault add GHOST::test
./bin/ghostkey wrap -- curl -H "Authorization: Bearer GHOST::test" https://httpbin.org/headers
```

## Before Submitting a PR

- [ ] `go test -race ./...` passes with zero failures
- [ ] `go vet ./...` passes
- [ ] New commands have `--help` text
- [ ] Sensitive data (real tokens) never appear in logs or test output
- [ ] Error messages follow this format:

```
  ✗ [What went wrong in plain English]
    [Why this happened — one sentence]
    Fix: [exact command to fix it]
```

## Architecture

```
cmd/ghostkey/main.go      — CLI commands (cobra)
internal/proxy/           — TLS interception and HTTP proxying
  proxy.go                — Core proxy server (ServeHTTP)
  tls.go                  — CA manager, leaf cert generation
  intercept.go            — GHOST:: token rewriting
internal/vault/           — Credential storage and hot-reload
  vault.go                — Vault interface + MemoryVault
  backends.go             — FileVault (YAML), EnvVault
internal/audit/           — Tamper-evident audit logging
  audit.go                — Auditor + NDJSON writer
internal/config/          — Configuration loading (Viper)
  config.go               — Config struct + Load()
scripts/
  install.sh              — One-liner installer
  install-ca.sh           — CA trust store installation helper
```

## Adding a New Vault Backend

1. Implement the `vault.Vault` interface in `internal/vault/backends.go`
2. Add a case in `buildVault()` in `cmd/ghostkey/main.go`
3. Add config fields to `VaultConfig` in `internal/config/config.go`
4. Add a test in `internal/vault/vault_test.go`

## Test Guidelines

- Unit tests live next to the code they test (`foo_test.go`)
- Integration tests use `httptest.NewTLSServer` for HTTPS testing
- Real credentials must never appear in test output or fixtures
- Use `t.TempDir()` for all temporary files in tests
- Table-driven tests are preferred for multiple cases

## Release Process

1. Update `Version` in `cmd/ghostkey/main.go`
2. Update `GHOSTKEY_VERSION` in `scripts/install.sh`
3. Run `go mod tidy`
4. Tag: `git tag v0.x.y && git push origin v0.x.y`
5. CI will build and publish the release with binaries + SHA256SUMS
