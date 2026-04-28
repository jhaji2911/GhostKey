# GhostKey

Your AI agent knows your API keys. It logs them, echoes them, and could be tricked into leaking them. GhostKey ensures it never had them in the first place.

**Tagline:** *Agents send the ghost. Servers get the key.*

---

## Status

GhostKey is **promising but not yet production-ready for shared infrastructure or regulated environments**.

What is verified today:

- The Go test suite passes (`go test ./...`).
- Core local workflows exist: TLS MITM proxying, ghost-token rewriting, file/env vault backends, audit logging, service helpers, and credential scanning.

What still keeps it out of a production-ready claim:

- The current release is best suited to a **single-user workstation or small internal setup**, not a hardened multi-tenant deployment.
- Only the **`file`** and **`env`** vault backends are implemented. The config examples still mention `hashicorp`, but there is no HashiCorp Vault backend in the code.
- HTTPS interception is limited to the current HTTP/1.1 proxy path; gRPC, WebSockets, and broader protocol coverage are not implemented.
- `ghostkey wrap` can now infer common provider env vars from configured ghost tokens, but protocol coverage and deployment hardening are still incomplete.
- CA trust, process trust, workstation hardening, and local file protection remain operational requirements outside the binary itself.

This README is written to match the current implementation rather than the intended future state.

---

## The Problem

AI agents run with your API keys in their environment. When they make requests, those keys travel through the agent's context window, logs, debug output, and error traces. A single prompt injection, jailbreak, or context exfiltration exposes every secret the agent possesses.

GhostKey fixes this at the network layer. The agent is given a fake placeholder token (`GHOST::openai-prod`). GhostKey intercepts every outbound request and silently replaces the placeholder with the real secret before the packet reaches the server — without the agent ever knowing.

---

## Quick Start

```bash
# Install via Homebrew tap
brew tap jhaji2911/ghostkey https://github.com/jhaji2911/ghostkey
brew install ghostkey

# or: install from source
go install github.com/jhaji2911/ghostkey/cmd/ghostkey@latest

# Bootstrap config, secrets, .gitignore entries, and the local CA in ~/.ghostkey
ghostkey init

# Trust the CA (one-time setup, after the CA exists)
ghostkey ca install

# Add a credential mapping to the configured secrets file
ghostkey vault add -c ~/.ghostkey/ghostkey.yaml GHOST::openai
# Enter real token twice when prompted

# Start the proxy with the explicit config file
ghostkey start -c ~/.ghostkey/ghostkey.yaml

# In another terminal: run your agent through GhostKey
# For common providers like OpenAI and Anthropic, wrap infers env vars automatically.
ghostkey wrap -c ~/.ghostkey/ghostkey.yaml --port 9876 -- python your_agent.py
```

The agent's logs, context window, and memory only ever contain `GHOST::openai`. The OpenAI API receives the real `sk-...` token.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  AI Agent Process                                            │
│  ENV: OPENAI_API_KEY=GHOST::openai-prod                     │
│       HTTPS_PROXY=http://localhost:9876                      │
│                            │                                 │
│                            ▼                                 │
│         ┌─────────────────────────────┐                      │
│         │   GhostKey Proxy (port 9876)│                      │
│         │                             │                      │
│         │  1. Terminate TLS (MITM CA) │                      │
│         │  2. Find GHOST:: tokens     │                      │
│         │  3. Lookup real credential  │                      │
│         │  4. Rewrite in-place        │                      │
│         │  5. Re-establish TLS to     │                      │
│         │     upstream server         │                      │
│         └─────────────────────────────┘                      │
│                            │                                 │
│                            ▼                                 │
│              api.openai.com / github.com / etc               │
└──────────────────────────────────────────────────────────────┘
```

---

## How It Works

GhostKey is a **transparent MITM proxy** with TLS interception:

1. **Ghost tokens** — You assign a placeholder like `GHOST::openai-prod` to each real credential. The agent only ever sees this value.
2. **TLS interception** — GhostKey generates a self-signed CA. Install it once with `ghostkey ca install`. GhostKey dynamically signs leaf certs per-hostname, decrypts HTTPS traffic, rewrites tokens, and re-encrypts to the real upstream.
3. **Vault** — Credentials live in a `secrets.yaml` file or in environment variables, depending on backend choice. The file backend hot-reloads on change — no restart needed during credential rotation.
4. **Audit log** — Every substitution is recorded as tamper-evident NDJSON. Ghost tokens are logged; real tokens are never recorded anywhere.

---

## Comparison

| | Env Vars | GhostKey |
|---|---|---|
| Agent can echo credentials | ✅ Yes | ❌ Never |
| Inspects HTTPS traffic | ❌ No | ✅ Yes (via MITM) |
| Audit log of every API call | ❌ No | ✅ Yes |
| Credential rotation without restart | ❌ No | ✅ Yes |
| Works with any agent framework | ✅ Yes | ✅ Yes |
| Single binary, no root daemon | ✅ Yes | ✅ Yes |

---

## Configuration

Copy `configs/ghostkey.example.yaml` to `ghostkey.yaml`:

```yaml
proxy:
  listen_addr: "127.0.0.1:9876"

vault:
  backend: file
  file_path: "./secrets.yaml"
  watch_file: true     # hot-reload on change

audit:
  enabled: true
  file_path: "./ghostkey-audit.ndjson"
```

Keep real credentials in a separate `secrets.yaml` (add to `.gitignore`):

```yaml
mappings:
  "GHOST::openai-prod": "sk-proj-..."
  "GHOST::github-ci": "ghp_..."
  "GHOST::aws-dev": "AKIA..."
```

Supported vault backends in the current codebase:

- `file` — YAML file containing `mappings:`
- `env` — `mappings` map ghost tokens to environment variable names

Not currently implemented:

- `hashicorp`

---

## CLI Reference

```
ghostkey start [-c config] [--listen addr] [-v]    Start the proxy
ghostkey init [--project] [--dir path] [--force]   Bootstrap config, secrets, and .gitignore
ghostkey wrap [--port 9876] -- <cmd> [args...]     Run command with proxy env vars injected
ghostkey ca install                                Install CA to system trust store
ghostkey ca uninstall                              Remove CA from trust store and disk
ghostkey ca show                                   Print CA PEM to stdout
ghostkey ca regen                                  Regenerate CA (invalidates leaf cache)
ghostkey vault list [-c config]                    List ghost tokens (never real values)
ghostkey vault add [-c config] <GHOST::name>       Add mapping (persists only with configured file backend)
ghostkey vault revoke [-c config] <GHOST::name>    Remove a mapping from the active vault
ghostkey audit tail [-c config]                    Stream audit log (like tail -f)
ghostkey audit stats [-c config]                   Summary statistics
ghostkey scan [path]                               Scan directory for exposed credentials
ghostkey service install [-c config]               Register as login service (launchd/systemd --user)
ghostkey service uninstall                         Remove service registration
ghostkey service status                            Show service status
ghostkey service logs                              Tail service log
ghostkey check [-c config]                         Verify config + CA + vault
ghostkey doctor [-c config]                        Installation health check
ghostkey version                                   Print version
```

---

## Operational Notes

- `ghostkey init` now defaults to `~/.ghostkey`. Use `ghostkey init --project` for repo-local setup.
- `ghostkey wrap` auto-infers common provider env vars such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `HF_TOKEN`, and `STRIPE_API_KEY` when their ghost tokens exist in configured vault.
- Use `ghostkey wrap --env OPENAI_API_KEY=GHOST::openai -- <cmd>` when you want explicit control over injected application env vars.
- `ghostkey ca install` requires the GhostKey CA to already exist. Running `ghostkey start` once is enough to generate it.
- `ghostkey init` can create `ghostkey.yaml`, `secrets.yaml`, `.gitignore` entries, and local CA in one step.
- Service management is implemented for macOS (`launchd`) and Linux (`systemd --user`). Windows binaries exist, but service helpers are not implemented here.
- The audit log stores ghost tokens and metadata only; file permissions still matter because request metadata may be sensitive.
- With the file backend, `ghostkey vault add` and `ghostkey vault revoke` now persist directly to `secrets.yaml`.

---

## Threat Model

**GhostKey protects against:**

- **Prompt injection / jailbreak** — The agent can only echo the ghost token (`GHOST::openai-prod`), never the real secret.
- **Log leakage** — Agent logs, debug output, and observability pipelines only ever see ghost tokens.
- **Context window exfiltration** — If the model's context is stolen or the provider is compromised, no real credentials are exposed.
- **Accidental credential commits** — Developers hardcode ghost tokens in configs; real secrets live only in `secrets.yaml`.

**GhostKey does NOT protect against:**

- An attacker with OS-level access to the GhostKey process itself (they can read process memory).
- A compromised GhostKey binary.
- Network-level attackers who can intercept the re-encrypted upstream TLS (use mTLS for that).

---

## Known Limitations

- **CA installation required** — One-time setup: `ghostkey ca install`. Firefox requires a manual import.
- **Not a process isolation boundary** — If an attacker can inspect the GhostKey process or host, they can still recover real credentials.
- **Backends are limited** — Only `file` and `env` backends are implemented in this release.
- **Large streaming responses** — Response bodies over 10MB are not inspected for echoed tokens (to avoid unbounded memory use).
- **HTTP/2 push** — Not supported; proxied connections use HTTP/1.1.
- **Protocol coverage is incomplete** — gRPC and WebSocket traffic are not supported.
- **OS-level attackers** — Anyone with access to the GhostKey process can extract real credentials from its memory.

---

## Comparison with Alternatives

| Tool | Approach | Gap |
|---|---|---|
| **Vault Agent sidecar** | Dynamic secrets injection | Does not intercept/inspect HTTP traffic; agent still holds real tokens |
| **mitmproxy** | General HTTPS proxy | No credential-aware rewriting; manual setup per request |
| **Environment variables** | Direct secret exposure | Agent possesses the real credential; logs and context leak it |
| **GhostKey** | Transparent token swap at network layer | Requires CA cert installation |

---

## Changelog

### v0.1.4

- `ghostkey wrap` — run any command with proxy env vars injected (no system proxy changes)
- `ghostkey scan` — detect real credentials in a directory and replace them with ghost tokens
- `ghostkey service` — register/unregister as a login service (launchd on macOS, systemd --user on Linux)
- `ghostkey doctor` — full installation health check (CA trust, proxy, vault, service)
- `ghostkey ca uninstall` — remove CA from system trust store and disk
- Fixed module path (`github.com/jhaji2911/ghostkey`) so `go install` works correctly

### v0.1.3 — Complete Rewrite in Go

- New name: **ghostkey** (was: agent-vault / ouroboros)
- Full TLS MITM interception (fixes the critical gap in the original Rust/eBPF prototype)
- Hot-reload credential rotation without proxy restart
- Multi-agent credential isolation via ghost token namespacing
- Structured audit log (NDJSON) — every interception recorded, real tokens never logged
- Single static binary, no Rust nightly toolchain required
- Cross-platform: Linux, macOS, Windows (amd64 + arm64)
- `ghostkey` CLI with `vault`, `ca`, and `audit` subcommands
