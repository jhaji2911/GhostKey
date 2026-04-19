# GhostKey

Your AI agent knows your API keys. It logs them, echoes them, and could be tricked into leaking them. GhostKey ensures it never had them in the first place.

**Tagline:** *Agents send the ghost. Servers get the key.*

---

## The Problem

AI agents run with your API keys in their environment. When they make requests, those keys travel through the agent's context window, logs, debug output, and error traces. A single prompt injection, jailbreak, or context exfiltration exposes every secret the agent possesses.

GhostKey fixes this at the network layer. The agent is given a fake placeholder token (`GHOST::openai-prod`). GhostKey intercepts every outbound request and silently replaces the placeholder with the real secret before the packet reaches the server — without the agent ever knowing.

---

## Quick Start

```bash
# Install
brew install ghostkey
# or: go install github.com/yourusername/ghostkey/cmd/ghostkey@latest

# Trust the CA (one-time setup)
ghostkey ca install

# Add a credential mapping (reads real token from stdin — never from CLI args)
ghostkey vault add GHOST::openai -
# Enter real token: sk-proj-...

# Start the proxy (port 9876)
ghostkey start

# In another terminal: run your AI agent with ghost tokens
export HTTPS_PROXY=http://localhost:9876
export HTTP_PROXY=http://localhost:9876
export OPENAI_API_KEY=GHOST::openai
python your_agent.py
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
3. **Vault** — Credentials live in a `secrets.yaml` file (or environment variables). GhostKey hot-reloads it on change — no restart needed during credential rotation.
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

---

## CLI Reference

```
ghostkey start [-c config] [--listen addr] [-v]    Start the proxy
ghostkey ca install                                Install CA to system trust store
ghostkey ca show                                   Print CA PEM to stdout
ghostkey ca regen                                  Regenerate CA (invalidates leaf cache)
ghostkey vault list                                List ghost tokens (never real values)
ghostkey vault add <GHOST::name> -                 Add mapping (reads real token from stdin)
ghostkey vault revoke <GHOST::name>                Remove a mapping
ghostkey audit tail                                Stream audit log (like tail -f)
ghostkey audit stats                               Summary statistics
ghostkey check                                     Verify config + CA + vault
ghostkey version                                   Print version
```

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
- **Large streaming responses** — Response bodies over 10MB are not inspected for echoed tokens (to avoid unbounded memory use).
- **HTTP/2 push** — Not supported; proxied connections use HTTP/1.1.
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

## Roadmap

The following are intentionally out of scope for v0.1.3:

- gRPC support (v0.2.0)
- WebSocket support (v0.2.0)
- mTLS between GhostKey and upstream (v0.2.0)
- Native Kubernetes sidecar injection (v0.3.0)
- UI dashboard (v0.3.0)
- WASM/browser agent support (v1.0.0)

---

## Changelog

### v0.1.3 — Complete Rewrite in Go

- New name: **ghostkey** (was: agent-vault / ouroboros)
- Full TLS MITM interception (fixes the critical gap in the original Rust/eBPF prototype)
- Hot-reload credential rotation without proxy restart
- Multi-agent credential isolation via ghost token namespacing
- Structured audit log (NDJSON) — every interception recorded, real tokens never logged
- Single static binary, no Rust nightly toolchain required
- Cross-platform: Linux, macOS, Windows (amd64 + arm64)
- `ghostkey` CLI with `vault`, `ca`, and `audit` subcommands
