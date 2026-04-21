# Using GhostKey with MCP Servers

MCP (Model Context Protocol) server configs often contain real API keys inline.
GhostKey can protect them without changing how your editor or agent uses the servers.

## Scan for Exposed Keys

```bash
# Cursor
ghostkey scan ~/.cursor/

# Claude Desktop
ghostkey scan ~/Library/Application\ Support/Claude/

# VS Code GitHub Copilot MCP
ghostkey scan ~/Library/Application\ Support/Code/User/

# All at once
ghostkey scan ~
```

GhostKey will find real keys and offer to:
1. Replace them with ghost tokens in the config files
2. Prompt you to add the real tokens to the vault

## Manual Setup

If you prefer to configure manually, here's an example `mcp.json` before and after:

**Before:**
```json
{
  "mcpServers": {
    "my-api-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "OPENAI_API_KEY": "sk-proj-abc123...",
        "GITHUB_TOKEN": "ghp_xyz789..."
      }
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "my-api-server": {
      "command": "ghostkey",
      "args": ["wrap", "--", "node", "server.js"],
      "env": {
        "OPENAI_API_KEY": "GHOST::openai",
        "GITHUB_TOKEN": "GHOST::github"
      }
    }
  }
}
```

Then add the real tokens:

```bash
ghostkey vault add GHOST::openai
ghostkey vault add GHOST::github
```

## Restart Your Editor

After modifying MCP configs, restart your editor (Cursor, VS Code, Claude Desktop).
The MCP server will launch through `ghostkey wrap`, which injects the proxy only
for that server process. Other servers and tools are unaffected.

## Verify

```bash
ghostkey audit tail
# Watch for lines showing your MCP server's API calls
```
