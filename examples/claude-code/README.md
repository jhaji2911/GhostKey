# Using GhostKey with Claude Code

## Setup

1. Install GhostKey and add your Anthropic key:

   ```bash
   ghostkey vault add GHOST::anthropic
   # Enter real token: (hidden — your sk-ant-... key)
   ```

2. Set the ghost token in your environment:

   ```bash
   export ANTHROPIC_API_KEY=GHOST::anthropic
   ```

   Or add to your `.env`:

   ```
   ANTHROPIC_API_KEY=GHOST::anthropic
   ```

3. Run Claude Code through GhostKey:

   ```bash
   ghostkey wrap -- claude
   ```

   GhostKey injects `HTTPS_PROXY` only for the Claude process — it does not
   affect your browser, git, or other tools.

4. **Permanent alias** — Add to `~/.zshrc` or `~/.bashrc`:

   ```bash
   alias claude="ghostkey wrap -- claude"
   ```

   Now every `claude` invocation is automatically protected.

## Verify It's Working

Watch the audit log while Claude makes API calls:

```bash
ghostkey audit tail
```

You should see lines like:

```
[2024-01-15T...] intercept  api.anthropic.com  POST /v1/messages  rewrites=1  tokens=[GHOST::anthropic]
```

The agent sent `GHOST::anthropic`. Anthropic received your real key.
The real key never appeared in Claude's context, logs, or tool output.

## MCP Server Configuration

If your Claude Desktop `claude_desktop_config.json` contains a real Anthropic
key, GhostKey can protect it:

```bash
ghostkey scan ~/Library/Application\ Support/Claude/
```

GhostKey will find the key, offer to replace it with a ghost token, and prompt
you to add the real token to the vault.
