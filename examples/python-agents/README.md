# Using GhostKey with Python Agents

Works with any framework: LangChain, LangGraph, CrewAI, AutoGen, plain `openai` SDK.

## Setup

1. Add your credentials to the vault:

   ```bash
   ghostkey vault add GHOST::openai
   # Enter real token: (hidden)

   ghostkey vault add GHOST::anthropic
   # Enter real token: (hidden)
   ```

2. Update your `.env` to use ghost tokens (replace real keys):

   ```
   OPENAI_API_KEY=GHOST::openai
   ANTHROPIC_API_KEY=GHOST::anthropic
   ```

   Or scan for existing real keys:

   ```bash
   ghostkey scan .
   # GhostKey finds real keys and offers to replace them automatically
   ```

3. Run your agent:

   ```bash
   ghostkey wrap -- python agent.py

   # With uv:
   ghostkey wrap -- uv run python agent.py

   # With poetry:
   ghostkey wrap -- poetry run python agent.py

   # With venv:
   ghostkey wrap -- .venv/bin/python agent.py
   ```

## How It Works

`ghostkey wrap` sets `HTTPS_PROXY` and `HTTP_PROXY` only for the subprocess.
The Python `openai` and `anthropic` SDKs both respect these standard proxy
environment variables, so no code changes are needed.

The proxy intercepts the HTTPS request, finds `GHOST::openai` in the
`Authorization` header, replaces it with the real key, and forwards to
OpenAI. OpenAI receives the real key. Your Python code, logs, and LangChain
traces only ever see `GHOST::openai`.

## LangChain Example

```python
import os
from langchain_openai import ChatOpenAI

# This is what your code sees — the ghost token
print(os.environ["OPENAI_API_KEY"])  # GHOST::openai

# This is what OpenAI receives — the real key (via GhostKey)
llm = ChatOpenAI(model="gpt-4o")
response = llm.invoke("What is 2+2?")
```

Run with:

```bash
ghostkey wrap -- python langchain_agent.py
```

## Verifying No Credential Leakage

```bash
# Run your agent
ghostkey wrap -- python agent.py

# Check that no real keys appeared in the audit log
ghostkey audit tail | grep -v "GHOST::"
# (should be empty — ghost tokens only)
```
