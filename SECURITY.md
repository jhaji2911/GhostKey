# Security Policy

## Reporting a Vulnerability

GhostKey sits in your network path and handles real credentials.
Security issues are taken very seriously.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues via GitHub's private vulnerability reporting:
https://github.com/jhaji2911/GhostKey/security/advisories/new

You will receive a response within 48 hours. We will work with you
on a coordinated disclosure timeline.

## Scope

**In scope:**
- Credential leakage through the proxy
- CA certificate vulnerabilities
- Vault file security (secrets.yaml)
- TLS interception bypass
- Ghost token format bypass (anything that causes a real token to appear in agent context)

**Out of scope:**
- Attacks requiring root access to the host machine
- Social engineering
- Vulnerabilities in upstream dependencies (report those to the dependency maintainers)

## Security Properties

GhostKey is designed with these properties:

1. **Real tokens never logged** — The audit log records ghost tokens only.
   Grep your audit log for real token patterns; you should find none.

2. **Vault file is 0600** — The secrets.yaml file is written with mode 0600.
   Only the owning user can read it.

3. **CA key is 0600** — The CA private key is written with mode 0700 on its
   directory and 0600 on the file.

4. **No outbound telemetry** — GhostKey makes no network connections other
   than relaying proxied agent traffic. There is no analytics, update check,
   or telemetry.

5. **Process isolation** — `ghostkey wrap` only injects proxy vars into the
   subprocess, not the parent shell or other terminals.

## Known Limitations

These are architectural limitations, not vulnerabilities, but are documented
honestly:

- An attacker with OS-level access to the GhostKey process can read real
  credentials from process memory.
- A compromised GhostKey binary undermines all security properties.
- Traffic from processes that don't use GhostKey's proxy is not protected.
