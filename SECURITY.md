# Security Policy

## Supported versions

WhatsCore is pre-1.0. Only the latest `v0.0.x` release line receives security
fixes; older releases should upgrade to the newest tag.

| Version | Supported |
|---------|-----------|
| v0.0.x  | Yes |
| earlier | No — upgrade |

## How to report a vulnerability

Use **GitHub's private vulnerability reporting**: on the repository, open the
**Security** tab and choose *Report a vulnerability*. Do **not** open public
issues, pull requests, or discussions for security reports.

Include in your report:

- Affected version or commit (`/version` output or `git rev-parse HEAD`)
- Reproduction steps (a minimal synthetic reproducer is ideal)
- Impact assessment
- Suggested mitigation, if you have one

## Scope

**In scope:**

- **Protocol engine** — crypto (Noise handshake, Signal-style E2E), transport
  (WebSocket framing, handshake), and memory handling of key material
- **REST server** — authentication (API key handling) and webhook signing
- **Credential storage** — how session credentials and secrets are stored,
  encrypted, and zeroed

**Out of scope:**

- WhatsApp server-side behavior — we cannot change Meta's infrastructure, and
  reports about server-side abuse detection or rate limiting are not
  actionable here
- Third-party webhook receivers and how they handle delivered payloads

## Expected response time

We aim to **acknowledge reports within 7 days** of submission. After
acknowledgment we will keep you informed as the report is triaged and fixed.
Note that WhatsCore is pre-1.0: where a correct fix requires a breaking
change, we will take the breaking change.

## Safe harbor

We consider security research conducted in good faith to be authorized, as
long as you:

- Use dedicated test accounts **you control** — never accounts you do not own
- Avoid privacy violations, destruction or exfiltration of data, and
  degradation of service for other users
- Give us reasonable time to fix an issue before public disclosure

## No real credentials in reports

Reports containing **real credentials, QR codes, pairing data, session
tokens, or API keys will be deleted** on sight. Please send **synthetic
reproductions only** — see
[tests/fixtures/README.md](tests/fixtures/README.md) for the synthetic key
conventions used by this project.
