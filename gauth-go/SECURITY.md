# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release on `main` | Yes |
| Older releases | Security fixes only |

## Reporting a Vulnerability

If you discover a security vulnerability in the GAuth Open Core Go SDK, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@gimel.foundation**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 5 business days
- **Fix timeline:** Depends on severity; critical issues are prioritized for immediate release

## Security Requirements for Contributions

All contributions must adhere to these security requirements:

1. **No credential leaks** — Never commit API keys, secrets, private keys, or tokens
2. **No unsafe cryptography** — Use only `crypto/ed25519`, `crypto/rsa`, `crypto/ecdsa`, and `crypto/hmac` from the Go standard library
3. **JWT algorithm restrictions** — RS256 and ES256 only; HS256 is prohibited per the GAuth protocol
4. **Fail-closed design** — All security checks must deny by default on error or ambiguity
5. **Ed25519 manifest verification** — Type C adapter manifests must be verified against the Gimel trusted key set; untrusted keys are rejected

## Scope

This security policy covers:
- The GAuth Open Core Go SDK source code (`pkg/` and `internal/`)
- The conformance test suite
- The Ed25519 manifest verification pipeline
- JWT token handling and validation

This security policy does not cover:
- Type C adapter proprietary implementations (covered by Gimel Technologies security processes)
- Third-party dependencies (report to the respective maintainers)

## Contact

Gimel Foundation gGmbH i.G.
security@gimel.foundation
https://gimelfoundation.com
