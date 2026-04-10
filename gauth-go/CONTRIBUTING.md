# Contributing to GAuth Open Core Go SDK

Thank you for your interest in contributing to the GAuth Open Core Go SDK.

## Contribution Streams

### Stream A — Community Pull Requests

1. Fork the repository.
2. Create a `feature/*` or `fix/*` branch from `main`.
3. Open a pull request targeting `main`.
4. CI runs the full conformance test suite (CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S).
5. The Gimel Foundation Board of Trustees reviews the PR for:
   - Code quality
   - Spec alignment (all conformance tests must pass)
   - License compliance (MPL 2.0; no Excluded Component code without CLA)
   - Security (no credential leaks, no unsafe crypto)
6. Board approves → PR merged to `main`.

### Stream B — Architecture Team Pushes

1. Architecture team works in the Replit development sandbox.
2. Changes are pushed to the `replit` branch.
3. A PR is opened from `replit` → `main` when work is ready.
4. Same CI gates and Board review as Stream A.

Both streams follow the same PR-based merge path for identical auditability.

## Branch Model

```
main                ← protected release branch (all tags created here)
  ↑ PR (reviewed)
  │
replit              ← architecture team integration branch
  │
  ↑ PR (reviewed)
  │
feature/*           ← community feature branches
fix/*               ← community bugfix branches
```

- Every change enters `main` through a pull request. No exceptions.
- Tags are only ever created on `main`.
- The `replit` branch is an integration staging area, not a second `main`.

## CI Gates

Every PR targeting `main` triggers:

| Gate | Scope | Blocking |
|------|-------|----------|
| Conformance tests | CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S | Yes |
| Unit tests | `go test ./...` | Yes |
| Linting | `go vet`, style checks | Yes |
| License scan | No Excluded Component code in Open Core | Yes |
| Security scan | No credential leaks, no unsafe crypto | Yes |

## Running Tests

```bash
cd gauth-go
go test ./... -v
go test ./... -cover
```

All conformance tests must pass and all packages must maintain >80% code coverage.

## Excluded Components

Contributions to Excluded Components (Type C adapter implementations for slots 5, 6, and 7) require a separate Contributor License Agreement (CLA) with the Gimel Foundation. See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md) for the three proprietary exclusions.

The Excluded Components are:

1. **AI-Enabled Governance** (Slot 5 — `ai_governance`)
2. **Web3 Identity Integration** (Slot 6 — `web3_identity`)
3. **DNA-Based Identities / PQC** (Slot 7 — `dna_identity`)

The Type C adapter *interfaces* (method signatures) are open-source under MPL 2.0. Only the Gimel *implementations* of those interfaces are proprietary.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Use struct types with JSON tags for all request/response types.
- Maintain the existing package structure.
- All exported types and functions must have documentation comments.

## Commit Messages

Use clear, descriptive commit messages. Reference conformance test IDs (e.g., CT-REG-001) when relevant.

## Contact

- Licensing inquiries: licensing@gimel.foundation
- General questions: https://github.com/Gimel-Foundation
