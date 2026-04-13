# GAuth Open Core Go SDK

**Version 0.91 — Public Preview**

**GiFo-RFC-0128** — Go implementation of the Gimel Foundation's GAuth authorization protocol.

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

The GAuth protocol enables AI systems — digital agents, agentic AI, and humanoid robots — to legitimize power of attorney towards third parties on behalf of their owners. This SDK implements the protocol as defined in:

- **GiFo-RFC 0110** — GAuth Protocol Engine
- **GiFo-RFC 0111** — GAuth Authorization Framework
- **GiFo-RFC 0115** — Power-of-Attorney Credential Definition
- **GiFo-RFC 0116** — GAuth Interoperability (v2.2)
- **GiFo-RFC 0117** — GAuth Policy Enforcement Point (v1.2)
- **GiFo-RFC 0118** — GAuth Management API & Administration Interface (v1.1)

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    GAuth Open Core Go SDK                    │
│                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐   │
│  │ pkg/poa │  │pkg/token│  │ pkg/pep │  │pkg/management│   │
│  │         │  │         │  │         │  │              │   │
│  │ PoA     │  │ JWT     │  │ 16-Check│  │ Mandate CRUD │   │
│  │ Types   │  │ Extended│  │ Pipeline│  │ State Machine│   │
│  │ Scope   │  │ Token   │  │ Enforce │  │ Lifecycle    │   │
│  │ Checksum│  │ RS256/  │  │ Batch   │  │ Validation   │   │
│  │ Verbs   │  │ ES256   │  │ HTTP    │  │ HTTP API     │   │
│  └─────────┘  └─────────┘  └─────────┘  └──────────────┘   │
│                                                              │
│  ┌────────────┐  ┌──────────┐  ┌────────────────────────┐   │
│  │pkg/adapter │  │pkg/oauth │  │  internal/canonical    │   │
│  │            │  │          │  │                        │   │
│  │ Sealed     │  │ OAuth    │  │  Deterministic JSON    │   │
│  │ Registry   │  │ Engine   │  │  SHA-256 Hashing       │   │
│  │ Ed25519    │  │ Token    │  │                        │   │
│  │ No-op Dflt │  │ Lifecycle│  │                        │   │
│  └────────────┘  └──────────┘  └────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Installation

```bash
go get github.com/gimelfoundation/gauth-go
```

## Quick Start

### Create a PoA Credential

```go
import "github.com/gimelfoundation/gauth-go/pkg/poa"

credential := &poa.PoACredential{
    SchemaVersion: poa.SchemaVersion,
    CredentialID:  "poa-001",
    Parties: poa.Parties{
        Subject:    "my-ai-agent",
        CustomerID: "cust_123",
        ProjectID:  "proj_456",
        IssuedBy:   "admin_user",
    },
    Scope: poa.Scope{
        GovernanceProfile: poa.ProfileStandard,
        Phase:             poa.PhaseBuild,
        AllowedPaths:      []string{"src/", "tests/"},
        DeniedPaths:       []string{".env", "secrets/"},
        CoreVerbs: map[string]poa.ToolPolicy{
            "foundry.file.create": {Allowed: true, CostCentsBase: 1},
            "foundry.file.modify": {Allowed: true, CostCentsBase: 1},
        },
    },
    Requirements: poa.Requirements{
        ApprovalMode: poa.ApprovalAutonomous,
        Budget:       &poa.Budget{TotalCents: 10000, RemainingCents: 10000},
        TTLSeconds:   3600,
    },
}

checksum, _ := poa.ComputeScopeChecksum(credential.Scope)
```

### Issue a JWT Extended Token

```go
import "github.com/gimelfoundation/gauth-go/pkg/token"

sigKey, verKey, _ := token.GenerateRS256Key("my-key-id")

gauthClaims := token.ClaimsFromPoA(credential, checksum, toolHash, platHash)
tokenStr, _ := token.NewTokenBuilder(sigKey).
    SetStandardClaims("https://gauth.example.dev", "my-ai-agent", []string{"https://api.dev"}, time.Hour).
    SetGAuthClaims(gauthClaims).
    Build()
```

### Enforce with PEP

```go
import "github.com/gimelfoundation/gauth-go/pkg/pep"

pepEngine := pep.New("1.0.0", poa.ModeStateless)
decision, _ := pepEngine.EnforceAction(&pep.EnforcementRequest{
    RequestID: "req-001",
    Agent:     pep.AgentIdentity{AgentID: "my-ai-agent"},
    Action:    pep.Action{Verb: "foundry.file.create", Resource: "src/main.go"},
    Credential: pep.CredentialReference{
        Format:      poa.FormatJWT,
        PoASnapshot: snapshot,
    },
})
// decision.Decision: PERMIT, DENY, or CONSTRAIN
```

### Manage Mandates

```go
import "github.com/gimelfoundation/gauth-go/pkg/management"

mgr := management.NewMandateManager(management.NewMemoryStore())
resp, _ := mgr.CreateMandate(&management.MandateCreationRequest{...}, "admin")
mgr.ActivateMandate(resp.MandateID, "admin")
mgr.SuspendMandate(resp.MandateID, "admin", "security review")
mgr.ResumeMandate(resp.MandateID, "admin")
mgr.RevokeMandate(resp.MandateID, "admin", "no longer needed")
```

### Register Adapters

```go
import "github.com/gimelfoundation/gauth-go/pkg/adapter"

registry := adapter.NewRegistry()
adapter.RegisterDefaults(registry) // registers no-op defaults

// Register a proprietary adapter with Ed25519 signature
registry.AddTrustedKey(publicKey)
registry.Register(adapter.Registration{
    Name:      "my-custom-adapter",
    Type:      adapter.TypeAIEnrichment,
    Adapter:   myAdapter,
    Signature: signature,
    Payload:   payload,
})
```

## Packages

| Package | Description |
|---------|-------------|
| `pkg/poa` | Core PoA credential types, enums, scope checksum, verb URNs |
| `pkg/token` | JWT Extended Token creation, signing (RS256/ES256), parsing, validation, JWKS |
| `pkg/pep` | Policy Enforcement Point with 16-check pipeline, HTTP binding |
| `pkg/management` | Mandate lifecycle CRUD, state machine, validation, HTTP API |
| `pkg/adapter` | 7-slot connector registry (Types A/B/C/D), sealed Ed25519 manifest verification, tariff gating, license/ToS state machine |
| `pkg/oauth` | OAuth 2.1 engine integration for token lifecycle |
| `internal/canonical` | Deterministic JSON serialization and SHA-256 hashing |

## PEP 16-Check Pipeline

| Check | ID | Description |
|-------|----|-------------|
| Credential Integrity | CHK-01 | Signature, format, schema version |
| Temporal & Status | CHK-02 | Expiration, not-before, mandate status, agent binding |
| Governance Profile | CHK-03 | Profile ceiling validation |
| Phase | CHK-04 | Plan/build/run phase check |
| Sector | CHK-05 | Allowed sectors (NAICS codes) |
| Region | CHK-06 | Allowed regions (ISO 3166-1) |
| Path | CHK-07 | Allowed/denied paths validation |
| Verb Permission | CHK-08 | Core verbs allowed check |
| Verb Constraints | CHK-09 | Per-verb constraints |
| Platform Permissions | CHK-10 | Layer 3 permissions |
| Transaction Type | CHK-11 | Transaction matrix cross-check |
| Decision Type | CHK-12 | Decision precedence check |
| Budget | CHK-13 | Budget remaining vs. estimated cost |
| Session Limits | CHK-14 | Tool calls, lines per commit |
| Approval | CHK-15 | Approval mode requirements |
| Delegation Chain | CHK-16 | Chain validity, depth, scope narrowing |

## Mandate Lifecycle

```
DRAFT → ACTIVE → SUSPENDED (reversible)
                → REVOKED / EXPIRED / BUDGET_EXCEEDED / SUPERSEDED (terminal)
```

## Governance Profiles

| Profile | Description |
|---------|-------------|
| `minimal` | Least restrictive, suitable for sandboxed environments |
| `standard` | Default profile with balanced permissions |
| `strict` | Restrictive profile for sensitive operations |
| `enterprise` | Enterprise-grade with comprehensive controls |
| `behoerde` | Government/authority profile with maximum restrictions |

## Running Tests

```bash
cd gauth-go
go test ./... -v
go test ./... -cover
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow, branch model, and CI gates.

All contributions enter `main` through a reviewed pull request. The full conformance test suite (CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S) must pass before merge.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process. Do not open public issues for security vulnerabilities — email info@gimelid.com instead.

## License

This SDK is licensed under the [Mozilla Public License 2.0](LICENSE) with
[Gimel Foundation Additional Terms](ADDITIONAL-TERMS.md).

### Dual-Layer Licensing Model

This SDK uses a coexistence licensing model. Both licenses apply simultaneously — the
Gimel Technologies ToS does not replace or revoke the MPL 2.0 license on SDK code:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL 2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (AaaS, managed infrastructure, Type C adapters) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

You may run the SDK in pure Open Core mode (MPL 2.0 only, self-hosted, no Gimel services)
indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS
applies **in addition to** MPL 2.0 — not as a replacement. Your SDK code and modifications
to SDK files remain MPL 2.0 regardless.

### Open Core Exclusions

Three capabilities are excluded from the open-source license and are available
only under the Gimel Technologies Terms of Service:

1. **AI-Enabled Governance** (Slot 5)
2. **Web3 Identity Integration** (Slot 6)
3. **DNA-Based Identities / PQC** (Slot 7)

The full PEP enforcement pipeline (16 checks), Management API, and all Type A/B
adapter interfaces are fully open-source. See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md)
for details and [NOTICE](NOTICE) for full exclusion text.

Copyright (c) 2026 Gimel Foundation gGmbH i.G.

## Attribution

- Gimel Foundation — https://gimelfoundation.com
- GAuth Protocol — GiFo-RFCs 0110, 0111, 0115, 0116, 0117, 0118
- SDK Specification — GiFo-RFC-0128
