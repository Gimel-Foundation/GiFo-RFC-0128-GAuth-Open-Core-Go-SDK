# GAuth Open Core — Monorepo

**Version 0.91 — Public Preview**

**Gimel Foundation** — Authorization for AI Agents

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

## What is GAuth?

GAuth is an authorization protocol for AI agents, digital agents, and humanoid robots. It enables these systems to legitimize power of attorney towards third parties on behalf of their owners, using a structured credential model (Vollmacht / PoA) with a 16-check policy enforcement pipeline.

The protocol is defined by the Gimel Foundation's RFC series (GiFo-RFCs 0110–0118) and published under the Mozilla Public License 2.0.

## Repository Structure

```
gauth-go/                   ← GAuth Open Core Go SDK
├── pkg/
│   ├── poa/                ← PoA credential types, scope checksum, verb URNs
│   ├── token/              ← JWT Extended Token (RS256/ES256), JWKS
│   ├── pep/                ← Policy Enforcement Point — 16-check pipeline
│   ├── management/         ← Mandate lifecycle CRUD, state machine, HTTP API
│   ├── adapter/            ← 7-slot connector registry, Ed25519 manifest, tariff gating
│   └── oauth/              ← OAuth 2.1 engine integration
├── internal/canonical/     ← Deterministic JSON serialization
├── LICENSE                 ← MPL 2.0
├── NOTICE                  ← Copyright, exclusions, third-party notices
├── ADDITIONAL-TERMS.md     ← Gimel Foundation Additional Terms
├── CONTRIBUTING.md         ← Contribution workflow and branch model
├── SECURITY.md             ← Vulnerability reporting
├── CHANGELOG.md            ← Release history
└── README.md               ← Go SDK documentation
```

## SDKs

| Language | Module | Status |
|----------|--------|--------|
| **Go** | `github.com/gimelfoundation/gauth-go` | Active |

Additional SDK languages (Python, TypeScript, Rust, .NET) will be published as separate repositories under the Gimel Foundation organization.

## What's in the Box

| Component | Description |
|-----------|-------------|
| **PEP Engine** | 16-check policy enforcement pipeline (CHK-01 through CHK-16) per RFC 0117 |
| **Management API** | Mandate lifecycle: create, activate, suspend, resume, revoke, delete |
| **Token Handling** | JWT Extended Token with PoA claims (RS256/ES256; HS256 prohibited) |
| **Adapter Registry** | 7-slot connector model with Type A/B/C/D classification |
| **Sealed Manifests** | Ed25519 manifest verification for Type C adapters |
| **Tariff Gating** | O/S/M/L/M+O/L+O deployment policy matrix |
| **License State Machine** | Dual-layer coexistence (MPL 2.0 + Gimel ToS) with per-service tracking |
| **Conformance Tests** | CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S test vectors |

## Quick Start

```bash
go get github.com/gimelfoundation/gauth-go
```

```go
import (
    "github.com/gimelfoundation/gauth-go/pkg/pep"
    "github.com/gimelfoundation/gauth-go/pkg/poa"
)

engine := pep.New("1.0.0", poa.ModeStateless)
decision, _ := engine.EnforceAction(&pep.EnforcementRequest{
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

## Running Tests

```bash
cd gauth-go
go test ./... -v
go test ./... -cover
```

All packages maintain >80% code coverage. The conformance test suite covers adapter registration (CT-REG-001–018), PEP enforcement (CT-PEP-001–031), management API (CT-MGMT-001+), license/attestation (CT-LIC-001–009), and S2S authentication (CT-S2S-001–004).

## Contributing

See [gauth-go/CONTRIBUTING.md](gauth-go/CONTRIBUTING.md) for the dual-stream PR workflow.

All changes enter `main` through a reviewed pull request. Both community contributions (Stream A) and architecture team pushes (Stream B via the `replit` branch) follow the same PR-based merge path with full CI gates.

## License

This project is licensed under the [Mozilla Public License 2.0](gauth-go/LICENSE) with
[Gimel Foundation Additional Terms](gauth-go/ADDITIONAL-TERMS.md).

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
adapter interfaces are fully open-source. See [ADDITIONAL-TERMS.md](gauth-go/ADDITIONAL-TERMS.md)
for details.

## Specifications

- GiFo-RFC 0110 — GAuth Protocol Engine
- GiFo-RFC 0111 — GAuth Authorization Framework
- GiFo-RFC 0115 — Power-of-Attorney Credential Definition
- GiFo-RFC 0116 — GAuth Interoperability (v2.2)
- GiFo-RFC 0117 — GAuth Policy Enforcement Point (v1.2)
- GiFo-RFC 0118 — GAuth Management API & Administration Interface (v1.1)
- GiFo-RFC 0128 — GAuth Open Core Go SDK

## Contact

Gimel Foundation gGmbH i.G.
Hardtweg 31, D-53639 Königswinter
https://gimelfoundation.com
https://github.com/Gimel-Foundation
info@gimelid.com
