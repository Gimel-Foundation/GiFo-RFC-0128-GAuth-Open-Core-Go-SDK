# Gimel Foundation Additional Terms

**Version 0.91 — Public Preview**

These additional terms apply on top of the Mozilla Public License 2.0 (MPL 2.0) base license for all GAuth SDK repositories.

## Open Core Exclusions

Three capabilities are excluded from the open-source license and are available only under the Gimel Technologies Terms of Service:

### 1. AI-Enabled Governance Exclusion

Third parties may not create, distribute, or offer competing implementations of AI-powered governance evaluation for the GAuth adapter slot system without a separate commercial license from the Gimel Foundation.

**Scope:** Slot 5 (`ai_governance`) — `GovernanceAdapter` interface implementations.

This includes:
- AI that supports and/or controls the process of an AI deployment lifecycle
- AI that tracks actions and/or decisions regarding authorization compliance
- AI that assures the quality of the outcome of AI engagements
- AI-assisted registration paths (Paths 1-3 as defined in RFC 0118)
- Risk scoring, regulatory interpretation, compliance reasoning
- Implied-authority mechanisms

### 2. Web3 Identity Integration Exclusion

Third parties may not create, distribute, or offer competing implementations of Web3/blockchain-based identity resolution for the GAuth adapter slot system without a separate commercial license.

**Scope:** Slot 6 (`web3_identity`) — `Web3IdentityAdapter` interface implementations.

This includes:
- Blockchain technology (including Web3 tokens and smart contracts) for the extended token of GAuth
- Any decentralized ledger integration for credential storage or verification

### 3. DNA-Based Identity / PQC Exclusion

Third parties may not create, distribute, or offer competing implementations of DNA-based identity verification or post-quantum cryptographic identity for the GAuth adapter slot system without a separate commercial license.

**Scope:** Slot 7 (`dna_identity`) — `DNAIdentityAdapter` interface implementations.

This includes:
- DNA-based identities or identities based on genetic data
- AI that tracks the quality of DNA-based identities
- AI that tracks risks in terms of identity theft or any other risks
- Post-quantum cryptography (PQC) associated features

## License Boundary

| Component | License | Modifiable | Redistributable |
|-----------|---------|------------|-----------------|
| SDK source code (all languages) | MPL 2.0 | Yes (file-level copyleft) | Yes |
| Type A/B adapter interfaces | MPL 2.0 | Yes | Yes |
| PEP engine, Management API | MPL 2.0 | Yes | Yes |
| Conformance test suite | MPL 2.0 | Yes | Yes |
| Type C adapter *interfaces* (method signatures) | MPL 2.0 | Yes | Yes |
| Type C adapter *implementations* | Gimel Technologies ToS (proprietary) | No | No |
| Ed25519 manifest verification code | MPL 2.0 | Yes | Yes |

## Important Distinctions

- The Type C adapter *interfaces* are open-source under MPL 2.0. Only the Gimel *implementations* are proprietary.
- These exclusions apply only to the specific adapter slot interfaces (slots 5, 6, 7). They do not restrict any other use, modification, or redistribution of the open-source components.
- The MPL 2.0 does not extend to the Excluded Components. They are outside its scope entirely.
- Use of any proprietary service or Excluded Component additionally requires acceptance of the Gimel Technologies Terms of Service. This does not replace or revoke the MPL 2.0 license — both licenses coexist.

## Legal Framework

| Layer | Scope | Governing Terms |
|-------|-------|-----------------|
| **Gimel Foundation Legal Terms** | All use of GAuth (Open Core and proprietary) | Apply universally |
| **MPL 2.0** | Open Core components only | Governs source code rights for Open Core |
| **Gimel Technologies Terms of Service** | Proprietary services including Excluded Components | Apply in addition to MPL 2.0 when using proprietary services |

**Gimel Foundation gGmbH i.G.** — The foundation publishes the GiFo-RFCs and the open-source project.

**Gimel Technologies** — The commercial entity that operates proprietary services.

## Contributions to Excluded Components

Contributors to Open Core components license their work under MPL 2.0. Contributions to Excluded Components require a separate Contributor License Agreement (CLA) with the Gimel Foundation.

## Contact

For proprietary licensing inquiries: licensing@gimel.foundation

Gimel Foundation gGmbH i.G.
Hardtweg 31, D-53639 Königswinter
https://gimelfoundation.com
