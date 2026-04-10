# Changelog

All notable changes to the GAuth Open Core Go SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 7-slot connector registry with Type A/B/C/D adapter classification
- Sealed Ed25519 manifest verification for Type C adapters (JCS canonicalization, @gimel/ namespace validation, temporal checks, trusted key set, revocation lists)
- Tariff gating matrix (O/S/M/L) with deployment policy enforcement
- License/ToS state machine: mpl_2_0 → gimel_tos transition with per-service ToS tracking
- New adapter interfaces: PolicyDecisionAdapter, WalletAdapter, GovernanceAdapter, Web3IdentityAdapter, DNAIdentityAdapter
- Conformance test suite: CT-REG-001 through CT-REG-018, CT-LIC-001 through CT-LIC-009
- CONTRIBUTING.md with dual-stream PR workflow
- ADDITIONAL-TERMS.md with three proprietary exclusions
- SECURITY.md with vulnerability reporting process
- 16-check PEP enforcement pipeline (CHK-01 through CHK-16)
- Fail-closed CHK-01: nil SignatureVerified → DENY
- JWT alg/key mismatch validation in Parse()
- TransitionToBudgetExceeded() for ACTIVE → BUDGET_EXCEEDED state path
- GovernanceProfile.Level() for ceiling enforcement (elevation only)
- Stateful and stateless PEP enforcement modes
- Mandate lifecycle state machine (DRAFT → ACTIVE → terminal states)
- Budget operations with idempotent consumption tracking
- Delegation chain validation with scope narrowing
- HTTP binding for PEP and Management API
