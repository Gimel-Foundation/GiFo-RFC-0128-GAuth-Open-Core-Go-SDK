# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

Additionally contains `gauth-go/` — the GAuth Open Core Go SDK (GiFo-RFC-0128).

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## GAuth Go SDK (`gauth-go/`)

Go module implementing the Gimel Foundation's GAuth authorization protocol.

- **Module**: `github.com/gimelfoundation/gauth-go`
- **Go version**: 1.16+
- **License**: MPL 2.0
- **RFC**: GiFo-RFC-0128-GAuth-Open-Core-Go-SDK

### Packages

| Package | Purpose |
|---------|---------|
| `pkg/poa` | Core PoA credential types, enums, scope checksum (SHA-256 canonical JSON), verb URNs |
| `pkg/token` | JWT Extended Token: RS256/ES256 signing, parsing, validation, JWKS. HS256 prohibited |
| `pkg/pep` | Policy Enforcement Point: 16-check pipeline (CHK-01–CHK-16), fail-closed, HTTP binding |
| `pkg/management` | Mandate lifecycle: CRUD, state machine (DRAFT→ACTIVE→terminal), validation, HTTP API |
| `pkg/adapter` | 7-slot connector registry (Types A/B/C/D), sealed Ed25519 manifest verification, tariff gating matrix, license/ToS state machine, conformance test suite (CT-REG/CT-LIC) |
| `pkg/oauth` | OAuth 2.1 engine integration for PoA-embedded token lifecycle |
| `internal/canonical` | Deterministic JSON serialization (sorted keys, no whitespace, UTF-8) |

### Key Commands

- `cd gauth-go && go test ./... -v` — run all tests (100+ tests across 5 packages)
- `cd gauth-go && go build ./...` — build all packages
- `cd gauth-go && go build ./examples/basic/` — build example program

## Key Commands (TypeScript)

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
