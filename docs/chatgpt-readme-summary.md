# Credential Service overview (copy/paste friendly)

## Purpose and value
- Go-based stack for issuing, delegating, verifying, and authorizing JWT-formatted W3C Verifiable Credentials (including SD-JWT) using DID-backed keys. Gateway can mint short-lived synthetic JWTs so legacy "Bearer" clients keep working.【F:README.md†L24-L149】
- Aims to start quickly, integrate easily, and be explicit about standards alignment for decentralized identity use cases.【F:README.md†L24-L149】

## Deployment shapes and components
- **Centralized (enterprise)**: Issuer (8080), Verifier/Gateway (8081), optional Sample API (8082), shared Postgres (tenants/policies/trust) plus optional Redis for caching/rate limits.【F:README.md†L35-L125】
- **Distributed (multi-org)**: Each org runs its own issuer/verifier/Postgres; verifiers resolve issuer DIDs (`did:jwk`, `did:web`) instead of pre-sharing keys and rely on a per-tenant trust registry.【F:README.md†L66-L110】

## Core capabilities
- Standards-compliant VC-JWTs with RFC 7638 `kid` thumbprints; EdDSA (Ed25519) and ES256 signing algorithms.【F:README.md†L115-L125】
- Issuance and delegation endpoints enforce scope/TTL narrowing and optional issuance policies (`ISSUER_POLICY_MAX_TTL_SECONDS`, allowed scopes, required claims).【F:README.md†L115-L149】【F:README.md†L586-L594】
- Verifier + Gateway validate credential chains, evaluate tenant-scoped policies (RBAC/ABAC style), and optionally mint synthetic JWTs for downstream services.【F:README.md†L115-L149】
- Trust registry (Postgres or in-memory) tracks trusted issuer DIDs; default issuer is seeded for local runs.【F:README.md†L115-L125】
- Observability and safety: structured audit logs with optional Postgres audit storage, readiness probes, Prometheus metrics hooks, and optional Redis caching/rate limiting.【F:README.md†L115-L125】【F:README.md†L586-L595】
- SD-JWT support: issue credentials with selective disclosure and verify by posting SD-JWT plus disclosures.【F:README.md†L195-L592】

## Primary interfaces
- Issuer (8080): `/v1/credentials/issue` (JWT or SD-JWT), delegation endpoint, optional bootstrap for local admin setup.【F:README.md†L115-L149】【F:README.md†L195-L592】
- Verifier (8081): `/v1/credentials/verify` for VC-JWT or SD-JWT chains; `/v1/trust/issuers` to manage trusted issuers; `/v1/gateway/authorize` for allow/deny + synthetic JWTs; health/readiness probes.【F:README.md†L115-L149】【F:README.md†L596-L620】
- Sample API (8082): `/orders` protected by synthetic JWTs to demonstrate gateway output.【F:README.md†L115-L125】【F:README.md†L596-L620】

## Tenancy and policy model
- `X-Tenant-ID` header scopes trust registry and policy evaluation; Docker Compose defaults to single-tenant mode.【F:README.md†L145-L149】
- Policies combine resource/action matching with optional scope or claim conditions and cache decisions in the gateway.【F:README.md†L115-L149】

## SDKs and tooling
- First-party Go module (`sdk-go`) and local Node package (`sdk-nodejs`) for issuance, verification, and gateway authorization; include DID generation helpers.【F:README.md†L115-L125】【F:README.md†L582-L585】
- CLI quick start: `make keygen` to generate a DID, Docker Compose stack, and cURL flows for issuance → trust registry → authorization with optional synthetic JWT minting.【F:README.md†L150-L193】【F:README.md†L596-L620】

## Current status and near-term roadmap
- Implemented: issuance/delegation, SD-JWT issuance/verification, policy-guarded TTL/scope/claim validation, optional Postgres audit persistence, DID-based verification, gateway authorization with synthetic JWTs, seeded trust registry, tenant-scoped policy engine, health/ready probes, Prometheus metrics hooks, optional Redis cache/rate limiting.【F:README.md†L596-L598】
- Upcoming: deeper KMS/Vault integrations and expanded integration/end-to-end testing (see `docs/ROADMAP.md`).【F:README.md†L596-L599】

## How to demo quickly
- Start stack: `docker compose up --build -d`.
- Generate DID: `make keygen && ./bin/keygen -did-only`.
- Issue credential, add issuer to trust registry, request gateway authorization with synthetic JWT, and call sample `/orders` with that token to see an allow flow.【F:README.md†L150-L193】【F:README.md†L596-L620】

_Copy/paste this document into ChatGPT to generate a roadmap or task list based on the current capabilities and roadmap signals above._
