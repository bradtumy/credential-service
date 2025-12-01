# Credential Service

Issue, delegate, verify, and authorize W3C Verifiable Credentials (VCs) with DID-backed keys and a gateway that can mint synthetic JWTs for legacy APIs.

## What this project is
A Go-based microservice stack for issuing JWT-encoded VCs, verifying delegation chains, enforcing tenant-scoped authorization policies, and translating trusted credentials into standard `Bearer` tokens for downstream services.

## Features at a Glance
- **Issuer (port 8080):** Issue root and delegated credentials, plus a one-time bootstrap endpoint for local admin setup.
- **Verifier & Gateway (port 8081):** Verify credential chains, evaluate policies, and optionally mint synthetic JWTs.
- **Sample API (port 8082):** A demo `/orders` endpoint protected by synthetic JWTs.
- **Delegation & Agents:** Constrain scope/TTL when minting child credentials so agents can act on behalf of users.
- **Trust Registry:** Per-tenant trusted issuer list backed by Postgres or in-memory store; default issuer is pre-seeded for local runs.
- **Policy Engine:** Hybrid RBAC/ABAC rules with resource/action matching and claim-based conditions.
- **DID Resolution:** Built-in `did:jwk` and `did:web` resolvers so verifiers can fetch public keys directly from DIDs.
- **Observability & Safety:** Structured audit logging, readiness probes, optional Redis caching/rate-limiting, and Prometheus metrics hooks.
- **SDKs:** First-party Go and Node.js clients for issuing, verifying, and gateway authorization.

## Key Concepts
- **Decentralized Identifiers (DIDs):** Public-key based identifiers (`did:jwk`, `did:web`) resolved at verification time—no manual key exchange.
- **Verifiable Credentials (VCs):** JWTs that carry issuer, subject, expiry, and arbitrary claims. Delegated VCs must tighten scope/TTL relative to parents.
- **Gateway & Synthetic JWTs:** `/v1/gateway/authorize` returns an allow/deny decision and can mint a short-lived JWT so downstream services can keep using `Authorization: Bearer <token>`.
- **Tenancy:** `X-Tenant-ID` header (or the default tenant in single-tenant mode) scopes trust registries and policies; Docker Compose runs in single-tenant mode by default.
- **Policy Evaluation:** Requests are authorized against tenant policies using action/resource matching plus optional scope/claim conditions.

## Quick Start
Prereqs: Docker and Docker Compose v2.

1. **Clone & start the stack**
   ```bash
   git clone https://github.com/bradtumy/credential-service.git
   cd credential-service
   docker compose up --build
   ```

2. **Health checks**
   ```bash
   curl http://localhost:8080/healthz   # issuer
   curl http://localhost:8081/readyz    # verifier + DB readiness
   curl http://localhost:8082/orders -i # expect 401 without token
   ```

3. **Issue a credential (issuer @ 8080)**
   ```bash
   VC=$(curl -s -X POST http://localhost:8080/v1/credentials/issue \
     -H "Content-Type: application/json" \
     -d '{
       "subject_did": "did:example:alice",
       "ttl_seconds": 600,
       "claims": {"aud": "sample-api", "scope": "read:orders"}
     }' | jq -r '.credential')
   echo "$VC"
   ```

4. **Verify it (verifier @ 8081)**
   ```bash
   curl -s -X POST http://localhost:8081/v1/credentials/verify \
     -H "Content-Type: application/json" \
     -d '{"credential": "'$VC'", "expected_audience": "sample-api"}' | jq
   ```

5. **Authorize through the gateway + mint a synthetic JWT**
   ```bash
   SYNTH=$(curl -s -X POST http://localhost:8081/v1/gateway/authorize \
     -H "Content-Type: application/json" \
     -d '{
       "credential": "'$VC'",
       "expected_audience": "sample-api",
       "want_synthetic_jwt": true,
       "resource": "orders",
       "action": "read"
     }' | tee /dev/tty | jq -r '.synthetic_jwt')
   ```

6. **Call the protected demo API (sample @ 8082)**
   ```bash
   curl -s http://localhost:8082/orders \
     -H "Authorization: Bearer $SYNTH" | jq
   ```

The verifier ships with a default policy that allows `read` on `orders` for any subject, and the trust registry is seeded with the local issuer key, so the above flow works out of the box.

### Delegation in one command (optional)
Mint a constrained agent credential and authorize it:
```bash
delegated=$(curl -s -X POST http://localhost:8080/v1/credentials/delegate \
  -H "Content-Type: application/json" \
  -d '{
    "parent_credential": "'$VC'",
    "delegate_did": "did:example:agent",
    "scope": ["read:orders"],
    "ttl_seconds": 300
  }' | jq -r '.credential')

curl -s -X POST http://localhost:8081/v1/gateway/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": ["'$VC'", "'$delegated'"],
    "expected_audience": "sample-api",
    "resource": "orders",
    "action": "read"
  }' | jq
```

## Architecture Overview
- **Issuer service (`cmd/issuer`, :8080):** Signs VCs, supports delegation, exposes `/v1/setup/bootstrap` for one-time admin credential creation, and serves `/healthz`/`/readyz`.
- **Verifier + Gateway (`cmd/verifier`, :8081):** Verifies chains via DID resolution, enforces trust registries, evaluates policies, and returns authorization decisions/synthetic JWTs; exposes `/metrics` when Prometheus is enabled.
- **Sample API (`samples/s2s/api-service`, :8082):** Consumes synthetic JWTs on `/orders` to demonstrate legacy compatibility.
- **Postgres (5432, Compose only):** Stores tenant data, policies, and trusted issuers when DB-backed stores are enabled.

See [ARCHITECTURE.md](ARCHITECTURE.md) for module layout, [TENANCY.md](TENANCY.md) for tenant scoping, [POLICY_ENGINE.md](POLICY_ENGINE.md) for authorization rules, and [GATEWAY_INTEGRATION.md](GATEWAY_INTEGRATION.md) for gateway usage.

## APIs & Docs
| Doc | What it covers |
| --- | --- |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI 3.1 for issuer, verifier, gateway, and health endpoints. |
| [API_OVERVIEW.md](API_OVERVIEW.md) | Endpoint summaries, sample payloads, and the happy-path flow. |
| [POLICY_ENGINE.md](POLICY_ENGINE.md) | Policy schema, evaluation order, and admin endpoints under `/v1/admin/policies`. |
| [TENANCY.md](TENANCY.md) | Single vs. multi-tenant behavior and tenant resolution rules. |
| [GATEWAY_INTEGRATION.md](GATEWAY_INTEGRATION.md) | How `/v1/gateway/authorize` plugs into reverse proxies and mints synthetic JWTs. |
| [AGENTS.md](AGENTS.md) | Delegation and on-behalf-of semantics for agents. |

## SDKs
- **Go (`sdk/go`):**
  ```go
  client := &sdk.Client{BaseURL: "http://localhost:8080"}
  issued, _ := client.IssueCredential(ctx, sdk.IssueRequest{SubjectDID: "did:example:alice", TTLSeconds: 600})
  decision, _ := client.GatewayAuthorize(ctx, sdk.GatewayAuthorizeRequest{Credential: issued.Credential, WantSyntheticJWT: true})
  ```
- **Node.js (`sdk/node`):**
  ```js
  import { Client } from '@credential-service/sdk'
  const client = new Client({ baseUrl: 'http://localhost:8080' })
  const issued = await client.issueCredential({ subject_did: 'did:example:alice', ttl_seconds: 600 })
  const decision = await client.gatewayAuthorize({ credential: issued.credential, want_synthetic_jwt: true })
  ```

## Roadmap / Current Status
- **Implemented:** Issuance and delegation endpoints, DID-based verification, gateway authorization with synthetic JWT minting, seeded trust registry for local runs, tenant-scoped policy engine with Postgres or in-memory stores, health/readiness probes, optional Prometheus metrics and Redis-backed caching/rate-limiting.
- **Upcoming (see [ROADMAP.md](ROADMAP.md)):** SD-JWT support, richer issuance policies and audit trails, deeper KMS/Vault integrations, and expanded integration/e2e testing.

## Contributing
1. Create a feature branch: `git checkout -b feature/your-change`.
2. Make changes and add tests.
3. Run the test suite: `go test ./...` (or `make test` for unit coverage on core services).
4. Commit and open a Pull Request.

## License
Apache License 2.0. See [LICENSE](LICENSE) for details.
