# Credential Service

Issue, delegate, verify, and authorize W3C Verifiable Credentials (VCs) using DID-backed keys. Includes a gateway that mints synthetic JWTs so existing APIs can keep using `Authorization: Bearer ...`.

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Try It Now](#try-it-now)
- [Core Concepts](#core-concepts)
- [Architecture](#architecture)
  - [Centralized Deployment](#centralized-deployment-enterprise)
  - [Distributed Deployment](#distributed-deployment-decentralized)
  - [Components](#architecture-components)
- [Standards Alignment](#standards-alignment-oauth-20-token-exchange-rfc-8693)
- [Troubleshooting](#troubleshooting)
- [Developer Workflow](#developer-workflow)
- [Documentation Index](#documentation)
- [SDKs](#sdks)
- [Roadmap](#roadmap--current-status)
- [Contributing](#contributing)
- [License](#license)

## Overview
Credential Service is a Go-based stack for:
- Issuing JWT-encoded Verifiable Credentials (VCs)
- Verifying credentials and delegation chains via DID resolution
- Evaluating tenant-scoped authorization policies
- Minting short-lived synthetic JWTs for legacy services

It aims to be fast to start, easy to integrate, and clear about standards alignment.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a detailed repository layout. At a glance:

- **cmd/** contains the binaries (`issuer`, `verifier`, and utility `keygen`).
- **services/** wires each HTTP server and composes shared middleware.
- **internal/** holds shared libraries such as credential primitives (`domain`), HTTP handlers (`httpserver`), keystore selection, policy engine, and persistence adapters.
- **sdk-go/** and **sdk-node/** surface the Go and Node SDKs while keeping module paths stable.

### Centralized Deployment (Enterprise)

Suitable for single-organization deployments where issuer and verifier share infrastructure:

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Issuer    │         │  Verifier    │         │   Gateway   │
│   :8080     │────────▶│   :8081      │◀────────│  (AuthZ)    │
│             │  Trust  │              │  Verify │             │
│ - Issue VCs │         │ - Verify VCs │         │ - Rate Limit│
│ - DID Mgmt  │         │ - Trust Reg  │         │ - Caching   │
│ - Key Mgmt  │         │ - Policy Eng │         │ - Decisions │
└─────────────┘         └──────────────┘         └─────────────┘
       │                        │                        │
       │                        │                        │
       └────────────────────────┴────────────────────────┘
                                │
                          ┌─────▼─────┐         ┌──────────┐
                          │ Postgres  │         │  Redis   │
                          │   :5432   │         │  :6379   │
                          │           │         │          │
                          │ - Tenants │         │ - Cache  │
                          │ - Policies│         │ - Limits │
                          │ - Trust   │         │          │
                          └───────────┘         └──────────┘
```

**Use Case**: Single enterprise, shared database, centralized trust management

---

### Distributed Deployment (Decentralized)

Suitable for multi-organization or cross-domain scenarios using DID resolution:

```
┌─────────────────────────────────┐     ┌─────────────────────────────────┐
│      Organization A             │     │      Organization B             │
│                                 │     │                                 │
│  ┌─────────────┐  ┌──────────┐ │     │  ┌──────────────┐  ┌──────────┐│
│  │   Issuer    │  │Postgres A││     │  │  Verifier    │  │Postgres B││
│  │   :8080     │  │  :5432   ││     │  │   :8081      │  │  :5432   ││
│  │             │  │          ││     │  │              │  │          ││
│  │ - Issue VCs │  │- Tenants ││     │  │ - Trust Reg  │  │- Tenants ││
│  │ - DID: A    │  │- Keys    ││     │  │ - Policies   │  │- Policies││
│  └─────────────┘  └──────────┘ │     │  │ - DID: B     │  │- Trust   ││
│         │                       │     │  └──────────────┘  └──────────┘│
│         │                       │     │         ▲                       │
└─────────┼───────────────────────┘     └─────────┼───────────────────────┘
          │                                       │
          │  VC Issued                           │ Verification
          │  (signed with did:jwk:A)             │ Request
          │                                       │
          └──────────────────────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   DID Resolution Layer    │
                    │                           │
                    │ - did:jwk  (self-signed)  │
                    │ - did:web  (DNS-hosted)   │
                    │                           │
                    │ No pre-shared keys needed │
                    └───────────────────────────┘
```

**Key Differences**:
- **No Shared Database**: Each organization maintains its own Postgres instance
- **DID Resolution**: Verifier fetches public keys by resolving issuer's DID (e.g., `did:jwk:...` or `did:web:orgA.com`)
- **Distributed Trust**: Verifier maintains local trust registry listing trusted issuer DIDs
- **No Pre-Configuration**: Organizations don't exchange keys in advance—DIDs are resolved at verification time

**Use Case**: Multi-org federation, supply chain, cross-domain identity, zero-trust networks

---

**Flow**: Issuer generates credentials with `did:jwk` or `did:web` identifiers → Verifier resolves DID to public key → checks trust registry → evaluates policies → Gateway caches decisions

## What this project is
A Go-based microservice stack for issuing JWT-encoded VCs, verifying delegation chains, enforcing tenant-scoped authorization policies, and translating trusted credentials into standard `Bearer` tokens for downstream services.

## Features at a Glance
- **Standards Compliant:** W3C VC-JWT format with `typ: "vc+jwt"`, RFC 7638 JWK Thumbprints for key IDs, EdDSA (Ed25519) and ES256 (P-256) signing algorithms.
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
- **Verifiable Credentials (VCs):** W3C VC-JWT compliant credentials where JWT claims (`iss`, `sub`, `iat`, `exp`) are at the top level with the VC nested under a `vc` claim. Delegated VCs must tighten scope/TTL relative to parents.
- **W3C VC-JWT Format:** Credentials follow the W3C VC-JWT specification with `typ: "vc+jwt"` header and proper payload structure:
  ```json
  {
    "iss": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWU...",
    "sub": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImFiY2RlZm...",
    "iat": 1234567890,
    "exp": 1234571490,
    "vc": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWU...",
      "credentialSubject": { "scope": "read:orders" }
    }
  }
  ```
- **RFC 7638 JWK Thumbprints:** Key identifiers (`kid`) are computed using RFC 7638 JWK Thumbprint for standards-compliant key identification.
- **Gateway & Synthetic JWTs:** `/v1/gateway/authorize` returns an allow/deny decision and can mint a short-lived JWT so downstream services can keep using `Authorization: Bearer <token>`.
- **Tenancy:** `X-Tenant-ID` header (or the default tenant in single-tenant mode) scopes trust registries and policies; Docker Compose runs in single-tenant mode by default.
- **Policy Evaluation:** Requests are authorized against tenant policies using action/resource matching plus optional scope/claim conditions.

## Quick Start

Prereqs: Docker and Docker Compose v2. Choose your path:

### 🚀 Fast Track (3 minutes)

Get running with minimal setup:

```bash
# 1. Start services
git clone https://github.com/bradtumy/credential-service.git
cd credential-service
docker compose up --build -d

# 2. Generate a test DID
make keygen
ALICE_DID=$(./bin/keygen -did-only)

# 3. Issue a credential (include audience)
# The gateway will enforce that `expected_audience` matches the credential's `aud` claim.
VC=$(curl -s -X POST http://localhost:8080/v1/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{"subject_did":"'$ALICE_DID'","ttl_seconds":600,"claims":{"role":"tester","aud":"sample-api"}}' \
  | jq -r .credential)

# 4. Add issuer to trust registry
ISSUER_DID=$(docker logs credential-service-issuer-1 2>&1 | grep "issuer_did" | tail -1 | sed 's/.*issuer_did=\([^ ]*\).*/\1/')
curl -s -X POST http://localhost:8081/v1/trust/issuers \
  -H "Content-Type: application/json" \
  -d '{"issuer_did":"'$ISSUER_DID'"}'

# 5. Verify and authorize
curl -s -X POST http://localhost:8081/v1/gateway/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "credential": "'$VC'",
    "expected_audience": "sample-api",
    "resource": "orders",
    "action": "read",
    "want_synthetic_jwt": true
  }' | jq
```

✅ **Done!** You should see `"allowed": true` with a synthetic JWT. Skip to [What's Next](#whats-next) or continue for production setup.

### 📦 Optional: Selective Disclosure (SD-JWT)
Issue a credential where individual claims can be selectively revealed later.

```bash
# 1. Issue an SD-JWT (returns credential + disclosures array)
SD_RESP=$(curl -s -X POST http://localhost:8080/v1/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{"subject_did":"'$ALICE_DID'","ttl_seconds":600,"claims":{"email":"alice@example.com","department":"engineering","scope":"read:orders"},"format":"sd-jwt"}')
SD_JWT=$(echo "$SD_RESP" | jq -r .credential)
DISCLOSURES=$(echo "$SD_RESP" | jq -r '.disclosures | join("\n")')
echo "SD-JWT: $SD_JWT"; echo "$DISCLOSURES" | sed 's/^/disclosure: /'

# 2. Verify with full disclosure set
curl -s -X POST http://localhost:8081/v1/credentials/verify \
  -H "Content-Type: application/json" \
  -d '{"credential":"'$SD_JWT'","format":"sd-jwt","disclosures":['$(echo "$SD_RESP" | jq -c '.disclosures | map("\""+ . +"\"") | join(",")')']}' | jq

# 3. (Optional) Verify revealing only the department claim
FIRST_DISC=$(echo "$SD_RESP" | jq -r '.disclosures[1]')
curl -s -X POST http://localhost:8081/v1/credentials/verify \
  -H "Content-Type: application/json" \
  -d '{"credential":"'$SD_JWT'","format":"sd-jwt","disclosures":["'$FIRST_DISC'"]}' | jq
```

Notes:
- The issuer salts each claim; the verifier recomputes digests using provided disclosures.
- Omitting a disclosure redacts that claim from reconstructed credential subject.
- Policy evaluation should be based only on revealed claims; avoid assuming hidden data for authorization.

#### SDK Examples (Minimal)

**Go (sdk-go helpers)**
```go
package main
import (
  "fmt"
  sdk "github.com/bradtumy/credential-service/sdk-go"
)
func main() {
  client := sdk.NewClient("", "")
  issued, err := client.IssueSDJWTCredential("http://localhost:8080", sdk.SDJWTIssueRequest{
    SubjectDID: "did:jwk:ALICE_REPLACE",
    TTLSeconds: 600,
    Claims: map[string]interface{}{
      "email": "alice@example.com",
      "department": "engineering",
      "scope": "read:orders",
    },
  })
  if err != nil { panic(err) }
  fmt.Println("SD-JWT:", issued.Credential)
  fmt.Println("Disclosures:", issued.Disclosures)

  verify, err := client.VerifySDJWT("http://localhost:8081", issued.Credential, issued.Disclosures[:1])
  if err != nil { panic(err) }
  fmt.Println("Partial verification active:", verify.Active)
}
```

**Node.js (sdk-nodejs helpers)**
```javascript
const Client = require('./sdk-nodejs/client');

async function run() {
  const c = new Client({ issuerURL: 'http://localhost:8080', verifierURL: 'http://localhost:8081' });
  const issued = await c.issueSdJwtCredential({
    subject_did: 'did:jwk:ALICE_REPLACE',
    ttl_seconds: 600,
    claims: { email: 'alice@example.com', department: 'engineering', scope: 'read:orders' }
  });
  console.log('SD-JWT:', issued.credential);
  console.log('Disclosures:', issued.disclosures);

  const verify = await c.verifySdJwtCredential({
    credential: issued.credential,
    disclosures: [issued.disclosures[1]]
  });
  console.log('Partial verification active:', verify.active);
}

run().catch(err => console.error(err.response?.data || err.message));
```

Replace `did:jwk:ALICE_REPLACE` with a DID generated earlier (e.g., from `./bin/keygen -did-only`).

### 🏗️ Production Setup (15 minutes)

Full walkthrough with detailed explanations:

1. **Clone & start the stack**
   ```bash
   git clone https://github.com/bradtumy/credential-service.git
   cd credential-service
   docker compose up --build
   ```

2. **Hit the health endpoints** to confirm the services are reachable:
   ```bash
   curl http://localhost:8080/healthz   # issuer
   curl http://localhost:8081/readyz    # verifier + DB readiness
   curl http://localhost:8082/orders -i # expect 401 without token
   ```

3. **Generate a DID for your subject (optional)**
   
   You can generate DIDs three ways:
   
   **Option A: Use the API**
   ```bash
   # Generate a DID via HTTP API (only returns the DID, not the private key for security)
   ALICE_DID=$(curl -s -X POST http://localhost:8080/v1/keys/generate \
     -H "Content-Type: application/json" \
     -d '{"algorithm": "EdDSA"}' | jq -r '.did')
   echo "Generated DID: $ALICE_DID"
   ```
   
   **Option B: Use the CLI tool**
   ```bash
   # Build and use the keygen CLI
   make keygen
   ./bin/keygen -output alice-key.pem
   # Outputs: DID: did:jwk:eyJrdHk... and saves private key to alice-key.pem
   ```
   
   **Option C: Use the SDK**
   ```go
   // Go SDK
   import "github.com/bradtumy/credential-service/sdk-go"
   keypair, _ := sdk.GenerateDIDJWK("EdDSA")
   fmt.Println("DID:", keypair.DID)
   ```
   ```javascript
   // Node.js SDK
   const { generateDIDJWK } = require('@credential-service/sdk-nodejs/keygen');
   const keypair = await generateDIDJWK('EdDSA');
   console.log('DID:', keypair.did);
   ```
   
4. **Add the issuer to the verifier's trust registry**

   The issuer and verifier use separate signing keys. The verifier needs to trust the issuer's DID:
   
   ```bash
   # Extract issuer DID from logs
   ISSUER_DID=$(docker logs credential-service-issuer-1 2>&1 | \
     grep -o 'issuer_did":"did:jwk:[^"]*' | head -1 | cut -d'"' -f3)
   echo "Issuer DID: $ISSUER_DID"
   
   # Add issuer to verifier's trust registry
   curl -X POST http://localhost:8081/v1/trust/issuers \
     -H "Content-Type: application/json" \
     -d '{"issuer_did": "'$ISSUER_DID'"}' | jq
   ```
   
5. **Issue a credential via the issuer API (port 8080)**

   ```bash
   # If you generated a DID in step 3, use $ALICE_DID
   # Otherwise, use this example DID for quick testing
   ALICE_DID="${ALICE_DID:-did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWUtGMWJuRjNyeEh0Q19FN2I4N1ZRdHJhRUp2WVU0aGRxNFU5SWsifQ}"
   
   VC=$(curl -s -X POST http://localhost:8080/v1/credentials/issue \
     -H "Content-Type: application/json" \
     -d "{
       \"subject_did\": \"$ALICE_DID\",
       \"ttl_seconds\": 600,
       \"claims\": {\"aud\": \"sample-api\", \"scope\": \"read:orders\"}
     }" | jq -r '.credential')

   # The response includes a W3C VC-JWT compliant signed credential with typ: "vc+jwt"
   # JWT header: {"alg":"EdDSA","typ":"vc+jwt"}
   # JWT payload has standard claims (iss, sub, iat, exp) at top level
   # with the VC structure nested under the "vc" claim per W3C spec
   ```

6. **Verify the credential through the verifier API (port 8081)**
   
   ```bash
   curl -s -X POST http://localhost:8081/v1/credentials/verify \
     -H "Content-Type: application/json" \
     -d '{"credential": "'$VC'", "expected_audience": "sample-api"}' | jq

   # Expected response:
   # { "active": true, "issuer": "did:jwk:...", "subject": "did:jwk:..." }
   ```

7. **Authorize through the gateway API and mint a synthetic JWT**
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

8. **Call the protected demo API using the synthetic JWT**
   ```bash
   curl -s http://localhost:8082/orders \
     -H "Authorization: Bearer $SYNTH" | jq
   ```

The verifier ships with a default policy that allows `read` on `orders` for any subject. For production use, you'll want to add trusted issuers to the trust registry via the admin API (see [GATEWAY_INTEGRATION.md](docs/GATEWAY_INTEGRATION.md)).

## Troubleshooting

**"untrusted_issuer" error:**
- Ensure you completed step 4 (adding issuer to trust registry)
- Check that issuer and verifier are both running: `docker ps`
- Verify issuer DID: `docker logs credential-service-issuer-1 | grep issuer_did`
- The trust registry is in-memory by default and resets on restart

**"unexpected audience" error:**
- Ensure the `aud` claim in your credential matches `expected_audience` in verification
- Check credential payload: `echo $VC | cut -d'.' -f2 | base64 -d`

**Services won't start:**
```bash
# Check for port conflicts
lsof -i :8080 -i :8081 -i :8082

# View service logs
docker compose logs issuer
docker compose logs verifier

# Rebuild from scratch
docker compose down -v
docker compose up --build
```

**Slow verification performance:**
- Enable Redis caching: Set `VERIFIER_GATEWAY_CACHE=true` and `REDIS_ADDR=redis:6379`
- Check metrics: `curl http://localhost:8081/metrics`
- Review audit logs for bottlenecks

### Delegation in one command (optional)
Mint a constrained agent credential and authorize it:
```bash
# Using did:jwk for the agent/delegate
delegated=$(curl -s -X POST http://localhost:8080/v1/credentials/delegate \
  -H "Content-Type: application/json" \
  -d '{
    "parent_credential": "'$VC'",
    "delegate_did": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InhYeVpBYmNEZWZHaGlKa2xNbm9QcXJTdFV2V3h5WjAxMjM0NTY3ODlBQkMifQ",
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

## Developer Workflow
- **Run tests with coverage**: `make test-coverage`
- **Run specific package tests**: `go test ./internal/domain/... -v`
- **Build all services**: `make build-all`
- **Run linter**: `make lint`
- **Security scan**: `make sec`
- **Local run (without Docker)**:
  ```bash
  export ISSUER_LOG_LEVEL=debug
  export VERIFIER_LOG_LEVEL=debug
  go run ./cmd/issuer &
  go run ./cmd/verifier &
  curl http://localhost:8080/healthz
  curl http://localhost:8081/readyz
  ```

### Architecture Components
- **Issuer service (`cmd/issuer`, :8080):** Signs VCs, supports delegation, exposes `/v1/setup/bootstrap` for one-time admin credential creation, and serves `/healthz`/`/readyz`.
- **Verifier + Gateway (`cmd/verifier`, :8081):** Verifies chains via DID resolution, enforces trust registries, evaluates policies, and returns authorization decisions/synthetic JWTs; exposes `/metrics` when Prometheus is enabled.
- **Sample API (`samples/s2s/api-service`, :8082):** Consumes synthetic JWTs on `/orders` to demonstrate legacy compatibility.
- **Postgres (5432, Compose only):** Stores tenant data, policies, and trusted issuers when DB-backed stores are enabled.

## Standards Alignment: OAuth 2.0 Token Exchange (RFC 8693)

This project DOES NOT implement a full OAuth 2.0 / OpenID Connect Authorization Server. It focuses narrowly on Verifiable Credential issuance, verification, delegation, and translating trusted credentials into short‑lived bearer tokens for legacy APIs.

We considered adding a `/v1/oauth/token` endpoint using the RFC 8693 Token Exchange grant, but chose to defer it to avoid the ecosystem expectations that come with an OAuth surface (discovery documents, refresh tokens, consent flows, introspection, revocation, dynamic client registration, etc.). Instead, we document the conceptual mapping so integrators can build adapters if needed.

### Conceptual Mapping
| RFC 8693 Concept            | Current Implementation (/v1/gateway/authorize)                         |
|-----------------------------|-------------------------------------------------------------------------|
| `subject_token`             | Primary credential (root or delegated VC JWT)                          |
| `subject_token_type`        | Implicit: W3C VC-JWT (`typ: "vc+jwt"`)                                 |
| `actor_token` (optional)    | Additional delegated credential(s) passed via `credentials` array       |
| `requested_token_type`      | Synthetic access JWT (short‑lived bearer token)                         |
| `audience`                  | `expected_audience` field (validated against credential claims/policy)  |
| `scope`                     | Derived from credential claims + policy evaluation                      |
| Response `access_token`     | `synthetic_jwt` (when `want_synthetic_jwt=true`)                        |
| Response token metadata     | Returned as decision object (issuer, subject, allowed, expiry)          |
| Error codes                 | Service-specific errors (e.g., `untrusted_issuer`) not yet normalized   |

### Why Defer a Formal Token Exchange Endpoint?
- Avoids accidental scope creep into full OAuth/OIDC feature sets.
- Keeps maintenance surface small (no refresh, revocation, introspection flows).
- Preserves focus on VC, DID resolution, and delegation policy logic.
- Reduces premature standardization before concrete integrator demand.

### Out of Scope (Explicitly Not Implemented)
- `/.well-known/openid-configuration` discovery
- Refresh tokens / offline access
- Token revocation / introspection endpoints
- User consent / authorization code flows
- Dynamic client registration
- OIDC ID Tokens / user claims aggregation

### Future Minimal Endpoint (Planned Criteria)
We will only add a constrained `/v1/oauth/token` (RFC 8693 grant) if:
1. Multiple integrators (≥2) require a standards wire format for automation.
2. Security review requests normative error codes and grant typing.
3. A gateway/product integration mandates formal `subject_token` / `actor_token` fields.

If implemented, it would:
- Support ONLY `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
- Accept form-encoded `subject_token`, optional `actor_token`, `requested_token_type`.
- Reject all unknown parameters with `invalid_request`.
- Return: `access_token`, `issued_token_type`, `token_type="Bearer"`, `expires_in`.
- Map internal errors to a small set (`invalid_token`, `access_denied`).
- Omit refresh, introspection, revocation, discovery.

### Recommended Integration Pattern Today
If you need full OAuth/OIDC: use an existing AS (e.g., Keycloak, Ory Hydra, Auth0) and implement a custom grant that:
1. Accepts a VC JWT (and optionally delegated chain).
2. Calls this service’s verification + policy APIs.
3. Mints an access token inside the OAuth server’s lifecycle.

### Summary
You can treat `/v1/gateway/authorize` as a logical token exchange without assuming broader OAuth semantics. This documented mapping enables adapter layers now, while leaving a minimal standards endpoint as a future, gated enhancement.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for module layout, [TENANCY.md](docs/TENANCY.md) for tenant scoping, [POLICY_ENGINE.md](docs/POLICY_ENGINE.md) for authorization rules, and [GATEWAY_INTEGRATION.md](docs/GATEWAY_INTEGRATION.md) for gateway usage.

## Documentation
- [api/openapi.yaml](api/openapi.yaml) — OpenAPI 3.1 for issuer, verifier, gateway, and health endpoints.
- [docs/API_OVERVIEW.md](docs/API_OVERVIEW.md) — Endpoint summaries, sample payloads, and the happy-path flow.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Module layout and component relationships.
- [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md) — Local development environment setup and tooling.
- [docs/TESTING.md](docs/TESTING.md) — Testing strategy and how to run the suites.
- [docs/SECURITY.md](docs/SECURITY.md) — Security model, threat considerations, and hardening tips.
- [docs/ROADMAP.md](docs/ROADMAP.md) — Planned features and upcoming work.
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — Project change history.
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — Contribution guidelines and development workflow.
- [docs/CODE_OF_CONDUCT.md](docs/CODE_OF_CONDUCT.md) — Expected standards for participation.
- [docs/AGENTS.md](docs/AGENTS.md) — Delegation and on-behalf-of semantics for agents.
- [docs/POLICY_ENGINE.md](docs/POLICY_ENGINE.md) — Policy schema, evaluation order, and admin endpoints under `/v1/admin/policies`.
- [docs/TENANCY.md](docs/TENANCY.md) — Single vs. multi-tenant behavior and tenant resolution rules.
- [docs/GATEWAY_INTEGRATION.md](docs/GATEWAY_INTEGRATION.md) — How `/v1/gateway/authorize` plugs into reverse proxies and mints synthetic JWTs.
- [docs/GATEWAY_HARDENING.md](docs/GATEWAY_HARDENING.md) — Security considerations when deploying the gateway.
- [docs/METRICS_IMPLEMENTATION.md](docs/METRICS_IMPLEMENTATION.md) — Prometheus metrics exposed by the services.
- [docs/KMS_DEPLOYMENT.md](docs/KMS_DEPLOYMENT.md) — Guidance for deploying with KMS integrations.
- [docs/PRODUCTION.md](docs/PRODUCTION.md) — Production readiness checklist and deployment notes.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) — Orientation for new developers and repo layout.
- [docs/DEVELOPER_GUIDE_IMPROVEMENTS.md](docs/DEVELOPER_GUIDE_IMPROVEMENTS.md) — Proposed updates to the developer guide.
- [docs/DID_RESOLVER_IMPROVEMENTS_SUMMARY.md](docs/DID_RESOLVER_IMPROVEMENTS_SUMMARY.md) — Summary of DID resolver improvements.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Threat modeling notes and mitigations.

## SDKs
- **Go (`sdk-go`):**
  - Import: `github.com/bradtumy/credential-service/sdk-go`
  - Example (SD-JWT helpers):
    ```go
    import sdk "github.com/bradtumy/credential-service/sdk-go"
    client := sdk.NewClient("", "")
    issued, _ := client.IssueSDJWTCredential("http://localhost:8080", sdk.SDJWTIssueRequest{
      SubjectDID: "did:jwk:alice", TTLSeconds: 600,
      Claims: map[string]interface{}{ "scope": "read:orders" },
    })
    verify, _ := client.VerifySDJWT("http://localhost:8081", issued.Credential, issued.Disclosures[:1])
    ```
- **Node.js (`sdk-nodejs`):**
  - Import (local repo): `const Client = require('./sdk-nodejs/client')`
  - Example (SD-JWT helpers):
    ```javascript
    const c = new Client({ issuerURL: 'http://localhost:8080', verifierURL: 'http://localhost:8081' })
    const issued = await c.issueSdJwtCredential({ subject_did: 'did:jwk:alice', ttl_seconds: 600, claims: { scope: 'read:orders' } })
    const verify = await c.verifySdJwtCredential({ credential: issued.credential, disclosures: [issued.disclosures[0]] })
    ```

Notes:
- Node package is local (`sdk-nodejs`) and not published; use relative import or publish to your registry before `npm install`.
- Go module path is `github.com/bradtumy/credential-service/sdk-go`; use `go get` with your VCS or replace with your org path if forked.

## SD-JWT and issuance policies
- **Selective Disclosure:** Request `format: "sd-jwt"` when issuing to receive a signed SD-JWT plus disclosure list. Example:
  ```bash
  curl -sX POST http://localhost:8080/v1/credentials/issue \
    -d '{"subject_did":"did:example:alice","ttl_seconds":600,"claims":{"email":"alice@example.com","scope":["read"]},"format":"sd-jwt"}'
  ```
  Verify by POSTing the SD-JWT, `format: "sd-jwt"`, and `disclosures` back to `/v1/credentials/verify`.
- **Issuance policy:** The issuer enforces `ISSUER_POLICY_MAX_TTL_SECONDS`, `ISSUER_POLICY_ALLOWED_SCOPES`, and `ISSUER_POLICY_REQUIRED_CLAIMS` during issuance/delegation to prevent over-broad credentials.
- **Audit storage:** When `ISSUER_AUDIT_DB_DSN` is set the issuer persists audit rows to Postgres in addition to structured logs whenever credentials are minted.

## Roadmap / Current Status
- **Implemented:** Issuance/delegation endpoints, SD-JWT issuance and verification alongside JWT VCs, policy-guarded TTL/scope/claim validation, audit trails with optional Postgres persistence, DID-based verification, gateway authorization with synthetic JWT minting, seeded trust registry for local runs, tenant-scoped policy engine with Postgres or in-memory stores, health/readiness probes, optional Prometheus metrics and Redis-backed caching/rate-limiting.
- **Upcoming (see [ROADMAP.md](docs/ROADMAP.md)):** Deeper KMS/Vault integrations and expanded integration/e2e testing.

## Prerequisites
- Docker and Docker Compose v2
- Go 1.21+ (for local runs)
- `jq` (for CLI examples)

## Try It Now
Quick smoke test against a running stack:
```bash
docker compose up --build -d
make keygen
ALICE_DID=$(./bin/keygen -did-only)
VC=$(curl -s -X POST http://localhost:8080/v1/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{"subject_did":"'$ALICE_DID'","ttl_seconds":600,"claims":{"aud":"sample-api","scope":"read:orders"}}' | jq -r .credential)
ISSUER_DID=$(docker logs credential-service-issuer-1 2>&1 | grep -o 'issuer_did":"did:jwk:[^"]*' | head -1 | cut -d'"' -f3)
curl -s -X POST http://localhost:8081/v1/trust/issuers -H "Content-Type: application/json" -d '{"issuer_did":"'$ISSUER_DID'"}'
SYNTH=$(curl -s -X POST http://localhost:8081/v1/gateway/authorize \
  -H "Content-Type: application/json" \
  -d '{"credential":"'$VC'","expected_audience":"sample-api","want_synthetic_jwt":true,"resource":"orders","action":"read"}' | jq -r .synthetic_jwt)
curl -s http://localhost:8082/orders -H "Authorization: Bearer $SYNTH" | jq
```

## Common Development Tasks
- **Generate a test DID**: `make keygen && ./bin/keygen -did-only`
- **Issue a test credential**:
  ```bash
  ALICE_DID=$(./bin/keygen -did-only)
  curl -X POST http://localhost:8080/v1/credentials/issue \
    -H "Content-Type: application/json" \
    -d '{"subject_did":"'$ALICE_DID'","ttl_seconds":600,"claims":{"test":true}}'
  ```
- **Reset database for testing**:
  ```bash
  docker compose down -v && docker compose up -d postgres
  sleep 3
  ```

## Contributing
1. Create a feature branch: `git checkout -b feature/your-change`.
2. Make changes and add tests.
3. Run the test suite: `make test` (or `go test ./...` for verbose output).
4. Run linter and security checks: `make lint sec`
5. Test the Quick Start guide end-to-end to ensure your changes work.
6. Commit and open a Pull Request.

## License
Apache License 2.0. See [LICENSE](LICENSE) for details.
