# API Overview

This document summarizes the primary HTTP entry points and how they fit together.

## Endpoints
- `POST /v1/credentials/issue` — issue a verifiable credential bound to a subject DID.
- `POST /v1/credentials/delegate` — issue a scoped, time-boxed delegated credential using a parent VC.
- `POST /v1/credentials/verify` — verify one or more credentials and return delegation metadata.
- `POST /v1/gateway/authorize` — perform verification plus authorization and mint an optional synthetic JWT.
- `GET /healthz` — liveness probe.
- `GET /readyz` — readiness probe (checks DB if enabled on verifier).

## Happy Path Flow (Text Diagram)
```
Client -> /v1/credentials/issue -> Credential (jwt)
Client -> /v1/credentials/delegate -> Delegated Credential (jwt)
Gateway -> /v1/gateway/authorize [credentials=[parent, child]] -> Allowed + Synthetic JWT
Downstream API <- Synthetic JWT from Gateway
```

## Payload Examples
- Issue: `{ "subject_did": "did:example:alice", "ttl_seconds": 600, "claims": {"aud": "orders-api"} }`
- Delegate: `{ "parent_credential": "<jwt>", "delegate_did": "did:example:agent", "scope": ["read"], "ttl_seconds": 300 }`
- Verify: `{ "credentials": ["<parent>", "<child>"], "expected_audience": "orders-api" }`
- Gateway Authorize: `{ "credentials": ["<parent>", "<child>"], "expected_audience": "orders-api", "want_synthetic_jwt": true }`

## Contract Reference
The structured schema is published at [api/openapi.yaml](api/openapi.yaml). Each successful response includes `api_version` to document the contract used.
