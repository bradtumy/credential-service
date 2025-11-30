# Credential Service

A robust microservice designed for creating, managing, and verifying **W3C-compliant Verifiable Credentials (VCs)**. This service allows organizations to issue credentials, link them to **Decentralized Identifiers (DIDs)**, and enable secure, privacy-preserving verification across multiple platforms. The platform now ships with agent-mode helpers so AI agents can safely act on behalf of humans with scoped, short-lived credentials.

## 🚀 Quick Start

1. **Start the services**

   ```bash
   docker compose up --build
   ```

2. **Issue a credential**

   ```bash
   curl -X POST http://localhost:8080/v1/credentials/issue \
     -H "Content-Type: application/json" \
     -d '{
       "subject_did": "did:jwk:user-123",
       "ttl_seconds": 3600,
       "claims": {"scope": ["orders:read"]}
     }'
   ```

3. **Verify the credential**

   ```bash
   curl -X POST http://localhost:8081/v1/credentials/verify \
     -H "Content-Type: application/json" \
     -d '{"credential": "<jwt-from-step-2>"}'
   ```

4. **Test the full workflow**

   ```bash
   go run ./examples/go-basic
   ```

### Agent mode (30-second example)

Use the Go helper to mint a short-lived delegated credential for an agent and call a service on behalf of a human:

```bash
go run ./examples/agent-basic
```

## API Overview

The platform exposes versioned HTTP endpoints under `/v1`:

- **Issuer Service (port 8080)**:
  - `POST /v1/credentials/issue` — issue a verifiable credential
  - `POST /v1/credentials/delegate` — mint a scoped delegated credential
  - `GET /healthz`, `GET /readyz` — health checks

- **Verifier Service (port 8081)**:
  - `POST /v1/credentials/verify` — verify a credential chain
  - `POST /v1/gateway/authorize` — perform authorization and mint synthetic JWT
  - `POST /v1/admin/policies` — manage authorization policies
  - `GET /healthz`, `GET /readyz` — health checks

- **S2S API (port 8082)**:
  - `GET /orders` — protected resource requiring valid credentials

See [API_OVERVIEW.md](API_OVERVIEW.md) for request/response flows, and the OpenAPI definition at [api/openapi.yaml](api/openapi.yaml).

## Versioning Policy

- Current API version: **v1** (surfaced in responses as `api_version`).
- Backward compatible changes land under the same major version; breaking changes will publish a new `/v{n}` path.
- Binary releases inject a build identifier via `-ldflags` to `internal/version.BuildVersion`.

## Error Format

All JSON errors follow a consistent envelope:

```json
{
  "error": "invalid_request",
  "description": "human-friendly message",
  "code": "invalid_request",
  "api_version": "v1"
}
```

## Developer Resources

- [API Overview](API_OVERVIEW.md) — endpoint guide with sample flows.
- [AGENTS.md](AGENTS.md) — agent lifecycle notes.
- [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) — deeper design context.
- [Quickstart](#-5-minute-quickstart) — fast start instructions.
- [OpenAPI Spec](api/openapi.yaml) — structured contract for the HTTP APIs.

## What Are DIDs and VCs?

Decentralized Identifiers (DIDs) are unique digital identifiers backed by cryptographic keys. They are not anchored to any single company or database, giving people, services, and AI agents a portable way to prove who they are without relying on a central authority.

Verifiable Credentials (VCs) are digitally signed statements about someone or something. Because they are signed, anyone can check that a VC has not been tampered with and that it really came from the claimed issuer. In this project, VCs can carry claims such as roles, permissions, or other attributes.

This service issues and verifies VCs bound to DIDs so that humans, services, and AI agents can authenticate and share trusted information across systems in an interoperable way.

## Key Features

- **JWT-based Verifiable Credentials**: Issue Ed25519-signed JWT credentials with configurable TTL
- **Credential Delegation**: Create scoped, short-lived credentials for agents acting on behalf of users
- **Policy-based Authorization**: Fine-grained access control with configurable policies
- **Trust Registry**: Manage trusted issuers and multi-tenant isolation
- **Gateway Integration**: Generate synthetic JWTs for downstream API authorization
- **Credential Chain Verification**: Validate delegation chains with proper scope inheritance
- **Microservice Architecture**: Containerized services for issuer, verifier, and demo APIs





## Requirements

- Go 1.22 or higher
- PostgreSQL 16+
- Docker 24+
- Docker Compose v2

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/bradtumy/credential-service.git
   cd credential-service
   ```

2. Start all services:

   ```bash
   docker compose up --build
   ```

## Configuration

The services are configured via environment variables in `docker-compose.yml`:

- **Issuer**: `ISSUER_HTTP_PORT=8080`
- **Verifier**: `VERIFIER_HTTP_PORT=8081`, database connection for trust registry
- **S2S API**: `API_HTTP_PORT=8082` for demo protected resources



## Testing

Instructions for running tests, if applicable.

**Example:**

```bash
go test ./...
```

Here's an updated section for the `README.md` that covers the new Verifier service:

---



## Contributing

How others can contribute to the project.

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Commit your changes (git commit -am 'Add new feature').
4. Push the branch (git push origin feature-branch).
5. Open a Pull Request.

## License

This project is licensed under the Apache2 License - see the LICENSE file for details.

## Contact

Email: <brad@tumy-tech.com>  
GitHub: [bradtumy/credential-service](https://github.com/bradtumy/credential-service)
