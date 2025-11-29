# Architecture

The credential-service repository now follows an idiomatic Go layout that separates binaries from shared libraries.

## Binaries
- `cmd/issuer`: starts the credential issuer HTTP service and worker.
- `cmd/verifier`: starts the credential verifier HTTP service.

## Internal Modules
- `internal/domain`: core verifiable credential types, issuance helpers, and multi-tenant context primitives.
- `internal/httpx`: HTTP helpers for error responses and middleware (request/tenant IDs).
- `internal/config`: lightweight environment-based configuration loader.
- `internal/keystore`: abstraction for retrieving signing keys for tenants.
- `internal/issuer`: issuer-specific routing, queueing, and issuance orchestration.
- `internal/verifier`: verification handlers that wrap domain validation.

## Data Flow (simplified)
1. **Issue**: HTTP request hits `cmd/issuer` → router (`internal/issuer`) → credential built/signature attached (`internal/domain`) → stored (PostgreSQL) and queued (RabbitMQ).
2. **Store/Queue**: Credentials persisted via `pgx` (if configured) and issuance jobs emitted to RabbitMQ for background processing.
3. **Verify**: Presentation posted to `cmd/verifier` → handler (`internal/verifier`) → validation rules in `internal/domain`.
4. **Future**: Trust registry and delegation rules will extend `internal/domain` and share middleware/config utilities.
