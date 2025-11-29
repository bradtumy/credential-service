# Security Guidelines

- **Secrets**: Never commit secrets or private keys. Fetch signing keys from Vault/KMS and keep them per-tenant.
- **Multi-tenancy**: Tenant context is carried via middleware; every new handler must respect tenant isolation.
- **Delegation**: Future delegation features must never increase privilege beyond the parent scope.
- **Transport**: Use TLS-terminated endpoints in production and prefer mTLS for service-to-service communication.
- **Dependency Scanning**: `make sec` runs gosec for quick checks; CI enforces this alongside linting.
