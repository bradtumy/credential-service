# Security Guidelines

- **Secrets**: Never commit secrets or private keys. The current development setup uses in-memory keys only; production deployments must fetch and protect signing keys with a KMS/HSM and avoid persisting private keys to disk or databases.
- **Multi-tenancy**: Tenant context is carried via middleware; every handler must enforce tenant isolation. Trust registry entries are per-tenant and should never be shared across tenants.
- **Delegation safety**: Delegated credentials must always shrink scope and TTL, and the verifier enforces a maximum delegation depth. Extending delegation logic must preserve these constraints.
- **Transport**: Use TLS-terminated endpoints in production and prefer mTLS for service-to-service communication.
- **Dependency Scanning**: `make sec` runs gosec for quick checks; CI enforces this alongside linting.
- **Threat model**: See `THREAT_MODEL.md` for a concise analysis of assets, threats, and planned mitigations.
