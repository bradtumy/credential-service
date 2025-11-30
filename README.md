# Credential Service

A robust microservice designed for creating, managing, and verifying **W3C-compliant Verifiable Credentials (VCs)**. This service allows organizations to issue credentials, link them to **Decentralized Identifiers (DIDs)**, and enable secure, privacy-preserving verification across multiple platforms. The platform now ships with agent-mode helpers so AI agents can safely act on behalf of humans with scoped, short-lived credentials.

## 🚀 Quick Start

1. **Start the services**

   ```bash
   docker compose up --build
   ```

2. **Bootstrap admin access** ⚠️ **Required for admin operations**

   ```bash
   # Create root admin VC (6-month validity)
   curl -X POST http://localhost:8080/v1/setup/bootstrap \
     -H "Content-Type: application/json" \
     -d '{
       "issuer_did": "did:example:admin",
       "issuer_name": "System Administrator"
     }'
   
   # Save the returned admin_vc token for admin operations
   ```

3. **Issue a user credential**

   ```bash
   curl -X POST http://localhost:8080/v1/credentials/issue \
     -H "Content-Type: application/json" \
     -d '{
       "subject_did": "did:jwk:user-123",
       "ttl_seconds": 3600,
       "claims": {"scope": ["orders:read"]}
     }'
   ```

4. **Verify the credential**

   ```bash
   curl -X POST http://localhost:8081/v1/credentials/verify \
     -H "Content-Type: application/json" \
     -d '{"credential": "<jwt-from-step-3>"}'
   ```

5. **Test the full workflow**

   ```bash
   go run ./examples/go-basic
   ```

### Agent mode (30-second example)

Use the Go helper to mint a short-lived delegated credential for an agent and call a service on behalf of a human:

```bash
go run ./examples/agent-basic
```

## 🔐 Admin Authentication

**🚨 Important**: Admin APIs now require authentication with admin VCs. You must bootstrap the system first.

### **Bootstrap Admin System**
```bash
# 1. Bootstrap creates issuer + root admin VC (one-time setup)
curl -X POST http://localhost:8080/v1/setup/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"root_admin_did": "did:jwk:your-admin-identity"}'

# 2. Save the returned root_admin_credential for admin operations
export ADMIN_VC="eyJhbGciOiJFZERTQSI..."
```

### **Admin Operations Require Authentication**
```bash
# All admin endpoints now require Authorization header
curl -X POST http://localhost:8081/v1/admin/policies \
  -H "Authorization: Bearer $ADMIN_VC" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

## API Overview

The platform exposes versioned HTTP endpoints under `/v1`:

- **Issuer Service (port 8080)**:
  - `POST /v1/setup/bootstrap` — **bootstrap system issuer + root admin VC**
  - `POST /v1/credentials/issue` — issue a verifiable credential
  - `POST /v1/credentials/delegate` — mint a scoped delegated credential  
  - `GET /healthz`, `GET /readyz` — health checks

- **Verifier Service (port 8081)**:
  - `POST /v1/credentials/verify` — verify a credential chain using DID resolution
  - `POST /v1/gateway/authorize` — perform authorization and mint synthetic JWT
  - **`POST /v1/admin/policies`** — **🔐 manage authorization policies (admin VC required)**
  - **`POST /v1/admin/trust-registry`** — **🔐 manage trusted issuer DIDs (admin VC required)**
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

## 📚 Learn More

- **[Demo Guide](#-demo-guide)** — step-by-step instructions for trying the system with your own data
- **[API Overview](API_OVERVIEW.md)** — complete endpoint reference with examples  
- **[Policy Engine](POLICY_ENGINE.md)** — authorization system deep dive
- **[Agent Delegation](AGENTS.md)** — how AI agents can act on behalf of users
- **[Developer Guide](DEVELOPER_GUIDE.md)** — architecture and design decisions
- **[OpenAPI Spec](api/openapi.yaml)** — structured API contracts

**Key Concepts to Understand**:
- **DID Resolution**: How verifiers automatically resolve public keys from DIDs without pre-configuration
- **Admin vs User VCs**: Admin VCs have `"vc_type": "admin"` and elevated permissions; user VCs cannot access admin endpoints
- **Bootstrap Security**: Initial admin VC creation requires the bootstrap endpoint for secure system initialization  
- **Credentials vs Policies**: Credentials prove identity/claims, policies control access to resources
- **Delegation Chains**: How agents inherit scoped permissions from parent credentials  
- **Trust Registry**: Which issuer DIDs are allowed to create valid credentials (managed per organization)
- **Multi-tenancy**: How organizations are isolated from each other

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
- **DID Resolution**: Distributed public key resolution enabling multi-organization deployment without pre-shared keys
- **Microservice Architecture**: Containerized services for issuer, verifier, and demo APIs
- **Admin Authentication**: Admin endpoints protected by verifiable credentials with super-admin roles

## 🔐 Security Model

### Admin vs User VCs

The system enforces strict separation between administrative and user operations:

- **Admin VCs**: Have `"vc_type": "admin"` and `"super-admin"` role, valid for 6 months
- **User VCs**: Standard credentials for application access, cannot access admin endpoints
- **Bootstrap Required**: Initial admin VC must be created via `/v1/setup/bootstrap`

### Admin Endpoint Protection

All `/v1/admin/*` endpoints require a valid admin VC in the Authorization header:

```bash
curl -X POST http://localhost:8081/v1/admin/policies \
  -H "Authorization: Bearer <admin-vc-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "example-policy", ...}'
```

**Security guarantees:**
- User VCs are rejected with `"admin_credential_required"` error
- Admin VCs are validated for proper type, role, and signature
- Bootstrap endpoint is unprotected (one-time setup only)

## 🌐 DID Resolution & Multi-Organization Support

### How DID Resolution Works

The system uses **DID Resolution** to enable distributed verification without pre-shared keys. Instead of manually configuring public keys, verifiers automatically resolve public keys from DIDs.

**Traditional Approach (❌ Doesn't Scale)**:
```go
// Hard-coded key maps - requires manual coordination
issuerKeys := map[string]crypto.PublicKey{
    "did:jwk:abc123...": publicKey1,
    "did:jwk:def456...": publicKey2,
}
```

**DID Resolution Approach (✅ Scales Globally)**:
```go
// Automatic resolution - no pre-configuration needed
publicKey, err := didResolver.ResolvePublicKey(ctx, "did:jwk:abc123...")
```

### Supported DID Methods

#### **did:jwk (Self-contained)**
- **Format**: `did:jwk:eyJrdHkiOiJPS1AiLCJjcnYi...` 
- **Resolution**: Extracts public key directly from the DID (no network calls)
- **Use Case**: Perfect for microservices, agents, and ephemeral identities
- **Example**: `did:jwk:eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ik9QRGhLb3hQeXJqbmJZUWc1cFNHS2FoOXFMQ3g2eE5vVEdJdHZ1MDhiZ1UifQ`

#### **did:web (Production Ready)** ✅
- **Format**: `did:web:example.org` or `did:web:bank.example.com:departments:hr`
- **Resolution**: HTTPS lookup to `https://example.org/.well-known/did.json`
- **Use Case**: Enterprise organizations with existing web infrastructure
- **Status**: Fully implemented with security-first approach
- **Security Features**:
  - HTTPS-only by default (configurable for testing)
  - Document size limits (10KB default)
  - Request timeouts (10s default)  
  - Comprehensive input validation

> **Note**: The repository includes a `resolver-service` for DID document storage/retrieval. The **DID Resolution** described here is different - it's the built-in capability for resolving public keys directly from DIDs during credential verification.

### Multi-Organization Deployment

**Step 1**: Organizations deploy independently
```bash
# Organization A (Bank)
docker run issuer-service:latest
# Issues credentials with did:jwk:bank-key...

# Organization B (Government) 
docker run verifier-service:latest
# Verifies credentials using DID resolution
```

**Step 2**: Establish trust relationships
```bash
# Government decides to trust Bank's issuer DID
curl -X POST http://gov-verifier/v1/admin/trust-registry \
  -H "Authorization: Bearer <admin-vc>" \
  -d '{"issuer_did": "did:jwk:bank-key...", "trusted": true}'
```

**Step 3**: Cross-organizational verification works automatically
```bash
# Bank issues credential
credential=$(curl -X POST http://bank-issuer/v1/credentials/issue \
  -d '{"subject_did": "did:jwk:citizen123", "claims": {"verified_citizen": true}}')

# Government verifies without any key exchange!
curl -X POST http://gov-verifier/v1/credentials/verify \
  -d '{"credential": "'$credential'"}'
# ✅ SUCCESS - DID resolution automatically found Bank's public key
```

### Trust Registry Management

Verifiers maintain trust registries that determine which issuer DIDs to accept:

```bash
# List trusted issuers
curl http://localhost:8081/v1/admin/trust-registry

# Add trusted issuer (requires admin VC)
curl -X POST http://localhost:8081/v1/admin/trust-registry \
  -H "Authorization: Bearer <admin-vc>" \
  -d '{
    "issuer_did": "did:jwk:eyJrdHkiOiJPS1AiLi4u",
    "trusted": true,
    "metadata": {"organization": "Trusted Bank Corp"}
  }'

# Remove trust
curl -X DELETE http://localhost:8081/v1/admin/trust-registry/did:jwk:eyJrdHkiOi... \
  -H "Authorization: Bearer <admin-vc>"
```

### Benefits for Distributed Deployment

✅ **No Key Exchange**: Organizations don't need to share public keys manually  
✅ **Automatic Resolution**: Public keys are resolved from DIDs cryptographically  
✅ **Trust Control**: Each verifier decides which issuers to trust  
✅ **Key Rotation**: New keys automatically work (did:jwk creates new DID)  
✅ **Global Scalability**: Works across any number of organizations  
✅ **Zero Dependencies**: did:jwk resolution requires no external infrastructure  

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

## 🎯 Demo Guide

### **Built-in Demo (Works Out of the Box)**

The system includes a working demo that issues credentials, verifies them, and accesses a protected API:

```bash
# Run the complete demo workflow
go run ./examples/go-basic

# Or run the agent delegation demo
go run ./examples/agent-basic
```

### **Custom Demo: Using Your Own Data**

⚠️ **Important**: The system uses **policy-based authorization**. If you change credential data, you may need to update policies to match.

#### **1. Issue Credential with Custom Data**

```bash
curl -X POST http://localhost:8080/v1/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{
    "subject_did": "did:jwk:your-custom-user",
    "ttl_seconds": 3600,
    "claims": {
      "scope": ["your-resource:read"],
      "roles": ["your-role"],
      "department": "engineering"
    }
  }'
```

#### **2. Create Matching Policy** 🔐 **Requires Admin VC**

The default policy only allows access to `"orders"` with `"read"` action. For custom resources, create a policy using your admin VC:

```bash
curl -X POST http://localhost:8081/v1/admin/policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-vc-from-bootstrap>" \
  -d '{
    "name": "custom-demo-policy",
    "description": "Allow access to your custom resource",
    "effect": "allow",
    "actions": ["read", "write"],
    "resources": ["your-resource", "your-resource/*"],
    "subjects": ["any"],
    "conditions": {
      "scope_contains": "your-resource:read"
    },
    "priority": 50,
    "enabled": true
  }'
```

#### **3. Test Authorization**

```bash
# Verify credential and check authorization
curl -X POST http://localhost:8081/v1/gateway/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": ["<your-jwt-credential>"],
    "resource": "your-resource",
    "action": "read",
    "want_synthetic_jwt": true
  }'
```

### **Policy Management for Demos**

#### **View Current Policies**
```bash
curl http://localhost:8081/v1/admin/policies | jq '.policies[]'
```

#### **Common Demo Scenarios**

1. **Role-based Access**:
   ```bash
   # Issue credential with role
   curl -X POST http://localhost:8080/v1/credentials/issue \
     -d '{"subject_did": "did:jwk:admin", "claims": {"roles": ["admin"]}}'
   
   # Create role-based policy  
   curl -X POST http://localhost:8081/v1/admin/policies \
     -d '{"name": "admin-access", "effect": "allow", "actions": ["*"], "resources": ["*"], "subjects": ["role:admin"]}'
   ```

2. **Scope-based Access**:
   ```bash
   # Different scopes require different policies
   curl -X POST http://localhost:8080/v1/credentials/issue \
     -d '{"subject_did": "did:jwk:user", "claims": {"scope": ["payments:read", "users:write"]}}'
   ```

3. **Resource Patterns**:
   ```bash
   # Wildcard resources
   curl -X POST http://localhost:8081/v1/admin/policies \
     -d '{"name": "api-access", "effect": "allow", "actions": ["read"], "resources": ["api/*"], "subjects": ["any"]}'
   ```

### **Using did:web for Enterprise Deployment**

The credential service now supports `did:web` for organizations with existing web infrastructure. This enables enterprise deployments where public keys are hosted on your existing domain.

#### **Setting Up did:web Identity**

1. **Host DID Document**: Create a DID document at `https://yourdomain.com/.well-known/did.json`

   ```json
   {
     "id": "did:web:yourdomain.com",
     "verificationMethod": [{
       "id": "did:web:yourdomain.com#key1",
       "type": "JsonWebKey2020",
       "controller": "did:web:yourdomain.com", 
       "publicKeyJwk": {
         "kty": "OKP",
         "crv": "Ed25519",
         "x": "your-base64url-encoded-public-key"
       }
     }]
   }
   ```

2. **Add to Trust Registry**: Register the did:web identity as a trusted issuer

   ```bash
   curl -X POST http://localhost:8081/v1/admin/trust-registry \
     -H "Authorization: Bearer <admin-vc>" \
     -H "Content-Type: application/json" \
     -d '{
       "issuer_did": "did:web:yourdomain.com",
       "trusted": true
     }'
   ```

3. **Issue Credentials**: Use the did:web identity to issue credentials

   ```bash
   curl -X POST http://localhost:8080/v1/credentials/issue \
     -H "Content-Type: application/json" \
     -d '{
       "subject_did": "did:jwk:user-key-here",
       "ttl_seconds": 3600,
       "claims": {"scope": ["orders:read"]},
       "issuer_override": "did:web:yourdomain.com"
     }'
   ```

#### **Advanced did:web Configuration**

- **Subdomain/Path Support**: `did:web:bank.example.com:departments:hr` resolves to `https://bank.example.com/departments/hr/did.json`
- **URL Encoding**: `did:web:example.com%3A8080` resolves to `https://example.com:8080/.well-known/did.json`
- **Security Features**: HTTPS-only by default, 10KB document size limit, 10-second timeout
- **Testing**: Set `AllowInsecureWeb: true` in configuration for HTTP testing (never use in production)
   ```

### **Demo Troubleshooting**

**❌ Problem**: Getting `{"allowed": false, "reason": "policy_denied"}`
**✅ Solution**: Create a policy that matches your credential's subject, claims, and target resource.

**❌ Problem**: Credential verification fails
**✅ Solution**: Check that the issuer is trusted and credential hasn't expired.

**❌ Problem**: `scope_contains` condition fails
**✅ Solution**: Ensure credential `claims.scope` includes the required values.

## Configuration

The services are configured via environment variables in `docker-compose.yml`:

- **Issuer**: `ISSUER_HTTP_PORT=8080`
- **Verifier**: `VERIFIER_HTTP_PORT=8081`, database connection for trust registry and policies
- **S2S API**: `API_HTTP_PORT=8082` for demo protected resources



## Testing

Instructions for running tests, if applicable.

**Example:**

```bash
go test ./...
```

## 🛡️ Security Best Practices

### Production Deployment

- **Secure Bootstrap**: Run bootstrap endpoint only during initial setup, then disable or restrict access
- **Admin VC Storage**: Store admin VCs securely (encrypted storage, key management systems)
- **Trust Registry Security**: Carefully manage trusted issuer DIDs - only trust verified organizations
- **DID Resolution**: Monitor DID resolution for security - did:jwk is self-contained and secure
- **Network Security**: Use HTTPS/TLS for all API communications in production
- **VC Rotation**: Regularly rotate admin VCs before 6-month expiry
- **Audit Logging**: Monitor all admin endpoint access and trust registry changes for security auditing

### Development vs Production

This README shows HTTP endpoints for simplicity. In production:
- Use HTTPS with proper certificates
- Implement network-level security (VPNs, firewalls)
- Regular security assessments of the credential verification logic
- Consider implementing admin VC revocation lists for immediate access termination

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
