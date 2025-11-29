# Policy Engine Skeleton

The policy engine evaluates authorization decisions after credentials are verified and the tenant is resolved. Day 12 ships a no-op engine to keep behavior backward compatible while establishing the contract for future ABAC/RBAC and delegation-aware policies.

## Input Model
- `TenantID`: Tenant derived from `X-Tenant-ID` or the default tenant in single-tenant mode
- `Subject`: DID of the acting subject
- `ActingOnBehalfOf`: Delegation chain root (if applicable)
- `Scope`: Requested scopes derived from credential claims
- `Claims`: Raw claims from the leaf credential
- `Resource`: Target resource (e.g., expected audience)
- `Action`: Operation being authorized (e.g., `gateway_authorize`)
- `Context`: Additional request context (path, delegation depth, etc.)

## Output Model
- `Allow`: Boolean decision
- `Reason`: Optional string describing the decision path

## Why a No-Op Default?
The default engine returns `Allow=true` with reason `allow_all` to avoid breaking existing integrations. It ensures a clean upgrade path while letting downstream deployments plug in richer engines later.

## Roadmap
- Attribute-based access control (ABAC)
- Role-based access control (RBAC)
- Permissioned delegation chains
- Resource/action templates for gateways
- Policy-as-code integration with versioned bundles
