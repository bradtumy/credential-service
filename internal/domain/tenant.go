package domain

// TenantContext captures multi-tenant request metadata.
type TenantContext struct {
	TenantID  string
	RequestID string
}
