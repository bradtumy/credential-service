package domain

import "sync"

// TrustRegistry describes issuer trust lookups.
type TrustRegistry interface {
	IsTrustedIssuer(tenantID, issuerDID string) bool
	AddTrustedIssuer(tenantID, issuerDID string)
}

// MemoryTrustRegistry provides an in-memory trust store.
type MemoryTrustRegistry struct {
	mu      sync.RWMutex
	trusted map[string]map[string]struct{}
}

// NewMemoryTrustRegistry constructs a MemoryTrustRegistry.
func NewMemoryTrustRegistry() *MemoryTrustRegistry {
	return &MemoryTrustRegistry{trusted: make(map[string]map[string]struct{})}
}

// IsTrustedIssuer checks whether an issuer is trusted for a tenant.
func (m *MemoryTrustRegistry) IsTrustedIssuer(tenantID, issuerDID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	issuers, ok := m.trusted[tenantID]
	if !ok {
		return false
	}

	_, trusted := issuers[issuerDID]
	return trusted
}

// AddTrustedIssuer marks an issuer as trusted for a tenant.
func (m *MemoryTrustRegistry) AddTrustedIssuer(tenantID, issuerDID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.trusted[tenantID] == nil {
		m.trusted[tenantID] = make(map[string]struct{})
	}

	m.trusted[tenantID][issuerDID] = struct{}{}
}
