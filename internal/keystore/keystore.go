package keystore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
)

// KeyStore abstracts retrieval of signing keys for tenants.
type KeyStore interface {
	GetSigningKey(tenantID string) (crypto.Signer, error)
}

// MemoryKeyStore is an in-memory implementation suitable for development.
type MemoryKeyStore struct {
	mu   sync.Mutex
	keys map[string]crypto.Signer
}

// NewMemoryKeyStore constructs a MemoryKeyStore instance.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]crypto.Signer),
	}
}

// GetSigningKey returns or lazily generates a signing key for the given tenant.
func (m *MemoryKeyStore) GetSigningKey(tenantID string) (crypto.Signer, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if signer, ok := m.keys[tenantID]; ok {
		return signer, nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	m.keys[tenantID] = priv
	return priv, nil
}
