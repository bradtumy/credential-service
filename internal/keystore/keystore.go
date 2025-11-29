package keystore

import "crypto"

// KeyStore abstracts retrieval of signing keys for tenants.
type KeyStore interface {
	GetSigningKey(tenantID string) (crypto.Signer, error)
}
