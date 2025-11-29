package keystore

import (
	"crypto"
	"crypto/ed25519"
	"testing"
)

type fakeKeyStore struct {
	key crypto.Signer
}

func (f fakeKeyStore) GetSigningKey(_ string) (crypto.Signer, error) {
	return f.key, nil
}

func TestKeyStoreContract(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ks := fakeKeyStore{key: priv}
	signer, err := ks.GetSigningKey("tenant")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if signer == nil {
		t.Fatal("expected signer to be returned")
	}
}
