package domain

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyCredentialSuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	token, err := IssueBasicCredential("did:jwk:issuer", "did:jwk:subject", priv, 5*time.Minute, map[string]interface{}{"aud": "example"})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	deps := VerifierDependencies{ResolveIssuerPublicKey: func(issuer string) (crypto.PublicKey, error) {
		if issuer != "did:jwk:issuer" {
			return nil, errors.New("unknown issuer")
		}
		return pub, nil
	}}

	result, err := VerifyCredential(token, deps, "example", time.Now())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if result.Credential.Subject != "did:jwk:subject" {
		t.Fatalf("unexpected subject: %s", result.Credential.Subject)
	}
}

func TestVerifyCredentialExpired(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, err := IssueBasicCredential("did:jwk:issuer", "did:jwk:subject", priv, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	vc := decodeCredentialPayload(t, token)
	deps := VerifierDependencies{ResolveIssuerPublicKey: func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}}

	if _, err := VerifyCredential(token, deps, "", vc.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrExpiredCredential) {
		t.Fatalf("expected ErrExpiredCredential, got %v", err)
	}
}

func TestVerifyCredentialInvalidSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, err := IssueBasicCredential("did:jwk:issuer", "did:jwk:subject", priv, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token segments")
	}
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("tampered"))
	tampered := strings.Join(parts, ".")

	deps := VerifierDependencies{ResolveIssuerPublicKey: func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}}

	if _, err := VerifyCredential(tampered, deps, "", time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyCredentialUntrustedIssuer(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, err := IssueBasicCredential("did:jwk:issuer", "did:jwk:subject", priv, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	deps := VerifierDependencies{ResolveIssuerPublicKey: func(string) (crypto.PublicKey, error) {
		return nil, errors.New("issuer not trusted")
	}}

	if _, err := VerifyCredential(token, deps, "", time.Now()); !errors.Is(err, ErrUntrustedIssuer) {
		t.Fatalf("expected ErrUntrustedIssuer, got %v", err)
	}
}

func decodeCredentialPayload(t *testing.T, token string) VerifiableCredential {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var vc VerifiableCredential
	if err := json.Unmarshal(payload, &vc); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return vc
}
