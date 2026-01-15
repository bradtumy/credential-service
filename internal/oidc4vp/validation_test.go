package oidc4vp

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
)

func TestValidateResponseJWTVC(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	holderPub, holderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}

	issuerDID, err := domain.DIDFromPublicKey(issuerPub)
	if err != nil {
		t.Fatalf("issuer did: %v", err)
	}
	holderDID, err := domain.DIDFromPublicKey(holderPub)
	if err != nil {
		t.Fatalf("holder did: %v", err)
	}

	vcToken, err := domain.IssueBasicCredential(issuerDID, "did:jwk:subject", issuerPriv, 5*time.Minute, map[string]any{"role": "user"})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	vpJWT := signJWT(t, holderPriv, map[string]any{
		"iss":   holderDID,
		"aud":   "client-123",
		"nonce": "nonce-abc",
		"vp": map[string]any{
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": []string{vcToken},
		},
	})

	vpTokenRaw, _ := json.Marshal(map[string][]string{
		"cred1": {vpJWT},
	})

	meta := map[string]any{}
	if err := json.Unmarshal([]byte(`{"type_values":[["VerifiableCredential"]]}`), &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}

	req := AuthorizationRequest{
		ClientID:     "client-123",
		State:        "state-1",
		Nonce:        "nonce-abc",
		ResponseType: "vp_token",
		DCQLQuery: DCQLQuery{
			Credentials: []CredentialQuery{
				{
					ID:     "cred1",
					Format: FormatJWTVCJSON,
					Meta:   meta,
				},
			},
		},
	}

	result, err := ValidateResponse(req, string(vpTokenRaw), ResponseDependencies{
		ResolveIssuerKey: func(issuer string) (crypto.PublicKey, error) {
			if issuer != issuerDID {
				return nil, domain.ErrUntrustedIssuer
			}
			return issuerPub, nil
		},
		ResolveHolderKey: func(holder string) (crypto.PublicKey, error) {
			if holder != holderDID {
				return nil, domain.ErrUntrustedIssuer
			}
			return holderPub, nil
		},
	})
	if err != nil {
		t.Fatalf("validate response: %v", err)
	}
	if result.HolderDID != holderDID {
		t.Fatalf("expected holder %s got %s", holderDID, result.HolderDID)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("expected 1 credential got %d", len(result.Credentials))
	}
}

func TestValidateResponseRevoked(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	holderPub, holderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}

	issuerDID, _ := domain.DIDFromPublicKey(issuerPub)
	holderDID, _ := domain.DIDFromPublicKey(holderPub)
	vcToken, err := domain.IssueBasicCredential(issuerDID, "did:jwk:subject", issuerPriv, 5*time.Minute, map[string]any{"role": "user"})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	credentialID := extractJTI(t, vcToken)
	domain.AddRevocation(credentialID, "revoked")
	t.Cleanup(func() { domain.RemoveRevocation(credentialID) })

	vpJWT := signJWT(t, holderPriv, map[string]any{
		"iss":   holderDID,
		"aud":   "client-123",
		"nonce": "nonce-abc",
		"vp": map[string]any{
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": []string{vcToken},
		},
	})

	vpTokenRaw, _ := json.Marshal(map[string][]string{
		"cred1": {vpJWT},
	})

	meta := map[string]any{}
	_ = json.Unmarshal([]byte(`{"type_values":[["VerifiableCredential"]]}`), &meta)

	req := AuthorizationRequest{
		ClientID:     "client-123",
		State:        "state-1",
		Nonce:        "nonce-abc",
		ResponseType: "vp_token",
		DCQLQuery: DCQLQuery{
			Credentials: []CredentialQuery{
				{ID: "cred1", Format: FormatJWTVCJSON, Meta: meta},
			},
		},
	}

	_, err = ValidateResponse(req, string(vpTokenRaw), ResponseDependencies{
		ResolveIssuerKey: func(issuer string) (crypto.PublicKey, error) { return issuerPub, nil },
		ResolveHolderKey: func(holder string) (crypto.PublicKey, error) { return holderPub, nil },
		RevocationStrict: true,
	})
	if err == nil {
		t.Fatalf("expected revocation error")
	}
}

func signJWT(t *testing.T, signer ed25519.PrivateKey, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerSegment + "." + payloadSegment
	signature := ed25519.Sign(signer, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func extractJTI(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	jti, _ := payload["jti"].(string)
	if jti == "" {
		t.Fatalf("jti missing")
	}
	return jti
}
