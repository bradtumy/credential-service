package httpserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/oidc4vp"
	"github.com/bradtumy/credential-service/internal/version"
)

func TestOIDC4VPResponseHandlerSuccess(t *testing.T) {
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

	vpJWT := signTestJWT(holderPriv, map[string]any{
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

	store := oidc4vp.NewMemoryRequestStore()
	req := oidc4vp.AuthorizationRequest{
		ClientID:     "client-123",
		State:        "state-1",
		Nonce:        "nonce-abc",
		ResponseType: "vp_token",
		DCQLQuery: oidc4vp.DCQLQuery{
			Credentials: []oidc4vp.CredentialQuery{
				{ID: "cred1", Format: oidc4vp.FormatJWTVCJSON, Meta: meta},
			},
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Save(context.Background(), req); err != nil {
		t.Fatalf("save request: %v", err)
	}

	registry := domain.NewMemoryTrustRegistry()
	if err := registry.AddTrustedIssuer(context.Background(), "tenant", issuerDID); err != nil {
		t.Fatalf("trust issuer: %v", err)
	}

	mux := http.NewServeMux()
	RegisterOIDC4VPRoutes(mux, OIDC4VPConfig{
		RequestStore:     store,
		IssuerResolver:   func(issuer string) (crypto.PublicKey, error) { return issuerPub, nil },
		HolderResolver:   func(holder string) (crypto.PublicKey, error) { return holderPub, nil },
		TrustRegistry:    registry,
		DefaultTenantID:  "tenant",
		MaxRequestSize:   64 * 1024,
		Now:              time.Now,
		RevocationStrict: true,
	})

	form := url.Values{}
	form.Set("state", "state-1")
	form.Set("vp_token", string(vpTokenRaw))

	reqHTTP := httptest.NewRequest(http.MethodPost, "/v1/oidc4vp/response", bytes.NewBufferString(form.Encode()))
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	mux.ServeHTTP(recorder, reqHTTP)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 got %d", recorder.Code)
	}

	var resp OIDC4VPResponse
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Verified || resp.APIVersion != version.APIVersion {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// replay should fail
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, reqHTTP)
	if recorder.Code == http.StatusOK {
		t.Fatalf("expected replay to fail")
	}
}

func signTestJWT(signer ed25519.PrivateKey, payload map[string]any) string {
	header := map[string]any{"alg": "EdDSA", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerSegment + "." + payloadSegment
	signature := ed25519.Sign(signer, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
