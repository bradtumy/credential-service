package httpx

import (
"bytes"
"context"
"crypto"
"crypto/ed25519"
"encoding/json"
"net/http"
"net/http/httptest"
"testing"
"time"

"github.com/bradtumy/credential-service/internal/domain"
)

func TestGatewayAuthorizeAllow(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

registry := domain.NewMemoryTrustRegistry()
registry.AddTrustedIssuer(context.Background(), "tenant", issuerDID)

	resolver := func(issuer string) (crypto.PublicKey, error) {
		if issuer != issuerDID {
			return nil, domain.ErrUntrustedIssuer
		}
		return priv.Public(), nil
	}

	token, err := domain.IssueBasicCredential(issuerDID, "did:example:agent", priv, 5*time.Minute, map[string]interface{}{"scope": "read:orders"})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	mux := http.NewServeMux()
	RegisterGatewayRoutes(mux, resolver, registry, "tenant", priv, issuerDID, time.Now)

	payload := GatewayAuthorizeRequest{Credential: token, WantSyntheticJWT: true}
	body, _ := json.Marshal(payload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateway/authorize", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp GatewayAuthorizeResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !resp.Allowed || resp.Subject != "did:example:agent" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	if resp.SyntheticJWT == "" {
		t.Fatalf("expected synthetic jwt to be present")
	}
}

func TestGatewayAuthorizeDenyExpired(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

registry := domain.NewMemoryTrustRegistry()
registry.AddTrustedIssuer(context.Background(), "tenant", issuerDID)

	resolver := func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}

	token, err := domain.IssueBasicCredential(issuerDID, "did:example:bob", priv, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	cred := decodeCredentialForHandlerTest(t, token)

	mux := http.NewServeMux()
	RegisterGatewayRoutes(mux, resolver, registry, "tenant", priv, issuerDID, func() time.Time {
		return cred.ExpiresAt.Add(time.Second)
	})

	payload := GatewayAuthorizeRequest{Credential: token}
	body, _ := json.Marshal(payload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateway/authorize", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	var resp GatewayAuthorizeResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed || resp.Reason != "expired_credential" {
		t.Fatalf("unexpected deny response: %+v", resp)
	}
}

func TestGatewayAuthorizeUntrustedIssuer(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

	registry := domain.NewMemoryTrustRegistry()
	resolver := func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}

	token, err := domain.IssueBasicCredential(issuerDID, "did:example:bob", priv, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	mux := http.NewServeMux()
	RegisterGatewayRoutes(mux, resolver, registry, "tenant", priv, issuerDID, time.Now)

	payload := GatewayAuthorizeRequest{Credential: token}
	body, _ := json.Marshal(payload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateway/authorize", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	var resp GatewayAuthorizeResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Allowed || resp.Reason != "untrusted_issuer" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
