package httpx

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
)

func TestVerifierHandlerSuccess(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

	registry := domain.NewMemoryTrustRegistry()
	registry.AddTrustedIssuer("tenant", issuerDID)

	resolver := func(issuer string) (crypto.PublicKey, error) {
		if issuer != issuerDID {
			return nil, domain.ErrUntrustedIssuer
		}
		return priv.Public(), nil
	}

	mux := http.NewServeMux()
	RegisterVerifierRoutes(mux, resolver, registry, "tenant", time.Now)

	token, err := domain.IssueBasicCredential(issuerDID, "did:jwk:subject", priv, 5*time.Minute, map[string]interface{}{"aud": "example-api"})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	reqPayload := VerifyRequest{Credential: token, ExpectedAudience: "example-api"}
	body, _ := json.Marshal(reqPayload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/verify", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp VerifyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !resp.Valid || resp.Subject != "did:jwk:subject" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	if resp.DelegationDepth != 0 || resp.ActingOnBehalfOf != resp.Subject {
		t.Fatalf("expected delegation metadata to mirror subject, got %+v", resp)
	}
}

func TestVerifierHandlerDelegatedCredential(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

	registry := domain.NewMemoryTrustRegistry()
	registry.AddTrustedIssuer("tenant", issuerDID)

	resolver := func(issuer string) (crypto.PublicKey, error) {
		if issuer != issuerDID {
			return nil, domain.ErrUntrustedIssuer
		}
		return priv.Public(), nil
	}

	parent, err := domain.IssueBasicCredential(issuerDID, "did:jwk:parent", priv, 10*time.Minute, map[string]interface{}{"scope": []string{"read", "write"}})
	if err != nil {
		t.Fatalf("issue parent: %v", err)
	}

	child, err := domain.IssueBasicCredential(issuerDID, "did:jwk:agent", priv, 5*time.Minute, map[string]interface{}{"scope": []string{"read"}})
	if err != nil {
		t.Fatalf("issue child: %v", err)
	}

	mux := http.NewServeMux()
	RegisterVerifierRoutes(mux, resolver, registry, "tenant", time.Now)

	reqPayload := VerifyRequest{Credentials: []string{parent, child}}
	body, _ := json.Marshal(reqPayload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/verify", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp VerifyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Subject != "did:jwk:agent" || resp.ActingOnBehalfOf != "did:jwk:parent" || resp.DelegationDepth != 1 {
		t.Fatalf("unexpected delegation response: %+v", resp)
	}
}

func TestVerifierHandlerExpiredCredential(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

	registry := domain.NewMemoryTrustRegistry()
	registry.AddTrustedIssuer("tenant", issuerDID)

	resolver := func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}

	token, err := domain.IssueBasicCredential(issuerDID, "did:jwk:subject", priv, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	credential := decodeCredentialForHandlerTest(t, token)

	mux := http.NewServeMux()
	RegisterVerifierRoutes(mux, resolver, registry, "tenant", func() time.Time {
		return credential.ExpiresAt.Add(time.Second)
	})

	reqPayload := VerifyRequest{Credential: token}
	body, _ := json.Marshal(reqPayload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/verify", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestVerifierHandlerUntrustedIssuer(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	issuerDID, _ := domain.DIDFromPublicKey(priv.Public())

	registry := domain.NewMemoryTrustRegistry()
	resolver := func(string) (crypto.PublicKey, error) {
		return priv.Public(), nil
	}

	mux := http.NewServeMux()
	RegisterVerifierRoutes(mux, resolver, registry, "tenant", time.Now)

	token, err := domain.IssueBasicCredential(issuerDID, "did:jwk:subject", priv, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	reqPayload := VerifyRequest{Credential: token}
	body, _ := json.Marshal(reqPayload)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/verify", bytes.NewReader(body))

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}
}

func decodeCredentialForHandlerTest(t *testing.T, token string) domain.VerifiableCredential {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var vc domain.VerifiableCredential
	if err := json.Unmarshal(payload, &vc); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return vc
}
