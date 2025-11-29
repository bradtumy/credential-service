package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/keystore"
)

func TestIssueHandlerSuccess(t *testing.T) {
	store := keystore.NewMemoryKeyStore()
	cfg := config.IssuerConfig{HTTPPort: "8080", DefaultTenantID: "tenant-1"}
	mux := http.NewServeMux()
	RegisterIssuerRoutes(mux, store, cfg)

	body := IssueRequest{
		SubjectDID: "did:jwk:subject",
		TTLSeconds: 600,
		Claims:     map[string]interface{}{"role": "agent"},
	}
	payload, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/issue", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()

	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var resp IssueResponse
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Credential == "" {
		t.Fatalf("expected credential in response")
	}

	if !strings.Contains(resp.Credential, ".") {
		t.Fatalf("expected jwt-like token")
	}
}

func TestIssueHandlerMissingSubject(t *testing.T) {
	store := keystore.NewMemoryKeyStore()
	cfg := config.IssuerConfig{HTTPPort: "8080", DefaultTenantID: "tenant-1"}
	mux := http.NewServeMux()
	RegisterIssuerRoutes(mux, store, cfg)

	body := IssueRequest{TTLSeconds: int64((10 * time.Minute).Seconds())}
	payload, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/issue", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()

	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", recorder.Code)
	}
}
