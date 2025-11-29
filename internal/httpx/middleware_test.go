package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestContextAddsIDs(t *testing.T) {
	handler := RequestContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestIDFromContext(r.Context()); id == "" {
			t.Fatalf("expected request ID to be set")
		}
		if tenant := TenantIDFromContext(r.Context()); tenant != "tenant-1" {
			t.Fatalf("expected tenant ID to be propagated")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestRequestContextUsesProvidedRequestID(t *testing.T) {
	const expected = "req-custom"
	handler := RequestContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestIDFromContext(r.Context()); id != expected {
			t.Fatalf("expected %s, got %s", expected, id)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", expected)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}
