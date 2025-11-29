package httpx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bradtumy/credential-service/internal/logging"
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

func TestLoggingMiddlewareInvokesNext(t *testing.T) {
	called := false
	logging.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))

	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/log", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey, "req-1"))
	req = req.WithContext(context.WithValue(req.Context(), tenantIDKey, "tenant-1"))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected status to propagate, got %d", rr.Code)
	}
}
