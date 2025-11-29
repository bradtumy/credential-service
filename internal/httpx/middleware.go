package httpx

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/bradtumy/credential-service/internal/logging"
)

type contextKey string

const (
	requestIDKey contextKey = "requestID"
	tenantIDKey  contextKey = "tenantID"
)

// RequestContext attaches a request ID and tenant ID to the request context.
func RequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.NewString()
		}

		tenantID := r.Header.Get("X-Tenant-ID")

		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		ctx = context.WithValue(ctx, tenantIDKey, tenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if v := ctx.Value(requestIDKey); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// TenantIDFromContext extracts the tenant ID from context.
func TenantIDFromContext(ctx context.Context) string {
	if v := ctx.Value(tenantIDKey); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// LoggingMiddleware emits structured request logs for HTTP handlers.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)
		logging.Logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", duration.Milliseconds(),
			"request_id", RequestIDFromContext(r.Context()),
			"tenant_id", TenantIDFromContext(r.Context()),
		)
	})
}
