package httpx

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
)

// VerifyRequest represents a verifier request payload.
type VerifyRequest struct {
	Credential       string `json:"credential"`
	ExpectedAudience string `json:"expected_audience"`
}

// VerifyResponse represents the verifier response payload.
type VerifyResponse struct {
	Valid     bool      `json:"valid"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterVerifierRoutes wires verifier HTTP routes into the provided mux.
func RegisterVerifierRoutes(mux *http.ServeMux, resolver func(string) (crypto.PublicKey, error), registry domain.TrustRegistry, tenantID string, now func() time.Time) {
	if now == nil {
		now = time.Now
	}

	mux.HandleFunc("/v1/credentials/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
			return
		}

		if req.Credential == "" {
			WriteError(w, http.StatusBadRequest, "invalid_request", "credential is required")
			return
		}

		deps := domain.VerifierDependencies{ResolveIssuerPublicKey: func(issuer string) (crypto.PublicKey, error) {
			if registry != nil && !registry.IsTrustedIssuer(tenantID, issuer) {
				return nil, domain.ErrUntrustedIssuer
			}
			if resolver == nil {
				return nil, fmt.Errorf("resolver not configured")
			}
			return resolver(issuer)
		}}

		result, err := domain.VerifyCredential(req.Credential, deps, req.ExpectedAudience, now())
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrUntrustedIssuer):
				WriteError(w, http.StatusForbidden, "untrusted_issuer", err.Error())
			case errors.Is(err, domain.ErrExpiredCredential), errors.Is(err, domain.ErrInvalidSignature), errors.Is(err, domain.ErrUnexpectedAudience), errors.Is(err, domain.ErrIssuedInFuture):
				WriteError(w, http.StatusUnauthorized, "invalid_credential", err.Error())
			default:
				WriteError(w, http.StatusBadRequest, "verification_failed", err.Error())
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Valid:     true,
			Subject:   result.Credential.Subject,
			Issuer:    result.Credential.Issuer,
			ExpiresAt: result.Credential.ExpiresAt,
		})
	})
}
