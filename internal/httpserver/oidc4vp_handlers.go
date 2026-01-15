package httpserver

import (
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/logging"
	"github.com/bradtumy/credential-service/internal/oidc4vp"
	"github.com/bradtumy/credential-service/internal/version"
)

// OIDC4VPConfig bundles dependencies for OIDC4VP response handling.
type OIDC4VPConfig struct {
	RequestStore     oidc4vp.RequestStore
	IssuerResolver   func(string) (crypto.PublicKey, error)
	HolderResolver   func(string) (crypto.PublicKey, error)
	TrustRegistry    domain.TrustRegistry
	DefaultTenantID  string
	MaxRequestSize   int64
	Now              func() time.Time
	RevocationStrict bool
}

// OIDC4VPResponse captures the verifier response payload.
type OIDC4VPResponse struct {
	Verified        bool   `json:"verified"`
	HolderDID       string `json:"holder_did,omitempty"`
	CredentialCount int    `json:"credential_count,omitempty"`
	APIVersion      string `json:"api_version"`
}

// RegisterOIDC4VPRoutes registers the OIDC4VP response endpoint.
func RegisterOIDC4VPRoutes(mux *http.ServeMux, cfg OIDC4VPConfig) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxRequestSize == 0 {
		cfg.MaxRequestSize = 256 * 1024
	}

	mux.HandleFunc("/v1/oidc4vp/response", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxRequestSize)
		if err := r.ParseForm(); err != nil {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "invalid form payload")
			return
		}

		state := r.PostFormValue("state")
		vpToken := r.PostFormValue("vp_token")
		if state == "" || vpToken == "" {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "state and vp_token are required")
			return
		}
		if cfg.RequestStore == nil || cfg.IssuerResolver == nil || cfg.HolderResolver == nil {
			WriteAPIError(w, http.StatusInternalServerError, "server_error", "request store not configured")
			return
		}

		req, err := cfg.RequestStore.Get(r.Context(), state)
		if err != nil {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "unknown or expired state")
			return
		}

		tenantID := TenantIDFromContext(r.Context())
		if tenantID == "" {
			tenantID = cfg.DefaultTenantID
		}

		resolveIssuer := func(issuer string) (crypto.PublicKey, error) {
			if cfg.TrustRegistry != nil {
				trusted, err := cfg.TrustRegistry.IsTrustedIssuer(r.Context(), tenantID, issuer)
				if err != nil {
					return nil, err
				}
				if !trusted {
					return nil, domain.ErrUntrustedIssuer
				}
			}
			return cfg.IssuerResolver(issuer)
		}

		result, err := oidc4vp.ValidateResponse(req, vpToken, oidc4vp.ResponseDependencies{
			ResolveIssuerKey: resolveIssuer,
			ResolveHolderKey: cfg.HolderResolver,
			Now:              cfg.Now,
			RevocationStrict: cfg.RevocationStrict,
		})
		if err != nil {
			status, code := mapOIDC4VPError(err)
			WriteAPIError(w, status, code, err.Error())
			logging.LogAuditEvent(r.Context(), logging.AuditEvent{
				EventType: logging.AuditEventOIDC4VPVerified,
				Outcome:   "failure",
				Reason:    code,
				Metadata: map[string]interface{}{
					"state": state,
					"error": err.Error(),
				},
			})
			return
		}

		if err := cfg.RequestStore.MarkUsed(r.Context(), state); err != nil {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "state already used")
			return
		}

		resp := OIDC4VPResponse{
			Verified:        true,
			HolderDID:       result.HolderDID,
			CredentialCount: len(result.Credentials),
			APIVersion:      version.APIVersion,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)

		logging.LogAuditEvent(r.Context(), logging.AuditEvent{
			EventType:  logging.AuditEventOIDC4VPVerified,
			Outcome:    "success",
			SubjectDID: result.HolderDID,
			Metadata: map[string]interface{}{
				"state":            state,
				"credential_count": len(result.Credentials),
			},
		})
	})
}

func mapOIDC4VPError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrUntrustedIssuer):
		return http.StatusForbidden, "access_denied"
	default:
		return http.StatusBadRequest, "invalid_request"
	}
}
