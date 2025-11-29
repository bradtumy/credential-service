package httpx

import (
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/keystore"
	"github.com/bradtumy/credential-service/internal/version"
)

// IssueRequest represents the request payload for issuing credentials.
type IssueRequest struct {
	SubjectDID string                 `json:"subject_did"`
	TTLSeconds int64                  `json:"ttl_seconds"`
	Claims     map[string]interface{} `json:"claims"`
}

// IssueResponse represents the response payload after issuance.
type IssueResponse struct {
	Credential string `json:"credential"`
	APIVersion string `json:"api_version"`
}

// DelegateRequest represents the payload for issuing delegated credentials.
type DelegateRequest struct {
	ParentCredential string   `json:"parent_credential"`
	DelegateDID      string   `json:"delegate_did"`
	Scope            []string `json:"scope"`
	TTLSeconds       int64    `json:"ttl_seconds"`
}

// RegisterIssuerRoutes wires issuer HTTP routes into the provided mux.
func RegisterIssuerRoutes(mux *http.ServeMux, store keystore.KeyStore, cfg config.IssuerConfig) {
	mux.HandleFunc("/v1/credentials/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteAPIError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
			return
		}

		if req.SubjectDID == "" {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "subject_did is required")
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be positive")
			return
		}

                tenantID := TenantIDFromContext(r.Context())
                if tenantID == "" {
                        tenantID = cfg.DefaultTenantID
                }

                signer, err := store.GetSigningKey(tenantID)
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "keystore_error", err.Error())
			return
		}

		issuerDID, err := domain.DIDFromPublicKey(signer.Public())
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "did_error", err.Error())
			return
		}

		token, err := domain.IssueBasicCredential(issuerDID, req.SubjectDID, signer, ttl, req.Claims)
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "issuance_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssueResponse{Credential: token, APIVersion: version.APIVersion})
	})

	mux.HandleFunc("/v1/credentials/delegate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		var req DelegateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteAPIError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
			return
		}

		if req.ParentCredential == "" || req.DelegateDID == "" {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "parent_credential and delegate_did are required")
			return
		}
		if len(req.Scope) == 0 {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "scope is required")
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be positive")
			return
		}

                tenantID := TenantIDFromContext(r.Context())
                if tenantID == "" {
                        tenantID = cfg.DefaultTenantID
                }

                signer, err := store.GetSigningKey(tenantID)
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "keystore_error", err.Error())
			return
		}

		issuerDID, err := domain.DIDFromPublicKey(signer.Public())
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "did_error", err.Error())
			return
		}

		deps := domain.VerifierDependencies{ResolveIssuerPublicKey: func(issuer string) (crypto.PublicKey, error) {
			if issuer != issuerDID {
				return nil, domain.ErrUntrustedIssuer
			}
			return signer.Public(), nil
		}}

		now := time.Now()
		parentResult, err := domain.VerifyCredentialChain([]string{req.ParentCredential}, deps, domain.VerificationOptions{MaxDelegationDepth: 1}, now)
		if err != nil {
			status := http.StatusBadRequest
			switch {
			case errors.Is(err, domain.ErrUntrustedIssuer):
				status = http.StatusForbidden
			case errors.Is(err, domain.ErrExpiredCredential), errors.Is(err, domain.ErrInvalidSignature):
				status = http.StatusUnauthorized
			}
			WriteAPIError(w, status, "invalid_parent", err.Error())
			return
		}

		parentCred := parentResult.Credentials[0]
		parentScope := domain.ScopeFromClaims(parentCred.Claims)
		if !domain.IsScopeSubset(parentScope, req.Scope) {
			WriteAPIError(w, http.StatusBadRequest, "invalid_scope", "delegated scope must be within parent scope")
			return
		}

		expiresAt := now.Add(ttl)
		if !domain.IsTTLWithinParent(parentCred.ExpiresAt, expiresAt) {
			WriteAPIError(w, http.StatusBadRequest, "invalid_ttl", "delegated credential must expire before parent")
			return
		}

		claims := map[string]interface{}{
			"scope":     req.Scope,
			"parent_id": parentCred.ID,
		}
		if aud, ok := parentCred.Claims["aud"]; ok {
			claims["aud"] = aud
		}

		token, err := domain.IssueBasicCredential(issuerDID, req.DelegateDID, signer, ttl, claims)
		if err != nil {
			WriteAPIError(w, http.StatusInternalServerError, "issuance_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssueResponse{Credential: token, APIVersion: version.APIVersion})
	})
}
