package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/keystore"
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
}

// RegisterIssuerRoutes wires issuer HTTP routes into the provided mux.
func RegisterIssuerRoutes(mux *http.ServeMux, store keystore.KeyStore, cfg config.IssuerConfig) {
	mux.HandleFunc("/v1/credentials/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
			return
		}

		if req.SubjectDID == "" {
			WriteError(w, http.StatusBadRequest, "invalid_request", "subject_did is required")
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be positive")
			return
		}

		signer, err := store.GetSigningKey(cfg.DefaultTenantID)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "keystore_error", err.Error())
			return
		}

		issuerDID, err := domain.DIDFromPublicKey(signer.Public())
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "did_error", err.Error())
			return
		}

		token, err := domain.IssueBasicCredential(issuerDID, req.SubjectDID, signer, ttl, req.Claims)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "issuance_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IssueResponse{Credential: token})
	})
}
