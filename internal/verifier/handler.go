package verifier

import (
	"encoding/json"
	"net/http"

	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/httpx"
)

// VerifyCredentialHandler verifies an incoming credential presentation.
func VerifyCredentialHandler(w http.ResponseWriter, r *http.Request) {
	var presentation domain.VerifiableCredential

	if err := json.NewDecoder(r.Body).Decode(&presentation); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
		return
	}

	isValid, err := domain.VerifyCredential(presentation)
	if err != nil || !isValid {
		httpx.WriteError(w, http.StatusBadRequest, "verification_failed", "credential verification failed")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Credential verified successfully"))
}

// HealthCheckHandler returns a simple health indicator.
func HealthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Verifier service is running"))
}
