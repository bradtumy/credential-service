package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/bradtumy/credential-service/internal/version"
)

// APIError provides a consistent error body for HTTP handlers.
type APIError struct {
	Error       string `json:"error"`
	Description string `json:"description,omitempty"`
	Code        string `json:"code,omitempty"`
	APIVersion  string `json:"api_version"`
}

// WriteAPIError writes a standardized API error response.
func WriteAPIError(w http.ResponseWriter, status int, code string, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIError{
		Error:       code,
		Description: description,
		Code:        code,
		APIVersion:  version.APIVersion,
	})
}
