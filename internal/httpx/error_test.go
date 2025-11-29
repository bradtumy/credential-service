package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteError(rr, http.StatusBadRequest, "bad_request", "invalid payload")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Code != "bad_request" || resp.Message != "invalid payload" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
