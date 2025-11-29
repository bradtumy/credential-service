package verifier

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/bradtumy/credential-service/internal/httpx"
)

// Router builds the verifier HTTP router with middleware.
func Router() http.Handler {
	r := mux.NewRouter()
	r.Use(httpx.RequestContext)

	v1 := r.PathPrefix("/v1").Subrouter()
	v1.Handle("/verifier/verify", http.HandlerFunc(VerifyCredentialHandler)).Methods(http.MethodPost)
	v1.Handle("/verifier/health", http.HandlerFunc(HealthCheckHandler)).Methods(http.MethodGet)

	return r
}
