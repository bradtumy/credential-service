package main

import (
	"log"
	"net/http"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/httpx"
	"github.com/bradtumy/credential-service/internal/keystore"
	"github.com/bradtumy/credential-service/internal/logging"
)

func main() {
	cfg := config.LoadIssuerConfigFromEnv()
	logging.Init(cfg.LogLevel)
	store := keystore.NewMemoryKeyStore()

	mux := http.NewServeMux()
	httpx.RegisterIssuerRoutes(mux, store, cfg)

	handler := httpx.RequestContext(httpx.LoggingMiddleware(mux))

	log.Printf("Issuer service running on port %s", cfg.HTTPPort)
	if err := http.ListenAndServe(":"+cfg.HTTPPort, handler); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
