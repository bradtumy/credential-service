package main

import (
	"log"
	"net/http"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/httpx"
	"github.com/bradtumy/credential-service/internal/keystore"
)

func main() {
	cfg := config.LoadIssuerConfigFromEnv()
	store := keystore.NewMemoryKeyStore()

	mux := http.NewServeMux()
	httpx.RegisterIssuerRoutes(mux, store, cfg)

	log.Printf("Issuer service running on port %s", cfg.HTTPPort)
	if err := http.ListenAndServe(":"+cfg.HTTPPort, mux); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
