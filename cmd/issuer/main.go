package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/httpx"
	"github.com/bradtumy/credential-service/internal/keystore"
	"github.com/bradtumy/credential-service/internal/logging"
	"github.com/bradtumy/credential-service/internal/tenant"
)

func main() {
	cfg := config.LoadIssuerConfigFromEnv()
	logging.Init(cfg.LogLevel)
	
	// Use production keystore with automatic backend detection
	var store keystore.KeyStore
	if os.Getenv("USE_PRODUCTION_KEYSTORE") == "true" {
		productionStore, err := keystore.NewProductionKeyStoreFromEnv()
		if err != nil {
			log.Fatalf("Failed to initialize production keystore: %v", err)
		}
		store = productionStore
		log.Printf("Using production keystore with backend: %s", productionStore.GetBackend())
	} else {
		store = keystore.NewMemoryKeyStore()
		log.Printf("Using memory keystore (development mode)")
	}

	tenantStore := tenant.NewMemoryStore()
	_ = tenantStore.UpsertTenant(context.Background(), domain.Tenant{ID: cfg.DefaultTenantID, Name: "default", Enabled: true})

	resolver := tenant.Resolver{Mode: tenant.Mode(cfg.TenancyMode), DefaultTenantID: cfg.DefaultTenantID, Store: tenantStore}

	mux := http.NewServeMux()
	httpx.RegisterIssuerRoutes(mux, store, cfg)
	httpx.RegisterBootstrapRoutes(mux, store, cfg, nil)  // Add bootstrap endpoint
	httpx.RegisterHealthRoutes(mux, nil)

	handler := httpx.RequestContext(httpx.TenantMiddleware(resolver, httpx.LoggingMiddleware(mux)))

	log.Printf("Issuer service running on port %s", cfg.HTTPPort)
	if err := http.ListenAndServe(":"+cfg.HTTPPort, handler); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
