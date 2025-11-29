package main

import (
	"context"
	"log"
	"net/http"

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
	store := keystore.NewMemoryKeyStore()

	tenantStore := tenant.NewMemoryStore()
	_ = tenantStore.UpsertTenant(context.Background(), domain.Tenant{ID: cfg.DefaultTenantID, Name: "default", Enabled: true})

	resolver := tenant.Resolver{Mode: tenant.Mode(cfg.TenancyMode), DefaultTenantID: cfg.DefaultTenantID, Store: tenantStore}

	mux := http.NewServeMux()
	httpx.RegisterIssuerRoutes(mux, store, cfg)
	httpx.RegisterHealthRoutes(mux, nil)

	handler := httpx.RequestContext(httpx.TenantMiddleware(resolver, httpx.LoggingMiddleware(mux)))

	log.Printf("Issuer service running on port %s", cfg.HTTPPort)
	if err := http.ListenAndServe(":"+cfg.HTTPPort, handler); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
