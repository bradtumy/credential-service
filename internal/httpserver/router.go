package httpserver

import (
	"context"
	"net/http"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/keystore"
	"github.com/bradtumy/credential-service/internal/metrics"
	"github.com/bradtumy/credential-service/internal/policy"
	"github.com/bradtumy/credential-service/internal/storage"
)

// RouterConfig aggregates optional dependencies for wiring HTTP routes.
type RouterConfig struct {
	KeyStore        keystore.KeyStore
	IssuerConfig    config.IssuerConfig
	TrustRegistry   domain.TrustRegistry
	PolicyStore     policy.Store
	AuditStore      storage.AuditStore
	GatewayCfg      *GatewayConfig
	DefaultTenantID string
	ReadinessCheck  func(context.Context) error
}

// NewRouter builds an http.ServeMux and conditionally registers routes
// based on which dependencies are provided in the config.
func NewRouter(cfg RouterConfig) *http.ServeMux {
	mux := http.NewServeMux()

	// health endpoints are always registered
	RegisterHealthRoutes(mux, cfg.ReadinessCheck)

	// admin/demo endpoints
	RegisterAdminRevocationRoutes(mux)

	// gateway routes
	if cfg.GatewayCfg != nil {
		RegisterGatewayRoutes(mux, cfg.GatewayCfg)
	}

	// bootstrap and issuer routes require keystore and issuer config
	if cfg.KeyStore != nil && cfg.IssuerConfig != (config.IssuerConfig{}) && cfg.TrustRegistry != nil {
		RegisterBootstrapRoutes(mux, cfg.KeyStore, cfg.IssuerConfig, cfg.TrustRegistry)
	}
	if cfg.KeyStore != nil && cfg.IssuerConfig != (config.IssuerConfig{}) && cfg.AuditStore != nil {
		RegisterIssuerRoutes(mux, cfg.KeyStore, cfg.IssuerConfig, cfg.AuditStore)
	}

	// policy admin
	if cfg.PolicyStore != nil {
		RegisterPolicyAdminRoutes(mux, cfg.PolicyStore, cfg.DefaultTenantID)
	}

	// trust registry admin
	if cfg.TrustRegistry != nil {
		RegisterTrustRegistryRoutes(mux, cfg.TrustRegistry, cfg.DefaultTenantID)
	}

	// verifier routes (optional)
	// Note: VerifierRoutes signature differs across implementations; only register when a resolver is present.
	return mux
}
