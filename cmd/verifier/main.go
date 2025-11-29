package main

import (
	"context"
	"crypto"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"

	"github.com/bradtumy/credential-service/internal/cache"
	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/httpx"
	"github.com/bradtumy/credential-service/internal/keystore"
	"github.com/bradtumy/credential-service/internal/logging"
	"github.com/bradtumy/credential-service/internal/policy"
	"github.com/bradtumy/credential-service/internal/ratelimit"
	"github.com/bradtumy/credential-service/internal/storage"
	"github.com/bradtumy/credential-service/internal/tenant"
)

func main() {
	cfg := config.LoadVerifierConfigFromEnv()
	logging.Init(cfg.LogLevel)

	var (
		trustRegistry domain.TrustRegistry = domain.NewMemoryTrustRegistry()
		db            *sql.DB
	)

	tenancyMode := tenant.Mode(cfg.TenancyMode)
	var tenantStore tenant.Store = tenant.NewMemoryStore()

	if cfg.UseDBTrustRegistry && cfg.DB_DSN != "" {
		var err error
		db, err = sql.Open("postgres", cfg.DB_DSN)
		if err != nil {
			log.Fatalf("connect to database: %v", err)
		}
		trustRegistry = storage.NewPGTrustRegistry(db)
		tenantStore = tenant.NewPGTenantStore(db)
	}

	if err := tenantStore.UpsertTenant(context.Background(), domain.Tenant{ID: cfg.DefaultTenantID, Name: "default", Enabled: true}); err != nil {
		log.Fatalf("seed default tenant: %v", err)
	}

	tenantResolver := tenant.Resolver{Mode: tenancyMode, DefaultTenantID: cfg.DefaultTenantID, Store: tenantStore}

	issuerKeys := make(map[string]crypto.PublicKey)

	store := keystore.NewMemoryKeyStore()
	signer, err := store.GetSigningKey(cfg.DefaultTenantID)
	if err != nil {
		log.Fatalf("get signing key: %v", err)
	}

	issuerDID, err := domain.DIDFromPublicKey(signer.Public())
	if err != nil {
		log.Fatalf("derive issuer did: %v", err)
	}

	issuerKeys[issuerDID] = signer.Public()
	if err := trustRegistry.AddTrustedIssuer(context.Background(), cfg.DefaultTenantID, issuerDID); err != nil {
		log.Fatalf("seed trust registry: %v", err)
	}

	resolver := func(issuer string) (crypto.PublicKey, error) {
		key, ok := issuerKeys[issuer]
		if !ok {
			return nil, fmt.Errorf("unknown issuer: %s", issuer)
		}
		return key, nil
	}

	readiness := func(ctx context.Context) error {
		if cfg.UseDBTrustRegistry && db != nil {
			return db.PingContext(ctx)
		}
		return nil
	}

	mux := http.NewServeMux()
	httpx.RegisterVerifierRoutes(mux, resolver, trustRegistry, cfg.DefaultTenantID, time.Now)
	var decisionCache cache.DecisionCache = cache.NoopDecisionCache{}
	if cfg.GatewayCache && cfg.RedisAddr != "" {
		redisCache, err := cache.NewRedisDecisionCacheFromEnv()
		if err != nil {
			log.Printf("gateway cache disabled: %v", err)
		} else {
			decisionCache = redisCache
		}
	}

	var limiter ratelimit.Limiter = ratelimit.NoopLimiter{}
	if cfg.RateLimitEnabled {
		log.Printf("rate limiting enabled but using noop limiter; configure backend to enforce limits")
	}

	httpx.RegisterGatewayRoutes(mux, resolver, trustRegistry, policy.NoOpEngine{}, cfg.DefaultTenantID, signer, issuerDID, decisionCache, limiter, nil, time.Now)
	httpx.RegisterHealthRoutes(mux, readiness)

	handler := httpx.RequestContext(httpx.TenantMiddleware(tenantResolver, httpx.LoggingMiddleware(mux)))

	log.Printf("Verifier service running on port %s...", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, handler))
}
