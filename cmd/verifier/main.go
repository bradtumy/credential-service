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
		policyStore   policy.Store = policy.NewMemoryStore()
	)

	tenancyMode := tenant.Mode(cfg.TenancyMode)
	var tenantStore tenant.Store = tenant.NewMemoryStore()

	if cfg.DB_DSN != "" {
		var err error
		db, err = sql.Open("postgres", cfg.DB_DSN)
		if err != nil {
			log.Fatalf("connect to database: %v", err)
		}
		if cfg.UseDBTrustRegistry {
			trustRegistry = storage.NewPGTrustRegistry(db)
		}
		tenantStore = tenant.NewPGTenantStore(db)
		policyStore = policy.NewPGStore(db)
	}

	if err := tenantStore.UpsertTenant(context.Background(), domain.Tenant{ID: cfg.DefaultTenantID, Name: "default", Enabled: true}); err != nil {
		log.Fatalf("seed default tenant: %v", err)
	}

	// Seed a default policy to allow the demo to work
	defaultPolicy := &policy.Policy{
		TenantID:    cfg.DefaultTenantID,
		Name:        "demo-read-orders",
		Description: "Allow reading orders for demo",
		Effect:      policy.EffectAllow,
		Actions:     []string{"read"},
		Resources:   []string{"orders"},
		Subjects:    []string{"any"}, // Allow any subject
		Priority:    100,
		Enabled:     true,
	}
	if err := policyStore.CreatePolicy(context.Background(), defaultPolicy); err != nil {
		log.Printf("warning: failed to seed default policy (may already exist): %v", err)
	} else {
		log.Printf("successfully created default policy: %s", defaultPolicy.Name)
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
		if db != nil {
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

	policyEngine := policy.NewEngine(policyStore)
	httpx.RegisterGatewayRoutes(mux, resolver, trustRegistry, policyEngine, cfg.DefaultTenantID, signer, issuerDID, decisionCache, limiter, nil, time.Now)
	httpx.RegisterPolicyAdminRoutes(mux, policyStore, cfg.DefaultTenantID)
	httpx.RegisterHealthRoutes(mux, readiness)

	handler := httpx.RequestContext(httpx.TenantMiddleware(tenantResolver, httpx.LoggingMiddleware(mux)))

	log.Printf("Verifier service running on port %s...", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, handler))
}
