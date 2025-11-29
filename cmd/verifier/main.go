package main

import (
	"crypto"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/httpx"
	"github.com/bradtumy/credential-service/internal/keystore"
)

func main() {
	cfg := config.LoadVerifierConfigFromEnv()

	trustRegistry := domain.NewMemoryTrustRegistry()
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
	trustRegistry.AddTrustedIssuer(cfg.DefaultTenantID, issuerDID)

	resolver := func(issuer string) (crypto.PublicKey, error) {
		key, ok := issuerKeys[issuer]
		if !ok {
			return nil, fmt.Errorf("unknown issuer: %s", issuer)
		}
		return key, nil
	}

	mux := http.NewServeMux()
	httpx.RegisterVerifierRoutes(mux, resolver, trustRegistry, cfg.DefaultTenantID, time.Now)

	log.Printf("Verifier service running on port %s...", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}
