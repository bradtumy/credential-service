package keystore

import (
	"crypto/ed25519"
	"os"
	"testing"
)

func TestProductionKeyStore_BackendDetection(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected KeyBackend
	}{
		{
			name: "vault detection",
			env: map[string]string{
				"ENABLE_VAULT": "true",
				"VAULT_ADDR":   "http://localhost:8200",
				"VAULT_TOKEN":  "test-token",
			},
			expected: BackendVault,
		},
		{
			name: "gcp kms detection",
			env: map[string]string{
				"ENABLE_KMS": "true",
			},
			expected: BackendGoogleKMS,
		},
		{
			name:     "fallback to memory",
			env:      map[string]string{},
			expected: BackendMemory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			clearKMSEnv()

			// Set test environment
			for k, v := range tt.env {
				os.Setenv(k, v)
			}
			defer func() {
				for k := range tt.env {
					os.Unsetenv(k)
				}
			}()

			detected := detectBackend()
			if detected != tt.expected {
				t.Errorf("Expected backend %s, got %s", tt.expected, detected)
			}
		})
	}
}

func TestProductionKeyStore_Configuration(t *testing.T) {
	tests := []struct {
		name        string
		config      ProductionConfig
		expectError bool
	}{
		{
			name: "memory backend always works",
			config: ProductionConfig{
				Backend:      BackendMemory,
				TenantPrefix: "test-",
			},
			expectError: false,
		},
		{
			name: "auto detection with no KMS falls back",
			config: ProductionConfig{
				Backend: BackendAuto,
			},
			expectError: false,
		},
		{
			name: "vault backend without config falls back",
			config: ProductionConfig{
				Backend: BackendVault,
			},
			expectError: false, // Falls back to memory with warning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearKMSEnv()

			store, err := NewProductionKeyStore(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && store == nil {
				t.Error("Expected non-nil store")
			}
		})
	}
}

func TestProductionKeyStore_MemoryFallback(t *testing.T) {
	clearKMSEnv()

	store, err := NewProductionKeyStore(ProductionConfig{
		Backend:      BackendMemory,
		TenantPrefix: "test-",
	})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Test key generation
	signer1, err := store.GetSigningKey("tenant1")
	if err != nil {
		t.Fatalf("Failed to get signing key: %v", err)
	}

	// Test key consistency
	signer2, err := store.GetSigningKey("tenant1")
	if err != nil {
		t.Fatalf("Failed to get signing key again: %v", err)
	}

	// Compare public key bytes instead of direct comparison
	pub1, ok1 := signer1.Public().(ed25519.PublicKey)
	pub2, ok2 := signer2.Public().(ed25519.PublicKey)
	if !ok1 || !ok2 {
		t.Fatal("Expected Ed25519 public keys")
	}
	if !pub1.Equal(pub2) {
		t.Error("Expected same public key for same tenant")
	}

	// Test tenant isolation
	signer3, err := store.GetSigningKey("tenant2")
	if err != nil {
		t.Fatalf("Failed to get signing key for tenant2: %v", err)
	}

	// Compare public key bytes for different tenants
	pub3, ok3 := signer3.Public().(ed25519.PublicKey)
	if !ok1 || !ok3 {
		t.Fatal("Expected Ed25519 public keys")
	}
	if pub1.Equal(pub3) {
		t.Error("Expected different keys for different tenants")
	}
}

func TestProductionKeyStore_FromEnv(t *testing.T) {
	clearKMSEnv()

	// Test with default environment
	store, err := NewProductionKeyStoreFromEnv()
	if err != nil {
		t.Fatalf("Failed to create store from env: %v", err)
	}

	if store.GetBackend() != string(BackendMemory) {
		t.Errorf("Expected memory backend, got %s", store.GetBackend())
	}

	// Test with explicit backend setting
	os.Setenv("KEY_BACKEND", "memory")
	os.Setenv("KEY_TENANT_PREFIX", "custom-")
	defer func() {
		os.Unsetenv("KEY_BACKEND")
		os.Unsetenv("KEY_TENANT_PREFIX")
	}()

	store2, err := NewProductionKeyStoreFromEnv()
	if err != nil {
		t.Fatalf("Failed to create store from env with explicit backend: %v", err)
	}

	if store2.tenantPrefix != "custom-" {
		t.Errorf("Expected custom- prefix, got %s", store2.tenantPrefix)
	}
}

func TestProductionKeyStore_CacheManagement(t *testing.T) {
	clearKMSEnv()

	store, err := NewProductionKeyStore(ProductionConfig{
		Backend: BackendMemory,
	})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Get a key to populate cache
	_, err = store.GetSigningKey("test-tenant")
	if err != nil {
		t.Fatalf("Failed to get signing key: %v", err)
	}

	// Verify cache has content
	if len(store.cache) == 0 {
		t.Error("Expected non-empty cache")
	}

	// Clear cache
	store.ClearCache()

	// Verify cache is empty
	if len(store.cache) != 0 {
		t.Error("Expected empty cache after clear")
	}
}

func TestProductionKeyStore_EmptyTenantID(t *testing.T) {
	clearKMSEnv()

	store, err := NewProductionKeyStore(ProductionConfig{
		Backend: BackendMemory,
	})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	_, err = store.GetSigningKey("")
	if err == nil {
		t.Error("Expected error for empty tenant ID")
	}
}

// Helper function to clear KMS-related environment variables
func clearKMSEnv() {
	vars := []string{
		"ENABLE_VAULT", "VAULT_ENABLE", "VAULT_ADDR", "VAULT_TOKEN", "VAULT_KEY_NAME",
		"ENABLE_KMS", "KMS_ENABLE", "KMS_KEY_ID", "GCP_PROJECT", "KMS_LOCATION", "KMS_KEYRING",
		"KEY_BACKEND", "KEY_TENANT_PREFIX",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}
}