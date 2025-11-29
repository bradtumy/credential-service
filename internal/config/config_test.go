package config

import "testing"

func TestLoadIssuerConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("ISSUER_HTTP_PORT", "")
	t.Setenv("DEFAULT_TENANT_ID", "")

	cfg := LoadIssuerConfigFromEnv()

	if cfg.HTTPPort != "8080" {
		t.Fatalf("expected default port 8080, got %s", cfg.HTTPPort)
	}
	if cfg.DefaultTenantID != "default-tenant" {
		t.Fatalf("expected default tenant id, got %s", cfg.DefaultTenantID)
	}
}

func TestLoadIssuerConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("ISSUER_HTTP_PORT", "9090")
	t.Setenv("DEFAULT_TENANT_ID", "tenant-123")

	cfg := LoadIssuerConfigFromEnv()

	if cfg.HTTPPort != "9090" {
		t.Fatalf("expected port 9090, got %s", cfg.HTTPPort)
	}
	if cfg.DefaultTenantID != "tenant-123" {
		t.Fatalf("expected tenant-123, got %s", cfg.DefaultTenantID)
	}
}
