package domain

import "testing"

func TestMemoryTrustRegistry(t *testing.T) {
	registry := NewMemoryTrustRegistry()

	tenantA := "tenant-a"
	tenantB := "tenant-b"
	issuer := "did:jwk:issuer"

	registry.AddTrustedIssuer(tenantA, issuer)

	if !registry.IsTrustedIssuer(tenantA, issuer) {
		t.Fatalf("expected issuer to be trusted for tenantA")
	}

	if registry.IsTrustedIssuer(tenantB, issuer) {
		t.Fatalf("issuer should not be trusted for tenantB")
	}

	if registry.IsTrustedIssuer(tenantA, "did:jwk:unknown") {
		t.Fatalf("unexpected trust for unknown issuer")
	}
}
