package domain

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestJWKResolver_ResolvePublicKey(t *testing.T) {
	resolver := NewJWKResolver()
	
	// Generate a test key pair
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	// Create a did:jwk DID from the public key
	expectedDID, err := DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create DID from public key: %v", err)
	}
	
	// Resolve the public key back from the DID
	resolvedKey, err := resolver.ResolvePublicKey(context.Background(), expectedDID)
	if err != nil {
		t.Fatalf("failed to resolve public key: %v", err)
	}
	
	// Verify the resolved key matches the original
	resolvedEd25519, ok := resolvedKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("resolved key is not Ed25519: %T", resolvedKey)
	}
	
	if !resolvedEd25519.Equal(pub) {
		t.Fatalf("resolved key does not match original")
	}
}

func TestJWKResolver_InvalidDID(t *testing.T) {
	resolver := NewJWKResolver()
	
	testCases := []struct {
		name string
		did  string
	}{
		{"not a DID", "not-a-did"},
		{"wrong method", "did:web:example.com"},
		{"empty JWK", "did:jwk:"},
		{"invalid base64", "did:jwk:invalid-base64!"},
		{"invalid JSON", "did:jwk:aW52YWxpZC1qc29u"}, // "invalid-json" in base64
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolver.ResolvePublicKey(context.Background(), tc.did)
			if err == nil {
				t.Fatalf("expected error for invalid DID: %s", tc.did)
			}
		})
	}
}

func TestJWKResolver_SupportedMethods(t *testing.T) {
	resolver := NewJWKResolver()
	methods := resolver.SupportedMethods()
	
	if len(methods) != 1 || methods[0] != "did:jwk" {
		t.Fatalf("expected [did:jwk], got %v", methods)
	}
}

func TestCompositeResolver(t *testing.T) {
	jwkResolver := NewJWKResolver()
	composite := NewCompositeResolver(jwkResolver)
	
	// Test that composite resolver delegates to JWK resolver
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	did, err := DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}
	
	resolvedKey, err := composite.ResolvePublicKey(context.Background(), did)
	if err != nil {
		t.Fatalf("composite resolver failed: %v", err)
	}
	
	resolvedEd25519, ok := resolvedKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("resolved key is not Ed25519: %T", resolvedKey)
	}
	
	if !resolvedEd25519.Equal(pub) {
		t.Fatalf("composite resolver returned wrong key")
	}
}

func TestCompositeResolver_UnsupportedMethod(t *testing.T) {
	jwkResolver := NewJWKResolver()
	composite := NewCompositeResolver(jwkResolver)
	
	_, err := composite.ResolvePublicKey(context.Background(), "did:web:example.com")
	if err == nil {
		t.Fatalf("expected error for unsupported method")
	}
	
	if err.Error() != "unsupported DID method: did:web" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestExtractDIDMethod(t *testing.T) {
	testCases := []struct {
		did      string
		expected string
	}{
		{"did:jwk:eyJrdHkiOi...", "did:jwk"},
		{"did:web:example.com", "did:web"},
		{"did:key:z6Mk...", "did:key"},
		{"not-a-did", ""},
		{"did", ""},
		{"did:onlymethod", ""},
	}
	
	for _, tc := range testCases {
		t.Run(tc.did, func(t *testing.T) {
			result := extractDIDMethod(tc.did)
			if result != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}