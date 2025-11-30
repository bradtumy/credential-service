package domain

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DIDResolver resolves DIDs to public keys for credential verification.
type DIDResolver interface {
	// ResolvePublicKey extracts the verification public key from a DID
	ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error)
	
	// SupportedMethods returns the DID methods this resolver can handle
	SupportedMethods() []string
}

// CompositeResolver combines multiple resolvers for different DID methods.
type CompositeResolver struct {
	resolvers map[string]DIDResolver // method -> resolver
}

// NewCompositeResolver creates a resolver that delegates to method-specific resolvers.
func NewCompositeResolver(resolvers ...DIDResolver) *CompositeResolver {
	methodMap := make(map[string]DIDResolver)
	
	for _, resolver := range resolvers {
		for _, method := range resolver.SupportedMethods() {
			methodMap[method] = resolver
		}
	}
	
	return &CompositeResolver{resolvers: methodMap}
}

// ResolvePublicKey resolves a DID using the appropriate method-specific resolver.
func (r *CompositeResolver) ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error) {
	method := extractDIDMethod(did)
	if method == "" {
		return nil, fmt.Errorf("invalid DID format: %s", did)
	}
	
	resolver, exists := r.resolvers[method]
	if !exists {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}
	
	return resolver.ResolvePublicKey(ctx, did)
}

// SupportedMethods returns all methods supported by component resolvers.
func (r *CompositeResolver) SupportedMethods() []string {
	methods := make([]string, 0, len(r.resolvers))
	for method := range r.resolvers {
		methods = append(methods, method)
	}
	return methods
}

// JWKResolver resolves did:jwk DIDs by extracting embedded public keys.
type JWKResolver struct{}

// NewJWKResolver creates a resolver for did:jwk method.
func NewJWKResolver() *JWKResolver {
	return &JWKResolver{}
}

// ResolvePublicKey extracts the public key from a did:jwk DID.
func (r *JWKResolver) ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error) {
	if !strings.HasPrefix(did, "did:jwk:") {
		return nil, fmt.Errorf("not a did:jwk DID: %s", did)
	}
	
	// Extract the encoded JWK part: did:jwk:{base64-encoded-jwk}
	encodedJWK := strings.TrimPrefix(did, "did:jwk:")
	if encodedJWK == "" {
		return nil, fmt.Errorf("empty JWK in DID: %s", did)
	}
	
	// Decode the base64-encoded JWK
	jwkBytes, err := base64.RawURLEncoding.DecodeString(encodedJWK)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding in did:jwk: %w", err)
	}
	
	// Parse the JWK JSON
	var jwk struct {
		Kty string `json:"kty"` // Key type
		Crv string `json:"crv"` // Curve (for OKP keys)
		X   string `json:"x"`   // Public key value
	}
	
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("invalid JWK JSON in did:jwk: %w", err)
	}
	
	// Convert JWK to crypto.PublicKey
	return jwkToPublicKey(jwk)
}

// SupportedMethods returns the DID methods this resolver supports.
func (r *JWKResolver) SupportedMethods() []string {
	return []string{"did:jwk"}
}

// jwkToPublicKey converts a JWK structure to a crypto.PublicKey.
func jwkToPublicKey(jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
		}
		
		keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in JWK x parameter: %w", err)
		}
		
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
		}
		
		return ed25519.PublicKey(keyBytes), nil
		
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", jwk.Kty)
	}
}

// extractDIDMethod extracts the method from a DID string.
func extractDIDMethod(did string) string {
	parts := strings.Split(did, ":")
	if len(parts) < 3 || parts[0] != "did" {
		return ""
	}
	return "did:" + parts[1]
}