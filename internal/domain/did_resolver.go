package domain

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// DID resolution errors - following Go error handling best practices
var (
	ErrInvalidDIDFormat      = errors.New("invalid DID format")
	ErrUnsupportedDIDMethod  = errors.New("unsupported DID method")
	ErrInvalidJWK           = errors.New("invalid JWK structure")
	ErrUnsupportedKeyType    = errors.New("unsupported key type")
	ErrEmptyDID             = errors.New("empty DID")
)

// DID method constants - avoid magic strings
const (
	DIDMethodJWK = "did:jwk"
	DIDPrefix    = "did:"
)

// JWK constants - cryptographic parameters
const (
	jwkTypeOKP     = "OKP"
	jwkCurveEd25519 = "Ed25519"
)

// Default limits - can be overridden via configuration
const (
	// DefaultMaxDIDLength - maximum DID length for security (prevent DoS)
	DefaultMaxDIDLength = 2048
	// DefaultMaxJWKSize - maximum JWK size for security
	DefaultMaxJWKSize = 1024
)

// ResolverConfig holds configuration options for DID resolvers.
type ResolverConfig struct {
	MaxDIDLength int
	MaxJWKSize   int
	Debug        bool
}

// DefaultResolverConfig returns sensible defaults for production use.
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		MaxDIDLength: DefaultMaxDIDLength,
		MaxJWKSize:   DefaultMaxJWKSize,
		Debug:        false,
	}
}

// DIDResolver resolves Decentralized Identifiers (DIDs) to cryptographic public keys
// for verifying verifiable credentials in a distributed environment.
//
// Implementations must be safe for concurrent use and should validate all inputs
// to prevent security vulnerabilities.
type DIDResolver interface {
	// ResolvePublicKey extracts the verification public key from a DID.
	// The context should be used for cancellation and timeouts.
	//
	// Returns ErrInvalidDIDFormat for malformed DIDs,
	// ErrUnsupportedDIDMethod for unknown methods, or
	// method-specific errors for resolution failures.
	ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error)
	
	// SupportedMethods returns the DID methods this resolver can handle.
	// The returned slice should not be modified by callers.
	SupportedMethods() []string
}

// CompositeResolver combines multiple resolvers for different DID methods.
// It is safe for concurrent use.
type CompositeResolver struct {
	// resolvers maps DID methods to their corresponding resolvers
	resolvers map[string]DIDResolver
	config    ResolverConfig
}

// NewCompositeResolver creates a resolver with default configuration.
func NewCompositeResolver(resolvers ...DIDResolver) (*CompositeResolver, error) {
	return NewCompositeResolverWithConfig(DefaultResolverConfig(), resolvers...)
}

// NewCompositeResolverWithConfig creates a resolver that delegates to method-specific resolvers.
// If multiple resolvers support the same method, the last one wins.
// Returns an error if no resolvers are provided.
func NewCompositeResolverWithConfig(config ResolverConfig, resolvers ...DIDResolver) (*CompositeResolver, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("at least one resolver required")
	}
	
	methodMap := make(map[string]DIDResolver)
	
	for _, resolver := range resolvers {
		if resolver == nil {
			return nil, errors.New("nil resolver provided")
		}
		
		for _, method := range resolver.SupportedMethods() {
			if method == "" {
				return nil, errors.New("empty method name not allowed")
			}
			methodMap[method] = resolver
		}
	}
	
	if len(methodMap) == 0 {
		return nil, errors.New("no valid DID methods found")
	}
	
	return &CompositeResolver{
		resolvers: methodMap,
		config:    config,
	}, nil
}

// ResolvePublicKey resolves a DID using the appropriate method-specific resolver.
func (r *CompositeResolver) ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error) {
	// Input validation for security
	if did == "" {
		return nil, ErrEmptyDID
	}
	
	if len(did) > r.config.MaxDIDLength {
		return nil, fmt.Errorf("%w: DID too long (%d > %d)", ErrInvalidDIDFormat, len(did), r.config.MaxDIDLength)
	}
	
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	method, err := extractDIDMethod(did)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidDIDFormat, err)
	}
	
	resolver, exists := r.resolvers[method]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDIDMethod, method)
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
// It is safe for concurrent use and performs comprehensive input validation.
type JWKResolver struct{
	config ResolverConfig
}

// NewJWKResolver creates a resolver for the did:jwk method with default config.
func NewJWKResolver() *JWKResolver {
	return NewJWKResolverWithConfig(DefaultResolverConfig())
}

// NewJWKResolverWithConfig creates a resolver with custom configuration.
func NewJWKResolverWithConfig(config ResolverConfig) *JWKResolver {
	return &JWKResolver{config: config}
}

// ResolvePublicKey extracts the public key from a did:jwk DID.
// This method is safe for concurrent use and validates all inputs.
func (r *JWKResolver) ResolvePublicKey(ctx context.Context, did string) (crypto.PublicKey, error) {
	// Check for context cancellation early
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	// Validate DID format
	if !strings.HasPrefix(did, DIDMethodJWK+":") {
		return nil, fmt.Errorf("%w: expected did:jwk, got %s", ErrInvalidDIDFormat, extractMethodPrefix(did))
	}
	
	// Extract and validate the encoded JWK part
	encodedJWK := strings.TrimPrefix(did, DIDMethodJWK+":")
	if encodedJWK == "" {
		return nil, fmt.Errorf("%w: missing JWK data", ErrInvalidJWK)
	}
	
	// Security: limit JWK size to prevent DoS
	if len(encodedJWK) > r.config.MaxJWKSize*4/3 { // base64 expansion factor
		return nil, fmt.Errorf("%w: JWK data too large", ErrInvalidJWK)
	}
	
	// Decode the base64-encoded JWK
	jwkBytes, err := base64.RawURLEncoding.DecodeString(encodedJWK)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 encoding: %v", ErrInvalidJWK, err)
	}
	
	// Security: validate decoded size
	if len(jwkBytes) > r.config.MaxJWKSize {
		return nil, fmt.Errorf("%w: JWK too large (%d > %d bytes)", ErrInvalidJWK, len(jwkBytes), r.config.MaxJWKSize)
	}
	
	// Parse and validate JWK JSON
	var jwk jwkKey
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrInvalidJWK, err)
	}
	
	// Convert JWK to crypto.PublicKey with validation
	return jwk.toPublicKey()
}

// SupportedMethods returns the DID methods this resolver supports.
func (r *JWKResolver) SupportedMethods() []string {
	return []string{"did:jwk"}
}

// jwkKey represents a JSON Web Key with proper validation.
type jwkKey struct {
	Kty string `json:"kty"` // Key type (required)
	Crv string `json:"crv"` // Curve (for OKP keys)
	X   string `json:"x"`   // Public key value (required)
}

// toPublicKey converts a JWK to a crypto.PublicKey with comprehensive validation.
func (jwk *jwkKey) toPublicKey() (crypto.PublicKey, error) {
	// Validate required fields
	if jwk.Kty == "" {
		return nil, fmt.Errorf("%w: missing 'kty' field", ErrInvalidJWK)
	}
	if jwk.X == "" {
		return nil, fmt.Errorf("%w: missing 'x' field", ErrInvalidJWK)
	}
	
	switch jwk.Kty {
	case jwkTypeOKP:
		return jwk.parseOKPKey()
	default:
		return nil, fmt.Errorf("%w: unsupported key type '%s'", ErrUnsupportedKeyType, jwk.Kty)
	}
}

// parseOKPKey parses an Octet Key Pair (OKP) JWK.
func (jwk *jwkKey) parseOKPKey() (crypto.PublicKey, error) {
	if jwk.Crv == "" {
		return nil, fmt.Errorf("%w: missing 'crv' field for OKP key", ErrInvalidJWK)
	}
	
	switch jwk.Crv {
	case jwkCurveEd25519:
		return jwk.parseEd25519Key()
	default:
		return nil, fmt.Errorf("%w: unsupported OKP curve '%s'", ErrUnsupportedKeyType, jwk.Crv)
	}
}

// parseEd25519Key parses an Ed25519 public key from JWK.
func (jwk *jwkKey) parseEd25519Key() (crypto.PublicKey, error) {
	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 in 'x' parameter: %v", ErrInvalidJWK, err)
	}
	
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 key size: got %d, want %d", ErrInvalidJWK, len(keyBytes), ed25519.PublicKeySize)
	}
	
	// Additional validation: ensure key is valid
	pubKey := ed25519.PublicKey(keyBytes)
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key validation failed", ErrInvalidJWK)
	}
	
	return pubKey, nil
}

// extractDIDMethod extracts the method from a DID string with proper validation.
func extractDIDMethod(did string) (string, error) {
	if did == "" {
		return "", errors.New("empty DID")
	}
	
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("DID must have at least 3 parts separated by ':'") 
	}
	
	if parts[0] != "did" {
		return "", fmt.Errorf("DID must start with 'did:'") 
	}
	
	if parts[1] == "" {
		return "", fmt.Errorf("DID method cannot be empty")
	}
	
	return DIDPrefix + parts[1], nil
}

// extractMethodPrefix extracts just the "did:method" part for error messages.
func extractMethodPrefix(did string) string {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) >= 2 {
		return DIDPrefix + parts[1]
	}
	return "invalid"
}