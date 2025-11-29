package domain

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verification errors.
var (
	ErrInvalidToken       = errors.New("invalid credential token")
	ErrInvalidSignature   = errors.New("invalid credential signature")
	ErrExpiredCredential  = errors.New("credential has expired")
	ErrIssuedInFuture     = errors.New("credential is issued in the future")
	ErrUntrustedIssuer    = errors.New("issuer is not trusted")
	ErrUnexpectedAudience = errors.New("unexpected audience")
	ErrInvalidDelegation  = errors.New("invalid delegation chain")
	ErrDelegationScope    = errors.New("delegated scope must be subset of parent")
	ErrDelegationTTL      = errors.New("delegated credential expires after parent")
	ErrDelegationDepth    = errors.New("delegation depth exceeded")
)

// VerificationResult captures the verified credential payload.
type VerificationResult struct {
	Credential VerifiableCredential
}

// DelegationChainResult captures details of a verified delegation chain.
type DelegationChainResult struct {
	Credentials     []VerifiableCredential
	CurrentSubject  string
	RootDelegator   string
	DelegationDepth int
}

// VerifierDependencies holds collaborators needed for verification.
type VerifierDependencies struct {
	ResolveIssuerPublicKey func(issuerDID string) (crypto.PublicKey, error)
}

// VerificationOptions captures optional verification constraints.
type VerificationOptions struct {
	ExpectedAudience   string
	MaxDelegationDepth int
}

// VerifyCredentialChain parses and verifies a chain of credential tokens.
func VerifyCredentialChain(tokens []string, deps VerifierDependencies, opts VerificationOptions, now time.Time) (*DelegationChainResult, error) {
	if deps.ResolveIssuerPublicKey == nil {
		return nil, fmt.Errorf("resolve issuer public key is required: %w", ErrInvalidToken)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no credentials supplied: %w", ErrInvalidDelegation)
	}

	maxDepth := opts.MaxDelegationDepth
	if maxDepth == 0 {
		maxDepth = 3
	}

	credentials := make([]VerifiableCredential, 0, len(tokens))
	for idx, token := range tokens {
		expectedAudience := ""
		if idx == len(tokens)-1 {
			expectedAudience = opts.ExpectedAudience
		}

		credential, err := verifySingleCredential(token, deps, expectedAudience, now)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, credential)

		if idx == 0 {
			continue
		}

		parent := credentials[idx-1]
		child := credential

		if !IsDepthAllowed(idx, maxDepth) {
			return nil, ErrDelegationDepth
		}

		if !IsScopeSubset(ScopeFromClaims(parent.Claims), ScopeFromClaims(child.Claims)) {
			return nil, ErrDelegationScope
		}

		if !IsTTLWithinParent(parent.ExpiresAt, child.ExpiresAt) {
			return nil, ErrDelegationTTL
		}
	}

	result := &DelegationChainResult{
		Credentials:     credentials,
		CurrentSubject:  credentials[len(credentials)-1].Subject,
		RootDelegator:   credentials[0].Subject,
		DelegationDepth: len(credentials) - 1,
	}

	if !IsDepthAllowed(result.DelegationDepth, maxDepth) {
		return nil, ErrDelegationDepth
	}

	return result, nil
}

// VerifyCredential parses and verifies a compact JWS/JWT credential token.
func VerifyCredential(token string, deps VerifierDependencies, expectedAudience string, now time.Time) (*VerificationResult, error) {
	res, err := VerifyCredentialChain([]string{token}, deps, VerificationOptions{ExpectedAudience: expectedAudience, MaxDelegationDepth: 1}, now)
	if err != nil {
		return nil, err
	}
	return &VerificationResult{Credential: res.Credentials[0]}, nil
}

func verifySingleCredential(token string, deps VerifierDependencies, expectedAudience string, now time.Time) (VerifiableCredential, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiableCredential{}, ErrInvalidToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiableCredential{}, ErrInvalidToken
	}

	var credential VerifiableCredential
	if err := json.Unmarshal(payloadBytes, &credential); err != nil {
		return VerifiableCredential{}, ErrInvalidToken
	}

	publicKey, err := deps.ResolveIssuerPublicKey(credential.Issuer)
	if err != nil {
		return VerifiableCredential{}, fmt.Errorf("resolve issuer: %w", ErrUntrustedIssuer)
	}

	edKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return VerifiableCredential{}, ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiableCredential{}, ErrInvalidToken
	}

	if !ed25519.Verify(edKey, []byte(signingInput), signatureBytes) {
		return VerifiableCredential{}, ErrInvalidSignature
	}

	if !credential.ExpiresAt.IsZero() && !now.Before(credential.ExpiresAt) {
		return VerifiableCredential{}, ErrExpiredCredential
	}

	// Allow small clock skew; reject tokens issued far in the future.
	if !credential.IssuedAt.IsZero() && credential.IssuedAt.After(now.Add(1*time.Minute)) {
		return VerifiableCredential{}, ErrIssuedInFuture
	}

	if expectedAudience != "" {
		aud, _ := credential.Claims["aud"].(string)
		if aud != expectedAudience {
			return VerifiableCredential{}, ErrUnexpectedAudience
		}
	}

	return credential, nil
}

func ScopeFromClaims(claims map[string]interface{}) []string {
	if claims == nil {
		return nil
	}
	scopeVal, ok := claims["scope"]
	if !ok {
		return nil
	}

	switch v := scopeVal.(type) {
	case []string:
		return append([]string{}, v...)
	case []interface{}:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	case string:
		return []string{v}
	default:
		return nil
	}
}
