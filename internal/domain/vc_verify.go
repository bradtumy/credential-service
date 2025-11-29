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
)

// VerificationResult captures the verified credential payload.
type VerificationResult struct {
	Credential VerifiableCredential
}

// VerifierDependencies holds collaborators needed for verification.
type VerifierDependencies struct {
	ResolveIssuerPublicKey func(issuerDID string) (crypto.PublicKey, error)
}

// VerifyCredential parses and verifies a compact JWS/JWT credential token.
func VerifyCredential(token string, deps VerifierDependencies, expectedAudience string, now time.Time) (*VerificationResult, error) {
	if deps.ResolveIssuerPublicKey == nil {
		return nil, fmt.Errorf("resolve issuer public key is required: %w", ErrInvalidToken)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var credential VerifiableCredential
	if err := json.Unmarshal(payloadBytes, &credential); err != nil {
		return nil, ErrInvalidToken
	}

	publicKey, err := deps.ResolveIssuerPublicKey(credential.Issuer)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", ErrUntrustedIssuer)
	}

	edKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !ed25519.Verify(edKey, []byte(signingInput), signatureBytes) {
		return nil, ErrInvalidSignature
	}

	if !credential.ExpiresAt.IsZero() && !now.Before(credential.ExpiresAt) {
		return nil, ErrExpiredCredential
	}

	// Allow small clock skew; reject tokens issued far in the future.
	if !credential.IssuedAt.IsZero() && credential.IssuedAt.After(now.Add(1*time.Minute)) {
		return nil, ErrIssuedInFuture
	}

	if expectedAudience != "" {
		aud, _ := credential.Claims["aud"].(string)
		if aud != expectedAudience {
			return nil, ErrUnexpectedAudience
		}
	}

	return &VerificationResult{Credential: credential}, nil
}
