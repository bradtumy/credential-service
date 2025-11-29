package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// KeyMetadata holds normalized information about a signer.
type KeyMetadata struct {
	Key       Signer
	PublicKey crypto.PublicKey
	KID       string
	Alg       string
	JWK       json.RawMessage
	NotBefore string
	NotAfter  string
}

// KeyID derives a stable kid for the provided signer.
func KeyID(s Signer) (string, error) {
	type keyed interface{ KeyID() string }
	if k, ok := s.(keyed); ok && k.KeyID() != "" {
		return k.KeyID(), nil
	}
	jwk, err := s.PublicJWK()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(jwk)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ParsePublicJWK decodes a public JWK into a crypto.PublicKey and algorithm.
func ParsePublicJWK(jwk []byte) (crypto.PublicKey, string, error) {
	var payload map[string]string
	if err := json.Unmarshal(jwk, &payload); err != nil {
		return nil, "", fmt.Errorf("unmarshal jwk: %w", err)
	}

	kty := payload["kty"]
	switch kty {
	case "OKP":
		crv := payload["crv"]
		if crv != "Ed25519" {
			return nil, "", fmt.Errorf("unsupported curve %s", crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(payload["x"])
		if err != nil {
			return nil, "", fmt.Errorf("decode x: %w", err)
		}
		return ed25519.PublicKey(x), "EdDSA", nil
	case "EC":
		crv := payload["crv"]
		if crv != "P-256" {
			return nil, "", fmt.Errorf("unsupported curve %s", crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(payload["x"])
		if err != nil {
			return nil, "", fmt.Errorf("decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(payload["y"])
		if err != nil {
			return nil, "", fmt.Errorf("decode y: %w", err)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return nil, "", errors.New("point not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, "ES256", nil
	case "RSA":
		return nil, "", errors.New("RSA keys are not supported")
	default:
		return nil, "", fmt.Errorf("unsupported kty %s", kty)
	}
}

// BuildKeyMetadata constructs metadata for a signer.
func BuildKeyMetadata(s Signer) (KeyMetadata, error) {
	jwk, err := s.PublicJWK()
	if err != nil {
		return KeyMetadata{}, err
	}
	kid, err := KeyID(s)
	if err != nil {
		return KeyMetadata{}, err
	}
	pub, alg, err := ParsePublicJWK(jwk)
	if err != nil {
		return KeyMetadata{}, err
	}

	meta := KeyMetadata{
		Key:       s,
		PublicKey: pub,
		KID:       kid,
		Alg:       alg,
		JWK:       jwk,
	}

	type windowed interface{ ValidityWindow() (string, string) }
	if w, ok := s.(windowed); ok {
		nb, na := w.ValidityWindow()
		meta.NotBefore = nb
		meta.NotAfter = na
	}

	return meta, nil
}

// algorithmForPublicKey infers JWT alg from a public key.
func algorithmForPublicKey(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return "EdDSA", nil
	case *ecdsa.PublicKey:
		if k.Params().Name != "P-256" {
			return "", fmt.Errorf("unsupported curve %s", k.Params().Name)
		}
		return "ES256", nil
	case *rsa.PublicKey:
		if k.Size()*8 < 2048 {
			return "", fmt.Errorf("rsa key too small")
		}
		return "RS256", nil
	default:
		return "", fmt.Errorf("unsupported key type %T", pub)
	}
}
