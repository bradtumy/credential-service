package crypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// ErrKMSSigningDisabled is returned when KMS is turned off via env vars.
var ErrKMSSigningDisabled = errors.New("kms signing disabled")

// KMSSigner implements Signer backed by Google Cloud KMS asymmetric keys.
type KMSSigner struct {
	client *kms.KeyManagementClient
	keyID  string
	jwk    []byte
	alg    string
	kid    string
}

// NewKMSSignerFromEnv builds a signer if ENABLE_KMS/KMS_ENABLE is true.
func NewKMSSignerFromEnv(ctx context.Context) (*KMSSigner, error) {
	enabled := os.Getenv("ENABLE_KMS") == "true" || os.Getenv("KMS_ENABLE") == "true"
	if !enabled {
		return nil, ErrKMSSigningDisabled
	}
	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		return nil, fmt.Errorf("KMS_KEY_ID is required when KMS is enabled")
	}
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}

	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("get kms public key: %w", err)
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("decode kms public key pem")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse kms public key: %w", err)
	}

	jwk, alg, err := jwkFromPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	kid, err := KeyID(&KMSSigner{jwk: jwk})
	if err != nil {
		return nil, err
	}

	return &KMSSigner{client: client, keyID: keyID, jwk: jwk, alg: alg, kid: kid}, nil
}

func jwkFromPublicKey(pub crypto.PublicKey) ([]byte, string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		jwk := map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(k),
		}
		b, _ := json.Marshal(jwk)
		return b, "EdDSA", nil
	case *ecdsa.PublicKey:
		if k.Params().Name != "P-256" {
			return nil, "", fmt.Errorf("unsupported curve %s", k.Params().Name)
		}
		jwk := map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		}
		b, _ := json.Marshal(jwk)
		return b, "ES256", nil
	default:
		return nil, "", fmt.Errorf("unsupported kms key type %T", pub)
	}
}

// PublicJWK returns the public key in JWK form.
func (k *KMSSigner) PublicJWK() ([]byte, error) { return append([]byte{}, k.jwk...), nil }

// Sign delegates signing to Google Cloud KMS using the appropriate signing call.
func (k *KMSSigner) Sign(payload []byte) ([]byte, error) {
	if k == nil || k.client == nil {
		return nil, fmt.Errorf("kms signer not configured")
	}
	ctx := context.Background()
	req := &kmspb.AsymmetricSignRequest{Name: k.keyID}
	switch k.alg {
	case "EdDSA":
		req.Data = payload
	case "ES256":
		digest := sha256.Sum256(payload)
		req.Digest = &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}}
	default:
		return nil, fmt.Errorf("unsupported alg %s", k.alg)
	}

	resp, err := k.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return resp.Signature, nil
}

// Algorithm returns the signing algorithm label.
func (k *KMSSigner) Algorithm() string { return k.alg }

// KeyID returns the derived key identifier.
func (k *KMSSigner) KeyID() string { return k.kid }

// ValidityWindow is empty for KMS backed keys.
func (k *KMSSigner) ValidityWindow() (string, string) { return "", "" }
