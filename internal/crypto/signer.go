package crypto

// Signer abstracts signing operations so implementations can back onto local keys
// or remote KMS providers.
type Signer interface {
	// PublicJWK returns the public key in JWK form.
	PublicJWK() ([]byte, error)
	// Sign signs the provided payload and returns the raw signature bytes.
	Sign(payload []byte) ([]byte, error)
	// Algorithm returns the JOSE/JWT alg header value for this signer.
	Algorithm() string
}
