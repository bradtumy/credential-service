package domain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// VerifiableCredential structure following W3C schema.
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	ID                string                 `json:"id"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	ExpirationDate    string                 `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             Proof                  `json:"proof,omitempty"`
}

// Proof structure for digital signature.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	ProofValue         string `json:"proofValue"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
}

// CredentialRequest represents the issuance request payload.
type CredentialRequest struct {
	IssuerDid string                   `json:"issuerDid"`
	Subjects  []map[string]interface{} `json:"subject"`
}

// BaseSchema represents the structure of the base schema.
type BaseSchema struct {
	CredentialID   Property `json:"credentialID"`
	CredentialType Property `json:"credentialType"`
	IssueDate      Property `json:"issueDate"`
	ExpirationDate Property `json:"expirationDate"`
	Issuer         Property `json:"issuer"`
}

// Property represents a property of the schema.
type Property struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// Schema represents a JSON Schema structure.
type Schema struct {
	Properties []Property `json:"properties"`
}

// LoadBaseSchema loads the base schema from a JSON file.
func LoadBaseSchema(filePath string) (BaseSchema, error) {
	var baseSchema BaseSchema
	file, err := osReadFile(filePath)
	if err != nil {
		return baseSchema, fmt.Errorf("failed to read base schema file: %w", err)
	}

	if err := json.Unmarshal(file, &baseSchema); err != nil {
		return baseSchema, fmt.Errorf("failed to unmarshal base schema JSON: %w", err)
	}

	return baseSchema, nil
}

// BuildCredential constructs a credential with consistent defaults.
func BuildCredential(id, issuer string, issuanceDate, expirationDate string, subject map[string]interface{}) VerifiableCredential {
	return VerifiableCredential{
		Context:        []string{"https://www.w3.org/2018/credentials/v1"},
		Type:           []string{"VerifiableCredential"},
		ID:             id,
		Issuer:         issuer,
		IssuanceDate:   issuanceDate,
		ExpirationDate: expirationDate,
		CredentialSubject: map[string]interface{}{
			"subject": subject,
		},
	}
}

// AttachProof adds the proof information to a credential.
func AttachProof(vc VerifiableCredential, signature []byte) VerifiableCredential {
	vc.Proof = Proof{
		Type:               "Ed25519Signature2018",
		Created:            time.Now().UTC().Format(time.RFC3339),
		ProofValue:         base64.StdEncoding.EncodeToString(signature),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: vc.Issuer + "#keys-1",
	}
	return vc
}

// ParseEd25519PrivateKeyFromBase64 parses the base64-encoded Ed25519 private key.
func ParseEd25519PrivateKeyFromBase64(base64Key string) ([]byte, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %w", err)
	}
	return privateKeyBytes, nil
}

// SignCredential signs the credential payload. The signing logic is intentionally
// simple and should be replaced with a secure implementation.
func SignCredential(_ context.Context, privateKey []byte, credentialJSON []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("private key is empty")
	}
	// TODO: replace with real Ed25519 signing logic
	if len(credentialJSON) == 0 {
		return nil, errors.New("credential payload is empty")
	}
	return []byte("SIGNATURE"), nil
}

// VerifyCredential validates a Verifiable Credential against basic checks.
func VerifyCredential(vc VerifiableCredential) (bool, error) {
	issuanceDate, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return false, errors.New("invalid issuance date")
	}

	expirationDate, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return false, errors.New("invalid expiration date")
	}

	if time.Now().After(expirationDate) {
		return false, errors.New("credential has expired")
	}

	if issuanceDate.After(expirationDate) {
		return false, errors.New("issuance date is after expiration date")
	}

	if vc.Proof.ProofValue == "" {
		return false, errors.New("missing proof or invalid signature")
	}

	return true, nil
}

// osReadFile is abstracted for testing.
var osReadFile = func(path string) ([]byte, error) {
	return osReadFileFn(path)
}

// osReadFileFn allows substitution during tests.
var osReadFileFn = defaultReadFile

func defaultReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
