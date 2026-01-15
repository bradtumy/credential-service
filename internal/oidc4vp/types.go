package oidc4vp

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	FormatJWTVCJSON = "jwt_vc_json"
	FormatSDJWTVC   = "dc+sd-jwt"
)

var (
	errEmptyID          = errors.New("credential query id is required")
	errInvalidID        = errors.New("credential query id format is invalid")
	errDuplicateID      = errors.New("duplicate credential query id")
	errMissingFormat    = errors.New("credential query format is required")
	errMissingMeta      = errors.New("credential query meta is required")
	errMissingOptions   = errors.New("credential set options are required")
	errMissingClaimPath = errors.New("claim path is required")
)

var queryIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// AuthorizationRequest captures the parameters required to validate an OIDC4VP response.
type AuthorizationRequest struct {
	ClientID     string
	ResponseURI  string
	State        string
	Nonce        string
	ResponseType string
	ResponseMode string
	DCQLQuery    DCQLQuery
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// DCQLQuery describes the Verifier's credential request.
type DCQLQuery struct {
	Credentials     []CredentialQuery    `json:"credentials"`
	CredentialSets  []CredentialSetQuery `json:"credential_sets,omitempty"`
	TransactionData []any                `json:"transaction_data,omitempty"`
}

// CredentialQuery captures a request for a credential presentation.
type CredentialQuery struct {
	ID                                string             `json:"id"`
	Format                            string             `json:"format"`
	Multiple                          bool               `json:"multiple,omitempty"`
	Meta                              map[string]any     `json:"meta"`
	TrustedAuthorities                []TrustedAuthority `json:"trusted_authorities,omitempty"`
	RequireCryptographicHolderBinding *bool              `json:"require_cryptographic_holder_binding,omitempty"`
	Claims                            []ClaimQuery       `json:"claims,omitempty"`
	ClaimSets                         [][]string         `json:"claim_sets,omitempty"`
}

// CredentialSetQuery captures a set of credential options.
type CredentialSetQuery struct {
	Options  [][]string `json:"options"`
	Required *bool      `json:"required,omitempty"`
}

// ClaimQuery captures a requested claim path and optional expected values.
type ClaimQuery struct {
	ID     string   `json:"id,omitempty"`
	Path   []string `json:"path"`
	Values []any    `json:"values,omitempty"`
}

// TrustedAuthority captures issuer constraints in DCQL.
type TrustedAuthority struct {
	Name   string `json:"name,omitempty"`
	Format string `json:"format,omitempty"`
}

// Validate ensures the authorization request is well-formed for response validation.
func (r AuthorizationRequest) Validate() error {
	if r.ClientID == "" {
		return errors.New("client_id is required")
	}
	if r.State == "" {
		return errors.New("state is required")
	}
	if r.ResponseType == "" {
		return errors.New("response_type is required")
	}
	if err := r.DCQLQuery.Validate(); err != nil {
		return fmt.Errorf("dcql_query: %w", err)
	}
	return nil
}

// Validate ensures the DCQL query is well-formed for response validation.
func (q DCQLQuery) Validate() error {
	if len(q.Credentials) == 0 {
		return errors.New("credentials are required")
	}
	seen := map[string]struct{}{}
	for _, cred := range q.Credentials {
		if cred.ID == "" {
			return errEmptyID
		}
		if !queryIDPattern.MatchString(cred.ID) {
			return errInvalidID
		}
		if _, ok := seen[cred.ID]; ok {
			return errDuplicateID
		}
		seen[cred.ID] = struct{}{}
		if cred.Format == "" {
			return errMissingFormat
		}
		if cred.Meta == nil {
			return errMissingMeta
		}
		if err := cred.ValidateClaims(); err != nil {
			return err
		}
	}
	for _, set := range q.CredentialSets {
		if len(set.Options) == 0 {
			return errMissingOptions
		}
		for _, option := range set.Options {
			if len(option) == 0 {
				return errMissingOptions
			}
		}
	}
	return nil
}

// HolderBindingRequired returns whether holder binding is required by the query.
func (q CredentialQuery) HolderBindingRequired() bool {
	if q.RequireCryptographicHolderBinding == nil {
		return true
	}
	return *q.RequireCryptographicHolderBinding
}

// ValidateClaims ensures claims query fields are valid.
func (q CredentialQuery) ValidateClaims() error {
	for _, claim := range q.Claims {
		if len(claim.Path) == 0 {
			return errMissingClaimPath
		}
	}
	return nil
}
