package oidc4vp

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
)

const (
	maxVPTokenSize = 128 * 1024
)

// ResponseDependencies defines collaborators needed to validate responses.
type ResponseDependencies struct {
	ResolveIssuerKey func(string) (crypto.PublicKey, error)
	ResolveHolderKey func(string) (crypto.PublicKey, error)
	Now              func() time.Time
	RevocationStrict bool
}

// ValidationResult captures the outcome of a response validation.
type ValidationResult struct {
	HolderDID       string
	Credentials     []domain.VerifiableCredential
	PresentationIDs []string
}

// ValidateResponse validates an OIDC4VP response payload.
func ValidateResponse(req AuthorizationRequest, vpTokenRaw string, deps ResponseDependencies) (*ValidationResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if req.ResponseType != "vp_token" {
		return nil, errors.New("unsupported response_type")
	}
	if vpTokenRaw == "" {
		return nil, errors.New("vp_token is required")
	}
	if len(vpTokenRaw) > maxVPTokenSize {
		return nil, errors.New("vp_token too large")
	}
	if deps.ResolveIssuerKey == nil || deps.ResolveHolderKey == nil {
		return nil, errors.New("missing key resolvers")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}

	vpToken, err := parseVPToken(vpTokenRaw)
	if err != nil {
		return nil, err
	}

	queries := map[string]CredentialQuery{}
	for _, query := range req.DCQLQuery.Credentials {
		queries[query.ID] = query
		if query.HolderBindingRequired() && req.Nonce == "" {
			return nil, errors.New("nonce required for holder binding")
		}
	}

	for id := range vpToken {
		if _, ok := queries[id]; !ok {
			return nil, fmt.Errorf("unexpected credential query id: %s", id)
		}
	}

	if err := verifyCredentialSetRequirements(req.DCQLQuery, vpToken); err != nil {
		return nil, err
	}

	verifierDeps := domain.VerifierDependencies{ResolveIssuerPublicKey: deps.ResolveIssuerKey}
	result := &ValidationResult{}

	for id, presentations := range vpToken {
		query := queries[id]
		if !query.Multiple && len(presentations) > 1 {
			return nil, fmt.Errorf("credential query %s does not allow multiple presentations", id)
		}

		for _, presentation := range presentations {
			holder, credentials, err := validatePresentation(req, query, presentation, deps)
			if err != nil {
				return nil, err
			}
			if holder != "" {
				result.HolderDID = holder
			}

			for _, credentialToken := range credentials {
				verified, err := domain.VerifyCredentialChain([]string{credentialToken}, verifierDeps, domain.VerificationOptions{}, deps.Now())
				if err != nil {
					return nil, err
				}
				leaf := verified.Credentials[len(verified.Credentials)-1]
				if deps.RevocationStrict {
					id := credentialIDForRevocation(leaf)
					if id == "" {
						return nil, errors.New("credential id missing for revocation check")
					}
					if revoked, reason := domain.IsRevoked(id); revoked {
						if reason == "" {
							reason = "revoked"
						}
						return nil, fmt.Errorf("credential revoked: %s", reason)
					}
				}
				if err := validateCredentialMetadata(query, leaf); err != nil {
					return nil, err
				}
				if err := validateClaimQueries(query, leaf.Claims); err != nil {
					return nil, err
				}
				result.Credentials = append(result.Credentials, leaf)
				result.PresentationIDs = append(result.PresentationIDs, id)
			}
		}
	}

	return result, nil
}

func parseVPToken(raw string) (map[string][]string, error) {
	var token map[string][]string
	if err := json.Unmarshal([]byte(raw), &token); err == nil {
		return token, nil
	}

	var generic map[string]any
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		return nil, errors.New("vp_token must be a JSON object")
	}
	parsed := make(map[string][]string, len(generic))
	for key, value := range generic {
		values, err := toStringSlice(value)
		if err != nil {
			return nil, fmt.Errorf("vp_token entry %s: %w", key, err)
		}
		parsed[key] = values
	}
	return parsed, nil
}

func toStringSlice(value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok || str == "" {
				return nil, errors.New("presentation value must be a string")
			}
			out = append(out, str)
		}
		return out, nil
	default:
		return nil, errors.New("presentations must be string or array")
	}
}

func verifyCredentialSetRequirements(query DCQLQuery, vpToken map[string][]string) error {
	if len(query.CredentialSets) == 0 {
		for _, cred := range query.Credentials {
			if len(vpToken[cred.ID]) == 0 {
				return fmt.Errorf("missing required credential query id: %s", cred.ID)
			}
		}
		return nil
	}

	for _, set := range query.CredentialSets {
		required := true
		if set.Required != nil {
			required = *set.Required
		}
		if !required {
			continue
		}
		matched := false
		for _, option := range set.Options {
			if len(option) == 0 {
				continue
			}
			ok := true
			for _, id := range option {
				if len(vpToken[id]) == 0 {
					ok = false
					break
				}
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("required credential set not satisfied")
		}
	}
	return nil
}

func validatePresentation(req AuthorizationRequest, query CredentialQuery, presentation string, deps ResponseDependencies) (string, []string, error) {
	holderBinding := query.HolderBindingRequired()

	switch query.Format {
	case FormatJWTVCJSON:
		return validateJWTPresentation(req, holderBinding, presentation, deps)
	case FormatSDJWTVC:
		if holderBinding {
			return "", nil, errors.New("holder binding required but not supported for dc+sd-jwt")
		}
		return "", []string{presentation}, nil
	default:
		return "", nil, fmt.Errorf("unsupported credential format: %s", query.Format)
	}
}

func validateJWTPresentation(req AuthorizationRequest, holderBindingRequired bool, presentation string, deps ResponseDependencies) (string, []string, error) {
	if !isJWT(presentation) {
		if holderBindingRequired {
			return "", nil, errors.New("holder binding required but presentation is not a JWT VP")
		}
		return "", []string{presentation}, nil
	}

	payload, err := parseAndVerifyJWT(presentation, deps.ResolveHolderKey)
	if err != nil {
		return "", nil, err
	}
	if err := validateJWTTimeClaims(payload, deps.Now()); err != nil {
		return "", nil, err
	}

	holder, _ := payload["iss"].(string)
	if holderBindingRequired {
		if err := validateAudience(payload["aud"], req.ClientID); err != nil {
			return "", nil, err
		}
		nonce, _ := payload["nonce"].(string)
		if nonce == "" || nonce != req.Nonce {
			return "", nil, errors.New("nonce mismatch")
		}
	}

	vp, ok := payload["vp"].(map[string]any)
	if !ok {
		return "", nil, errors.New("vp claim missing")
	}
	credentials, err := extractCredentials(vp["verifiableCredential"])
	if err != nil {
		return "", nil, err
	}
	if len(credentials) == 0 {
		return "", nil, errors.New("verifiableCredential is empty")
	}

	return holder, credentials, nil
}

func isJWT(value string) bool {
	return strings.Count(value, ".") == 2
}

func parseAndVerifyJWT(token string, resolveKey func(string) (crypto.PublicKey, error)) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid jwt header")
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("invalid jwt header")
	}
	if alg, _ := header["alg"].(string); alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported jwt algorithm: %v", header["alg"])
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid jwt payload")
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errors.New("invalid jwt payload")
	}

	issuer, _ := payload["iss"].(string)
	if issuer == "" {
		return nil, errors.New("issuer missing")
	}

	publicKey, err := resolveKey(issuer)
	if err != nil {
		return nil, err
	}
	edKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unsupported holder key type")
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid jwt signature")
	}
	if !ed25519.Verify(edKey, []byte(signingInput), sigBytes) {
		return nil, errors.New("invalid jwt signature")
	}

	return payload, nil
}

func validateJWTTimeClaims(payload map[string]any, now time.Time) error {
	if exp, ok := payload["exp"].(float64); ok {
		if now.Unix() >= int64(exp) {
			return errors.New("presentation has expired")
		}
	}
	if iat, ok := payload["iat"].(float64); ok {
		if int64(iat) > now.Add(time.Minute).Unix() {
			return errors.New("presentation issued in the future")
		}
	}
	return nil
}

func validateAudience(aud any, expected string) error {
	if expected == "" {
		return nil
	}
	switch v := aud.(type) {
	case string:
		if v != expected {
			return errors.New("audience mismatch")
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return nil
			}
		}
		return errors.New("audience mismatch")
	default:
		return errors.New("audience missing")
	}
	return nil
}

func extractCredentials(value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("credential must be a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("verifiableCredential must be a string or array")
	}
}

func credentialIDForRevocation(credential domain.VerifiableCredential) string {
	if credential.ID != "" {
		return credential.ID
	}
	if credential.JTI != "" {
		return credential.JTI
	}
	return ""
}

func validateCredentialMetadata(query CredentialQuery, credential domain.VerifiableCredential) error {
	switch query.Format {
	case FormatJWTVCJSON:
		return validateTypeValues(query.Meta, credential.Type)
	case FormatSDJWTVC:
		return validateVCTValues(query.Meta, credential.Claims)
	default:
		return nil
	}
}

func validateTypeValues(meta map[string]any, types []string) error {
	raw, ok := meta["type_values"]
	if !ok {
		return errors.New("type_values is required for jwt_vc_json")
	}
	options, ok := raw.([]any)
	if !ok {
		return errors.New("type_values must be an array")
	}
	for _, option := range options {
		requiredTypes, ok := option.([]any)
		if !ok || len(requiredTypes) == 0 {
			continue
		}
		if containsAll(types, requiredTypes) {
			return nil
		}
	}
	return errors.New("credential type does not match request")
}

func validateVCTValues(meta map[string]any, claims map[string]any) error {
	raw, ok := meta["vct_values"]
	if !ok {
		return errors.New("vct_values is required for dc+sd-jwt")
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return errors.New("vct_values must be a non-empty array")
	}
	vct, _ := claims["vct"].(string)
	if vct == "" {
		return errors.New("vct claim missing")
	}
	for _, value := range values {
		if v, ok := value.(string); ok && v == vct {
			return nil
		}
	}
	return errors.New("vct claim does not match request")
}

func containsAll(actual []string, required []any) bool {
	for _, item := range required {
		needle, ok := item.(string)
		if !ok || needle == "" {
			return false
		}
		found := false
		for _, value := range actual {
			if value == needle {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validateClaimQueries(query CredentialQuery, claims map[string]any) error {
	for _, claim := range query.Claims {
		value, ok := lookupClaimPath(claims, claim.Path)
		if !ok {
			return fmt.Errorf("claim not found: %v", claim.Path)
		}
		if len(claim.Values) > 0 {
			matched := false
			for _, expected := range claim.Values {
				if reflect.DeepEqual(value, expected) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("claim value mismatch: %v", claim.Path)
			}
		}
	}
	return nil
}

func lookupClaimPath(claims map[string]any, path []string) (any, bool) {
	var current any = claims
	for _, segment := range path {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := asMap[segment]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}
