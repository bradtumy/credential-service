package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// computeDisclosureDigest computes the digest used for SD-JWT disclosures.
func computeDisclosureDigest(disclosure []byte) string {
	h := sha256.Sum256(disclosure)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// applyDisclosures applies SD-JWT disclosures to a VerifiableCredential.
// It verifies that disclosures match the expected digests and populates vc.Claims.
func applyDisclosures(vc *VerifiableCredential, disclosures []string) error {
	if len(vc.SDDigests) == 0 {
		return nil
	}
	digestSet := map[string]struct{}{}
	for _, d := range vc.SDDigests {
		digestSet[d] = struct{}{}
	}

	resolvedClaims := map[string]interface{}{}
	for _, disclosure := range disclosures {
		raw, err := base64.RawURLEncoding.DecodeString(disclosure)
		if err != nil {
			return ErrInvalidToken
		}
		var arr []interface{}
		if err := json.Unmarshal(raw, &arr); err != nil {
			return ErrInvalidToken
		}
		if len(arr) != 3 {
			return ErrInvalidToken
		}
		salt, _ := arr[0].(string)
		key, _ := arr[1].(string)
		if salt == "" || key == "" {
			return ErrInvalidToken
		}
		reconstructed, err := json.Marshal(arr)
		if err != nil {
			return ErrInvalidToken
		}

		digest := computeDisclosureDigest(reconstructed)
		if _, ok := digestSet[digest]; !ok {
			return ErrInvalidDisclosure
		}
		resolvedClaims[key] = arr[2]
	}

	for digest := range digestSet {
		match := false
		for _, disclosure := range disclosures {
			raw, err := base64.RawURLEncoding.DecodeString(disclosure)
			if err != nil {
				return ErrInvalidDisclosure
			}
			if computeDisclosureDigest(raw) == digest {
				match = true
				break
			}
		}
		if !match {
			return ErrMissingDisclosure
		}
	}

	if vc.Claims == nil {
		vc.Claims = map[string]interface{}{}
	}
	for k, v := range resolvedClaims {
		vc.Claims[k] = v
	}
	vc.SDDigests = nil
	return nil
}
