package httpx

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/metrics"
	"github.com/bradtumy/credential-service/internal/version"
)

// GatewayAuthorizeRequest is the payload expected by the gateway authorize endpoint.
type GatewayAuthorizeRequest struct {
	Credential       string   `json:"credential"`
	Credentials      []string `json:"credentials"`
	ExpectedAudience string   `json:"expected_audience"`
	WantSyntheticJWT bool     `json:"want_synthetic_jwt"`
}

// GatewayAuthorizeResponse is returned to gateways or reverse proxies.
type GatewayAuthorizeResponse struct {
	Allowed          bool                   `json:"allowed"`
	Subject          string                 `json:"subject,omitempty"`
	ActingOnBehalfOf string                 `json:"acting_on_behalf_of,omitempty"`
	DelegationDepth  int                    `json:"delegation_depth,omitempty"`
	Claims           map[string]interface{} `json:"claims,omitempty"`
	Reason           string                 `json:"reason,omitempty"`
	SyntheticJWT     string                 `json:"synthetic_jwt,omitempty"`
	Agent            *AgentContext          `json:"agent,omitempty"`
	APIVersion       string                 `json:"api_version"`
}

// AgentContext surfaces on-behalf-of metadata for agent invocations.
type AgentContext struct {
	ActingOnBehalfOf string   `json:"acting_on_behalf_of"`
	DelegationDepth  int      `json:"delegation_depth"`
	Scope            []string `json:"scope,omitempty"`
}

// RegisterGatewayRoutes wires gateway-specific routes into the provided mux.
func RegisterGatewayRoutes(mux *http.ServeMux, resolver func(string) (crypto.PublicKey, error), registry domain.TrustRegistry, tenantID string, signingKey crypto.Signer, jwtIssuer string, now func() time.Time) {
	if now == nil {
		now = time.Now
	}

	mux.HandleFunc("/v1/gateway/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}

		var req GatewayAuthorizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteAPIError(w, http.StatusBadRequest, "bad_request", "invalid request payload")
			return
		}

		tokens := req.Credentials
		if len(tokens) == 0 && req.Credential != "" {
			tokens = []string{req.Credential}
		}

		if len(tokens) == 0 {
			WriteAPIError(w, http.StatusBadRequest, "invalid_request", "credential is required")
			return
		}

		deps := domain.VerifierDependencies{ResolveIssuerPublicKey: func(issuer string) (crypto.PublicKey, error) {
			if registry != nil {
				trusted, err := registry.IsTrustedIssuer(r.Context(), tenantID, issuer)
				if err != nil {
					return nil, fmt.Errorf("trust lookup: %w", err)
				}
				if !trusted {
					return nil, domain.ErrUntrustedIssuer
				}
			}
			if resolver == nil {
				return nil, fmt.Errorf("resolver not configured")
			}
			return resolver(issuer)
		}}

		chainResult, err := domain.VerifyCredentialChain(tokens, deps, domain.VerificationOptions{ExpectedAudience: req.ExpectedAudience, MaxDelegationDepth: 3}, now())
		if err != nil {
			reason := mapVerificationErrorToReason(err)
			metrics.DefaultVerifierMetrics.IncVerificationFailure(reason)
			writeDecision(w, GatewayAuthorizeResponse{Allowed: false, Reason: reason, APIVersion: version.APIVersion})
			return
		}

		decision := domain.BuildAuthzDecisionFromVerification(chainResult)
		var agentContext *AgentContext
		if len(chainResult.Credentials) > 1 {
			parent := chainResult.Credentials[len(chainResult.Credentials)-2]
			child := chainResult.Credentials[len(chainResult.Credentials)-1]
			ctx := domain.BuildOnBehalfOfContext(&parent, &child)
			agentContext = &AgentContext{
				ActingOnBehalfOf: ctx.ActingFor,
				DelegationDepth:  ctx.DelegationDepth,
				Scope:            ctx.Scope,
			}
		}

		response := GatewayAuthorizeResponse{
			Allowed:          decision.Allowed,
			Subject:          decision.SubjectDID,
			ActingOnBehalfOf: decision.ActingOnBehalfOf,
			DelegationDepth:  decision.DelegationDepth,
			Claims:           decision.Claims,
			Reason:           decision.Reason,
			Agent:            agentContext,
			APIVersion:       version.APIVersion,
		}

		if req.WantSyntheticJWT {
			jwt, err := domain.BuildSyntheticJWT(decision, signingKey, jwtIssuer, 15*time.Minute)
			if err != nil {
				writeDecision(w, GatewayAuthorizeResponse{Allowed: false, Reason: "jwt_error", APIVersion: version.APIVersion})
				return
			}
			response.SyntheticJWT = jwt.Token
		}

		metrics.DefaultVerifierMetrics.IncVerificationSuccess("ok")
		writeDecision(w, response)
	})
}

func writeDecision(w http.ResponseWriter, resp GatewayAuthorizeResponse) {
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if !resp.Allowed {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func mapVerificationErrorToReason(err error) string {
	switch {
	case errors.Is(err, domain.ErrExpiredCredential):
		return "expired_credential"
	case errors.Is(err, domain.ErrUntrustedIssuer):
		return "untrusted_issuer"
	case errors.Is(err, domain.ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, domain.ErrUnexpectedAudience):
		return "unexpected_audience"
	case errors.Is(err, domain.ErrDelegationDepth):
		return "delegation_depth_exceeded"
	case errors.Is(err, domain.ErrDelegationScope):
		return "invalid_scope"
	case errors.Is(err, domain.ErrDelegationTTL):
		return "invalid_ttl"
	default:
		return "verification_failed"
	}
}
