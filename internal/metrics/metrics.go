package metrics

// VerifierMetrics describes counters for verification outcomes.
type VerifierMetrics interface {
	IncVerificationSuccess(reason string)
	IncVerificationFailure(reason string)
}

// NoopVerifierMetrics is a placeholder implementation used by default.
type NoopVerifierMetrics struct{}

// IncVerificationSuccess satisfies VerifierMetrics without recording metrics.
func (NoopVerifierMetrics) IncVerificationSuccess(reason string) {}

// IncVerificationFailure satisfies VerifierMetrics without recording metrics.
func (NoopVerifierMetrics) IncVerificationFailure(reason string) {}

// DefaultVerifierMetrics is the global metrics collector for the verifier.
var DefaultVerifierMetrics VerifierMetrics = NoopVerifierMetrics{}
