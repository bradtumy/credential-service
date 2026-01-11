package policy

import (
	"context"
	"testing"
)

func TestHasRoleWithInterfaceSlice(t *testing.T) {
	store := NewMemoryStore()
	p := &Policy{TenantID: "t1", Name: "role-any", Effect: EffectAllow, Actions: []string{"write"}, Resources: []string{"docs"}, Subjects: []string{"role:admin"}, Priority: 1, Enabled: true}
	_ = store.CreatePolicy(context.Background(), p)

	engine := NewEngine(store)
	// roles as []any ([]interface{})
	claims := map[string]any{"roles": []any{"admin"}}
	res, err := engine.Evaluate(EvaluationInput{TenantID: "t1", Subject: "did:alice", Resource: "docs", Action: "write", Claims: claims})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Allow {
		t.Fatalf("expected allow when roles provided as []any")
	}
}

func TestScopeContainsWithArrayTypes(t *testing.T) {
	store := NewMemoryStore()
	cond := map[string]any{"scope_contains": []any{"orders:read", "payments:read"}}
	p := &Policy{TenantID: "t1", Name: "scoped-array", Effect: EffectAllow, Actions: []string{"read"}, Resources: []string{"orders"}, Subjects: []string{"any"}, Priority: 1, Enabled: true, Conditions: cond}
	_ = store.CreatePolicy(context.Background(), p)

	engine := NewEngine(store)
	scope := []string{"orders:read", "payments:read"}
	res, err := engine.Evaluate(EvaluationInput{TenantID: "t1", Subject: "did:x", Resource: "orders", Action: "read", Scope: scope})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Allow {
		t.Fatalf("expected allow when scope contains required values")
	}
}

func TestClaimEqualsNumericTypes(t *testing.T) {
	store := NewMemoryStore()
	cond := map[string]any{"claim_equals": map[string]any{"score": 42}}
	p := &Policy{TenantID: "t1", Name: "numeric", Effect: EffectAllow, Actions: []string{"read"}, Resources: []string{"reports"}, Subjects: []string{"any"}, Priority: 1, Enabled: true, Conditions: cond}
	_ = store.CreatePolicy(context.Background(), p)

	engine := NewEngine(store)
	// store and evaluate using float64 (common when decoding JSON numbers)
	claims := map[string]any{"score": 42.0}
	res, err := engine.Evaluate(EvaluationInput{TenantID: "t1", Subject: "did:x", Resource: "reports", Action: "read", Claims: claims})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Allow {
		t.Fatalf("expected allow when numeric claim types are compatible")
	}
}
