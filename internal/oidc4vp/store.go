package oidc4vp

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RequestStore persists authorization requests for OIDC4VP responses.
type RequestStore interface {
	Save(ctx context.Context, req AuthorizationRequest) error
	Get(ctx context.Context, state string) (AuthorizationRequest, error)
	MarkUsed(ctx context.Context, state string) error
}

// MemoryRequestStore stores requests in memory with basic TTL enforcement.
type MemoryRequestStore struct {
	mu      sync.RWMutex
	records map[string]requestRecord
}

type requestRecord struct {
	request AuthorizationRequest
	used    bool
}

// NewMemoryRequestStore constructs an in-memory request store.
func NewMemoryRequestStore() *MemoryRequestStore {
	return &MemoryRequestStore{records: make(map[string]requestRecord)}
}

// Save stores a request by its state value.
func (s *MemoryRequestStore) Save(_ context.Context, req AuthorizationRequest) error {
	if req.State == "" {
		return errors.New("state is required")
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[req.State] = requestRecord{request: req}
	return nil
}

// Get returns a request by state, enforcing expiration.
func (s *MemoryRequestStore) Get(_ context.Context, state string) (AuthorizationRequest, error) {
	s.mu.RLock()
	record, ok := s.records[state]
	s.mu.RUnlock()
	if !ok {
		return AuthorizationRequest{}, errors.New("request not found")
	}
	if !record.request.ExpiresAt.IsZero() && time.Now().After(record.request.ExpiresAt) {
		return AuthorizationRequest{}, errors.New("request expired")
	}
	return record.request, nil
}

// MarkUsed marks a request as used to prevent replay.
func (s *MemoryRequestStore) MarkUsed(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[state]
	if !ok {
		return errors.New("request not found")
	}
	if record.used {
		return errors.New("request already used")
	}
	record.used = true
	s.records[state] = record
	return nil
}
