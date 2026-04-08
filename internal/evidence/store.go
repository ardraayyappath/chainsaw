package evidence

import (
	"fmt"
	"sync"
)

// ArtifactStore is a thread-safe in-memory collection of artifacts gathered
// during a forensic run. All collectors write here; the correlation engine reads from it.
type ArtifactStore struct {
	mu        sync.RWMutex
	artifacts map[string]*Artifact // keyed by Artifact.ID
}

// NewArtifactStore returns an empty, ready-to-use ArtifactStore.
func NewArtifactStore() *ArtifactStore {
	return &ArtifactStore{
		artifacts: make(map[string]*Artifact),
	}
}

// Add inserts an artifact into the store. Returns an error if the ID is empty
// or already present.
func (s *ArtifactStore) Add(a *Artifact) error {
	if a.ID == "" {
		return fmt.Errorf("artifact ID must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.artifacts[a.ID]; exists {
		return fmt.Errorf("artifact %q already in store", a.ID)
	}
	s.artifacts[a.ID] = a
	return nil
}

// GetByKind returns all artifacts whose Kind matches the given value.
func (s *ArtifactStore) GetByKind(kind ArtifactKind) []*Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Artifact
	for _, a := range s.artifacts {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// GetByEcosystem returns all artifacts whose Ecosystem matches the given value.
func (s *ArtifactStore) GetByEcosystem(eco Ecosystem) []*Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Artifact
	for _, a := range s.artifacts {
		if a.Ecosystem == eco {
			out = append(out, a)
		}
	}
	return out
}

// GetBySeverity returns all artifacts at or above the given severity level.
// Order from lowest to highest: info < low < medium < high < critical.
func (s *ArtifactStore) GetBySeverity(min Severity) []*Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Artifact
	for _, a := range s.artifacts {
		if severityRank(a.Severity) >= severityRank(min) {
			out = append(out, a)
		}
	}
	return out
}

// LinkArtifacts records a bidirectional causal relationship between two artifacts.
// Both IDs must already be present in the store.
func (s *ArtifactStore) LinkArtifacts(idA, idB string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.artifacts[idA]
	if !ok {
		return fmt.Errorf("artifact %q not found", idA)
	}
	b, ok := s.artifacts[idB]
	if !ok {
		return fmt.Errorf("artifact %q not found", idB)
	}
	if !contains(a.LinkedIDs, idB) {
		a.LinkedIDs = append(a.LinkedIDs, idB)
	}
	if !contains(b.LinkedIDs, idA) {
		b.LinkedIDs = append(b.LinkedIDs, idA)
	}
	return nil
}

// All returns a snapshot of every artifact in the store.
func (s *ArtifactStore) All() []*Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Artifact, 0, len(s.artifacts))
	for _, a := range s.artifacts {
		out = append(out, a)
	}
	return out
}

// Len returns the number of artifacts currently in the store.
func (s *ArtifactStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.artifacts)
}

// severityRank maps Severity values to comparable integers.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return -1
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
