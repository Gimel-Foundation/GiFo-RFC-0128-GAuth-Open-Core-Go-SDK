package management

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gimelfoundation/gauth-go/pkg/poa"
)

type MemoryStore struct {
	mu       sync.RWMutex
	mandates map[string]*Mandate
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		mandates: make(map[string]*Mandate),
	}
}

func deepCopyMandate(m *Mandate) *Mandate {
	data, err := json.Marshal(m)
	if err != nil {
		copy := *m
		return &copy
	}
	var copy Mandate
	if err := json.Unmarshal(data, &copy); err != nil {
		shallow := *m
		return &shallow
	}
	return &copy
}

func (s *MemoryStore) Save(mandate *Mandate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mandates[mandate.MandateID] = deepCopyMandate(mandate)
	return nil
}

func (s *MemoryStore) Get(mandateID string) (*Mandate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.mandates[mandateID]
	if !ok {
		return nil, fmt.Errorf("gauth: mandate %q not found", mandateID)
	}
	return deepCopyMandate(m), nil
}

func (s *MemoryStore) List(customerID, projectID string, status *poa.MandateStatus, limit, offset int) ([]*Mandate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Mandate
	for _, m := range s.mandates {
		if customerID != "" && m.Parties.CustomerID != customerID {
			continue
		}
		if projectID != "" && m.Parties.ProjectID != projectID {
			continue
		}
		if status != nil && m.Status != *status {
			continue
		}
		result = append(result, deepCopyMandate(m))
	}

	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *MemoryStore) FindActive(agentID, projectID string) (*Mandate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.mandates {
		if m.Status == poa.StatusActive &&
			m.Parties.Subject == agentID &&
			m.Parties.ProjectID == projectID {
			return deepCopyMandate(m), nil
		}
	}
	return nil, fmt.Errorf("gauth: no active mandate found for agent %q project %q", agentID, projectID)
}
