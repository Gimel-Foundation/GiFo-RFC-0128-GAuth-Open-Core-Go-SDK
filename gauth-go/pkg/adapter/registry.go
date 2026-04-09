package adapter

import (
        "crypto/ed25519"
        "errors"
        "fmt"
        "sync"
)

var (
        ErrAdapterNotFound     = errors.New("gauth: adapter not found")
        ErrInvalidSignature    = errors.New("gauth: adapter signature verification failed")
        ErrAdapterAlreadyExists = errors.New("gauth: adapter already registered")
        ErrMissingSignature    = errors.New("gauth: adapter registration requires Ed25519 signature")
)

type AdapterType string

const (
        TypeAIEnrichment       AdapterType = "ai_enrichment"
        TypeRiskScoring        AdapterType = "risk_scoring"
        TypeRegulatoryReasoning AdapterType = "regulatory_reasoning"
        TypeOAuthEngine        AdapterType = "oauth_engine"
        TypeFoundry            AdapterType = "foundry"
)

type Registration struct {
        Name      string
        Type      AdapterType
        Adapter   interface{}
        Signature []byte
        Payload   []byte
}

type Registry struct {
        mu          sync.RWMutex
        adapters    map[string]interface{}
        trustedKeys []ed25519.PublicKey
}

func NewRegistry() *Registry {
        return &Registry{
                adapters: make(map[string]interface{}),
        }
}

func (r *Registry) AddTrustedKey(key ed25519.PublicKey) {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.trustedKeys = append(r.trustedKeys, key)
}


func (r *Registry) Register(reg Registration) error {
        r.mu.Lock()
        defer r.mu.Unlock()

        key := registryKey(reg.Type, reg.Name)
        if _, exists := r.adapters[key]; exists {
                return fmt.Errorf("%w: %s", ErrAdapterAlreadyExists, key)
        }

        if reg.Signature == nil || reg.Payload == nil {
                return ErrMissingSignature
        }

        verified := false
        for _, pubKey := range r.trustedKeys {
                if ed25519.Verify(pubKey, reg.Payload, reg.Signature) {
                        verified = true
                        break
                }
        }

        if !verified {
                return ErrInvalidSignature
        }

        r.adapters[key] = reg.Adapter
        return nil
}

func (r *Registry) registerInternal(reg Registration) error {
        r.mu.Lock()
        defer r.mu.Unlock()

        key := registryKey(reg.Type, reg.Name)
        if _, exists := r.adapters[key]; exists {
                return fmt.Errorf("%w: %s", ErrAdapterAlreadyExists, key)
        }

        r.adapters[key] = reg.Adapter
        return nil
}

func (r *Registry) Get(adapterType AdapterType, name string) (interface{}, error) {
        r.mu.RLock()
        defer r.mu.RUnlock()

        key := registryKey(adapterType, name)
        adapter, ok := r.adapters[key]
        if !ok {
                return nil, fmt.Errorf("%w: %s", ErrAdapterNotFound, key)
        }
        return adapter, nil
}

func (r *Registry) Validate(adapterType AdapterType, name string) bool {
        r.mu.RLock()
        defer r.mu.RUnlock()
        key := registryKey(adapterType, name)
        _, ok := r.adapters[key]
        return ok
}

func (r *Registry) List(adapterType AdapterType) []string {
        r.mu.RLock()
        defer r.mu.RUnlock()

        prefix := string(adapterType) + ":"
        var names []string
        for k := range r.adapters {
                if len(k) > len(prefix) && k[:len(prefix)] == prefix {
                        names = append(names, k[len(prefix):])
                }
        }
        return names
}

func registryKey(t AdapterType, name string) string {
        return string(t) + ":" + name
}
