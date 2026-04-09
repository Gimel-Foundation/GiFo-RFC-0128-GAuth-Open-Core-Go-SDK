package adapter

import (
        "context"
        "crypto/ed25519"
        "crypto/rand"
        "testing"
)

func TestRegistryWithTrustedPackage(t *testing.T) {
        registry := NewRegistry()
        RegisterDefaults(registry)

        adapters := registry.List(TypeAIEnrichment)
        if len(adapters) == 0 {
                t.Error("Expected default AI enrichment adapter")
        }

        a, err := registry.Get(TypeAIEnrichment, "noop")
        if err != nil {
                t.Fatalf("Get noop AI enrichment: %v", err)
        }

        enricher, ok := a.(AIEnrichmentAdapter)
        if !ok {
                t.Fatal("Expected AIEnrichmentAdapter interface")
        }

        if enricher.Name() != "noop-ai-enrichment" {
                t.Errorf("Name = %q, want %q", enricher.Name(), "noop-ai-enrichment")
        }
}

func TestRegistrySignatureVerification(t *testing.T) {
        registry := NewRegistry()

        pub, priv, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatalf("GenerateKey: %v", err)
        }

        registry.AddTrustedKey(pub)

        payload := []byte("test-adapter-registration-payload")
        sig := ed25519.Sign(priv, payload)

        err = registry.Register(Registration{
                Name:      "custom-enrichment",
                Type:      TypeAIEnrichment,
                Adapter:   &NoOpAIEnrichmentAdapter{},
                Signature: sig,
                Payload:   payload,
        })
        if err != nil {
                t.Fatalf("Register with valid signature: %v", err)
        }

        if !registry.Validate(TypeAIEnrichment, "custom-enrichment") {
                t.Error("Adapter should be valid after registration")
        }
}

func TestRegistryInvalidSignature(t *testing.T) {
        registry := NewRegistry()

        pub, _, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatalf("GenerateKey: %v", err)
        }
        registry.AddTrustedKey(pub)

        _, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
        payload := []byte("test-adapter-registration-payload")
        wrongSig := ed25519.Sign(wrongPriv, payload)

        err = registry.Register(Registration{
                Name:      "bad-adapter",
                Type:      TypeAIEnrichment,
                Adapter:   &NoOpAIEnrichmentAdapter{},
                Signature: wrongSig,
                Payload:   payload,
        })

        if err != ErrInvalidSignature {
                t.Errorf("Expected ErrInvalidSignature, got %v", err)
        }
}

func TestRegistryMissingSignature(t *testing.T) {
        registry := NewRegistry()

        err := registry.Register(Registration{
                Name:    "unsigned-adapter",
                Type:    TypeAIEnrichment,
                Adapter: &NoOpAIEnrichmentAdapter{},
        })

        if err != ErrMissingSignature {
                t.Errorf("Expected ErrMissingSignature, got %v", err)
        }
}

func TestRegistryDuplicateAdapter(t *testing.T) {
        registry := NewRegistry()
        RegisterDefaults(registry)

        pub, priv, _ := ed25519.GenerateKey(rand.Reader)
        registry.AddTrustedKey(pub)

        payload := []byte("dup-adapter-payload")
        sig := ed25519.Sign(priv, payload)

        err := registry.Register(Registration{
                Name:      "noop",
                Type:      TypeAIEnrichment,
                Adapter:   &NoOpAIEnrichmentAdapter{},
                Signature: sig,
                Payload:   payload,
        })

        if err == nil {
                t.Error("Expected error for duplicate adapter registration")
        }
}

func TestNoOpAdapters(t *testing.T) {
        ctx := context.Background()

        enrichment := &NoOpAIEnrichmentAdapter{}
        risk, _ := enrichment.AnalyzeRisk(ctx, nil)
        if risk.Level != "none" {
                t.Errorf("Risk level = %q, want %q", risk.Level, "none")
        }

        scoring := &NoOpRiskScoringAdapter{}
        score, _ := scoring.ScoreRisk(ctx, "verb", "resource", nil)
        if score.Level != "none" {
                t.Errorf("Score level = %q, want %q", score.Level, "none")
        }

        regulatory := &NoOpRegulatoryReasoningAdapter{}
        compliance, _ := regulatory.EvaluateCompliance(ctx, nil, "EU")
        if !compliance.Compliant {
                t.Error("No-op regulatory should return compliant")
        }

        oauth := &NoOpOAuthEngineAdapter{}
        introspect, _ := oauth.IntrospectToken(ctx, "test")
        if introspect.Active {
                t.Error("No-op OAuth introspect should return inactive")
        }

        foundry := &NoOpFoundryAdapter{}
        result, _ := foundry.ExecuteAction(ctx, "verb", "resource", nil)
        if result.Success {
                t.Error("No-op foundry should return not successful")
        }
}

func TestRegistryListAndGet(t *testing.T) {
        registry := NewRegistry()
        RegisterDefaults(registry)

        types := []AdapterType{TypeAIEnrichment, TypeRiskScoring, TypeRegulatoryReasoning, TypeOAuthEngine, TypeFoundry}
        for _, at := range types {
                list := registry.List(at)
                if len(list) == 0 {
                        t.Errorf("No adapters registered for type %q", at)
                }

                _, err := registry.Get(at, "noop")
                if err != nil {
                        t.Errorf("Get noop for type %q: %v", at, err)
                }
        }

        _, err := registry.Get(TypeAIEnrichment, "nonexistent")
        if err == nil {
                t.Error("Expected error for nonexistent adapter")
        }
}
