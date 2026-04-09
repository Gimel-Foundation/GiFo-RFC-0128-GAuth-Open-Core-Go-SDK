package adapter

import (
        "context"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type NoOpAIEnrichmentAdapter struct{}

func (n *NoOpAIEnrichmentAdapter) Name() string { return "noop-ai-enrichment" }

func (n *NoOpAIEnrichmentAdapter) EnrichScope(_ context.Context, scope *poa.Scope) (*poa.Scope, error) {
        return scope, nil
}

func (n *NoOpAIEnrichmentAdapter) AnalyzeRisk(_ context.Context, _ *poa.PoACredential) (*RiskAssessment, error) {
        return &RiskAssessment{
                Score:  0,
                Level:  "none",
                Detail: "No-op adapter: no risk analysis performed",
        }, nil
}

type NoOpRiskScoringAdapter struct{}

func (n *NoOpRiskScoringAdapter) Name() string { return "noop-risk-scoring" }

func (n *NoOpRiskScoringAdapter) ScoreRisk(_ context.Context, _ string, _ string, _ *poa.PoACredential) (*RiskScore, error) {
        return &RiskScore{
                Score:  0,
                Level:  "none",
                Detail: "No-op adapter: no risk scoring performed",
        }, nil
}

type NoOpRegulatoryReasoningAdapter struct{}

func (n *NoOpRegulatoryReasoningAdapter) Name() string { return "noop-regulatory-reasoning" }

func (n *NoOpRegulatoryReasoningAdapter) EvaluateCompliance(_ context.Context, _ *poa.PoACredential, region string) (*ComplianceResult, error) {
        return &ComplianceResult{
                Compliant: true,
                Region:    region,
                Detail:    "No-op adapter: compliance evaluation skipped",
        }, nil
}

type NoOpOAuthEngineAdapter struct{}

func (n *NoOpOAuthEngineAdapter) Name() string { return "noop-oauth-engine" }

func (n *NoOpOAuthEngineAdapter) IssueToken(_ context.Context, _ *poa.PoACredential) (string, error) {
        return "", ErrAdapterNotFound
}

func (n *NoOpOAuthEngineAdapter) IntrospectToken(_ context.Context, _ string) (*TokenIntrospection, error) {
        return &TokenIntrospection{Active: false}, nil
}

func (n *NoOpOAuthEngineAdapter) RevokeToken(_ context.Context, _ string) error {
        return nil
}

func (n *NoOpOAuthEngineAdapter) GetJWKS(_ context.Context) ([]byte, error) {
        return []byte(`{"keys":[]}`), nil
}

type NoOpFoundryAdapter struct{}

func (n *NoOpFoundryAdapter) Name() string { return "noop-foundry" }

func (n *NoOpFoundryAdapter) ExecuteAction(_ context.Context, verb string, resource string, _ map[string]interface{}) (*ActionResult, error) {
        return &ActionResult{
                Success: false,
                Error:   "No-op adapter: action execution not available",
        }, nil
}

func RegisterDefaults(registry *Registry) {
        noopReg := func(t AdapterType, name string, a interface{}) {
                registry.registerInternal(Registration{
                        Name:    name,
                        Type:    t,
                        Adapter: a,
                })
        }

        noopReg(TypeAIEnrichment, "noop", &NoOpAIEnrichmentAdapter{})
        noopReg(TypeRiskScoring, "noop", &NoOpRiskScoringAdapter{})
        noopReg(TypeRegulatoryReasoning, "noop", &NoOpRegulatoryReasoningAdapter{})
        noopReg(TypeOAuthEngine, "noop", &NoOpOAuthEngineAdapter{})
        noopReg(TypeFoundry, "noop", &NoOpFoundryAdapter{})
}
