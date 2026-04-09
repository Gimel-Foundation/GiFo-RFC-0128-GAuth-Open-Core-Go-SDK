package adapter

import (
	"context"

	"github.com/gimelfoundation/gauth-go/pkg/poa"
)

type AIEnrichmentAdapter interface {
	Name() string
	EnrichScope(ctx context.Context, scope *poa.Scope) (*poa.Scope, error)
	AnalyzeRisk(ctx context.Context, credential *poa.PoACredential) (*RiskAssessment, error)
}

type RiskScoringAdapter interface {
	Name() string
	ScoreRisk(ctx context.Context, action string, resource string, credential *poa.PoACredential) (*RiskScore, error)
}

type RegulatoryReasoningAdapter interface {
	Name() string
	EvaluateCompliance(ctx context.Context, credential *poa.PoACredential, region string) (*ComplianceResult, error)
}

type OAuthEngineAdapter interface {
	Name() string
	IssueToken(ctx context.Context, credential *poa.PoACredential) (string, error)
	IntrospectToken(ctx context.Context, token string) (*TokenIntrospection, error)
	RevokeToken(ctx context.Context, token string) error
	GetJWKS(ctx context.Context) ([]byte, error)
}

type FoundryAdapter interface {
	Name() string
	ExecuteAction(ctx context.Context, verb string, resource string, params map[string]interface{}) (*ActionResult, error)
}

type RiskAssessment struct {
	Score   float64            `json:"score"`
	Level   string             `json:"level"`
	Factors map[string]float64 `json:"factors,omitempty"`
	Detail  string             `json:"detail,omitempty"`
}

type RiskScore struct {
	Score  float64 `json:"score"`
	Level  string  `json:"level"`
	Detail string  `json:"detail,omitempty"`
}

type ComplianceResult struct {
	Compliant bool     `json:"compliant"`
	Violations []string `json:"violations,omitempty"`
	Region    string   `json:"region"`
	Detail    string   `json:"detail,omitempty"`
}

type TokenIntrospection struct {
	Active       bool              `json:"active"`
	Subject      string            `json:"sub,omitempty"`
	ClientID     string            `json:"client_id,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	ExpiresAt    int64             `json:"exp,omitempty"`
	MandateID    string            `json:"mandate_id,omitempty"`
	MandateStatus poa.MandateStatus `json:"mandate_status,omitempty"`
}

type ActionResult struct {
	Success bool                   `json:"success"`
	Output  map[string]interface{} `json:"output,omitempty"`
	Error   string                 `json:"error,omitempty"`
}
