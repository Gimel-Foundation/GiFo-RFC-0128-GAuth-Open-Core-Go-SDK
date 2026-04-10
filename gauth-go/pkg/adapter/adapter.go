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

type PolicyDecisionAdapter interface {
        Name() string
        EvaluateMandate(ctx context.Context, mandate interface{}, profile string) (*PolicyDecision, error)
        ValidateCeilings(ctx context.Context, mandate interface{}, profile string) (*CeilingValidation, error)
        EvaluateAction(ctx context.Context, action interface{}, mandate interface{}) (*ActionDecision, error)
        AdjustSeverity(baseSeverity string, profile string) string
        HealthCheck(ctx context.Context) (*AdapterHealthResult, error)
}

type WalletAdapter interface {
        Name() string
        StoreSecret(ctx context.Context, key string, value []byte) error
        RetrieveSecret(ctx context.Context, key string) ([]byte, error)
        DeleteSecret(ctx context.Context, key string) error
        HealthCheck(ctx context.Context) (*AdapterHealthResult, error)
}

type GovernanceAdapter interface {
        Name() string
        AnalyzeAuthority(ctx context.Context, mandate interface{}) (*GovernanceResult, error)
        AssessThreat(ctx context.Context, action interface{}) (*GovernanceResult, error)
        CheckCompliance(ctx context.Context, action interface{}, region string) (*GovernanceResult, error)
        HealthCheck(ctx context.Context) (*AdapterHealthResult, error)
}

type Web3IdentityAdapter interface {
        Name() string
        ResolveIdentity(ctx context.Context, identifier string) (*IdentityResult, error)
        VerifyCredential(ctx context.Context, credential []byte) (*IdentityResult, error)
        HealthCheck(ctx context.Context) (*AdapterHealthResult, error)
}

type DNAIdentityAdapter interface {
        Name() string
        VerifyBiometric(ctx context.Context, sample []byte) (*IdentityResult, error)
        HealthCheck(ctx context.Context) (*AdapterHealthResult, error)
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

type PolicyDecision struct {
        Allowed    bool     `json:"allowed"`
        Reason     string   `json:"reason"`
        Violations []string `json:"violations,omitempty"`
}

type CeilingValidation struct {
        Valid      bool     `json:"valid"`
        Violations []string `json:"violations,omitempty"`
}

type ActionDecision struct {
        Allowed     bool                   `json:"allowed"`
        Reason      string                 `json:"reason"`
        Constraints map[string]interface{} `json:"constraints,omitempty"`
}

type AdapterHealthResult struct {
        Healthy   bool    `json:"healthy"`
        LatencyMs float64 `json:"latency_ms"`
        Details   string  `json:"details,omitempty"`
}

type GovernanceResult struct {
        Decision string                 `json:"decision"`
        Score    float64                `json:"score,omitempty"`
        Details  map[string]interface{} `json:"details,omitempty"`
}

type IdentityResult struct {
        Verified bool                   `json:"verified"`
        Subject  string                 `json:"subject,omitempty"`
        Claims   map[string]interface{} `json:"claims,omitempty"`
}
