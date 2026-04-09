package pep

import (
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type StateStore interface {
        GetMandateState(mandateID string) (*LiveMandateState, error)
        DeductBudget(mandateID string, cents int) error
        IncrementToolCalls(mandateID string) error
}

type PEP struct {
        Version    string
        Mode       poa.EnforcementMode
        StateStore StateStore
}

func New(version string, mode poa.EnforcementMode) *PEP {
        return &PEP{
                Version: version,
                Mode:    mode,
        }
}

func NewStateful(version string, store StateStore) *PEP {
        return &PEP{
                Version:    version,
                Mode:       poa.ModeStateful,
                StateStore: store,
        }
}

func (p *PEP) EnforceAction(req *EnforcementRequest) (*EnforcementDecision, error) {
        start := time.Now()

        if req.RequestID == "" {
                return nil, &EnforcementError{
                        ErrorCode: "INVALID_REQUEST",
                        Message:   "request_id is required",
                        Timestamp: time.Now(),
                }
        }

        snap := req.Credential.PoASnapshot
        if snap == nil {
                return nil, &EnforcementError{
                        ErrorCode: "CREDENTIAL_PARSE_ERROR",
                        Message:   "poa_snapshot is required for enforcement evaluation",
                        Timestamp: time.Now(),
                        RequestID: req.RequestID,
                }
        }

        if p.Mode == poa.ModeStateful {
                if p.StateStore == nil {
                        return nil, &EnforcementError{
                                ErrorCode: "STATE_STORE_MISSING",
                                Message:   "stateful mode requires a StateStore",
                                Timestamp: time.Now(),
                                RequestID: req.RequestID,
                        }
                }
                liveState, err := p.StateStore.GetMandateState(snap.MandateID)
                if err != nil {
                        return nil, &EnforcementError{
                                ErrorCode: "STATE_LOOKUP_FAILED",
                                Message:   "failed to retrieve live mandate state: " + err.Error(),
                                Timestamp: time.Now(),
                                RequestID: req.RequestID,
                        }
                }
                if req.Context == nil {
                        req.Context = &EnforcementContext{}
                }
                req.Context.LiveMandateState = liveState
        }

        var checks []CheckResult
        var violations []Violation
        var constraints []EnforcedConstraint

        passed := 0
        failed := 0
        skipped := 0

        for _, chk := range checkPipeline {
                result := chk.Fn(req, snap)
                result.CheckID = chk.ID
                result.CheckName = chk.Name
                checks = append(checks, result)

                switch result.Result {
                case poa.CheckPass:
                        passed++
                case poa.CheckSkip:
                        skipped++
                case poa.CheckFail:
                        failed++
                        violations = append(violations, Violation{
                                Code:     violationCodeForCheck(chk.ID),
                                Message:  result.Detail,
                                CheckID:  chk.ID,
                                Severity: poa.SeverityError,
                        })
                case poa.CheckConstrain:
                        passed++
                        constraints = append(constraints, EnforcedConstraint{
                                ConstraintType: chk.ID + "_constraint",
                                CheckID:        chk.ID,
                                Requested:      req.Action.Resource,
                                Enforced:       result.Detail,
                        })
                }
        }

        decision := poa.DecisionPermit
        if failed > 0 {
                decision = poa.DecisionDeny
        } else if len(constraints) > 0 {
                decision = poa.DecisionConstrain
        }

        if p.Mode == poa.ModeStateful && decision == poa.DecisionPermit {
                cost := req.Action.AmountCents()
                if cost > 0 {
                        if err := p.StateStore.DeductBudget(snap.MandateID, cost); err != nil {
                                return nil, &EnforcementError{
                                        ErrorCode: "STATE_UPDATE_FAILED",
                                        Message:   "failed to deduct budget: " + err.Error(),
                                        Timestamp: time.Now(),
                                        RequestID: req.RequestID,
                                }
                        }
                }
                if err := p.StateStore.IncrementToolCalls(snap.MandateID); err != nil {
                        return nil, &EnforcementError{
                                ErrorCode: "STATE_UPDATE_FAILED",
                                Message:   "failed to increment tool calls: " + err.Error(),
                                Timestamp: time.Now(),
                                RequestID: req.RequestID,
                        }
                }
        }

        elapsed := time.Since(start)

        return &EnforcementDecision{
                RequestID:       req.RequestID,
                Decision:        decision,
                Timestamp:       time.Now(),
                EnforcementMode: p.Mode,
                Checks:          checks,
                EnforcedConstraints: constraints,
                Violations:      violations,
                Audit: AuditRecord{
                        ProcessingTimeMs:    float64(elapsed.Microseconds()) / 1000.0,
                        PEPVersion:          p.Version,
                        PEPInterfaceVersion: InterfaceVersion,
                        CredentialJTI:       "",
                        MandateID:           snap.MandateID,
                        AgentID:             req.Agent.AgentID,
                        ActionVerb:          req.Action.Verb,
                        ActionResource:      req.Action.Resource,
                        ChecksPerformed:     len(checks),
                        ChecksPassed:        passed,
                        ChecksFailed:        failed,
                        ChecksSkipped:       skipped,
                },
        }, nil
}

func (p *PEP) BatchEnforce(requests []EnforcementRequest, mode BatchMode) (*BatchDecision, error) {
        var decisions []EnforcementDecision

        for i := range requests {
                dec, err := p.EnforceAction(&requests[i])
                if err != nil {
                        return nil, err
                }
                decisions = append(decisions, *dec)
        }

        overall := poa.DecisionPermit
        hasConstrain := false

        for _, d := range decisions {
                if d.Decision == poa.DecisionDeny {
                        if mode == BatchAllOrNothing {
                                overall = poa.DecisionDeny
                                break
                        }
                        overall = poa.DecisionDeny
                }
                if d.Decision == poa.DecisionConstrain {
                        hasConstrain = true
                }
        }

        if overall != poa.DecisionDeny && hasConstrain {
                overall = poa.DecisionConstrain
        }

        if mode == BatchAllOrNothing && overall == poa.DecisionDeny {
                for i := range decisions {
                        decisions[i].Decision = poa.DecisionDeny
                }
        }

        return &BatchDecision{
                OverallDecision: overall,
                Decisions:       decisions,
        }, nil
}

func (p *PEP) GetEnforcementPolicy(snap *PoASnapshot) *EnforcementPolicy {
        var allowedVerbs []string
        if snap.Scope.CoreVerbs != nil {
                for k, v := range snap.Scope.CoreVerbs {
                        if v.Allowed {
                                allowedVerbs = append(allowedVerbs, k)
                        }
                }
        }

        policy := &EnforcementPolicy{
                GovernanceProfile: snap.Scope.GovernanceProfile,
                Phase:             snap.Scope.Phase,
                AllowedVerbs:      allowedVerbs,
                DeniedPaths:       snap.Scope.DeniedPaths,
                AllowedPaths:      snap.Scope.AllowedPaths,
                Budget:            snap.Budget,
                ApprovalMode:      snap.Requirements.ApprovalMode,
        }

        if snap.Scope.CoreVerbs != nil {
                if dp, ok := snap.Scope.CoreVerbs["foundry.agent.delegate"]; ok {
                        delegation := &DelegationPolicy{
                                Allowed: dp.Allowed,
                        }
                        if dp.Constraints != nil && dp.Constraints.MaxDelegationDepth != nil {
                                delegation.MaxDepth = *dp.Constraints.MaxDelegationDepth
                        }
                        policy.Delegation = delegation
                }
        }

        return policy
}

func violationCodeForCheck(checkID string) string {
        codes := map[string]string{
                "CHK-01": "CREDENTIAL_INVALID",
                "CHK-02": "CREDENTIAL_EXPIRED",
                "CHK-03": "PROFILE_CEILING_EXCEEDED",
                "CHK-04": "PHASE_MISMATCH",
                "CHK-05": "SECTOR_MISMATCH",
                "CHK-06": "REGION_MISMATCH",
                "CHK-07": "PATH_DENIED",
                "CHK-08": "VERB_NOT_ALLOWED",
                "CHK-09": "CONSTRAINT_VIOLATED",
                "CHK-10": "PLATFORM_PERMISSION_DENIED",
                "CHK-11": "TRANSACTION_NOT_ALLOWED",
                "CHK-12": "DECISION_NOT_ALLOWED",
                "CHK-13": "BUDGET_EXCEEDED",
                "CHK-14": "SESSION_LIMIT_EXCEEDED",
                "CHK-15": "APPROVAL_REQUIRED",
                "CHK-16": "DELEGATION_DEPTH_EXCEEDED",
        }
        if code, ok := codes[checkID]; ok {
                return code
        }
        return "UNKNOWN"
}
