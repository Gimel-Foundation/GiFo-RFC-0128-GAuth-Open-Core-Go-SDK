package pep

import (
        "testing"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

func validSnapshot() *PoASnapshot {
        return &PoASnapshot{
                SchemaVersion: poa.SchemaVersion,
                CredentialID:  "poa-test-001",
                MandateID:     "mandate-test-001",
                Subject:       "agent-test",
                CustomerID:    "cust_test",
                ProjectID:     "proj_test",
                Scope: poa.Scope{
                        GovernanceProfile: poa.ProfileStandard,
                        Phase:             poa.PhaseBuild,
                        AllowedPaths:      []string{"src/", "tests/"},
                        DeniedPaths:       []string{".env", "secrets/"},
                        CoreVerbs: map[string]poa.ToolPolicy{
                                "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                                "foundry.file.modify": {Allowed: true, CostCentsBase: 1},
                                "foundry.file.delete": {Allowed: true, CostCentsBase: 2},
                                "foundry.command.run": {Allowed: true, CostCentsBase: 1},
                                "foundry.agent.delegate": {Allowed: false, CostCentsBase: 5},
                        },
                        PlatformPermissions: &poa.PlatformPermissions{
                                Database: &poa.DatabasePermissions{Read: true, Write: false},
                                Secrets:  &poa.SecretPermissions{Read: false, Create: false},
                        },
                },
                Requirements: poa.Requirements{
                        ApprovalMode: poa.ApprovalAutonomous,
                        Budget:       &poa.Budget{TotalCents: 10000, RemainingCents: 5000},
                        SessionLimits: &poa.SessionLimits{
                                MaxToolCalls:      100,
                                MaxLinesPerCommit: 200,
                        },
                },
                Budget:    &poa.Budget{TotalCents: 10000, RemainingCents: 5000},
                Session:   &poa.SessionLimits{MaxToolCalls: 100, MaxLinesPerCommit: 200},
                ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
                NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
        }
}

func TestPEPPermit(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-001",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "src/main.go",
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionPermit {
                t.Errorf("Decision = %q, want PERMIT", dec.Decision)
                for _, v := range dec.Violations {
                        t.Logf("  Violation: %s (%s): %s", v.Code, v.CheckID, v.Message)
                }
        }

        if len(dec.Checks) != 16 {
                t.Errorf("Checks count = %d, want 16", len(dec.Checks))
        }
}

func TestPEPDenyPathNotAllowed(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-deny-path",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "config/database.yml",
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY", dec.Decision)
        }

        foundPathViolation := false
        for _, v := range dec.Violations {
                if v.Code == "PATH_DENIED" || v.Code == "PATH_NOT_ALLOWED" {
                        foundPathViolation = true
                }
        }
        if !foundPathViolation {
                t.Error("Expected PATH_DENIED or PATH_NOT_ALLOWED violation")
        }
}

func TestPEPDenyDeniedPath(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-deny-explicit",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.modify",
                        Resource: ".env",
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for denied path", dec.Decision)
        }
}

func TestPEPDenyVerbNotAllowed(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-deny-verb",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.agent.delegate",
                        Resource: "src/main.go",
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for disallowed verb", dec.Decision)
        }
}

func TestPEPDenyExpiredCredential(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

        req := &EnforcementRequest{
                RequestID: "req-expired",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for expired credential", dec.Decision)
        }
}

func TestPEPDenyAgentMismatch(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-mismatch",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "wrong-agent"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for agent mismatch", dec.Decision)
        }
}

func TestPEPDenyBudgetExceeded(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Budget.RemainingCents = 5

        req := &EnforcementRequest{
                RequestID: "req-budget",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "src/main.go",
                        Parameters: map[string]interface{}{
                                "amount_cents": float64(100),
                        },
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for budget exceeded", dec.Decision)
        }
}

func TestPEPDenySessionLimitExceeded(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-session",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
                Context: &EnforcementContext{
                        SessionState: &SessionState{
                                ToolCallsUsed: 100,
                        },
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for session limit exceeded", dec.Decision)
        }
}

func TestPEPConstrainFourEyes(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Requirements.ApprovalMode = poa.ApprovalFourEyes

        req := &EnforcementRequest{
                RequestID: "req-constrain",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionConstrain {
                t.Errorf("Decision = %q, want CONSTRAIN for four-eyes", dec.Decision)
        }
}

func TestPEPSkipSectorRegion(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-skip",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        sectorSkipped := false
        regionSkipped := false
        for _, c := range dec.Checks {
                if c.CheckID == "CHK-05" && c.Result == poa.CheckSkip {
                        sectorSkipped = true
                }
                if c.CheckID == "CHK-06" && c.Result == poa.CheckSkip {
                        regionSkipped = true
                }
        }

        if !sectorSkipped {
                t.Error("CHK-05 (Sector) should be skipped when no restrictions")
        }
        if !regionSkipped {
                t.Error("CHK-06 (Region) should be skipped when no restrictions")
        }
}

func TestPEPSectorDeny(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.AllowedSectors = []string{"5112", "5415"}

        req := &EnforcementRequest{
                RequestID: "req-sector-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "src/main.go",
                        Sector:   "9999",
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for sector mismatch", dec.Decision)
        }
}

func TestPEPBatchAllOrNothing(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()

        requests := []EnforcementRequest{
                {
                        RequestID:  "batch-1",
                        Timestamp:  time.Now(),
                        Agent:      AgentIdentity{AgentID: "agent-test"},
                        Action:     Action{Verb: "foundry.file.create", Resource: "src/a.go"},
                        Credential: CredentialReference{Format: poa.FormatJWT, PoASnapshot: snap},
                },
                {
                        RequestID:  "batch-2",
                        Timestamp:  time.Now(),
                        Agent:      AgentIdentity{AgentID: "agent-test"},
                        Action:     Action{Verb: "foundry.file.create", Resource: "config/bad.yml"},
                        Credential: CredentialReference{Format: poa.FormatJWT, PoASnapshot: snap},
                },
        }

        batch, err := p.BatchEnforce(requests, BatchAllOrNothing)
        if err != nil {
                t.Fatalf("BatchEnforce: %v", err)
        }

        if batch.OverallDecision != poa.DecisionDeny {
                t.Errorf("OverallDecision = %q, want DENY (all_or_nothing with one denied)", batch.OverallDecision)
        }
}

func TestPEPMissingRequestID(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                Agent:  AgentIdentity{AgentID: "agent-test"},
                Action: Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        _, err := p.EnforceAction(req)
        if err == nil {
                t.Error("Expected error for missing request_id")
        }
}

func TestPEPAuditRecord(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        req := &EnforcementRequest{
                RequestID: "req-audit",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: validSnapshot(),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }

        if dec.Audit.PEPVersion != "1.0.0-test" {
                t.Errorf("PEPVersion = %q, want %q", dec.Audit.PEPVersion, "1.0.0-test")
        }
        if dec.Audit.PEPInterfaceVersion != InterfaceVersion {
                t.Errorf("PEPInterfaceVersion = %q, want %q", dec.Audit.PEPInterfaceVersion, InterfaceVersion)
        }
        if dec.Audit.ChecksPerformed != 16 {
                t.Errorf("ChecksPerformed = %d, want 16", dec.Audit.ChecksPerformed)
        }
        if dec.Audit.AgentID != "agent-test" {
                t.Errorf("AgentID = %q, want %q", dec.Audit.AgentID, "agent-test")
        }
}

func TestPEPTransactionTypeInvalid(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-txn-invalid",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", TransactionType: "destroy"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for invalid transaction type", dec.Decision)
        }
}

func TestPEPTransactionTypePlanPhaseBlock(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        snap.Scope.Phase = poa.PhasePlan
        req := &EnforcementRequest{
                RequestID: "req-txn-plan",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", TransactionType: "write"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for write in plan phase", dec.Decision)
        }
}

func TestPEPDecisionTypeInvalid(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-dec-invalid",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", DecisionType: "magic"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for invalid decision type", dec.Decision)
        }
}

func TestPEPDecisionTypeAutomatedFourEyes(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        snap.Requirements.ApprovalMode = poa.ApprovalFourEyes
        req := &EnforcementRequest{
                RequestID: "req-dec-4eyes",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", DecisionType: "automated"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for automated under four-eyes", dec.Decision)
        }
}

func TestPEPDelegationChainNonMonotonic(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.agent.delegate"] = poa.ToolPolicy{Allowed: true, CostCentsBase: 5}
        snap.DelegationChain = &poa.DelegationChain{
                Entries: []poa.DelegationEntry{
                        {DelegateeID: "agent-a", Depth: 1},
                        {DelegateeID: "agent-b", Depth: 1},
                },
        }
        req := &EnforcementRequest{
                RequestID: "req-chain-mono",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-b"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for non-monotonic chain", dec.Decision)
        }
}

func TestPEPDelegationChainSubjectMismatch(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)

        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.agent.delegate"] = poa.ToolPolicy{Allowed: true, CostCentsBase: 5}
        snap.Subject = "agent-test"
        snap.DelegationChain = &poa.DelegationChain{
                Entries: []poa.DelegationEntry{
                        {DelegateeID: "agent-a", Depth: 1},
                        {DelegateeID: "agent-different", Depth: 2},
                },
        }
        req := &EnforcementRequest{
                RequestID: "req-chain-subj",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for terminal delegatee mismatch", dec.Decision)
        }
}
