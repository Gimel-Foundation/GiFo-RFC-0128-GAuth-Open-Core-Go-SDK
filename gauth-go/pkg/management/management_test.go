package management

import (
        "net/http"
        "net/http/httptest"
        "testing"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

func newTestManager() *MandateManager {
        return NewMandateManager(NewMemoryStore())
}

func validCreationRequest() *MandateCreationRequest {
        return &MandateCreationRequest{
                Parties: poa.Parties{
                        Subject:    "agent-test",
                        CustomerID: "cust_test",
                        ProjectID:  "proj_test",
                        IssuedBy:   "user_test",
                },
                Scope: poa.Scope{
                        GovernanceProfile: poa.ProfileStandard,
                        Phase:             poa.PhaseBuild,
                        AllowedPaths:      []string{"src/"},
                        DeniedPaths:       []string{".env"},
                        CoreVerbs: map[string]poa.ToolPolicy{
                                "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                        },
                },
                Requirements: poa.Requirements{
                        ApprovalMode: poa.ApprovalAutonomous,
                        Budget: &poa.Budget{
                                TotalCents:     10000,
                                RemainingCents: 10000,
                        },
                        TTLSeconds: 3600,
                },
        }
}

func TestCreateMandate(t *testing.T) {
        mgr := newTestManager()
        resp, err := mgr.CreateMandate(validCreationRequest(), "admin")
        if err != nil {
                t.Fatalf("CreateMandate: %v", err)
        }

        if resp.MandateID == "" {
                t.Error("MandateID should not be empty")
        }
        if resp.Status != poa.StatusDraft {
                t.Errorf("Status = %q, want draft", resp.Status)
        }
        if resp.ScopeChecksum == "" {
                t.Error("ScopeChecksum should not be empty")
        }
}

func TestMandateLifecycle(t *testing.T) {
        mgr := newTestManager()
        resp, err := mgr.CreateMandate(validCreationRequest(), "admin")
        if err != nil {
                t.Fatalf("CreateMandate: %v", err)
        }

        if err := mgr.ActivateMandate(resp.MandateID, "admin"); err != nil {
                t.Fatalf("ActivateMandate: %v", err)
        }

        mandate, err := mgr.GetMandate(resp.MandateID)
        if err != nil {
                t.Fatalf("GetMandate: %v", err)
        }
        if mandate.Status != poa.StatusActive {
                t.Errorf("Status = %q, want active", mandate.Status)
        }

        if err := mgr.SuspendMandate(resp.MandateID, "admin", "security review"); err != nil {
                t.Fatalf("SuspendMandate: %v", err)
        }

        mandate, _ = mgr.GetMandate(resp.MandateID)
        if mandate.Status != poa.StatusSuspended {
                t.Errorf("Status = %q, want suspended", mandate.Status)
        }

        if err := mgr.ResumeMandate(resp.MandateID, "admin"); err != nil {
                t.Fatalf("ResumeMandate: %v", err)
        }

        mandate, _ = mgr.GetMandate(resp.MandateID)
        if mandate.Status != poa.StatusActive {
                t.Errorf("Status = %q, want active after resume", mandate.Status)
        }

        if err := mgr.RevokeMandate(resp.MandateID, "admin", "no longer needed"); err != nil {
                t.Fatalf("RevokeMandate: %v", err)
        }

        mandate, _ = mgr.GetMandate(resp.MandateID)
        if mandate.Status != poa.StatusRevoked {
                t.Errorf("Status = %q, want revoked", mandate.Status)
        }
}

func TestInvalidTransitions(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")

        if err := mgr.SuspendMandate(resp.MandateID, "admin", "test"); err == nil {
                t.Error("Should not suspend a DRAFT mandate")
        }

        if err := mgr.ResumeMandate(resp.MandateID, "admin"); err == nil {
                t.Error("Should not resume a DRAFT mandate")
        }

        mgr.ActivateMandate(resp.MandateID, "admin")
        mgr.RevokeMandate(resp.MandateID, "admin", "test")

        if err := mgr.ActivateMandate(resp.MandateID, "admin"); err == nil {
                t.Error("Should not activate a REVOKED mandate")
        }

        if err := mgr.SuspendMandate(resp.MandateID, "admin", "test"); err == nil {
                t.Error("Should not suspend a REVOKED mandate")
        }

        if err := mgr.RevokeMandate(resp.MandateID, "admin", "again"); err == nil {
                t.Error("Should not revoke a REVOKED mandate (terminal)")
        }
}

func TestExtendTTL(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        mandate, _ := mgr.GetMandate(resp.MandateID)
        origTTL := mandate.Requirements.TTLSeconds

        if err := mgr.ExtendTTL(resp.MandateID, "admin", 1800); err != nil {
                t.Fatalf("ExtendTTL: %v", err)
        }

        mandate, _ = mgr.GetMandate(resp.MandateID)
        if mandate.Requirements.TTLSeconds != origTTL+1800 {
                t.Errorf("TTL = %d, want %d", mandate.Requirements.TTLSeconds, origTTL+1800)
        }
}

func TestExtendTTLNotAdditive(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        if err := mgr.ExtendTTL(resp.MandateID, "admin", -100); err != ErrTTLOnlyAdditive {
                t.Errorf("Expected ErrTTLOnlyAdditive, got %v", err)
        }
}

func TestIncreaseBudget(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        if err := mgr.IncreaseBudget(resp.MandateID, "admin", 5000); err != nil {
                t.Fatalf("IncreaseBudget: %v", err)
        }

        mandate, _ := mgr.GetMandate(resp.MandateID)
        if mandate.Requirements.Budget.TotalCents != 15000 {
                t.Errorf("TotalCents = %d, want 15000", mandate.Requirements.Budget.TotalCents)
        }
        if mandate.Requirements.Budget.RemainingCents != 15000 {
                t.Errorf("RemainingCents = %d, want 15000", mandate.Requirements.Budget.RemainingCents)
        }
}

func TestIncreaseBudgetNotAdditive(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        if err := mgr.IncreaseBudget(resp.MandateID, "admin", -100); err != ErrBudgetOnlyAdditive {
                t.Errorf("Expected ErrBudgetOnlyAdditive, got %v", err)
        }
}

func TestTerminalStateOperations(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")
        mgr.RevokeMandate(resp.MandateID, "admin", "test")

        if err := mgr.ExtendTTL(resp.MandateID, "admin", 1000); err != ErrTerminalState {
                t.Errorf("Expected ErrTerminalState, got %v", err)
        }

        if err := mgr.IncreaseBudget(resp.MandateID, "admin", 1000); err != ErrTerminalState {
                t.Errorf("Expected ErrTerminalState, got %v", err)
        }
}

func TestSupersede(t *testing.T) {
        mgr := newTestManager()

        req := validCreationRequest()
        resp1, _ := mgr.CreateMandate(req, "admin")
        mgr.ActivateMandate(resp1.MandateID, "admin")

        resp2, _ := mgr.CreateMandate(req, "admin")
        mgr.ActivateMandate(resp2.MandateID, "admin")

        mandate1, _ := mgr.GetMandate(resp1.MandateID)
        if mandate1.Status != poa.StatusSuperseded {
                t.Errorf("Old mandate status = %q, want superseded", mandate1.Status)
        }

        mandate2, _ := mgr.GetMandate(resp2.MandateID)
        if mandate2.Status != poa.StatusActive {
                t.Errorf("New mandate status = %q, want active", mandate2.Status)
        }
}

func TestValidationErrors(t *testing.T) {
        mgr := newTestManager()

        tests := []struct {
                name string
                req  *MandateCreationRequest
        }{
                {"missing subject", &MandateCreationRequest{
                        Parties:      poa.Parties{CustomerID: "c", ProjectID: "p", IssuedBy: "u"},
                        Scope:        poa.Scope{GovernanceProfile: poa.ProfileStandard, Phase: poa.PhaseBuild},
                        Requirements: poa.Requirements{ApprovalMode: poa.ApprovalAutonomous},
                }},
                {"missing customer_id", &MandateCreationRequest{
                        Parties:      poa.Parties{Subject: "s", ProjectID: "p", IssuedBy: "u"},
                        Scope:        poa.Scope{GovernanceProfile: poa.ProfileStandard, Phase: poa.PhaseBuild},
                        Requirements: poa.Requirements{ApprovalMode: poa.ApprovalAutonomous},
                }},
                {"invalid approval_mode", &MandateCreationRequest{
                        Parties:      poa.Parties{Subject: "s", CustomerID: "c", ProjectID: "p", IssuedBy: "u"},
                        Scope:        poa.Scope{GovernanceProfile: poa.ProfileStandard, Phase: poa.PhaseBuild},
                        Requirements: poa.Requirements{ApprovalMode: "invalid"},
                }},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        _, err := mgr.CreateMandate(tt.req, "admin")
                        if err == nil {
                                t.Error("Expected validation error")
                        }
                })
        }
}

func TestFourEyesRequiresApprovalChain(t *testing.T) {
        mgr := newTestManager()
        req := validCreationRequest()
        req.Requirements.ApprovalMode = poa.ApprovalFourEyes

        resp, err := mgr.CreateMandate(req, "admin")
        if err != nil {
                t.Fatalf("CreateMandate: %v", err)
        }

        err = mgr.ActivateMandate(resp.MandateID, "admin")
        if err == nil {
                t.Error("Expected error: four-eyes requires approval_chain")
        }
}

func TestAuditLog(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")
        mgr.SuspendMandate(resp.MandateID, "security", "investigation")

        mandate, _ := mgr.GetMandate(resp.MandateID)
        if len(mandate.AuditLog) < 3 {
                t.Errorf("AuditLog entries = %d, want >= 3", len(mandate.AuditLog))
        }
}

func TestCreateDelegation(t *testing.T) {
        mgr := newTestManager()
        req := validCreationRequest()
        maxDepth := 2
        req.Scope.CoreVerbs["foundry.agent.delegate"] = poa.ToolPolicy{
                Allowed:       true,
                CostCentsBase: 5,
                Constraints: &poa.VerbConstraints{
                        MaxDelegationDepth: &maxDepth,
                },
        }
        resp, _ := mgr.CreateMandate(req, "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        if err := mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub-1"); err != nil {
                t.Fatalf("CreateDelegation: %v", err)
        }

        mandate, _ := mgr.GetMandate(resp.MandateID)
        if mandate.Parties.Delegation == nil || len(mandate.Parties.Delegation.Entries) != 1 {
                t.Fatal("Expected 1 delegation entry")
        }
        if mandate.Parties.Delegation.Entries[0].DelegateeID != "agent-sub-1" {
                t.Errorf("DelegateeID = %q, want %q", mandate.Parties.Delegation.Entries[0].DelegateeID, "agent-sub-1")
        }

        if err := mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub-2"); err != nil {
                t.Fatalf("CreateDelegation 2: %v", err)
        }

        err := mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub-3")
        if err == nil {
                t.Error("Expected error: max delegation depth reached")
        }
}

func TestCreateDelegationNotAllowed(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        err := mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub")
        if err == nil {
                t.Error("Expected error: delegation verb not allowed")
        }
}

func TestRevokeDelegation(t *testing.T) {
        mgr := newTestManager()
        req := validCreationRequest()
        req.Scope.CoreVerbs["foundry.agent.delegate"] = poa.ToolPolicy{Allowed: true}
        resp, _ := mgr.CreateMandate(req, "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub-1")
        mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub-2")

        if err := mgr.RevokeDelegation(resp.MandateID, "admin", "agent-sub-1"); err != nil {
                t.Fatalf("RevokeDelegation: %v", err)
        }

        mandate, _ := mgr.GetMandate(resp.MandateID)
        if len(mandate.Parties.Delegation.Entries) != 0 {
                t.Errorf("Entries = %d, want 0 (revoke cascades downstream)", len(mandate.Parties.Delegation.Entries))
        }
}

func TestAssignGovernanceProfile(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")

        if err := mgr.AssignGovernanceProfile(resp.MandateID, "admin", poa.ProfileStrict); err != nil {
                t.Fatalf("AssignGovernanceProfile: %v", err)
        }

        mandate, _ := mgr.GetMandate(resp.MandateID)
        if mandate.Scope.GovernanceProfile != poa.ProfileStrict {
                t.Errorf("GovernanceProfile = %q, want %q", mandate.Scope.GovernanceProfile, poa.ProfileStrict)
        }
        if mandate.ScopeChecksum == "" {
                t.Error("ScopeChecksum should be updated after profile change")
        }
}

func TestAssignGovernanceProfileInvalid(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")

        err := mgr.AssignGovernanceProfile(resp.MandateID, "admin", "invalid_profile")
        if err == nil {
                t.Error("Expected error for invalid governance profile")
        }
}

func TestAssignGovernanceProfileTerminal(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")
        mgr.RevokeMandate(resp.MandateID, "admin", "test")

        err := mgr.AssignGovernanceProfile(resp.MandateID, "admin", poa.ProfileStrict)
        if err == nil {
                t.Error("Expected error for terminal state")
        }
}

func TestStoreMutationIsolation(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")

        m1, _ := mgr.GetMandate(resp.MandateID)
        m1.Status = poa.StatusActive

        m2, _ := mgr.GetMandate(resp.MandateID)
        if m2.Status != poa.StatusDraft {
                t.Errorf("Store mutation leaked: status = %q, want draft", m2.Status)
        }
}

func TestHTTPEmptyMandateID(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodGet, "/gauth/mgmt/v1/mandates/", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusBadRequest {
                t.Errorf("Expected 400 for empty mandate ID, got %d", rr.Code)
        }
}

func TestHTTPDelegationRoute(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodPost, "/gauth/mgmt/v1/mandates/"+resp.MandateID+"/delegate", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code == http.StatusNotFound {
                t.Error("Delegation route should be registered, got 404")
        }
}

func TestCreateDelegationNilCoreVerbsDenied(t *testing.T) {
        mgr := newTestManager()
        reqBody := validCreationRequest()
        reqBody.Scope.CoreVerbs = nil
        resp, _ := mgr.CreateMandate(reqBody, "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")

        err := mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub")
        if err == nil {
                t.Error("Expected error for delegation with nil CoreVerbs (fail-closed)")
        }
}
