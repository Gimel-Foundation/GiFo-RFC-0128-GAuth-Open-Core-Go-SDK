package management

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
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
                                "foundry.file.create":    {Allowed: true, CostCentsBase: 1},
                                "foundry.agent.delegate": {Allowed: true, CostCentsBase: 0},
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
        req := validCreationRequest()
        req.Scope.CoreVerbs = map[string]poa.ToolPolicy{
                "foundry.file.create": {Allowed: true, CostCentsBase: 1},
        }
        resp, _ := mgr.CreateMandate(req, "admin")
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

func TestClientIntegration(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        client := NewClient(ClientConfig{
                BaseURL: srv.URL,
                ActorID: "test-actor",
        })

        resp, err := client.CreateMandate(validCreationRequest())
        if err != nil {
                t.Fatalf("CreateMandate: %v", err)
        }
        if resp.MandateID == "" {
                t.Fatal("Expected mandate ID")
        }

        mandate, err := client.GetMandate(resp.MandateID)
        if err != nil {
                t.Fatalf("GetMandate: %v", err)
        }
        if mandate.Status != poa.StatusDraft {
                t.Errorf("Status = %q, want draft", mandate.Status)
        }

        mandate, err = client.ActivateMandate(resp.MandateID)
        if err != nil {
                t.Fatalf("ActivateMandate: %v", err)
        }
        if mandate.Status != poa.StatusActive {
                t.Errorf("Status = %q, want active", mandate.Status)
        }

        mandate, err = client.SuspendMandate(resp.MandateID, "test")
        if err != nil {
                t.Fatalf("SuspendMandate: %v", err)
        }
        if mandate.Status != poa.StatusSuspended {
                t.Errorf("Status = %q, want suspended", mandate.Status)
        }

        mandate, err = client.ResumeMandate(resp.MandateID)
        if err != nil {
                t.Fatalf("ResumeMandate: %v", err)
        }
        if mandate.Status != poa.StatusActive {
                t.Errorf("Status = %q, want active", mandate.Status)
        }

        listResp, err := client.ListMandates("", "", nil, 50, 0)
        if err != nil {
                t.Fatalf("ListMandates: %v", err)
        }
        if listResp.Total == 0 {
                t.Error("Expected at least one mandate in list")
        }
}

func TestClientFullLifecycle(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        client := NewClient(ClientConfig{BaseURL: srv.URL, ActorID: "admin"})

        resp, _ := client.CreateMandate(validCreationRequest())
        client.ActivateMandate(resp.MandateID)

        _, err := client.ExtendTTL(resp.MandateID, 3600)
        if err != nil {
                t.Fatalf("ExtendTTL: %v", err)
        }

        _, err = client.IncreaseBudget(resp.MandateID, 500)
        if err != nil {
                t.Fatalf("IncreaseBudget: %v", err)
        }

        _, err = client.CreateDelegation(resp.MandateID, "agent-sub")
        if err != nil {
                t.Fatalf("CreateDelegation: %v", err)
        }

        _, err = client.RevokeDelegation(resp.MandateID, "agent-sub")
        if err != nil {
                t.Fatalf("RevokeDelegation: %v", err)
        }

        _, err = client.AssignGovernanceProfile(resp.MandateID, poa.ProfileStandard)
        if err != nil {
                t.Fatalf("AssignGovernanceProfile: %v", err)
        }

        _, err = client.RevokeMandate(resp.MandateID, "test complete")
        if err != nil {
                t.Fatalf("RevokeMandate: %v", err)
        }
}

func TestClientAPIError(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        client := NewClient(ClientConfig{BaseURL: srv.URL})

        _, err := client.GetMandate("nonexistent")
        if err == nil {
                t.Fatal("Expected error for nonexistent mandate")
        }
        apiErr, ok := err.(*APIError)
        if !ok {
                t.Fatalf("Expected *APIError, got %T", err)
        }
        if apiErr.HTTPCode != 404 {
                t.Errorf("HTTPCode = %d, want 404", apiErr.HTTPCode)
        }
        if apiErr.ErrorCode != "NOT_FOUND" {
                t.Errorf("ErrorCode = %q, want NOT_FOUND", apiErr.ErrorCode)
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

func TestHTTPHandlerRevokeMandate(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/activate", "application/json", nil)

        body := map[string]string{"reason": "test revoke"}
        resp, err := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/revoke", "application/json",
                strings.NewReader(mustJSON(body)))
        if err != nil {
                t.Fatalf("revoke request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("revoke status = %d, want 200", resp.StatusCode)
        }
}

func TestHTTPHandlerExtendTTL(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/activate", "application/json", nil)

        body := map[string]int{"additional_seconds": 7200}
        resp, err := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/extend-ttl", "application/json",
                strings.NewReader(mustJSON(body)))
        if err != nil {
                t.Fatalf("extend-ttl request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("extend-ttl status = %d, want 200", resp.StatusCode)
        }
}

func TestHTTPHandlerIncreaseBudget(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/activate", "application/json", nil)

        body := map[string]int{"additional_cents": 5000}
        resp, err := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/increase-budget", "application/json",
                strings.NewReader(mustJSON(body)))
        if err != nil {
                t.Fatalf("increase-budget request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("increase-budget status = %d, want 200", resp.StatusCode)
        }
}

func TestHTTPHandlerDelegationAndRevoke(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/activate", "application/json", nil)

        delBody := map[string]string{"delegatee_id": "agent-sub"}
        resp, err := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/delegate", "application/json",
                strings.NewReader(mustJSON(delBody)))
        if err != nil {
                t.Fatalf("delegate request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("delegate status = %d, want 200", resp.StatusCode)
        }

        revokeBody := map[string]string{"delegatee_id": "agent-sub"}
        resp, err = http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/revoke-delegation", "application/json",
                strings.NewReader(mustJSON(revokeBody)))
        if err != nil {
                t.Fatalf("revoke-delegation request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("revoke-delegation status = %d, want 200", resp.StatusCode)
        }
}

func TestHTTPHandlerGovernanceProfile(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/activate", "application/json", nil)

        gpBody := map[string]string{"profile": string(poa.ProfileEnterprise)}
        resp, err := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+created.MandateID+"/governance-profile", "application/json",
                strings.NewReader(mustJSON(gpBody)))
        if err != nil {
                t.Fatalf("governance-profile request: %v", err)
        }
        if resp.StatusCode != 200 {
                t.Errorf("governance-profile status = %d, want 200", resp.StatusCode)
        }
}

func TestHTTPHandlerInvalidJSON(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader("{invalid"))
        if resp.StatusCode != 400 {
                t.Errorf("Expected 400 for invalid JSON create, got %d", resp.StatusCode)
        }
}

func TestHTTPHandlerListWithFilters(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))

        resp, _ := http.Get(srv.URL + "/gauth/mgmt/v1/mandates?status=draft&limit=5&offset=0")
        if resp.StatusCode != 200 {
                t.Errorf("list with filters status = %d, want 200", resp.StatusCode)
        }
}

func TestStoreDeepCopyIsolation(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")

        m1, _ := mgr.store.Get(resp.MandateID)
        m2, _ := mgr.store.Get(resp.MandateID)

        m1.Parties.Subject = "mutated"
        if m2.Parties.Subject == "mutated" {
                t.Error("Store Get should return deep copies; mutation leaked")
        }
}

func TestMandateListFiltering(t *testing.T) {
        mgr := newTestManager()
        mgr.CreateMandate(validCreationRequest(), "admin")

        activeStatus := poa.StatusActive
        list, _ := mgr.ListMandates("", "", &activeStatus, 10, 0)
        if len(list) != 0 {
                t.Error("No mandates should be active yet")
        }

        draftStatus := poa.StatusDraft
        list, _ = mgr.ListMandates("", "", &draftStatus, 10, 0)
        if len(list) != 1 {
                t.Errorf("Expected 1 draft mandate, got %d", len(list))
        }

        list, _ = mgr.ListMandates("", "", nil, 10, 0)
        if len(list) != 1 {
                t.Errorf("Expected 1 total mandate, got %d", len(list))
        }
}

func TestConsistencyChecksEdgeCases(t *testing.T) {
        mgr := newTestManager()
        reqBody := validCreationRequest()
        reqBody.Parties.Subject = ""
        _, err := mgr.CreateMandate(reqBody, "admin")
        if err == nil {
                t.Error("Expected error for empty subject")
        }

        reqBody2 := validCreationRequest()
        reqBody2.Requirements.ApprovalMode = "invalid-mode"
        _, err = mgr.CreateMandate(reqBody2, "admin")
        if err == nil {
                t.Error("Expected error for invalid approval mode")
        }
}

func TestAPIErrorString(t *testing.T) {
        e := &APIError{HTTPCode: 400, ErrorCode: "BAD", Message: "bad request"}
        s := e.Error()
        if s == "" {
                t.Error("APIError.Error() should return non-empty string")
        }
}

func TestClientListMandates(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        client := NewClient(ClientConfig{BaseURL: srv.URL, ActorID: "admin"})
        client.CreateMandate(validCreationRequest())

        activeStatus := poa.StatusActive
        resp, err := client.ListMandates("", "", &activeStatus, 10, 0)
        if err != nil {
                t.Fatalf("ListMandates: %v", err)
        }
        if resp == nil {
                t.Fatal("ListMandates response nil")
        }
}

func TestHTTPHandlerMethodNotAllowed(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)
        id := created.MandateID

        endpoints := []string{
                "/activate", "/suspend", "/resume", "/revoke",
                "/extend-ttl", "/increase-budget",
                "/delegate", "/revoke-delegation", "/governance-profile",
        }

        for _, ep := range endpoints {
                req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/gauth/mgmt/v1/mandates/"+id+ep, nil)
                resp, err := http.DefaultClient.Do(req)
                if err != nil {
                        t.Fatalf("request %s: %v", ep, err)
                }
                if resp.StatusCode != 405 {
                        t.Errorf("%s: status = %d, want 405", ep, resp.StatusCode)
                }
        }
}

func TestHTTPHandlerInvalidJSONActions(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)
        id := created.MandateID

        http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+id+"/activate", "application/json", nil)

        badJSON := "{invalid"
        endpoints := []string{
                "/extend-ttl", "/increase-budget",
                "/delegate", "/revoke-delegation", "/governance-profile",
        }
        for _, ep := range endpoints {
                resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+id+ep, "application/json",
                        strings.NewReader(badJSON))
                if resp.StatusCode != 400 {
                        t.Errorf("%s bad JSON: status = %d, want 400", ep, resp.StatusCode)
                }
        }
}

func TestHTTPHandlerEmptyDelegatee(t *testing.T) {
        mgr := newTestManager()
        handler := NewHTTPHandler(mgr)
        mux := http.NewServeMux()
        handler.RegisterRoutes(mux)
        srv := httptest.NewServer(mux)
        defer srv.Close()

        resp, _ := http.Post(srv.URL+"/gauth/mgmt/v1/mandates", "application/json",
                strings.NewReader(mustJSON(validCreationRequest())))
        var created struct{ MandateID string `json:"mandate_id"` }
        json.NewDecoder(resp.Body).Decode(&created)
        id := created.MandateID

        resp, _ = http.Post(srv.URL+"/gauth/mgmt/v1/mandates/"+id+"/delegate", "application/json",
                strings.NewReader(`{"delegatee_id":""}`))
        if resp.StatusCode != 400 {
                t.Errorf("empty delegatee: status = %d, want 400", resp.StatusCode)
        }
}

func TestDeepCopyWithDelegations(t *testing.T) {
        mgr := newTestManager()
        resp, _ := mgr.CreateMandate(validCreationRequest(), "admin")
        mgr.ActivateMandate(resp.MandateID, "admin")
        mgr.CreateDelegation(resp.MandateID, "admin", "agent-sub")

        m, _ := mgr.store.Get(resp.MandateID)
        if m.Parties.Delegation == nil || len(m.Parties.Delegation.Entries) == 0 {
                t.Fatal("Expected delegation chain entries")
        }
}

func TestListMandatesPagination(t *testing.T) {
        mgr := newTestManager()
        for i := 0; i < 5; i++ {
                mgr.CreateMandate(validCreationRequest(), "admin")
        }

        list, _ := mgr.ListMandates("", "", nil, 2, 0)
        if len(list) != 2 {
                t.Errorf("Expected 2 mandates with limit=2, got %d", len(list))
        }

        list, _ = mgr.ListMandates("", "", nil, 2, 3)
        if len(list) != 2 {
                t.Errorf("Expected 2 mandates with offset=3, got %d", len(list))
        }
}

func mustJSON(v interface{}) string {
        b, _ := json.Marshal(v)
        return string(b)
}
