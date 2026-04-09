package management

import (
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
