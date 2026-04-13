// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package pep

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type mockStateStore struct {
        state          *LiveMandateState
        errGet         error
        errDeduct      error
        errIncrement   error
        deductedCents  int
        toolCallsAdded int
}

func (m *mockStateStore) GetMandateState(mandateID string) (*LiveMandateState, error) {
        if m.errGet != nil {
                return nil, m.errGet
        }
        return m.state, nil
}

func (m *mockStateStore) DeductBudget(mandateID string, cents int) error {
        if m.errDeduct != nil {
                return m.errDeduct
        }
        m.deductedCents += cents
        return nil
}

func (m *mockStateStore) IncrementToolCalls(mandateID string) error {
        if m.errIncrement != nil {
                return m.errIncrement
        }
        m.toolCallsAdded++
        return nil
}

func boolPtr(b bool) *bool { return &b }

func TestStatefulPEPPermitDeductsBudget(t *testing.T) {
        store := &mockStateStore{
                state: &LiveMandateState{Status: "active", BudgetRemainingCents: 1000},
        }
        p := NewStateful("1.0.0-test", store)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "src/main.go",
                        Parameters: map[string]interface{}{
                                "amount_cents": float64(50),
                        },
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionPermit {
                t.Errorf("Decision = %q, want PERMIT", dec.Decision)
        }
        if store.deductedCents != 50 {
                t.Errorf("deductedCents = %d, want 50", store.deductedCents)
        }
        if store.toolCallsAdded != 1 {
                t.Errorf("toolCallsAdded = %d, want 1", store.toolCallsAdded)
        }
}

func TestStatefulPEPNoStoreError(t *testing.T) {
        p := &PEP{Version: "1.0.0", Mode: poa.ModeStateful, StateStore: nil}

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-nostore",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        _, err := p.EnforceAction(req)
        if err == nil {
                t.Fatal("Expected error for stateful mode without StateStore")
        }
}

func TestStatefulPEPStateLookupError(t *testing.T) {
        store := &mockStateStore{errGet: fmt.Errorf("connection refused")}
        p := NewStateful("1.0.0", store)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-err",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        _, err := p.EnforceAction(req)
        if err == nil {
                t.Fatal("Expected error for state lookup failure")
        }
}

func TestStatefulPEPDeductBudgetError(t *testing.T) {
        store := &mockStateStore{
                state:     &LiveMandateState{Status: "active", BudgetRemainingCents: 1000},
                errDeduct: fmt.Errorf("store write failed"),
        }
        p := NewStateful("1.0.0", store)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-deduct-err",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action: Action{
                        Verb:     "foundry.file.create",
                        Resource: "src/main.go",
                        Parameters: map[string]interface{}{
                                "amount_cents": float64(10),
                        },
                },
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        _, err := p.EnforceAction(req)
        if err == nil {
                t.Fatal("Expected error for budget deduct failure")
        }
}

func TestStatefulPEPIncrementError(t *testing.T) {
        store := &mockStateStore{
                state:        &LiveMandateState{Status: "active", BudgetRemainingCents: 1000},
                errIncrement: fmt.Errorf("increment failed"),
        }
        p := NewStateful("1.0.0", store)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-incr-err",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        _, err := p.EnforceAction(req)
        if err == nil {
                t.Fatal("Expected error for tool call increment failure")
        }
}

func TestStatefulPEPDenyDoesNotMutateState(t *testing.T) {
        store := &mockStateStore{
                state: &LiveMandateState{Status: "active", BudgetRemainingCents: 1000},
        }
        p := NewStateful("1.0.0", store)

        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-stateful-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "secrets/key.pem"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY", dec.Decision)
        }
        if store.deductedCents != 0 {
                t.Errorf("Should not have deducted budget on deny, got %d", store.deductedCents)
        }
        if store.toolCallsAdded != 0 {
                t.Errorf("Should not have incremented tool calls on deny, got %d", store.toolCallsAdded)
        }
}

func TestCHK01UnsupportedFormat(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-bad-format",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      "unknown-format",
                        PoASnapshot: snap,
                        SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for unsupported format", dec.Decision)
        }
}

func TestCHK01SignatureNotVerified(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-sig-unverified",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:            poa.FormatJWT,
                        PoASnapshot:       snap,
                        SignatureVerified:  boolPtr(false),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for unverified signature", dec.Decision)
        }
}

func TestCHK01NilSignatureVerifiedDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-sig-nil",
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
                t.Errorf("Decision = %q, want DENY for nil SignatureVerified (fail-closed)", dec.Decision)
        }
        found := false
        for _, v := range dec.Violations {
                if v.CheckID == "CHK-01" {
                        found = true
                        break
                }
        }
        if !found {
                t.Error("Expected CHK-01 violation for nil SignatureVerified")
        }
}

func TestCHK01MissingCredentialID(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.CredentialID = ""
        req := &EnforcementRequest{
                RequestID: "req-no-cred-id",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for missing credential_id", dec.Decision)
        }
}

func TestCHK01ScopeChecksumMismatch(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.ScopeChecksum = "bad-checksum"
        req := &EnforcementRequest{
                RequestID: "req-bad-checksum",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for checksum mismatch", dec.Decision)
        }
}

func TestCHK02NotBefore(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.NotBefore = time.Now().Add(1 * time.Hour).Unix()
        req := &EnforcementRequest{
                RequestID: "req-nbf",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for not-yet-valid", dec.Decision)
        }
}

func TestCHK02MandateStatusSuspended(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.MandateStatus = poa.StatusSuspended
        req := &EnforcementRequest{
                RequestID: "req-suspended",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for suspended mandate", dec.Decision)
        }
}

func TestCHK02LiveMandateStatusSuspended(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        req := &EnforcementRequest{
                RequestID: "req-live-suspended",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{Status: "suspended"},
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for live mandate suspended", dec.Decision)
        }
}

func TestCHK03InvalidGovernanceProfile(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = "invalid_profile"
        req := &EnforcementRequest{
                RequestID: "req-bad-profile",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for invalid governance profile", dec.Decision)
        }
}

func TestCHK04InvalidPhase(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.Phase = "invalid_phase"
        req := &EnforcementRequest{
                RequestID: "req-bad-phase",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for invalid phase", dec.Decision)
        }
}

func TestCHK04DeployInBuildPhase(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.deployment.deploy"] = poa.ToolPolicy{Allowed: true, CostCentsBase: 5}
        req := &EnforcementRequest{
                RequestID: "req-deploy-build",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.deployment.deploy", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for deploy in build phase", dec.Decision)
        }
}

func TestCHK06RegionAllowed(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.AllowedRegions = []string{"us-east", "eu-west"}
        req := &EnforcementRequest{
                RequestID: "req-region-ok",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", Region: "us-east"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionPermit {
                t.Errorf("Decision = %q, want PERMIT for allowed region", dec.Decision)
        }
}

func TestCHK06RegionDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.AllowedRegions = []string{"us-east"}
        req := &EnforcementRequest{
                RequestID: "req-region-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go", Region: "ap-south"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for disallowed region", dec.Decision)
        }
}

func TestCHK06RegionMissingInRequest(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.AllowedRegions = []string{"us-east"}
        req := &EnforcementRequest{
                RequestID: "req-region-missing",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for missing region", dec.Decision)
        }
}

func TestCHK09VerbConstraintsPathPattern(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.file.create"] = poa.ToolPolicy{
                Allowed:       true,
                CostCentsBase: 1,
                Constraints: &poa.VerbConstraints{
                        PathPatterns: []string{"src/", "lib/"},
                },
        }

        req := &EnforcementRequest{
                RequestID: "req-constraint-path",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "config/app.yaml"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for path pattern constraint violation", dec.Decision)
        }
}

func TestCHK09DeniedCommand(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.command.run"] = poa.ToolPolicy{
                Allowed:       true,
                CostCentsBase: 1,
                Constraints: &poa.VerbConstraints{
                        DeniedCommands: []string{"rm -rf /"},
                },
        }

        req := &EnforcementRequest{
                RequestID: "req-denied-cmd",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.command.run", Resource: "rm -rf /", ResourceType: "command"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for denied command", dec.Decision)
        }
}

func TestCHK09AllowedCommandNotInList(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.CoreVerbs["foundry.command.run"] = poa.ToolPolicy{
                Allowed:       true,
                CostCentsBase: 1,
                Constraints: &poa.VerbConstraints{
                        AllowedCommands: []string{"ls", "cat"},
                },
        }

        req := &EnforcementRequest{
                RequestID: "req-cmd-not-allowed",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.command.run", Resource: "wget", ResourceType: "command"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for command not in allowed list", dec.Decision)
        }
}

func TestCHK10DatabaseWriteDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.PlatformPermissions = &poa.PlatformPermissions{
                Database: &poa.DatabasePermissions{Read: true, Write: false, Migrate: false},
        }

        req := &EnforcementRequest{
                RequestID: "req-db-write-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.database.write", Resource: "src/main.go", ResourceType: "database"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for database write denied", dec.Decision)
        }
}

func TestCHK10DatabaseMigrateDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.PlatformPermissions = &poa.PlatformPermissions{
                Database: &poa.DatabasePermissions{Read: true, Write: true, Migrate: false},
        }

        req := &EnforcementRequest{
                RequestID: "req-db-migrate-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.database.migrate", Resource: "src/main.go", ResourceType: "database"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for database migrate denied", dec.Decision)
        }
}

func TestCHK10DeploymentAutoDeployDisabled(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.Phase = poa.PhaseRun
        snap.Scope.PlatformPermissions = &poa.PlatformPermissions{
                Deployment: &poa.DeploymentPermissions{AutoDeploy: false},
        }
        snap.Scope.CoreVerbs["foundry.deployment.deploy"] = poa.ToolPolicy{Allowed: true, CostCentsBase: 5}

        req := &EnforcementRequest{
                RequestID: "req-deploy-constrain",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.deployment.deploy", Resource: "src/main.go", ResourceType: "deployment"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionConstrain {
                t.Errorf("Decision = %q, want CONSTRAIN for auto-deploy disabled", dec.Decision)
        }
}

func TestCHK10SecretReadDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.PlatformPermissions = &poa.PlatformPermissions{
                Secrets: &poa.SecretPermissions{Read: false, Create: true},
        }

        req := &EnforcementRequest{
                RequestID: "req-secret-read-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.secret.read", Resource: "src/main.go", ResourceType: "secret"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for secret read denied", dec.Decision)
        }
}

func TestCHK10SecretCreateDenied(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.PlatformPermissions = &poa.PlatformPermissions{
                Secrets: &poa.SecretPermissions{Read: true, Create: false},
        }

        req := &EnforcementRequest{
                RequestID: "req-secret-create-deny",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.secret.create", Resource: "src/main.go", ResourceType: "secret"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for secret create denied", dec.Decision)
        }
}

func TestCHK13BudgetExhausted(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Budget = &poa.Budget{TotalCents: 100, RemainingCents: 0}

        req := &EnforcementRequest{
                RequestID: "req-budget-zero",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for exhausted budget", dec.Decision)
        }
}

func TestCHK13BudgetLiveMandateState(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Budget = &poa.Budget{TotalCents: 100, RemainingCents: 100}

        req := &EnforcementRequest{
                RequestID: "req-budget-live",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{
                                Status:               "active",
                                BudgetRemainingCents: 0,
                        },
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for live budget exhausted", dec.Decision)
        }
}

func TestCHK14SessionLinesCommitted(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        snap.Session = &poa.SessionLimits{MaxToolCalls: 100, MaxLinesPerCommit: 10}

        req := &EnforcementRequest{
                RequestID: "req-session-lines",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
                Context: &EnforcementContext{
                        SessionState: &SessionState{ToolCallsUsed: 5, LinesCommitted: 10},
                },
        }

        dec, err := p.EnforceAction(req)
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("Decision = %q, want DENY for lines committed exceeded", dec.Decision)
        }
}

func TestGetEnforcementPolicy(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)
        snap := validSnapshot()
        maxDepth := 3
        snap.Scope.CoreVerbs["foundry.agent.delegate"] = poa.ToolPolicy{
                Allowed:       true,
                CostCentsBase: 5,
                Constraints:   &poa.VerbConstraints{MaxDelegationDepth: &maxDepth},
        }

        policy := p.GetEnforcementPolicy(snap)
        if policy.GovernanceProfile != poa.ProfileStandard {
                t.Errorf("GovernanceProfile = %q, want standard", policy.GovernanceProfile)
        }
        if policy.Delegation == nil {
                t.Fatal("Expected delegation policy")
        }
        if !policy.Delegation.Allowed {
                t.Error("Expected delegation allowed")
        }
        if policy.Delegation.MaxDepth != 3 {
                t.Errorf("MaxDepth = %d, want 3", policy.Delegation.MaxDepth)
        }
}

func TestAmountCentsInt(t *testing.T) {
        a := Action{Parameters: map[string]interface{}{"amount_cents": 42}}
        if a.AmountCents() != 42 {
                t.Errorf("AmountCents() = %d, want 42", a.AmountCents())
        }
}

func TestAmountCentsUnknownType(t *testing.T) {
        a := Action{Parameters: map[string]interface{}{"amount_cents": "not-a-number"}}
        if a.AmountCents() != 0 {
                t.Errorf("AmountCents() = %d, want 0", a.AmountCents())
        }
}

func TestEnforcementErrorString(t *testing.T) {
        e := &EnforcementError{ErrorCode: "TEST", Message: "test message"}
        if e.Error() != "TEST: test message" {
                t.Errorf("Error() = %q", e.Error())
        }
}

func TestPEPHTTPHealth(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodGet, "/gauth/pep/v1/health", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusOK {
                t.Errorf("Health status = %d, want 200", rr.Code)
        }
}

func TestPEPHTTPHealthMethodNotAllowed(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/health", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusMethodNotAllowed {
                t.Errorf("Status = %d, want 405", rr.Code)
        }
}

func TestPEPHTTPEnforce(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        snap := validSnapshot()
        body, _ := json.Marshal(&EnforcementRequest{
                RequestID: "req-http-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        })

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/enforce", bytes.NewReader(body))
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusOK {
                t.Errorf("Status = %d, want 200", rr.Code)
        }
        if rr.Header().Get("X-PEP-Version") != "1.0.0-test" {
                t.Errorf("X-PEP-Version = %q", rr.Header().Get("X-PEP-Version"))
        }
}

func TestPEPHTTPEnforceMethodNotAllowed(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodGet, "/gauth/pep/v1/enforce", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusMethodNotAllowed {
                t.Errorf("Status = %d, want 405", rr.Code)
        }
}

func TestPEPHTTPEnforceBadBody(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/enforce", bytes.NewReader([]byte("not json")))
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusBadRequest {
                t.Errorf("Status = %d, want 400", rr.Code)
        }
}

func TestPEPHTTPEnforceWithRequestIDHeader(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        snap := validSnapshot()
        body, _ := json.Marshal(&EnforcementRequest{
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                },
        })

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/enforce", bytes.NewReader(body))
        req.Header.Set("X-Request-ID", "header-req-id")
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusOK {
                t.Errorf("Status = %d, want 200", rr.Code)
        }
}

func TestPEPHTTPBatchEnforce(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        snap := validSnapshot()
        body, _ := json.Marshal(map[string]interface{}{
                "requests": []EnforcementRequest{
                        {
                                RequestID: "batch-1",
                                Timestamp: time.Now(),
                                Agent:     AgentIdentity{AgentID: "agent-test"},
                                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                                Credential: CredentialReference{
                                        Format:      poa.FormatJWT,
                                        PoASnapshot: snap,
                                SignatureVerified:  boolPtr(true),
                                },
                        },
                },
                "mode": "all_or_nothing",
        })

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/enforce/batch", bytes.NewReader(body))
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusOK {
                t.Errorf("Status = %d, want 200", rr.Code)
        }
}

func TestPEPHTTPBatchEnforceMethodNotAllowed(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        req := httptest.NewRequest(http.MethodGet, "/gauth/pep/v1/enforce/batch", nil)
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusMethodNotAllowed {
                t.Errorf("Status = %d, want 405", rr.Code)
        }
}

func TestPEPHTTPPolicy(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        snap := validSnapshot()
        body, _ := json.Marshal(map[string]interface{}{
                "credential": CredentialReference{
                        Format:      poa.FormatJWT,
                        PoASnapshot: snap,
                        SignatureVerified:  boolPtr(true),
                },
        })

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/policy", bytes.NewReader(body))
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusOK {
                t.Errorf("Status = %d, want 200", rr.Code)
        }
}

func TestPEPHTTPPolicyNoSnapshot(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        h := NewHTTPHandler(p)
        mux := http.NewServeMux()
        h.RegisterRoutes(mux)

        body, _ := json.Marshal(map[string]interface{}{
                "credential": CredentialReference{Format: poa.FormatJWT},
        })

        req := httptest.NewRequest(http.MethodPost, "/gauth/pep/v1/policy", bytes.NewReader(body))
        rr := httptest.NewRecorder()
        mux.ServeHTTP(rr, req)

        if rr.Code != http.StatusBadRequest {
                t.Errorf("Status = %d, want 400", rr.Code)
        }
}

func TestBatchIndependentMode(t *testing.T) {
        p := New("1.0.0", poa.ModeStateless)

        snap := validSnapshot()

        reqs := []EnforcementRequest{
                {
                        RequestID: "batch-ind-1",
                        Timestamp: time.Now(),
                        Agent:     AgentIdentity{AgentID: "agent-test"},
                        Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                        Credential: CredentialReference{
                                Format:            poa.FormatJWT,
                                PoASnapshot:       snap,
                                SignatureVerified:  boolPtr(true),
                        },
                },
                {
                        RequestID: "batch-ind-2",
                        Timestamp: time.Now(),
                        Agent:     AgentIdentity{AgentID: "agent-test"},
                        Action:    Action{Verb: "foundry.file.create", Resource: "secrets/key.pem"},
                        Credential: CredentialReference{
                                Format:            poa.FormatJWT,
                                PoASnapshot:       snap,
                                SignatureVerified:  boolPtr(true),
                        },
                },
        }

        dec, err := p.BatchEnforce(reqs, BatchIndependent)
        if err != nil {
                t.Fatalf("BatchEnforce: %v", err)
        }
        if dec.OverallDecision != poa.DecisionDeny {
                t.Errorf("Overall = %q, want DENY", dec.OverallDecision)
        }
        if dec.Decisions[0].Decision != poa.DecisionPermit {
                t.Errorf("Decision[0] = %q, want PERMIT", dec.Decisions[0].Decision)
        }
        if dec.Decisions[1].Decision != poa.DecisionDeny {
                t.Errorf("Decision[1] = %q, want DENY", dec.Decisions[1].Decision)
        }
}

func TestEscalationAIGovernanceProfile(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = poa.ProfileEnterprise

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-ai-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{Status: "active", BudgetRemainingCents: 500},
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("expected DENY (fail-closed), got %s", dec.Decision)
        }
        if dec.Escalation == nil {
                t.Fatal("expected escalation info for enterprise profile")
        }
        if !dec.Escalation.Required {
                t.Error("expected escalation required=true")
        }
        found := false
        for _, r := range dec.Escalation.Reasons {
                if r == EscalationAIGovernance {
                        found = true
                }
        }
        if !found {
                t.Errorf("expected EscalationAIGovernance in reasons, got %v", dec.Escalation.Reasons)
        }
}

func TestEscalationProprietaryRoute(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.CoreVerbs["gimel.proprietary.action"] = poa.ToolPolicy{Allowed: true}

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-prop-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "gimel.proprietary.action", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{Status: "active", BudgetRemainingCents: 500},
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("expected DENY (fail-closed), got %s", dec.Decision)
        }
        if dec.Escalation == nil {
                t.Fatal("expected escalation info for proprietary route")
        }
        found := false
        for _, r := range dec.Escalation.Reasons {
                if r == EscalationProprietaryRoute {
                        found = true
                }
        }
        if !found {
                t.Errorf("expected EscalationProprietaryRoute in reasons, got %v", dec.Escalation.Reasons)
        }
}

func TestEscalationLiveMandateStateNil(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = poa.ProfileStrict

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-lms-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(true),
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("expected DENY (fail-closed), got %s", dec.Decision)
        }
        if dec.Escalation == nil {
                t.Fatal("expected escalation info when LiveMandateState is nil")
        }
        found := false
        for _, r := range dec.Escalation.Reasons {
                if r == EscalationLiveMandateState {
                        found = true
                }
        }
        if !found {
                t.Errorf("expected EscalationLiveMandateState in reasons, got %v", dec.Escalation.Reasons)
        }
}

func TestNoEscalationWhenDenied(t *testing.T) {
        p := New("1.0.0-test", poa.ModeStateless)
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = poa.ProfileEnterprise

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-deny-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(false),
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("expected DENY, got %s", dec.Decision)
        }
        if dec.Escalation != nil {
                t.Error("expected no escalation when decision is DENY")
        }
}

type mockForwarder struct {
        called  bool
        result  *EnforcementDecision
        err     error
}

func (m *mockForwarder) Forward(req *EnforcementRequest, reasons []EscalationReason) (*EnforcementDecision, error) {
        m.called = true
        return m.result, m.err
}

func TestForwarderCalledOnEscalation(t *testing.T) {
        fwd := &mockForwarder{
                result: &EnforcementDecision{
                        RequestID: "forwarded",
                        Decision:  poa.DecisionPermit,
                },
        }
        p := &PEP{
                Version:   "1.0.0-test",
                Mode:      poa.ModeStateless,
                Forwarder: fwd,
        }
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = poa.ProfileEnterprise

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-fwd-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{Status: "active", BudgetRemainingCents: 500},
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if !fwd.called {
                t.Error("expected forwarder to be called")
        }
        if dec.RequestID != "forwarded" {
                t.Errorf("expected forwarded result, got %s", dec.RequestID)
        }
}

func TestForwarderErrorFailsClosed(t *testing.T) {
        fwd := &mockForwarder{
                err: fmt.Errorf("auth pep unreachable"),
        }
        p := &PEP{
                Version:   "1.0.0-test",
                Mode:      poa.ModeStateless,
                Forwarder: fwd,
        }
        snap := validSnapshot()
        snap.Scope.GovernanceProfile = poa.ProfileBehoerde

        dec, err := p.EnforceAction(&EnforcementRequest{
                RequestID: "esc-fwd-err-1",
                Timestamp: time.Now(),
                Agent:     AgentIdentity{AgentID: "agent-test"},
                Action:    Action{Verb: "foundry.file.create", Resource: "src/main.go"},
                Credential: CredentialReference{
                        Format:           poa.FormatJWT,
                        PoASnapshot:      snap,
                        SignatureVerified: boolPtr(true),
                },
                Context: &EnforcementContext{
                        LiveMandateState: &LiveMandateState{Status: "active", BudgetRemainingCents: 500},
                },
        })
        if err != nil {
                t.Fatalf("EnforceAction: %v", err)
        }
        if !fwd.called {
                t.Error("expected forwarder to be called")
        }
        if dec.Decision != poa.DecisionDeny {
                t.Errorf("expected DENY (fail-closed on forwarder error), got %s", dec.Decision)
        }
        if dec.Escalation == nil {
                t.Fatal("expected escalation info on forwarder error")
        }
        if !dec.Escalation.Required {
                t.Error("expected escalation required=true")
        }
}

func TestNewHybridConstructor(t *testing.T) {
        fwd := &mockForwarder{}
        store := &mockStateStore{state: &LiveMandateState{Status: "active", BudgetRemainingCents: 100}}
        p := NewHybrid("1.0.0-test", store, fwd)
        if p.Mode != poa.ModeStateful {
                t.Errorf("expected stateful mode, got %s", p.Mode)
        }
        if p.Forwarder == nil {
                t.Error("expected forwarder to be set")
        }
        if p.StateStore == nil {
                t.Error("expected state store to be set")
        }
}
