package poa

import (
        "encoding/json"
        "testing"
)

func TestPoACredentialSerializationRoundtrip(t *testing.T) {
        cred := &PoACredential{
                SchemaVersion: SchemaVersion,
                CredentialID:  "poa-cs-001-abc123",
                Parties: Parties{
                        Subject:    "foundry-claude-opus-4.6",
                        CustomerID: "cust_123",
                        ProjectID:  "proj_456",
                        IssuedBy:   "user_789",
                },
                Scope: Scope{
                        GovernanceProfile: ProfileEnterprise,
                        ActiveModules:     []string{"security-basics", "data-model-first"},
                        Phase:             PhaseBuild,
                        AllowedPaths:      []string{"src/", "tests/"},
                        DeniedPaths:       []string{".env", "secrets/"},
                        CoreVerbs: map[string]ToolPolicy{
                                "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                                "foundry.file.modify": {Allowed: true, CostCentsBase: 1},
                                "foundry.file.delete": {Allowed: true, CostCentsBase: 2},
                        },
                        PlatformPermissions: &PlatformPermissions{
                                Deployment: &DeploymentPermissions{
                                        Targets:    []string{"staging"},
                                        AutoDeploy: false,
                                },
                                Database: &DatabasePermissions{
                                        Read:  true,
                                        Write: false,
                                },
                        },
                },
                Requirements: Requirements{
                        ApprovalMode: ApprovalSupervised,
                        Budget: &Budget{
                                TotalCents:     10000,
                                RemainingCents: 8500,
                        },
                        SessionLimits: &SessionLimits{
                                MaxToolCalls:       100,
                                RemainingToolCalls: 87,
                                MaxLinesPerCommit:  100,
                        },
                        TTLSeconds: 3600,
                },
        }

        data, err := json.Marshal(cred)
        if err != nil {
                t.Fatalf("Marshal failed: %v", err)
        }

        var decoded PoACredential
        if err := json.Unmarshal(data, &decoded); err != nil {
                t.Fatalf("Unmarshal failed: %v", err)
        }

        if decoded.SchemaVersion != SchemaVersion {
                t.Errorf("SchemaVersion = %q, want %q", decoded.SchemaVersion, SchemaVersion)
        }
        if decoded.CredentialID != cred.CredentialID {
                t.Errorf("CredentialID = %q, want %q", decoded.CredentialID, cred.CredentialID)
        }
        if decoded.Parties.Subject != cred.Parties.Subject {
                t.Errorf("Subject = %q, want %q", decoded.Parties.Subject, cred.Parties.Subject)
        }
        if decoded.Scope.GovernanceProfile != ProfileEnterprise {
                t.Errorf("GovernanceProfile = %q, want %q", decoded.Scope.GovernanceProfile, ProfileEnterprise)
        }
        if decoded.Scope.Phase != PhaseBuild {
                t.Errorf("Phase = %q, want %q", decoded.Scope.Phase, PhaseBuild)
        }
        if len(decoded.Scope.CoreVerbs) != 3 {
                t.Errorf("CoreVerbs count = %d, want 3", len(decoded.Scope.CoreVerbs))
        }
        if decoded.Requirements.Budget.TotalCents != 10000 {
                t.Errorf("Budget.TotalCents = %d, want 10000", decoded.Requirements.Budget.TotalCents)
        }
}

func TestScopeChecksum(t *testing.T) {
        scope := Scope{
                GovernanceProfile: ProfileStandard,
                Phase:             PhaseBuild,
                AllowedPaths:      []string{"src/"},
                DeniedPaths:       []string{".env"},
                ActiveModules:     []string{"security-basics"},
                CoreVerbs: map[string]ToolPolicy{
                        "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                },
                PlatformPermissions: &PlatformPermissions{
                        Database: &DatabasePermissions{Read: true},
                },
        }

        checksum1, err := ComputeScopeChecksum(scope)
        if err != nil {
                t.Fatalf("ComputeScopeChecksum failed: %v", err)
        }

        if checksum1 == "" {
                t.Fatal("Checksum should not be empty")
        }

        if len(checksum1) < 10 {
                t.Fatalf("Checksum too short: %q", checksum1)
        }

        checksum2, err := ComputeScopeChecksum(scope)
        if err != nil {
                t.Fatalf("Second ComputeScopeChecksum failed: %v", err)
        }

        if checksum1 != checksum2 {
                t.Errorf("Checksums not deterministic: %q != %q", checksum1, checksum2)
        }

        scope2 := scope
        scope2.Phase = PhaseRun
        checksum3, err := ComputeScopeChecksum(scope2)
        if err != nil {
                t.Fatalf("Third ComputeScopeChecksum failed: %v", err)
        }

        if checksum1 == checksum3 {
                t.Error("Different scopes should produce different checksums")
        }
}

func TestGovernanceProfileValid(t *testing.T) {
        valid := []GovernanceProfile{ProfileMinimal, ProfileStandard, ProfileStrict, ProfileEnterprise, ProfileBehoerde}
        for _, p := range valid {
                if !p.IsValid() {
                        t.Errorf("Profile %q should be valid", p)
                }
        }
        if GovernanceProfile("invalid").IsValid() {
                t.Error("Invalid profile should not be valid")
        }
}

func TestMandateStatusTerminal(t *testing.T) {
        terminal := []MandateStatus{StatusRevoked, StatusExpired, StatusBudgetExceeded, StatusSuperseded}
        for _, s := range terminal {
                if !s.IsTerminal() {
                        t.Errorf("Status %q should be terminal", s)
                }
        }

        nonTerminal := []MandateStatus{StatusDraft, StatusActive, StatusSuspended}
        for _, s := range nonTerminal {
                if s.IsTerminal() {
                        t.Errorf("Status %q should not be terminal", s)
                }
        }
}

func TestVerbURN(t *testing.T) {
        urn := VerbURN("foundry", "file", "create")
        expected := "urn:gauth:verb:foundry:file:create"
        if urn != expected {
                t.Errorf("VerbURN = %q, want %q", urn, expected)
        }

        purn := PlatformURN("deployment", "targets")
        expectedP := "urn:gauth:platform:deployment:targets"
        if purn != expectedP {
                t.Errorf("PlatformURN = %q, want %q", purn, expectedP)
        }
}

func TestToolPermissionsHash(t *testing.T) {
        verbs := map[string]ToolPolicy{
                "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                "foundry.file.modify": {Allowed: true, CostCentsBase: 1},
        }

        hash1, err := ComputeToolPermissionsHash(verbs)
        if err != nil {
                t.Fatalf("ComputeToolPermissionsHash failed: %v", err)
        }

        hash2, err := ComputeToolPermissionsHash(verbs)
        if err != nil {
                t.Fatalf("Second ComputeToolPermissionsHash failed: %v", err)
        }

        if hash1 != hash2 {
                t.Error("Same verbs should produce same hash")
        }

        hash3, err := ComputeToolPermissionsHash(nil)
        if err != nil {
                t.Fatalf("Nil ComputeToolPermissionsHash failed: %v", err)
        }
        if hash3 == hash1 {
                t.Error("Empty verbs should produce different hash")
        }
}

func TestApprovalModeIsValid(t *testing.T) {
        tests := []struct {
                mode  ApprovalMode
                valid bool
        }{
                {ApprovalAutonomous, true},
                {ApprovalSupervised, true},
                {ApprovalFourEyes, true},
                {"invalid", false},
                {"", false},
        }
        for _, tt := range tests {
                if got := tt.mode.IsValid(); got != tt.valid {
                        t.Errorf("ApprovalMode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
                }
        }
}

func TestPhaseIsValid(t *testing.T) {
        tests := []struct {
                phase Phase
                valid bool
        }{
                {PhasePlan, true},
                {PhaseBuild, true},
                {PhaseRun, true},
                {"invalid", false},
        }
        for _, tt := range tests {
                if got := tt.phase.IsValid(); got != tt.valid {
                        t.Errorf("Phase(%q).IsValid() = %v, want %v", tt.phase, got, tt.valid)
                }
        }
}

func TestMandateStatusIsValid(t *testing.T) {
        tests := []struct {
                status MandateStatus
                valid  bool
        }{
                {StatusDraft, true},
                {StatusActive, true},
                {StatusSuspended, true},
                {StatusRevoked, true},
                {StatusExpired, true},
                {StatusBudgetExceeded, true},
                {StatusSuperseded, true},
                {"unknown", false},
        }
        for _, tt := range tests {
                if got := tt.status.IsValid(); got != tt.valid {
                        t.Errorf("MandateStatus(%q).IsValid() = %v, want %v", tt.status, got, tt.valid)
                }
        }
}

func TestComputePlatformPermissionsHash(t *testing.T) {
        pp := &PlatformPermissions{
                Database: &DatabasePermissions{Read: true, Write: false},
                Secrets:  &SecretPermissions{Read: true, Create: false},
        }

        hash1, err := ComputePlatformPermissionsHash(pp)
        if err != nil {
                t.Fatalf("ComputePlatformPermissionsHash: %v", err)
        }

        hash2, err := ComputePlatformPermissionsHash(pp)
        if err != nil {
                t.Fatalf("Second ComputePlatformPermissionsHash: %v", err)
        }

        if hash1 != hash2 {
                t.Error("Same permissions should produce same hash")
        }

        hash3, err := ComputePlatformPermissionsHash(nil)
        if err != nil {
                t.Fatalf("Nil ComputePlatformPermissionsHash: %v", err)
        }
        if hash3 == hash1 {
                t.Error("Nil permissions should produce different hash")
        }
}

func TestComputeScopeChecksumWithSectorsRegions(t *testing.T) {
        scope := Scope{
                GovernanceProfile: ProfileStandard,
                Phase:             PhaseBuild,
                AllowedSectors:    []string{"finance", "health"},
                AllowedRegions:    []string{"us-east", "eu-west"},
                AllowedPaths:      []string{"src/"},
        }

        hash1, err := ComputeScopeChecksum(scope)
        if err != nil {
                t.Fatalf("ComputeScopeChecksum: %v", err)
        }

        scope2 := scope
        scope2.AllowedSectors = []string{"health", "finance"}
        hash2, err := ComputeScopeChecksum(scope2)
        if err != nil {
                t.Fatalf("ComputeScopeChecksum: %v", err)
        }

        if hash1 == hash2 {
                t.Error("Different sector ordering should produce different checksums")
        }
}
