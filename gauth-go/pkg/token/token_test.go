package token

import (
	"testing"
	"time"

	"github.com/gimelfoundation/gauth-go/pkg/poa"
)

func TestTokenCreateAndParse_RS256(t *testing.T) {
	sigKey, verKey, err := GenerateRS256Key("test-rs256-key")
	if err != nil {
		t.Fatalf("GenerateRS256Key: %v", err)
	}

	gauthClaims := &GAuthClaims{
		Version:      poa.SchemaVersion,
		CredentialID: "poa-test-001",
		CustomerID:   "cust_test",
		ProjectID:    "proj_test",
		Scope: ScopeClaims{
			GovernanceProfile: poa.ProfileStandard,
			Phase:             poa.PhaseBuild,
			AllowedPaths:      []string{"src/"},
			DeniedPaths:       []string{".env"},
		},
		ScopeChecksum:       "sha256:abc123",
		ToolPermissionsHash: "sha256:def456",
		PlatformPermHash:    "sha256:ghi789",
		IssuedBy:            "user_test",
		ApprovalMode:        poa.ApprovalAutonomous,
	}

	builder := NewTokenBuilder(sigKey).
		SetStandardClaims("https://gauth.test.dev", "agent-test", []string{"https://api.test.dev"}, 1*time.Hour).
		SetGAuthClaims(gauthClaims)

	tokenStr, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(tokenStr) == 0 {
		t.Fatal("Token should not be empty")
	}

	if len(tokenStr) > MaxTokenSize {
		t.Fatalf("Token exceeds max size: %d > %d", len(tokenStr), MaxTokenSize)
	}

	claims, err := Parse(tokenStr, []VerificationKey{*verKey})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if claims.Issuer != "https://gauth.test.dev" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "https://gauth.test.dev")
	}
	if claims.Subject != "agent-test" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "agent-test")
	}
	if claims.GAuth == nil {
		t.Fatal("GAuth claims should not be nil")
	}
	if claims.GAuth.Version != poa.SchemaVersion {
		t.Errorf("GAuth.Version = %q, want %q", claims.GAuth.Version, poa.SchemaVersion)
	}
}

func TestTokenCreateAndParse_ES256(t *testing.T) {
	sigKey, verKey, err := GenerateES256Key("test-es256-key")
	if err != nil {
		t.Fatalf("GenerateES256Key: %v", err)
	}

	builder := NewTokenBuilder(sigKey).
		SetStandardClaims("https://gauth.test.dev", "agent-es256", []string{"https://api.test.dev"}, 1*time.Hour).
		SetGAuthClaims(&GAuthClaims{
			Version:      poa.SchemaVersion,
			CredentialID: "poa-es256-001",
			CustomerID:   "cust_es",
			ProjectID:    "proj_es",
			Scope: ScopeClaims{
				GovernanceProfile: poa.ProfileMinimal,
				Phase:             poa.PhasePlan,
			},
			IssuedBy:     "user_es",
			ApprovalMode: poa.ApprovalAutonomous,
		})

	tokenStr, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	claims, err := Parse(tokenStr, []VerificationKey{*verKey})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if claims.Subject != "agent-es256" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "agent-es256")
	}
}

func TestTokenValidation(t *testing.T) {
	sigKey, verKey, err := GenerateRS256Key("test-validate-key")
	if err != nil {
		t.Fatalf("GenerateRS256Key: %v", err)
	}

	builder := NewTokenBuilder(sigKey).
		SetStandardClaims("https://gauth.test.dev", "agent-val", []string{"https://api.test.dev"}, 1*time.Hour).
		SetGAuthClaims(&GAuthClaims{
			Version:      poa.SchemaVersion,
			CredentialID: "poa-val-001",
			Scope: ScopeClaims{
				GovernanceProfile: poa.ProfileStandard,
				Phase:             poa.PhaseBuild,
			},
			ApprovalMode: poa.ApprovalAutonomous,
		})

	tokenStr, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	claims, err := Parse(tokenStr, []VerificationKey{*verKey})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if err := Validate(claims, "https://api.test.dev"); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if err := Validate(claims, "https://wrong.dev"); err == nil {
		t.Error("Validate should fail for wrong audience")
	}
}

func TestTokenInvalidSignature(t *testing.T) {
	sigKey, _, err := GenerateRS256Key("key-1")
	if err != nil {
		t.Fatalf("GenerateRS256Key: %v", err)
	}

	_, wrongVerKey, err := GenerateRS256Key("key-1")
	if err != nil {
		t.Fatalf("Second GenerateRS256Key: %v", err)
	}

	builder := NewTokenBuilder(sigKey).
		SetStandardClaims("https://test.dev", "agent", []string{"https://api.dev"}, 1*time.Hour).
		SetGAuthClaims(&GAuthClaims{
			Version: poa.SchemaVersion,
			Scope: ScopeClaims{
				GovernanceProfile: poa.ProfileMinimal,
				Phase:             poa.PhasePlan,
			},
		})

	tokenStr, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err = Parse(tokenStr, []VerificationKey{*wrongVerKey})
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestHS256Prohibited(t *testing.T) {
	builder := NewTokenBuilder(&SigningKey{
		Algorithm: "HS256",
		KeyID:     "test",
	})
	builder.SetStandardClaims("iss", "sub", []string{"aud"}, time.Hour)

	_, err := builder.Build()
	if err != ErrUnsupportedAlg {
		t.Errorf("Expected ErrUnsupportedAlg for HS256, got %v", err)
	}
}

func TestMissingKID(t *testing.T) {
	builder := NewTokenBuilder(&SigningKey{
		Algorithm: AlgRS256,
		KeyID:     "",
	})
	builder.SetStandardClaims("iss", "sub", []string{"aud"}, time.Hour)

	_, err := builder.Build()
	if err != ErrMissingKID {
		t.Errorf("Expected ErrMissingKID, got %v", err)
	}
}

func TestMandateClaims(t *testing.T) {
	sigKey, verKey, err := GenerateRS256Key("mandate-key")
	if err != nil {
		t.Fatalf("GenerateRS256Key: %v", err)
	}

	builder := NewTokenBuilder(sigKey).
		SetStandardClaims("https://test.dev", "agent-m", []string{"aud"}, time.Hour).
		SetGAuthClaims(&GAuthClaims{
			Version: poa.SchemaVersion,
			Scope: ScopeClaims{
				GovernanceProfile: poa.ProfileStandard,
				Phase:             poa.PhaseBuild,
			},
		}).
		SetMandateClaims(&MandateClaims{
			MandateID:     "mdt_abc",
			MandateStatus: poa.StatusActive,
			Budget: &poa.Budget{
				TotalCents:     10000,
				RemainingCents: 4200,
			},
			Session: &poa.SessionLimits{
				MaxToolCalls:       100,
				RemainingToolCalls: 87,
			},
		})

	tokenStr, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	claims, err := Parse(tokenStr, []VerificationKey{*verKey})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if claims.GAuthMandate == nil {
		t.Fatal("GAuthMandate should not be nil")
	}
	if claims.GAuthMandate.MandateID != "mdt_abc" {
		t.Errorf("MandateID = %q, want %q", claims.GAuthMandate.MandateID, "mdt_abc")
	}
	if claims.GAuthMandate.Budget.RemainingCents != 4200 {
		t.Errorf("RemainingCents = %d, want 4200", claims.GAuthMandate.Budget.RemainingCents)
	}
}
