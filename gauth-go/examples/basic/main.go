package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gimelfoundation/gauth-go/pkg/adapter"
	"github.com/gimelfoundation/gauth-go/pkg/management"
	"github.com/gimelfoundation/gauth-go/pkg/pep"
	"github.com/gimelfoundation/gauth-go/pkg/poa"
	"github.com/gimelfoundation/gauth-go/pkg/token"
)

func main() {
	fmt.Println("=== GAuth Open Core Go SDK — Basic Example ===")
	fmt.Println()

	credential := &poa.PoACredential{
		SchemaVersion: poa.SchemaVersion,
		CredentialID:  "poa-example-001",
		Parties: poa.Parties{
			Subject:    "foundry-agent-1",
			CustomerID: "cust_demo",
			ProjectID:  "proj_demo",
			IssuedBy:   "admin_user",
		},
		Scope: poa.Scope{
			GovernanceProfile: poa.ProfileStandard,
			ActiveModules:     []string{"security-basics"},
			Phase:             poa.PhaseBuild,
			AllowedPaths:      []string{"src/", "tests/"},
			DeniedPaths:       []string{".env", "secrets/"},
			CoreVerbs: map[string]poa.ToolPolicy{
				"foundry.file.create": {Allowed: true, CostCentsBase: 1},
				"foundry.file.modify": {Allowed: true, CostCentsBase: 1},
				"foundry.file.delete": {Allowed: true, CostCentsBase: 2},
				"foundry.command.run": {Allowed: true, CostCentsBase: 1},
			},
			PlatformPermissions: &poa.PlatformPermissions{
				Database: &poa.DatabasePermissions{Read: true, Write: false},
				Shell:    &poa.ShellPermissions{Mode: poa.ShellModeAllowlist, Allowlist: []string{"npm", "node", "tsc"}},
			},
		},
		Requirements: poa.Requirements{
			ApprovalMode: poa.ApprovalAutonomous,
			Budget:       &poa.Budget{TotalCents: 10000, RemainingCents: 10000},
			SessionLimits: &poa.SessionLimits{
				MaxToolCalls:      100,
				MaxLinesPerCommit: 200,
			},
			TTLSeconds: 3600,
		},
	}

	checksum, err := poa.ComputeScopeChecksum(credential.Scope)
	if err != nil {
		log.Fatalf("Compute scope checksum: %v", err)
	}
	fmt.Printf("1. PoA Credential created: %s\n", credential.CredentialID)
	fmt.Printf("   Scope checksum: %s\n\n", checksum)

	sigKey, verKey, err := token.GenerateRS256Key("ga_demo_key_001")
	if err != nil {
		log.Fatalf("Generate key: %v", err)
	}

	toolHash, _ := poa.ComputeToolPermissionsHash(credential.Scope.CoreVerbs)
	platHash, _ := poa.ComputePlatformPermissionsHash(credential.Scope.PlatformPermissions)

	gauthClaims := token.ClaimsFromPoA(credential, checksum, toolHash, platHash)
	builder := token.NewTokenBuilder(sigKey).
		SetStandardClaims("https://gauth.example.dev", credential.Parties.Subject, []string{"https://api.example.dev"}, 1*time.Hour).
		SetGAuthClaims(gauthClaims).
		SetMandateClaims(&token.MandateClaims{
			MandateID:     "mdt_demo_001",
			MandateStatus: poa.StatusActive,
			Budget:        credential.Requirements.Budget,
			Session:       credential.Requirements.SessionLimits,
		})

	tokenStr, err := builder.Build()
	if err != nil {
		log.Fatalf("Build token: %v", err)
	}
	fmt.Printf("2. JWT Extended Token issued (%d bytes)\n", len(tokenStr))
	fmt.Printf("   Token: %s...%s\n\n", tokenStr[:40], tokenStr[len(tokenStr)-20:])

	claims, err := token.Parse(tokenStr, []token.VerificationKey{*verKey})
	if err != nil {
		log.Fatalf("Parse token: %v", err)
	}

	if err := token.Validate(claims, "https://api.example.dev"); err != nil {
		log.Fatalf("Validate token: %v", err)
	}
	fmt.Printf("3. Token validated successfully\n")
	fmt.Printf("   Agent: %s, Profile: %s, Phase: %s\n\n", claims.Subject, claims.GAuth.Scope.GovernanceProfile, claims.GAuth.Scope.Phase)

	pepEngine := pep.New("1.0.0", poa.ModeStateless)
	enfReq := &pep.EnforcementRequest{
		RequestID: "req-demo-001",
		Timestamp: time.Now(),
		Agent:     pep.AgentIdentity{AgentID: credential.Parties.Subject},
		Action: pep.Action{
			Verb:     "foundry.file.create",
			Resource: "src/main.go",
		},
		Credential: pep.CredentialReference{
			Format: poa.FormatJWT,
			PoASnapshot: &pep.PoASnapshot{
				SchemaVersion: poa.SchemaVersion,
				CredentialID:  credential.CredentialID,
				Subject:       credential.Parties.Subject,
				Scope:         credential.Scope,
				Requirements:  credential.Requirements,
				Budget:        credential.Requirements.Budget,
				Session:       credential.Requirements.SessionLimits,
				ExpiresAt:     claims.ExpiresAt,
				NotBefore:     claims.NotBefore,
			},
		},
	}

	decision, err := pepEngine.EnforceAction(enfReq)
	if err != nil {
		log.Fatalf("Enforce action: %v", err)
	}
	fmt.Printf("4. PEP Enforcement Decision: %s\n", decision.Decision)
	fmt.Printf("   Checks: %d performed, %d passed, %d failed\n", decision.Audit.ChecksPerformed, decision.Audit.ChecksPassed, decision.Audit.ChecksFailed)
	fmt.Printf("   Processing time: %.2fms\n\n", decision.Audit.ProcessingTimeMs)

	store := management.NewMemoryStore()
	mgr := management.NewMandateManager(store)

	resp, err := mgr.CreateMandate(&management.MandateCreationRequest{
		Parties:      credential.Parties,
		Scope:        credential.Scope,
		Requirements: credential.Requirements,
	}, "admin_user")
	if err != nil {
		log.Fatalf("Create mandate: %v", err)
	}
	fmt.Printf("5. Mandate created: %s (status: %s)\n", resp.MandateID, resp.Status)

	if err := mgr.ActivateMandate(resp.MandateID, "admin_user"); err != nil {
		log.Fatalf("Activate mandate: %v", err)
	}

	mandate, _ := mgr.GetMandate(resp.MandateID)
	fmt.Printf("   Activated: %s (status: %s)\n\n", mandate.MandateID, mandate.Status)

	registry := adapter.NewRegistry()
	adapter.RegisterDefaults(registry)

	enrichmentAdapters := registry.List(adapter.TypeAIEnrichment)
	fmt.Printf("6. Adapter Registry: %d AI enrichment adapter(s) registered\n", len(enrichmentAdapters))
	fmt.Printf("   Registered types: AI Enrichment, Risk Scoring, Regulatory Reasoning, OAuth Engine, Foundry\n\n")

	fmt.Println("=== Complete ===")
	fmt.Println()

	decJSON, _ := json.MarshalIndent(decision, "", "  ")
	fmt.Printf("Full enforcement decision:\n%s\n", string(decJSON))
}
