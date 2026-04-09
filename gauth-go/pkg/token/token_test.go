package token

import (
        "crypto/ecdsa"
        "crypto/rsa"
        "encoding/base64"
        "encoding/json"
        "math/big"
        "net/http"
        "net/http/httptest"
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

func TestValidateIntegrity(t *testing.T) {
        scope := poa.Scope{
                GovernanceProfile: poa.ProfileStandard,
                Phase:             poa.PhaseBuild,
                AllowedPaths:      []string{"src/"},
                DeniedPaths:       []string{".env"},
                CoreVerbs: map[string]poa.ToolPolicy{
                        "foundry.file.create": {Allowed: true, CostCentsBase: 1},
                },
                PlatformPermissions: &poa.PlatformPermissions{
                        Database: &poa.DatabasePermissions{Read: true, Write: false},
                },
        }

        scopeChecksum, _ := poa.ComputeScopeChecksum(scope)
        toolHash, _ := poa.ComputeToolPermissionsHash(scope.CoreVerbs)
        platHash, _ := poa.ComputePlatformPermissionsHash(scope.PlatformPermissions)

        claims := &ExtendedTokenClaims{
                GAuth: &GAuthClaims{
                        Version:             poa.SchemaVersion,
                        ScopeChecksum:       scopeChecksum,
                        ToolPermissionsHash: toolHash,
                        PlatformPermHash:    platHash,
                },
        }

        if err := ValidateIntegrity(claims, scope); err != nil {
                t.Fatalf("ValidateIntegrity should pass: %v", err)
        }

        claims.GAuth.ScopeChecksum = "sha256:tampered"
        if err := ValidateIntegrity(claims, scope); err != ErrScopeChecksumMismatch {
                t.Errorf("Expected ErrScopeChecksumMismatch, got %v", err)
        }

        claims.GAuth.ScopeChecksum = scopeChecksum
        claims.GAuth.ToolPermissionsHash = "sha256:tampered"
        if err := ValidateIntegrity(claims, scope); err != ErrToolPermHashMismatch {
                t.Errorf("Expected ErrToolPermHashMismatch, got %v", err)
        }

        claims.GAuth.ToolPermissionsHash = toolHash
        claims.GAuth.PlatformPermHash = "sha256:tampered"
        if err := ValidateIntegrity(claims, scope); err != ErrPlatformPermHashMismatch {
                t.Errorf("Expected ErrPlatformPermHashMismatch, got %v", err)
        }
}

func TestValidateIntegrityMissingClaims(t *testing.T) {
        claims := &ExtendedTokenClaims{}
        scope := poa.Scope{}

        if err := ValidateIntegrity(claims, scope); err != ErrMissingGAuthClaims {
                t.Errorf("Expected ErrMissingGAuthClaims, got %v", err)
        }
}

func TestValidateAll(t *testing.T) {
        scope := poa.Scope{
                GovernanceProfile: poa.ProfileStandard,
                Phase:             poa.PhaseBuild,
                AllowedPaths:      []string{"src/"},
        }

        scopeChecksum, _ := poa.ComputeScopeChecksum(scope)
        toolHash, _ := poa.ComputeToolPermissionsHash(nil)
        platHash, _ := poa.ComputePlatformPermissionsHash(nil)

        claims := &ExtendedTokenClaims{
                Subject:   "agent-test",
                Audience:  []string{"gauth-test"},
                ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
                IssuedAt:  time.Now().Unix(),
                GAuth: &GAuthClaims{
                        Version:             poa.SchemaVersion,
                        ScopeChecksum:       scopeChecksum,
                        ToolPermissionsHash: toolHash,
                        PlatformPermHash:    platHash,
                },
        }

        if err := ValidateAll(claims, "gauth-test", scope); err != nil {
                t.Errorf("ValidateAll should pass: %v", err)
        }

        if err := ValidateAll(claims, "wrong-aud", scope); err == nil {
                t.Error("ValidateAll should fail for wrong audience")
        }

        claims.GAuth.ScopeChecksum = "sha256:wrong"
        if err := ValidateAll(claims, "gauth-test", scope); err == nil {
                t.Error("ValidateAll should fail for wrong checksum")
        }
}

func TestClaimsFromPoA(t *testing.T) {
        cred := &poa.PoACredential{
                SchemaVersion: poa.SchemaVersion,
                CredentialID:  "poa-test-001",
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
                        ActiveModules:     []string{"security-basics"},
                },
                Requirements: poa.Requirements{
                        ApprovalMode: poa.ApprovalAutonomous,
                },
        }

        claims := ClaimsFromPoA(cred, "sha256:scope", "sha256:tool", "sha256:plat")
        if claims.CredentialID != "poa-test-001" {
                t.Errorf("CredentialID = %q", claims.CredentialID)
        }
        if claims.CustomerID != "cust_test" {
                t.Errorf("CustomerID = %q", claims.CustomerID)
        }
        if claims.ScopeChecksum != "sha256:scope" {
                t.Errorf("ScopeChecksum = %q", claims.ScopeChecksum)
        }
        if claims.Scope.GovernanceProfile != poa.ProfileStandard {
                t.Errorf("GovernanceProfile = %q", claims.Scope.GovernanceProfile)
        }
        if claims.ApprovalMode != poa.ApprovalAutonomous {
                t.Errorf("ApprovalMode = %q", claims.ApprovalMode)
        }
}

func TestGenerateKeyPairs(t *testing.T) {
        _, _, err := GenerateRS256Key("rs256-test")
        if err != nil {
                t.Fatalf("GenerateRS256Key: %v", err)
        }

        _, _, err = GenerateES256Key("es256-test")
        if err != nil {
                t.Fatalf("GenerateES256Key: %v", err)
        }
}

func TestFetchJWKS(t *testing.T) {
        rsaSigKey, rsaVerKey, _ := GenerateRS256Key("rsa-kid")
        ecSigKey, ecVerKey, _ := GenerateES256Key("ec-kid")
        _ = rsaSigKey
        _ = ecSigKey

        rsaPub := rsaVerKey.PublicKey.(*rsa.PublicKey)
        ecPub := ecVerKey.PublicKey.(*ecdsa.PublicKey)

        jwks := JWKSet{
                Keys: []JWK{
                        {
                                KeyType:   "RSA",
                                KeyID:     "rsa-kid",
                                Algorithm: "RS256",
                                N:         base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
                                E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
                        },
                        {
                                KeyType:   "EC",
                                KeyID:     "ec-kid",
                                Algorithm: "ES256",
                                Curve:     "P-256",
                                X:         base64.RawURLEncoding.EncodeToString(ecPub.X.Bytes()),
                                Y:         base64.RawURLEncoding.EncodeToString(ecPub.Y.Bytes()),
                        },
                },
        }

        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                json.NewEncoder(w).Encode(jwks)
        }))
        defer srv.Close()

        fetched, err := FetchJWKS(srv.URL)
        if err != nil {
                t.Fatalf("FetchJWKS: %v", err)
        }

        keys, err := fetched.ToVerificationKeys()
        if err != nil {
                t.Fatalf("ToVerificationKeys: %v", err)
        }

        if len(keys) != 2 {
                t.Fatalf("Expected 2 keys, got %d", len(keys))
        }
}

func TestFetchJWKS_ErrorCases(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
        }))
        defer srv.Close()

        _, err := FetchJWKS(srv.URL)
        if err == nil {
                t.Error("Expected error for 500 response")
        }

        _, err = FetchJWKS("http://invalid-host-that-does-not-exist.test")
        if err == nil {
                t.Error("Expected error for invalid host")
        }
}

func TestJWKToVerificationKey_UnsupportedTypes(t *testing.T) {
        jwk := JWK{KeyType: "oct", KeyID: "hmac-key"}
        _, err := jwk.ToVerificationKey()
        if err == nil {
                t.Error("Expected error for unsupported key type")
        }

        ecJWK := JWK{KeyType: "EC", KeyID: "ec-key", Curve: "P-384"}
        _, err = ecJWK.ToVerificationKey()
        if err == nil {
                t.Error("Expected error for unsupported curve")
        }
}

func TestParseEdgeCases(t *testing.T) {
        _, err := Parse("not.a.valid.jwt.token", nil)
        if err == nil {
                t.Error("Expected error for invalid JWT format")
        }

        _, err = Parse("", nil)
        if err == nil {
                t.Error("Expected error for empty token")
        }
}

func TestParseAlgKeyMismatch(t *testing.T) {
        rsSigKey, _, _ := GenerateRS256Key("rs-key")
        _, ecVerKey, _ := GenerateES256Key("rs-key")

        gauthClaims := &GAuthClaims{
                Version:             poa.SchemaVersion,
                CredentialID:        "poa-mismatch",
                ScopeChecksum:       "sha256:abc",
                ToolPermissionsHash: "sha256:def",
                PlatformPermHash:    "sha256:ghi",
        }

        builder := NewTokenBuilder(rsSigKey).
                SetStandardClaims("iss", "sub", []string{"aud"}, time.Hour).
                SetGAuthClaims(gauthClaims)
        tok, err := builder.Build()
        if err != nil {
                t.Fatalf("Build: %v", err)
        }

        _, err = Parse(tok, []VerificationKey{*ecVerKey})
        if err == nil {
                t.Error("Expected error for alg/key mismatch (RS256 header with ES256 key)")
        }
}

func TestBuildAndParse_ES256(t *testing.T) {
        sigKey, verKey, err := GenerateES256Key("test-es256-key")
        if err != nil {
                t.Fatalf("GenerateES256Key: %v", err)
        }

        gauthClaims := &GAuthClaims{
                Version:      poa.SchemaVersion,
                CredentialID: "poa-test-es256",
                CustomerID:   "cust_es",
                ProjectID:    "proj_es",
                Scope: ScopeClaims{
                        GovernanceProfile: poa.ProfileStandard,
                        Phase:             poa.PhaseBuild,
                },
                ScopeChecksum:       "sha256:abc",
                ToolPermissionsHash: "sha256:def",
                PlatformPermHash:    "sha256:ghi",
                IssuedBy:            "user_es",
                ApprovalMode:        poa.ApprovalAutonomous,
        }

        builder := NewTokenBuilder(sigKey).
                SetStandardClaims("gauth-test", "agent-es256", []string{"gauth-test"}, time.Hour).
                SetGAuthClaims(gauthClaims)
        tok, err := builder.Build()
        if err != nil {
                t.Fatalf("Build ES256: %v", err)
        }

        claims, err := Parse(tok, []VerificationKey{*verKey})
        if err != nil {
                t.Fatalf("Parse ES256: %v", err)
        }

        if claims.GAuth.CredentialID != "poa-test-es256" {
                t.Errorf("CredentialID = %q", claims.GAuth.CredentialID)
        }
}
