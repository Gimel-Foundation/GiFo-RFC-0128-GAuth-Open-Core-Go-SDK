// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package adapter

import (
        "crypto/ed25519"
        "crypto/rand"
        "encoding/hex"
        "encoding/json"
        "testing"
        "time"
)

func makeTestManifest(t *testing.T, slot SlotName, namespace string, pub ed25519.PublicKey, priv ed25519.PrivateKey, overrides map[string]interface{}) []byte {
        t.Helper()
        now := time.Now().UTC()
        m := map[string]interface{}{
                "manifest_version": "1.0",
                "adapter_name":     "Test Adapter",
                "adapter_type":     "C",
                "adapter_version":  "1.0.0",
                "slot_name":        string(slot),
                "namespace":        namespace,
                "issued_at":        now.Add(-1 * time.Hour).Format(time.RFC3339),
                "expires_at":       now.Add(180 * 24 * time.Hour).Format(time.RFC3339),
                "issuer":           "gimel-foundation",
                "capabilities":     []string{"test.capability"},
                "public_key":       hex.EncodeToString(pub),
        }
        for k, v := range overrides {
                m[k] = v
        }

        withoutSig := make(map[string]interface{})
        for k, v := range m {
                withoutSig[k] = v
        }
        canonical, err := canonicalizeJSON(withoutSig)
        if err != nil {
                t.Fatalf("canonicalize: %v", err)
        }
        sig := ed25519.Sign(priv, canonical)
        m["signature"] = hex.EncodeToString(sig)

        data, err := json.Marshal(m)
        if err != nil {
                t.Fatalf("marshal manifest: %v", err)
        }
        return data
}

func setupVerifier(t *testing.T) (*ManifestVerifier, ed25519.PublicKey, ed25519.PrivateKey) {
        t.Helper()
        pub, priv, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatalf("GenerateKey: %v", err)
        }
        v := NewManifestVerifier()
        v.AddTrustedKey("gimel-prod-v1", pub)
        return v, pub, priv
}

func TestCTREG001_RegisterTypeA(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotOAuthEngine,
                ImplementationLabel: "HydraOAuthEngineAdapter",
                Adapter:             &NoOpOAuthEngineAdapter{},
        })
        if !result.Success {
                t.Fatalf("CT-REG-001: expected success, got error: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotOAuthEngine)
        if slot.Status != StatusActive {
                t.Errorf("CT-REG-001: expected status active, got %s", slot.Status)
        }
}

func TestCTREG002_RegisterTypeB(t *testing.T) {
        cr := NewConnectorRegistry(TariffS)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotFoundry,
                ImplementationLabel: "GimelFoundryAdapter",
                Adapter:             &NoOpFoundryAdapter{},
        })
        if !result.Success {
                t.Fatalf("CT-REG-002: expected success, got error: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotFoundry)
        if slot.Status != StatusActive {
                t.Errorf("CT-REG-002: expected status active, got %s", slot.Status)
        }
}

func TestCTREG003_RegisterTypeCWithoutAttestation(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgentGovernanceAdapter",
                Adapter:             struct{}{},
        })
        if !result.Success {
                t.Fatalf("CT-REG-003: expected success, got error: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotAIGovernance)
        if slot.Status != StatusPending {
                t.Errorf("CT-REG-003: expected status pending, got %s", slot.Status)
        }
}

func TestCTREG004_RegisterTypeCWithAttestation(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgentGovernanceAdapter",
                Adapter:             struct{}{},
        })

        result := cr.SatisfyAttestation(SlotAIGovernance)
        if !result.Success {
                t.Fatalf("CT-REG-004: satisfy attestation failed: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotAIGovernance)
        if slot.Status != StatusActive {
                t.Errorf("CT-REG-004: expected status active, got %s", slot.Status)
        }
}

func TestCTREG005_TariffGateBlocksTypeCForS(t *testing.T) {
        gate := CheckTariffGate(SlotAIGovernance, TariffS)
        if gate.Allowed {
                t.Error("CT-REG-005: expected tariff gate to block ai_governance for tariff S")
        }
        if gate.Availability != AvailNull {
                t.Errorf("CT-REG-005: expected availability null, got %s", gate.Availability)
        }
}

func TestCTREG006_TariffGateBlocksTypeCForO(t *testing.T) {
        gate := CheckTariffGate(SlotAIGovernance, TariffO)
        if gate.Allowed {
                t.Error("CT-REG-006: expected tariff gate to block ai_governance for tariff O")
        }
        if gate.Availability != AvailNull {
                t.Errorf("CT-REG-006: expected availability null, got %s", gate.Availability)
        }
}

func TestCTREG007_TariffMEnablesTypeC(t *testing.T) {
        gate := CheckTariffGate(SlotAIGovernance, TariffM)
        if !gate.Allowed {
                t.Error("CT-REG-007: expected tariff gate to allow ai_governance for tariff M")
        }
        if gate.Availability != AvailAttestedGimel {
                t.Errorf("CT-REG-007: expected availability attested_gimel, got %s", gate.Availability)
        }
}

func TestCTREG008_UnregisterMandatorySlotRejected(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Unregister(SlotPDP)
        if result.Success {
                t.Error("CT-REG-008: expected unregister of pdp to fail")
        }
        if result.Error != "Cannot unregister pdp — it is mandatory" {
                t.Errorf("CT-REG-008: unexpected error: %s", result.Error)
        }
}

func TestCTREG009_UnregisterOptionalSlotSucceeds(t *testing.T) {
        cr := NewConnectorRegistry(TariffS)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotFoundry,
                ImplementationLabel: "GimelFoundryAdapter",
                Adapter:             &NoOpFoundryAdapter{},
        })

        result := cr.Unregister(SlotFoundry)
        if !result.Success {
                t.Fatalf("CT-REG-009: expected success, got error: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotFoundry)
        if slot.Status != StatusNull {
                t.Errorf("CT-REG-009: expected status null, got %s", slot.Status)
        }
        if slot.ImplementationLabel != "None" {
                t.Errorf("CT-REG-009: expected label None, got %s", slot.ImplementationLabel)
        }
}

func TestCTREG010_DNAIdentityBlockedForTariffM(t *testing.T) {
        gate := CheckTariffGate(SlotDNAIdentity, TariffM)
        if gate.Allowed {
                t.Error("CT-REG-010: expected tariff gate to block dna_identity for tariff M")
        }
        if gate.Availability != AvailNull {
                t.Errorf("CT-REG-010: expected availability null, got %s", gate.Availability)
        }
}

func TestCTREG011_ValidEd25519ManifestAccepted(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, nil)

        m, err := v.Verify(manifest, SlotAIGovernance)
        if err != nil {
                t.Fatalf("CT-REG-011: expected valid manifest, got error: %v", err)
        }
        if m.SlotName != "ai_governance" {
                t.Errorf("CT-REG-011: expected slot ai_governance, got %s", m.SlotName)
        }
}

func TestCTREG012_TamperedManifestRejected(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, nil)

        var raw map[string]interface{}
        json.Unmarshal(manifest, &raw)
        raw["adapter_version"] = "2.0.0"
        tampered, _ := json.Marshal(raw)

        _, err := v.Verify(tampered, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-012: expected error for tampered manifest")
        }
        if err != ErrManifestSignature {
                t.Errorf("CT-REG-012: expected ErrManifestSignature, got: %v", err)
        }
}

func TestCTREG013_WrongSigningKeyRejected(t *testing.T) {
        v, _, _ := setupVerifier(t)

        untrustedPub, untrustedPriv, _ := ed25519.GenerateKey(rand.Reader)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", untrustedPub, untrustedPriv, nil)

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-013: expected error for wrong signing key")
        }
        if err != ErrManifestUntrustedKey {
                t.Errorf("CT-REG-013: expected ErrManifestUntrustedKey, got: %v", err)
        }
}

func TestCTREG014_UntrustedNamespaceRejected(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@evil/ai-governance", pub, priv, nil)

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-014: expected error for untrusted namespace")
        }
        if err != ErrManifestNamespace {
                t.Errorf("CT-REG-014: expected ErrManifestNamespace, got: %v", err)
        }
}

func TestCTREG015_ExpiredManifestRejected(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        v.SetNowFunc(func() time.Time {
                return time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
        })
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "issued_at":  "2026-06-01T00:00:00Z",
                "expires_at": "2027-06-01T00:00:00Z",
        })

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-015: expected error for expired manifest")
        }
        if err != ErrManifestExpired {
                t.Errorf("CT-REG-015: expected ErrManifestExpired, got: %v", err)
        }
}

func TestCTREG016_SlotNameMismatchRejected(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotWeb3Identity, "@gimel/web3-identity", pub, priv, nil)

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-016: expected error for slot mismatch")
        }
        if err != ErrManifestSlotMismatch {
                t.Errorf("CT-REG-016: expected ErrManifestSlotMismatch, got: %v", err)
        }
}

func TestCTREG017_RevokedKeyRejected(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        v.RevokeKey(hex.EncodeToString(pub))

        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, nil)

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-017: expected error for revoked key")
        }
        if err != ErrManifestRevokedKey {
                t.Errorf("CT-REG-017: expected ErrManifestRevokedKey, got: %v", err)
        }
}

func TestCTREG018_ManifestValidityExceeds1Year(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        now := time.Now().UTC()
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "issued_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
                "expires_at": now.Add(400 * 24 * time.Hour).Format(time.RFC3339),
        })

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Fatal("CT-REG-018: expected error for >1 year validity")
        }
        if err != ErrManifestMaxValidity {
                t.Errorf("CT-REG-018: expected ErrManifestMaxValidity, got: %v", err)
        }
}

func TestCTLIC001_DefaultLicenseIsMPL2(t *testing.T) {
        ls := NewLicenseState()
        if ls.LicenseType != LicenseMPL2 {
                t.Errorf("CT-LIC-001: expected license_type mpl_2_0, got %s", ls.LicenseType)
        }
        if ls.LicenseAcceptedAt != nil {
                t.Error("CT-LIC-001: expected license_accepted_at to be nil")
        }
}

func TestCTLIC002_LicenseSwitchOnTypeCActivation(t *testing.T) {
        ls := NewLicenseState()
        ls.AcceptPlatformToS("2026.1")

        if ls.LicenseType != LicenseGimelToS {
                t.Errorf("CT-LIC-002: expected license_type gimel_tos, got %s", ls.LicenseType)
        }
        if ls.LicenseAcceptedAt == nil {
                t.Error("CT-LIC-002: expected license_accepted_at to be set")
        }
        if ls.LicenseVersion != "2026.1" {
                t.Errorf("CT-LIC-002: expected license_version 2026.1, got %s", ls.LicenseVersion)
        }
}

func TestCTLIC003_TypeCRegistrationBlockedWithoutLicense(t *testing.T) {
        ls := NewLicenseState()
        err := ls.CheckPlatformToS("")
        if err == nil {
                t.Error("CT-LIC-003: expected error for mpl_2_0 customer accessing Gimel-hosted service")
        }
        if err != ErrLicenseRequired {
                t.Errorf("CT-LIC-003: expected ErrLicenseRequired, got: %v", err)
        }
}

func TestCTLIC004_AttestationSatisfiedTransition(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgentGovernanceAdapter",
                Adapter:             struct{}{},
        })

        slot, _ := cr.GetSlot(SlotAIGovernance)
        if slot.Status != StatusPending {
                t.Fatalf("CT-LIC-004: expected pending, got %s", slot.Status)
        }

        result := cr.SatisfyAttestation(SlotAIGovernance)
        if !result.Success {
                t.Fatalf("CT-LIC-004: satisfy failed: %s", result.Error)
        }

        slot, _ = cr.GetSlot(SlotAIGovernance)
        if !slot.AttestationSatisfied {
                t.Error("CT-LIC-004: expected attestation_satisfied true")
        }
        if slot.Status != StatusActive {
                t.Errorf("CT-LIC-004: expected status active, got %s", slot.Status)
        }
}

func TestCTLIC005_AttestationOnNonTypeCRejected(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.SatisfyAttestation(SlotFoundry)
        if result.Success {
                t.Error("CT-LIC-005: expected failure for non-Type-C slot")
        }
        if result.Error != "Slot foundry does not require attestation" {
                t.Errorf("CT-LIC-005: unexpected error: %s", result.Error)
        }
}

func TestCTLIC006_PlatformToSRequiredBeforeGimelHosted(t *testing.T) {
        ls := NewLicenseState()
        if !ls.RequiresGimelToS(SlotOAuthEngine) {
                t.Error("CT-LIC-006: oauth_engine should require Gimel ToS")
        }
        err := ls.CheckPlatformToS("")
        if err != ErrLicenseRequired {
                t.Errorf("CT-LIC-006: expected ErrLicenseRequired, got: %v", err)
        }
}

func TestCTLIC007_ProprietaryServiceToSPerSlot(t *testing.T) {
        ls := NewLicenseState()
        ls.AcceptPlatformToS("2026.1")

        err := ls.CheckServiceToS(SlotAIGovernance, "")
        if err != ErrServiceToSRequired {
                t.Errorf("CT-LIC-007: expected ErrServiceToSRequired, got: %v", err)
        }

        ls.AcceptServiceToS(SlotAIGovernance, "2026.1")
        err = ls.CheckServiceToS(SlotAIGovernance, "")
        if err != nil {
                t.Errorf("CT-LIC-007: expected nil after accepting service ToS, got: %v", err)
        }
}

func TestCTLIC008_ToSVersionBumpTriggersReAcceptance(t *testing.T) {
        ls := NewLicenseState()
        ls.AcceptPlatformToS("2026.1")

        err := ls.CheckPlatformToS("2026.2")
        if err != ErrLicenseVersionOutdated {
                t.Errorf("CT-LIC-008: expected ErrLicenseVersionOutdated, got: %v", err)
        }
}

func TestCTLIC009_ServiceToSIndependenceAcrossSlots(t *testing.T) {
        ls := NewLicenseState()
        ls.AcceptPlatformToS("2026.1")
        ls.AcceptServiceToS(SlotAIGovernance, "2026.1")

        err := ls.CheckServiceToS(SlotAIGovernance, "")
        if err != nil {
                t.Errorf("CT-LIC-009: ai_governance should be accessible, got: %v", err)
        }

        err = ls.CheckServiceToS(SlotWeb3Identity, "")
        if err != ErrServiceToSRequired {
                t.Errorf("CT-LIC-009: web3_identity should still be blocked, got: %v", err)
        }
}

func TestCTLIC010_HybridMOTariffMatchesM(t *testing.T) {
        slots := []SlotName{SlotPDP, SlotOAuthEngine, SlotFoundry, SlotWallet, SlotAIGovernance, SlotWeb3Identity, SlotDNAIdentity}
        for _, slot := range slots {
                gateM := CheckTariffGate(slot, TariffM)
                gateMO := CheckTariffGate(slot, TariffMO)
                if gateM.Allowed != gateMO.Allowed {
                        t.Errorf("CT-LIC-010: slot %s: M+O allowed=%v but M allowed=%v — must match", slot, gateMO.Allowed, gateM.Allowed)
                }
                if gateM.Availability != gateMO.Availability {
                        t.Errorf("CT-LIC-010: slot %s: M+O availability=%s but M availability=%s — must match", slot, gateMO.Availability, gateM.Availability)
                }
        }
}

func TestCTLIC011_HybridLOTariffMatchesL(t *testing.T) {
        slots := []SlotName{SlotPDP, SlotOAuthEngine, SlotFoundry, SlotWallet, SlotAIGovernance, SlotWeb3Identity, SlotDNAIdentity}
        for _, slot := range slots {
                gateL := CheckTariffGate(slot, TariffL)
                gateLO := CheckTariffGate(slot, TariffLO)
                if gateL.Allowed != gateLO.Allowed {
                        t.Errorf("CT-LIC-011: slot %s: L+O allowed=%v but L allowed=%v — must match", slot, gateLO.Allowed, gateL.Allowed)
                }
                if gateL.Availability != gateLO.Availability {
                        t.Errorf("CT-LIC-011: slot %s: L+O availability=%s but L availability=%s — must match", slot, gateLO.Availability, gateL.Availability)
                }
        }
}

func TestCTLIC012_HybridMORegistersTypeCToPending(t *testing.T) {
        cr := NewConnectorRegistry(TariffMO)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgentGovernanceAdapter",
                Adapter:             struct{}{},
        })
        if !result.Success {
                t.Fatalf("CT-LIC-012: expected success, got error: %s", result.Error)
        }
        slot, _ := cr.GetSlot(SlotAIGovernance)
        if slot.Status != StatusPending {
                t.Errorf("CT-LIC-012: expected status pending for M+O Type C, got %s", slot.Status)
        }
}

func TestCTLIC013_HybridLOEnablesDNAIdentity(t *testing.T) {
        gate := CheckTariffGate(SlotDNAIdentity, TariffLO)
        if !gate.Allowed {
                t.Error("CT-LIC-013: expected tariff gate to allow dna_identity for L+O")
        }
        if gate.Availability != AvailAttestedGimel {
                t.Errorf("CT-LIC-013: expected availability attested_gimel, got %s", gate.Availability)
        }
}

func TestCTLIC014_HybridMOBlocksDNAIdentity(t *testing.T) {
        gate := CheckTariffGate(SlotDNAIdentity, TariffMO)
        if gate.Allowed {
                t.Error("CT-LIC-014: expected tariff gate to block dna_identity for M+O (same as M)")
        }
}

func TestCTLIC015_EffectiveTariffMapping(t *testing.T) {
        if TariffMO.EffectiveTariff() != TariffM {
                t.Errorf("CT-LIC-015: M+O effective should be M, got %s", TariffMO.EffectiveTariff())
        }
        if TariffLO.EffectiveTariff() != TariffL {
                t.Errorf("CT-LIC-015: L+O effective should be L, got %s", TariffLO.EffectiveTariff())
        }
        if TariffO.EffectiveTariff() != TariffO {
                t.Errorf("CT-LIC-015: O effective should be O, got %s", TariffO.EffectiveTariff())
        }
        if TariffM.EffectiveTariff() != TariffM {
                t.Errorf("CT-LIC-015: M effective should be M, got %s", TariffM.EffectiveTariff())
        }
}

func TestTariffGateAllSlots(t *testing.T) {
        tests := []struct {
                slot    SlotName
                tariff  TariffCode
                allowed bool
        }{
                {SlotPDP, TariffO, true},
                {SlotPDP, TariffL, true},
                {SlotOAuthEngine, TariffO, true},
                {SlotOAuthEngine, TariffM, true},
                {SlotFoundry, TariffO, true},
                {SlotFoundry, TariffS, true},
                {SlotWallet, TariffO, true},
                {SlotWallet, TariffL, true},
                {SlotAIGovernance, TariffO, false},
                {SlotAIGovernance, TariffS, false},
                {SlotAIGovernance, TariffM, true},
                {SlotAIGovernance, TariffL, true},
                {SlotWeb3Identity, TariffO, false},
                {SlotWeb3Identity, TariffS, false},
                {SlotWeb3Identity, TariffM, true},
                {SlotWeb3Identity, TariffL, true},
                {SlotDNAIdentity, TariffO, false},
                {SlotDNAIdentity, TariffS, false},
                {SlotDNAIdentity, TariffM, false},
                {SlotDNAIdentity, TariffL, true},

                {SlotPDP, TariffMO, true},
                {SlotPDP, TariffLO, true},
                {SlotAIGovernance, TariffMO, true},
                {SlotAIGovernance, TariffLO, true},
                {SlotDNAIdentity, TariffMO, false},
                {SlotDNAIdentity, TariffLO, true},
        }

        for _, tt := range tests {
                gate := CheckTariffGate(tt.slot, tt.tariff)
                if gate.Allowed != tt.allowed {
                        t.Errorf("CheckTariffGate(%s, %s): allowed=%v, want %v (reason: %s)",
                                tt.slot, tt.tariff, gate.Allowed, tt.allowed, gate.Reason)
                }
        }
}

func TestTariffGateUnknownSlot(t *testing.T) {
        gate := CheckTariffGate("nonexistent", TariffM)
        if gate.Allowed {
                t.Error("expected disallowed for unknown slot")
        }
}

func TestTariffGateUnknownTariff(t *testing.T) {
        gate := CheckTariffGate(SlotPDP, "X")
        if gate.Allowed {
                t.Error("expected disallowed for unknown tariff")
        }
}

func TestConnectorRegistrySetGetTariff(t *testing.T) {
        cr := NewConnectorRegistry(TariffO)
        if cr.GetTariff() != TariffO {
                t.Errorf("expected O, got %s", cr.GetTariff())
        }
        cr.SetTariff(TariffM)
        if cr.GetTariff() != TariffM {
                t.Errorf("expected M, got %s", cr.GetTariff())
        }
}

func TestConnectorRegistryTariffBlocksRegistration(t *testing.T) {
        cr := NewConnectorRegistry(TariffO)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "Test",
                Adapter:             struct{}{},
        })
        if result.Success {
                t.Error("expected registration to be blocked by tariff O for ai_governance")
        }
}

func TestConnectorRegistryWithManifest(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        pub, priv, _ := ed25519.GenerateKey(rand.Reader)
        cr.ManifestVerifier().AddTrustedKey("test-key", pub)

        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, nil)

        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgent",
                Adapter:             struct{}{},
                ManifestJSON:        manifest,
        })
        if !result.Success {
                t.Fatalf("expected success with valid manifest, got: %s", result.Error)
        }

        slot, _ := cr.GetSlot(SlotAIGovernance)
        if slot.Status != StatusActive {
                t.Errorf("expected active with valid manifest, got %s", slot.Status)
        }
        if !slot.AttestationSatisfied {
                t.Error("expected attestation satisfied")
        }
}

func TestConnectorRegistryBadManifest(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Register(ConnectorRegistration{
                SlotName:            SlotAIGovernance,
                ImplementationLabel: "GAgent",
                Adapter:             struct{}{},
                ManifestJSON:        []byte(`{"manifest_version":"1.0","adapter_type":"C","slot_name":"ai_governance","namespace":"@evil/bad","issuer":"gimel-foundation","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-06-01T00:00:00Z","public_key":"aa","signature":"bb"}`),
        })
        if result.Success {
                t.Error("expected registration failure with bad manifest namespace")
        }
}

func TestConnectorRegistryUnregisterUnknownSlot(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Unregister("nonexistent")
        if result.Success {
                t.Error("expected failure for unknown slot")
        }
}

func TestConnectorRegistrySatisfyAttestationUnknownSlot(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.SatisfyAttestation("nonexistent")
        if result.Success {
                t.Error("expected failure for unknown slot")
        }
}

func TestConnectorRegistrySatisfyAttestationNotPending(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.SatisfyAttestation(SlotAIGovernance)
        if result.Success {
                t.Error("expected failure - slot not in pending state")
        }
}

func TestConnectorRegistryGetStatus(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        status := cr.GetStatus()
        if len(status) != 7 {
                t.Errorf("expected 7 slots, got %d", len(status))
        }
        for _, slot := range AllSlots {
                info, ok := status[slot]
                if !ok {
                        t.Errorf("missing slot %s", slot)
                }
                if info.Status != StatusNull {
                        t.Errorf("slot %s: expected null, got %s", slot, info.Status)
                }
        }
}

func TestConnectorRegistrySlotErrorAndRecovery(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotFoundry,
                ImplementationLabel: "Test",
                Adapter:             struct{}{},
        })

        err := cr.SetSlotError(SlotFoundry)
        if err != nil {
                t.Fatalf("SetSlotError: %v", err)
        }
        slot, _ := cr.GetSlot(SlotFoundry)
        if slot.Status != StatusError {
                t.Errorf("expected error status, got %s", slot.Status)
        }

        err = cr.RecoverSlot(SlotFoundry)
        if err != nil {
                t.Fatalf("RecoverSlot: %v", err)
        }
        slot, _ = cr.GetSlot(SlotFoundry)
        if slot.Status != StatusActive {
                t.Errorf("expected active after recovery, got %s", slot.Status)
        }
}

func TestConnectorRegistrySlotErrorUnknown(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        err := cr.SetSlotError("nonexistent")
        if err == nil {
                t.Error("expected error for unknown slot")
        }
        err = cr.RecoverSlot("nonexistent")
        if err == nil {
                t.Error("expected error for unknown slot")
        }
}

func TestConnectorRegistryEvents(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotFoundry,
                ImplementationLabel: "Test",
                Adapter:             struct{}{},
        })
        events := cr.Events()
        if len(events) == 0 {
                t.Error("expected at least one event")
        }
}

func TestConnectorRegistryGetSlotUnknown(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        _, err := cr.GetSlot("nonexistent")
        if err == nil {
                t.Error("expected error for unknown slot")
        }
}

func TestConnectorRegistryRegisterUnknownSlot(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        result := cr.Register(ConnectorRegistration{
                SlotName: "nonexistent",
                Adapter:  struct{}{},
        })
        if result.Success {
                t.Error("expected failure for unknown slot")
        }
}

func TestManifestVerifierRevokedVersion(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        v.RevokeVersion("1.0.0")
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, nil)

        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestRevokedVersion {
                t.Errorf("expected ErrManifestRevokedVersion, got: %v", err)
        }
}

func TestManifestVerifierBadManifestVersion(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "manifest_version": "2.0",
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestVersion {
                t.Errorf("expected ErrManifestVersion, got: %v", err)
        }
}

func TestManifestVerifierBadAdapterType(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "adapter_type": "B",
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestType {
                t.Errorf("expected ErrManifestType, got: %v", err)
        }
}

func TestManifestVerifierBadIssuer(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "issuer": "evil-corp",
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestIssuer {
                t.Errorf("expected ErrManifestIssuer, got: %v", err)
        }
}

func TestManifestVerifierNotYetValid(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        future := time.Now().UTC().Add(48 * time.Hour)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "issued_at":  future.Format(time.RFC3339),
                "expires_at": future.Add(180 * 24 * time.Hour).Format(time.RFC3339),
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestNotYetValid {
                t.Errorf("expected ErrManifestNotYetValid, got: %v", err)
        }
}

func TestManifestVerifierInvalidJSON(t *testing.T) {
        v := NewManifestVerifier()
        _, err := v.Verify([]byte(`not-json`), SlotAIGovernance)
        if err == nil {
                t.Error("expected error for invalid JSON")
        }
}

func TestManifestVerifierBadDates(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "issued_at": "not-a-date",
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Error("expected error for bad issued_at")
        }

        manifest2 := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "expires_at": "not-a-date",
        })
        _, err = v.Verify(manifest2, SlotAIGovernance)
        if err == nil {
                t.Error("expected error for bad expires_at")
        }
}

func TestManifestVerifierBadPublicKeyHex(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "public_key": "not-hex",
        })
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err == nil {
                t.Error("expected error for bad public_key hex")
        }
}

func TestManifestVerifierBadSignatureHex(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/ai-governance", pub, priv, map[string]interface{}{
                "signature": "not-hex-sig",
        })

        var raw map[string]interface{}
        json.Unmarshal(manifest, &raw)
        raw["signature"] = "not-hex-sig"
        bad, _ := json.Marshal(raw)

        _, err := v.Verify(bad, SlotAIGovernance)
        if err == nil {
                t.Error("expected error for bad signature hex")
        }
}

func TestManifestVerifierBadPublicKeyLength(t *testing.T) {
        v := NewManifestVerifier()
        shortKey := make([]byte, 16)
        v.AddTrustedKey("test", shortKey)

        now := time.Now().UTC()
        m := map[string]interface{}{
                "manifest_version": "1.0",
                "adapter_name":     "Test",
                "adapter_type":     "C",
                "adapter_version":  "1.0.0",
                "slot_name":        "ai_governance",
                "namespace":        "@gimel/ai-governance",
                "issued_at":        now.Add(-1 * time.Hour).Format(time.RFC3339),
                "expires_at":       now.Add(180 * 24 * time.Hour).Format(time.RFC3339),
                "issuer":           "gimel-foundation",
                "public_key":       hex.EncodeToString(shortKey),
                "signature":        hex.EncodeToString(make([]byte, 64)),
        }
        data, _ := json.Marshal(m)
        _, err := v.Verify(data, SlotAIGovernance)
        if err == nil {
                t.Error("expected error for bad public_key length")
        }
}

func TestManifestNamespaceMismatch(t *testing.T) {
        v, pub, priv := setupVerifier(t)
        manifest := makeTestManifest(t, SlotAIGovernance, "@gimel/wrong-namespace", pub, priv, nil)
        _, err := v.Verify(manifest, SlotAIGovernance)
        if err != ErrManifestNamespaceSlot {
                t.Errorf("expected ErrManifestNamespaceSlot, got: %v", err)
        }
}

func TestLicenseServiceToSOnNonTypeC(t *testing.T) {
        ls := NewLicenseState()
        err := ls.AcceptServiceToS(SlotFoundry, "2026.1")
        if err != ErrNotTypeCSlot {
                t.Errorf("expected ErrNotTypeCSlot, got: %v", err)
        }

        err = ls.CheckServiceToS(SlotFoundry, "")
        if err != ErrNotTypeCSlot {
                t.Errorf("expected ErrNotTypeCSlot for check, got: %v", err)
        }
}

func TestLicenseServiceToSVersionBump(t *testing.T) {
        ls := NewLicenseState()
        ls.AcceptPlatformToS("2026.1")
        ls.AcceptServiceToS(SlotAIGovernance, "2026.1")

        err := ls.CheckServiceToS(SlotAIGovernance, "2026.2")
        if err != ErrServiceToSOutdated {
                t.Errorf("expected ErrServiceToSOutdated, got: %v", err)
        }
}

func TestLicenseRequiresGimelToS(t *testing.T) {
        ls := NewLicenseState()
        if ls.RequiresGimelToS(SlotPDP) {
                t.Error("PDP (internal) should not require Gimel ToS")
        }
        if !ls.RequiresGimelToS(SlotOAuthEngine) {
                t.Error("oauth_engine (Type A) should require Gimel ToS")
        }
        if !ls.RequiresGimelToS(SlotFoundry) {
                t.Error("foundry (Type B) should require Gimel ToS")
        }
        if !ls.RequiresGimelToS(SlotAIGovernance) {
                t.Error("ai_governance (Type C) should require Gimel ToS")
        }
        if ls.RequiresGimelToS("nonexistent") {
                t.Error("unknown slot should not require Gimel ToS")
        }
}

func TestSlotRecoverNotInError(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        cr.Register(ConnectorRegistration{
                SlotName:            SlotFoundry,
                ImplementationLabel: "Test",
                Adapter:             struct{}{},
        })
        err := cr.RecoverSlot(SlotFoundry)
        if err != nil {
                t.Fatalf("RecoverSlot: %v", err)
        }
        slot, _ := cr.GetSlot(SlotFoundry)
        if slot.Status != StatusActive {
                t.Errorf("expected active (no change), got %s", slot.Status)
        }
}

func TestSetSlotErrorNullSlot(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        err := cr.SetSlotError(SlotFoundry)
        if err != nil {
                t.Fatalf("SetSlotError: %v", err)
        }
        slot, _ := cr.GetSlot(SlotFoundry)
        if slot.Status != StatusNull {
                t.Errorf("expected null (unchanged), got %s", slot.Status)
        }
}

func TestConnectorRegistryLicense(t *testing.T) {
        cr := NewConnectorRegistry(TariffM)
        ls := cr.License()
        if ls == nil {
                t.Fatal("expected non-nil license state")
        }
        if ls.LicenseType != LicenseMPL2 {
                t.Errorf("expected mpl_2_0, got %s", ls.LicenseType)
        }
}

func TestCanonicalizeJSON(t *testing.T) {
        input := map[string]interface{}{
                "z": "last",
                "a": "first",
                "m": []interface{}{"b", "a"},
        }
        result, err := canonicalizeJSON(input)
        if err != nil {
                t.Fatalf("canonicalizeJSON: %v", err)
        }
        expected := `{"a":"first","m":["b","a"],"z":"last"}`
        if string(result) != expected {
                t.Errorf("canonical = %s, want %s", string(result), expected)
        }
}

func TestAllSlotsCount(t *testing.T) {
        if len(AllSlots) != 7 {
                t.Errorf("expected 7 slots, got %d", len(AllSlots))
        }
}

func TestMandatorySlots(t *testing.T) {
        if !MandatorySlots[SlotPDP] {
                t.Error("pdp should be mandatory")
        }
        if !MandatorySlots[SlotOAuthEngine] {
                t.Error("oauth_engine should be mandatory")
        }
        if MandatorySlots[SlotFoundry] {
                t.Error("foundry should not be mandatory")
        }
}

func TestSlotTypeClassMapping(t *testing.T) {
        expected := map[SlotName]AdapterTypeClass{
                SlotPDP:          TypeClassInternal,
                SlotOAuthEngine:  TypeClassA,
                SlotFoundry:      TypeClassB,
                SlotWallet:       TypeClassB,
                SlotAIGovernance: TypeClassC,
                SlotWeb3Identity: TypeClassC,
                SlotDNAIdentity:  TypeClassC,
        }
        for slot, tc := range expected {
                if SlotTypeClass[slot] != tc {
                        t.Errorf("slot %s: expected %s, got %s", slot, tc, SlotTypeClass[slot])
                }
        }
}
