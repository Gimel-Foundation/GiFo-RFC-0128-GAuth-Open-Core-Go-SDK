// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package adapter

import (
        "time"
)

type SlotName string

const (
        SlotPDP           SlotName = "pdp"
        SlotOAuthEngine   SlotName = "oauth_engine"
        SlotFoundry       SlotName = "foundry"
        SlotWallet        SlotName = "wallet"
        SlotAIGovernance  SlotName = "ai_governance"
        SlotWeb3Identity  SlotName = "web3_identity"
        SlotDNAIdentity   SlotName = "dna_identity"
)

var AllSlots = []SlotName{
        SlotPDP, SlotOAuthEngine, SlotFoundry, SlotWallet,
        SlotAIGovernance, SlotWeb3Identity, SlotDNAIdentity,
}

var MandatorySlots = map[SlotName]bool{
        SlotPDP:         true,
        SlotOAuthEngine: true,
}

type AdapterTypeClass string

const (
        TypeClassInternal AdapterTypeClass = "Internal"
        TypeClassA        AdapterTypeClass = "A"
        TypeClassB        AdapterTypeClass = "B"
        TypeClassC        AdapterTypeClass = "C"
        TypeClassD        AdapterTypeClass = "D"
)

var SlotTypeClass = map[SlotName]AdapterTypeClass{
        SlotPDP:          TypeClassInternal,
        SlotOAuthEngine:  TypeClassA,
        SlotFoundry:      TypeClassB,
        SlotWallet:       TypeClassB,
        SlotAIGovernance: TypeClassC,
        SlotWeb3Identity: TypeClassC,
        SlotDNAIdentity:  TypeClassC,
}

type SlotStatus string

const (
        StatusNull    SlotStatus = "null"
        StatusPending SlotStatus = "pending"
        StatusActive  SlotStatus = "active"
        StatusError   SlotStatus = "error"
)

type TariffCode string

const (
        TariffO  TariffCode = "O"
        TariffS  TariffCode = "S"
        TariffM  TariffCode = "M"
        TariffL  TariffCode = "L"
        TariffMO TariffCode = "M+O"
        TariffLO TariffCode = "L+O"
)

func (t TariffCode) EffectiveTariff() TariffCode {
        switch t {
        case TariffMO:
                return TariffM
        case TariffLO:
                return TariffL
        default:
                return t
        }
}

type AvailabilityCode string

const (
        AvailActiveAlways       AvailabilityCode = "active_always"
        AvailGimelOrUser        AvailabilityCode = "gimel_or_user"
        AvailUserProvidedReq    AvailabilityCode = "user_provided_required"
        AvailNullOrUser         AvailabilityCode = "null_or_user"
        AvailAttestedGimel      AvailabilityCode = "attested_gimel"
        AvailNullOrAttestedGimel AvailabilityCode = "null_or_attested_gimel"
        AvailNull               AvailabilityCode = "null"
)

type SlotInfo struct {
        SlotName            SlotName         `json:"slot_name"`
        TypeClass           AdapterTypeClass `json:"adapter_type"`
        Status              SlotStatus       `json:"status"`
        ImplementationLabel string           `json:"implementation_label"`
        Adapter             interface{}      `json:"-"`
        AttestationSatisfied bool            `json:"attestation_satisfied"`
        Manifest            *SealedManifest  `json:"manifest,omitempty"`
}

type SealedManifest struct {
        ManifestVersion string   `json:"manifest_version"`
        AdapterName     string   `json:"adapter_name"`
        AdapterType     string   `json:"adapter_type"`
        AdapterVersion  string   `json:"adapter_version"`
        SlotName        string   `json:"slot_name"`
        Namespace       string   `json:"namespace"`
        IssuedAt        string   `json:"issued_at"`
        ExpiresAt       string   `json:"expires_at"`
        Issuer          string   `json:"issuer"`
        Capabilities    []string `json:"capabilities,omitempty"`
        Checksum        string   `json:"checksum,omitempty"`
        PublicKey       string   `json:"public_key"`
        Signature       string   `json:"signature"`
}

type TariffGateResult struct {
        Allowed    bool             `json:"allowed"`
        Reason     string           `json:"reason,omitempty"`
        Provenance string           `json:"provenance,omitempty"`
        Availability AvailabilityCode `json:"availability,omitempty"`
}

type LicenseType string

const (
        LicenseMPL2    LicenseType = "mpl_2_0"
        LicenseGimelToS LicenseType = "gimel_tos"
)

type LicenseState struct {
        LicenseType       LicenseType        `json:"license_type"`
        LicenseAcceptedAt *time.Time         `json:"license_accepted_at"`
        LicenseVersion    string             `json:"license_version,omitempty"`
        ServiceToS        map[SlotName]*ServiceToSState `json:"service_tos,omitempty"`
}

type ServiceToSState struct {
        Accepted   bool      `json:"service_tos_accepted"`
        Version    string    `json:"service_tos_version,omitempty"`
        AcceptedAt *time.Time `json:"service_tos_accepted_at,omitempty"`
}

type TrustedKey struct {
        KeyID     string `json:"key_id"`
        PublicKey []byte `json:"public_key"`
}

var CanonicalSlotNamespace = map[SlotName]string{
        SlotAIGovernance: "@gimel/ai-governance",
        SlotWeb3Identity: "@gimel/web3-identity",
        SlotDNAIdentity:  "@gimel/dna-identity",
}
