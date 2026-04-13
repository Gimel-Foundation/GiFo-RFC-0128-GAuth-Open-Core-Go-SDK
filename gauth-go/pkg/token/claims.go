// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package token

import "github.com/gimelfoundation/gauth-go/pkg/poa"

type GAuthClaims struct {
	Version               string    `json:"version"`
	CredentialID          string    `json:"credential_id"`
	CustomerID            string    `json:"customer_id"`
	ProjectID             string    `json:"project_id"`
	Scope                 ScopeClaims `json:"scope"`
	ScopeChecksum         string    `json:"scope_checksum"`
	ToolPermissionsHash   string    `json:"tool_permissions_hash"`
	PlatformPermHash      string    `json:"platform_permissions_hash"`
	IssuedBy              string    `json:"issued_by"`
	ApprovalMode          poa.ApprovalMode `json:"approval_mode"`
}

type ScopeClaims struct {
	GovernanceProfile poa.GovernanceProfile `json:"governance_profile"`
	ActiveModules     []string              `json:"active_modules,omitempty"`
	Phase             poa.Phase             `json:"phase"`
	AllowedPaths      []string              `json:"allowed_paths,omitempty"`
	DeniedPaths       []string              `json:"denied_paths,omitempty"`
}

type MandateClaims struct {
	MandateID           string       `json:"mandate_id"`
	MandateStatus       poa.MandateStatus `json:"mandate_status"`
	Budget              *poa.Budget       `json:"budget,omitempty"`
	Session             *poa.SessionLimits `json:"session,omitempty"`
	AgentCapabilityHash string       `json:"agent_capability_hash,omitempty"`
}

type ExtendedTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	JWTID     string   `json:"jti"`

	GAuth        *GAuthClaims   `json:"gauth,omitempty"`
	GAuthMandate *MandateClaims `json:"gauth_mandate,omitempty"`
}

func ClaimsFromPoA(cred *poa.PoACredential, scopeChecksum, toolHash, platHash string) *GAuthClaims {
	return &GAuthClaims{
		Version:             poa.SchemaVersion,
		CredentialID:        cred.CredentialID,
		CustomerID:          cred.Parties.CustomerID,
		ProjectID:           cred.Parties.ProjectID,
		Scope: ScopeClaims{
			GovernanceProfile: cred.Scope.GovernanceProfile,
			ActiveModules:     cred.Scope.ActiveModules,
			Phase:             cred.Scope.Phase,
			AllowedPaths:      cred.Scope.AllowedPaths,
			DeniedPaths:       cred.Scope.DeniedPaths,
		},
		ScopeChecksum:       scopeChecksum,
		ToolPermissionsHash: toolHash,
		PlatformPermHash:    platHash,
		IssuedBy:            cred.Parties.IssuedBy,
		ApprovalMode:        cred.Requirements.ApprovalMode,
	}
}
