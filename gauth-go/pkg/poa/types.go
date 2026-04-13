// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package poa

import (
        "time"
)

const SchemaVersion = "0116.2.2"
const SchemaID = "https://gimelfoundation.com/schemas/poa/v2.2/poa-credential.json"

type PoACredential struct {
        SchemaVersion string       `json:"schema_version"`
        CredentialID  string       `json:"credential_id"`
        Parties       Parties      `json:"parties"`
        Scope         Scope        `json:"scope"`
        Requirements  Requirements `json:"requirements"`
}

type Parties struct {
        Subject       string           `json:"subject"`
        CustomerID    string           `json:"customer_id"`
        ProjectID     string           `json:"project_id"`
        IssuedBy      string           `json:"issued_by"`
        ApprovalChain []string         `json:"approval_chain,omitempty"`
        Delegation    *DelegationChain `json:"delegation,omitempty"`
}

type DelegationChain struct {
        Entries []DelegationEntry `json:"entries"`
}

type DelegationEntry struct {
        DelegatorID string    `json:"delegator_id"`
        DelegateeID string    `json:"delegatee_id"`
        Depth       int       `json:"depth"`
        DelegatedAt time.Time `json:"delegated_at"`
        ScopeHash   string    `json:"scope_hash"`
}

type Scope struct {
        GovernanceProfile   GovernanceProfile  `json:"governance_profile"`
        ActiveModules       []string           `json:"active_modules,omitempty"`
        Phase               Phase              `json:"phase"`
        AllowedPaths        []string           `json:"allowed_paths,omitempty"`
        DeniedPaths         []string           `json:"denied_paths,omitempty"`
        AllowedSectors      []string           `json:"allowed_sectors,omitempty"`
        AllowedRegions      []string           `json:"allowed_regions,omitempty"`
        CoreVerbs           map[string]ToolPolicy      `json:"core_verbs,omitempty"`
        PlatformPermissions *PlatformPermissions       `json:"platform_permissions,omitempty"`
}

type ToolPolicy struct {
        Allowed       bool              `json:"allowed"`
        CostCentsBase float64           `json:"cost_cents_base,omitempty"`
        Constraints   *VerbConstraints  `json:"constraints,omitempty"`
}

type VerbConstraints struct {
        PathPatterns       []string `json:"path_patterns,omitempty"`
        AllowedCommands    []string `json:"allowed_commands,omitempty"`
        DeniedCommands     []string `json:"denied_commands,omitempty"`
        MaxDelegationDepth *int     `json:"max_delegation_depth,omitempty"`
        MaxFileSizeBytes   *int     `json:"max_file_size_bytes,omitempty"`
}

type PlatformPermissions struct {
        Deployment   *DeploymentPermissions   `json:"deployment,omitempty"`
        Database     *DatabasePermissions     `json:"database,omitempty"`
        Shell        *ShellPermissions        `json:"shell,omitempty"`
        Packages     *PackagePermissions      `json:"packages,omitempty"`
        ExternalAPIs *ExternalAPIPermissions  `json:"external_apis,omitempty"`
        Secrets      *SecretPermissions       `json:"secrets,omitempty"`
}

type DeploymentPermissions struct {
        Targets    []string `json:"targets,omitempty"`
        AutoDeploy bool     `json:"auto_deploy,omitempty"`
}

type DatabasePermissions struct {
        Read             bool `json:"read,omitempty"`
        Write            bool `json:"write,omitempty"`
        Migrate          bool `json:"migrate,omitempty"`
        ProductionAccess bool `json:"production_access,omitempty"`
}

type ShellPermissions struct {
        Mode      ShellMode `json:"mode,omitempty"`
        Allowlist []string  `json:"allowlist,omitempty"`
        Denylist  []string  `json:"denylist,omitempty"`
}

type PackagePermissions struct {
        VerifiedOnly bool `json:"verified_only,omitempty"`
}

type ExternalAPIPermissions struct {
        AllowedDomains []string `json:"allowed_domains,omitempty"`
}

type SecretPermissions struct {
        Read   bool `json:"read,omitempty"`
        Create bool `json:"create,omitempty"`
}

type Requirements struct {
        ApprovalMode  ApprovalMode   `json:"approval_mode"`
        Budget        *Budget        `json:"budget,omitempty"`
        SessionLimits *SessionLimits `json:"session_limits,omitempty"`
        TTLSeconds    int            `json:"ttl_seconds,omitempty"`
}

type Budget struct {
        TotalCents     int `json:"total_cents"`
        RemainingCents int `json:"remaining_cents"`
}

type PoAPermission struct {
        Action   string `json:"action"`
        Resource string `json:"resource,omitempty"`
        Effect   string `json:"effect"`
}

type PoAMapSummary struct {
        MandateID        string          `json:"mandate_id"`
        Subject          string          `json:"subject"`
        Scope            Scope           `json:"scope"`
        Permissions      []PoAPermission `json:"permissions,omitempty"`
        AllowedActions   []string        `json:"allowed_actions,omitempty"`
        AllowedDecisions []string        `json:"allowed_decisions,omitempty"`
}

type SessionLimits struct {
        MaxToolCalls       int       `json:"max_tool_calls,omitempty"`
        RemainingToolCalls int       `json:"remaining_tool_calls,omitempty"`
        MaxLinesPerCommit  int       `json:"max_lines_per_commit,omitempty"`
        SessionID          string    `json:"session_id,omitempty"`
        StartedAt          time.Time `json:"started_at,omitempty"`
}
