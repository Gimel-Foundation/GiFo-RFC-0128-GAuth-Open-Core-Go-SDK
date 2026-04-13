// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package pep

import (
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

const InterfaceVersion = "1.2"

type EnforcementRequest struct {
        RequestID  string              `json:"request_id"`
        Timestamp  time.Time           `json:"timestamp"`
        Agent      AgentIdentity       `json:"agent"`
        Action     Action              `json:"action"`
        Credential CredentialReference `json:"credential"`
        Context    *EnforcementContext `json:"context,omitempty"`
}

type AgentIdentity struct {
        AgentID   string `json:"agent_id"`
        Service   string `json:"service,omitempty"`
        SessionID string `json:"session_id,omitempty"`
        DID       string `json:"did,omitempty"`
}

type Action struct {
        Verb            string                 `json:"verb"`
        Resource        string                 `json:"resource"`
        ResourceType    string                 `json:"resource_type,omitempty"`
        Parameters      map[string]interface{} `json:"parameters,omitempty"`
        Sector          string                 `json:"sector,omitempty"`
        Region          string                 `json:"region,omitempty"`
        TransactionType string                 `json:"transaction_type,omitempty"`
        DecisionType    string                 `json:"decision_type,omitempty"`
}

func (a *Action) AmountCents() int {
        if a.Parameters == nil {
                return 0
        }
        v, ok := a.Parameters["amount_cents"]
        if !ok {
                return 0
        }
        switch val := v.(type) {
        case float64:
                return int(val)
        case int:
                return val
        default:
                return 0
        }
}

type CredentialReference struct {
        Format            poa.CredentialFormat `json:"format"`
        Token             string              `json:"token,omitempty"`
        MandateID         string              `json:"mandate_id,omitempty"`
        PoASnapshot       *PoASnapshot        `json:"poa_snapshot,omitempty"`
        SignatureVerified *bool               `json:"signature_verified,omitempty"`
}

type PoASnapshot struct {
        SchemaVersion     string                    `json:"schema_version"`
        CredentialID      string                    `json:"credential_id"`
        Subject           string                    `json:"subject"`
        CustomerID        string                    `json:"customer_id"`
        ProjectID         string                    `json:"project_id"`
        Scope             poa.Scope                 `json:"scope"`
        ScopeChecksum     string                    `json:"scope_checksum"`
        Requirements      poa.Requirements          `json:"requirements"`
        MandateID         string                    `json:"mandate_id,omitempty"`
        MandateStatus     poa.MandateStatus         `json:"mandate_status,omitempty"`
        Budget            *poa.Budget               `json:"budget,omitempty"`
        Session           *poa.SessionLimits        `json:"session,omitempty"`
        DelegationChain   *poa.DelegationChain      `json:"delegation_chain,omitempty"`
        ExpiresAt         int64                     `json:"exp,omitempty"`
        NotBefore         int64                     `json:"nbf,omitempty"`
        Audience          []string                  `json:"aud,omitempty"`
}

type EnforcementContext struct {
        SessionState    *SessionState    `json:"session_state,omitempty"`
        LiveMandateState *LiveMandateState `json:"live_mandate_state,omitempty"`
}

type SessionState struct {
        ToolCallsUsed    int       `json:"tool_calls_used"`
        LinesCommitted   int       `json:"lines_committed"`
        SessionStartedAt time.Time `json:"session_started_at,omitempty"`
        SessionCostCents int       `json:"session_cost_cents"`
}

type LiveMandateState struct {
        Status              string                 `json:"status"`
        BudgetRemainingCents int                   `json:"budget_remaining_cents"`
        ToolPermissions     map[string]interface{} `json:"tool_permissions,omitempty"`
        PlatformPermissions map[string]interface{} `json:"platform_permissions,omitempty"`
}

type EscalationReason string

const (
        EscalationAIGovernance    EscalationReason = "ai_governance_required"
        EscalationLiveMandateState EscalationReason = "live_mandate_state_required"
        EscalationProprietaryRoute EscalationReason = "proprietary_service_routing"
)

type EscalationInfo struct {
        Required bool               `json:"required"`
        Reasons  []EscalationReason `json:"reasons,omitempty"`
        Fallback poa.Decision       `json:"fallback"`
}

type AuthPEPForwarder interface {
        Forward(req *EnforcementRequest, reasons []EscalationReason) (*EnforcementDecision, error)
}

type EnforcementDecision struct {
        RequestID          string               `json:"request_id"`
        Decision           poa.Decision         `json:"decision"`
        Timestamp          time.Time            `json:"timestamp"`
        EnforcementMode    poa.EnforcementMode  `json:"enforcement_mode"`
        Checks             []CheckResult        `json:"checks"`
        EnforcedConstraints []EnforcedConstraint `json:"enforced_constraints,omitempty"`
        Violations         []Violation          `json:"violations,omitempty"`
        Escalation         *EscalationInfo      `json:"escalation,omitempty"`
        Audit              AuditRecord          `json:"audit"`
}

type CheckResult struct {
        CheckID   string                `json:"check_id"`
        CheckName string                `json:"check_name"`
        Result    poa.CheckResultStatus `json:"result"`
        Detail    string                `json:"detail,omitempty"`
}

type EnforcedConstraint struct {
        ConstraintType string      `json:"constraint_type"`
        CheckID        string      `json:"check_id"`
        Requested      interface{} `json:"requested"`
        Enforced       interface{} `json:"enforced"`
}

type Violation struct {
        Code     string                `json:"code"`
        Message  string                `json:"message"`
        CheckID  string                `json:"check_id"`
        Severity poa.ViolationSeverity `json:"severity"`
}

type AuditRecord struct {
        ProcessingTimeMs    float64 `json:"processing_time_ms"`
        PEPVersion          string  `json:"pep_version"`
        PEPInterfaceVersion string  `json:"pep_interface_version,omitempty"`
        CredentialJTI       string  `json:"credential_jti,omitempty"`
        MandateID           string  `json:"mandate_id,omitempty"`
        AgentID             string  `json:"agent_id,omitempty"`
        ActionVerb          string  `json:"action_verb,omitempty"`
        ActionResource      string  `json:"action_resource,omitempty"`
        ChecksPerformed     int     `json:"checks_performed"`
        ChecksPassed        int     `json:"checks_passed"`
        ChecksFailed        int     `json:"checks_failed"`
        ChecksSkipped       int     `json:"checks_skipped"`
}

type EnforcementError struct {
        ErrorCode string            `json:"error_code"`
        Message   string            `json:"message"`
        Timestamp time.Time         `json:"timestamp"`
        RequestID string            `json:"request_id,omitempty"`
        Detail    *ErrorDetail      `json:"detail,omitempty"`
}

type ErrorDetail struct {
        FailedField string  `json:"failed_field,omitempty"`
        IssuerURL   string  `json:"issuer_url,omitempty"`
        TimeoutMs   float64 `json:"timeout_ms,omitempty"`
}

func (e *EnforcementError) Error() string {
        return e.ErrorCode + ": " + e.Message
}

type BatchMode string

const (
        BatchAllOrNothing BatchMode = "all_or_nothing"
        BatchIndependent  BatchMode = "independent"
)

type BatchDecision struct {
        OverallDecision poa.Decision          `json:"overall_decision"`
        Decisions       []EnforcementDecision `json:"decisions"`
}

type EnforcementPolicy struct {
        GovernanceProfile poa.GovernanceProfile  `json:"governance_profile"`
        Phase             poa.Phase              `json:"phase"`
        AllowedVerbs      []string               `json:"allowed_verbs"`
        DeniedPaths       []string               `json:"denied_paths"`
        AllowedPaths      []string               `json:"allowed_paths"`
        Permissions       map[string]interface{} `json:"permissions,omitempty"`
        Budget            *poa.Budget            `json:"budget,omitempty"`
        SessionLimits     map[string]interface{} `json:"session_limits,omitempty"`
        ApprovalMode      poa.ApprovalMode       `json:"approval_mode"`
        Delegation        *DelegationPolicy      `json:"delegation,omitempty"`
}

type DelegationPolicy struct {
        Allowed  bool `json:"allowed"`
        MaxDepth int  `json:"max_depth"`
}
