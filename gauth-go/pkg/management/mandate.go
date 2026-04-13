// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package management

import (
        "crypto/rand"
        "errors"
        "fmt"
        "sort"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

var (
        ErrInvalidTransition    = errors.New("gauth: invalid mandate state transition")
        ErrTerminalState        = errors.New("gauth: mandate is in a terminal state")
        ErrScopeImmutable       = errors.New("gauth: scope is immutable once mandate is active")
        ErrBudgetOnlyAdditive   = errors.New("gauth: budget ceiling may only increase, never decrease")
        ErrTTLOnlyAdditive      = errors.New("gauth: TTL may only be extended, never shortened")
        ErrMissingRequiredField = errors.New("gauth: missing required field")
        ErrValidationFailed     = errors.New("gauth: mandate validation failed")
)

type Mandate struct {
        MandateID   string            `json:"mandate_id"`
        Status      poa.MandateStatus `json:"status"`
        Parties     poa.Parties       `json:"parties"`
        Scope       poa.Scope         `json:"scope"`
        Requirements poa.Requirements `json:"requirements"`
        ScopeChecksum string          `json:"scope_checksum,omitempty"`
        CreatedAt   time.Time         `json:"created_at"`
        ActivatedAt *time.Time        `json:"activated_at,omitempty"`
        UpdatedAt   time.Time         `json:"updated_at"`
        ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
        AuditLog    []AuditEntry      `json:"audit_log,omitempty"`
}

type AuditEntry struct {
        Timestamp  time.Time `json:"timestamp"`
        Action     string    `json:"action"`
        ActorID    string    `json:"actor_id"`
        FromStatus string    `json:"from_status,omitempty"`
        ToStatus   string    `json:"to_status,omitempty"`
        Detail     string    `json:"detail,omitempty"`
}

type MandateCreationRequest struct {
        Parties      poa.Parties      `json:"parties"`
        Scope        poa.Scope        `json:"scope"`
        Requirements poa.Requirements `json:"requirements"`
}

type MandateCreationResponse struct {
        MandateID     string            `json:"mandate_id"`
        Status        poa.MandateStatus `json:"status"`
        ScopeChecksum string            `json:"scope_checksum"`
        CreatedAt     time.Time         `json:"created_at"`
}

type MandateManager struct {
        store MandateStore
}

type MandateStore interface {
        Save(mandate *Mandate) error
        Get(mandateID string) (*Mandate, error)
        List(customerID, projectID string, status *poa.MandateStatus, limit, offset int) ([]*Mandate, error)
        FindActive(agentID, projectID string) (*Mandate, error)
}

func NewMandateManager(store MandateStore) *MandateManager {
        return &MandateManager{store: store}
}

func (m *MandateManager) CreateMandate(req *MandateCreationRequest, actorID string) (*MandateCreationResponse, error) {
        if err := validateCreationRequest(req); err != nil {
                return nil, err
        }

        checksum, err := poa.ComputeScopeChecksum(req.Scope)
        if err != nil {
                return nil, fmt.Errorf("gauth: compute scope checksum: %w", err)
        }

        now := time.Now()
        mandate := &Mandate{
                MandateID:     fmt.Sprintf("mdt_%s", generateID()),
                Status:        poa.StatusDraft,
                Parties:       req.Parties,
                Scope:         req.Scope,
                Requirements:  req.Requirements,
                ScopeChecksum: checksum,
                CreatedAt:     now,
                UpdatedAt:     now,
                AuditLog: []AuditEntry{{
                        Timestamp: now,
                        Action:    "create",
                        ActorID:   actorID,
                        ToStatus:  string(poa.StatusDraft),
                        Detail:    "Mandate created",
                }},
        }

        if err := m.store.Save(mandate); err != nil {
                return nil, fmt.Errorf("gauth: save mandate: %w", err)
        }

        return &MandateCreationResponse{
                MandateID:     mandate.MandateID,
                Status:        mandate.Status,
                ScopeChecksum: mandate.ScopeChecksum,
                CreatedAt:     mandate.CreatedAt,
        }, nil
}

func (m *MandateManager) GetMandate(mandateID string) (*Mandate, error) {
        return m.store.Get(mandateID)
}

func (m *MandateManager) ListMandates(customerID, projectID string, status *poa.MandateStatus, limit, offset int) ([]*Mandate, error) {
        if limit <= 0 {
                limit = 50
        }
        return m.store.List(customerID, projectID, status, limit, offset)
}

func (m *MandateManager) ActivateMandate(mandateID, actorID string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusDraft {
                return fmt.Errorf("%w: cannot activate from %s (must be draft)", ErrInvalidTransition, mandate.Status)
        }

        if err := m.runConsistencyChecks(mandate); err != nil {
                return err
        }

        existing, err := m.store.FindActive(mandate.Parties.Subject, mandate.Parties.ProjectID)
        if err == nil && existing != nil {
                if err := m.transitionStatus(existing, poa.StatusSuperseded, actorID, "Superseded by "+mandateID); err != nil {
                        return fmt.Errorf("gauth: supersede existing mandate: %w", err)
                }
        }

        now := time.Now()
        mandate.ActivatedAt = &now

        if mandate.Requirements.TTLSeconds > 0 {
                exp := now.Add(time.Duration(mandate.Requirements.TTLSeconds) * time.Second)
                mandate.ExpiresAt = &exp
        }

        return m.transitionStatus(mandate, poa.StatusActive, actorID, "Mandate activated")
}

func (m *MandateManager) SuspendMandate(mandateID, actorID, reason string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusActive {
                return fmt.Errorf("%w: cannot suspend from %s (must be active)", ErrInvalidTransition, mandate.Status)
        }

        return m.transitionStatus(mandate, poa.StatusSuspended, actorID, "Suspended: "+reason)
}

func (m *MandateManager) ResumeMandate(mandateID, actorID string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusSuspended {
                return fmt.Errorf("%w: cannot resume from %s (must be suspended)", ErrInvalidTransition, mandate.Status)
        }

        if mandate.ExpiresAt != nil && time.Now().After(*mandate.ExpiresAt) {
                return m.transitionStatus(mandate, poa.StatusExpired, "system", "TTL elapsed during suspension")
        }

        return m.transitionStatus(mandate, poa.StatusActive, actorID, "Mandate resumed")
}

func (m *MandateManager) RevokeMandate(mandateID, actorID, reason string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status.IsTerminal() {
                return fmt.Errorf("%w: mandate is already in terminal state %s", ErrTerminalState, mandate.Status)
        }

        if mandate.Status != poa.StatusActive && mandate.Status != poa.StatusSuspended {
                return fmt.Errorf("%w: cannot revoke from %s", ErrInvalidTransition, mandate.Status)
        }

        return m.transitionStatus(mandate, poa.StatusRevoked, actorID, "Revoked: "+reason)
}

func (m *MandateManager) TransitionToBudgetExceeded(mandateID, actorID string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusActive {
                return fmt.Errorf("%w: can only transition to budget_exceeded from active state, current: %s", ErrInvalidTransition, mandate.Status)
        }

        return m.transitionStatus(mandate, poa.StatusBudgetExceeded, actorID, "Budget exhausted")
}

func (m *MandateManager) ExtendTTL(mandateID, actorID string, additionalSeconds int) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status.IsTerminal() {
                return ErrTerminalState
        }

        if mandate.Status != poa.StatusActive && mandate.Status != poa.StatusSuspended {
                return fmt.Errorf("%w: cannot extend TTL in state %s", ErrInvalidTransition, mandate.Status)
        }

        if additionalSeconds <= 0 {
                return ErrTTLOnlyAdditive
        }

        mandate.Requirements.TTLSeconds += additionalSeconds
        if mandate.ExpiresAt != nil {
                newExp := mandate.ExpiresAt.Add(time.Duration(additionalSeconds) * time.Second)
                mandate.ExpiresAt = &newExp
        }

        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp: time.Now(),
                Action:    "extend_ttl",
                ActorID:   actorID,
                Detail:    fmt.Sprintf("TTL extended by %d seconds", additionalSeconds),
        })

        return m.store.Save(mandate)
}

func (m *MandateManager) IncreaseBudget(mandateID, actorID string, additionalCents int) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status.IsTerminal() {
                return ErrTerminalState
        }

        if mandate.Status != poa.StatusActive && mandate.Status != poa.StatusSuspended {
                return fmt.Errorf("%w: cannot increase budget in state %s", ErrInvalidTransition, mandate.Status)
        }

        if additionalCents <= 0 {
                return ErrBudgetOnlyAdditive
        }

        if mandate.Requirements.Budget == nil {
                mandate.Requirements.Budget = &poa.Budget{}
        }

        mandate.Requirements.Budget.TotalCents += additionalCents
        mandate.Requirements.Budget.RemainingCents += additionalCents
        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp: time.Now(),
                Action:    "increase_budget",
                ActorID:   actorID,
                Detail:    fmt.Sprintf("Budget increased by %d cents", additionalCents),
        })

        return m.store.Save(mandate)
}

func (m *MandateManager) CreateDelegation(mandateID, actorID, delegateeID string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusActive {
                return fmt.Errorf("%w: cannot delegate from state %s (must be active)", ErrInvalidTransition, mandate.Status)
        }

        if mandate.Scope.CoreVerbs == nil {
                return fmt.Errorf("%w: no core_verbs defined — delegation denied by default", ErrValidationFailed)
        }

        dp, exists := mandate.Scope.CoreVerbs["foundry.agent.delegate"]
        if !exists || !dp.Allowed {
                return fmt.Errorf("%w: delegation verb is not allowed in this mandate", ErrValidationFailed)
        }

        if dp.Constraints != nil && dp.Constraints.MaxDelegationDepth != nil {
                currentDepth := 0
                if mandate.Parties.Delegation != nil {
                        currentDepth = len(mandate.Parties.Delegation.Entries)
                }
                if currentDepth >= *dp.Constraints.MaxDelegationDepth {
                        return fmt.Errorf("%w: max delegation depth %d reached", ErrValidationFailed, *dp.Constraints.MaxDelegationDepth)
                }
        }

        scopeHash, err := poa.ComputeScopeChecksum(mandate.Scope)
        if err != nil {
                return fmt.Errorf("gauth: compute scope hash for delegation: %w", err)
        }

        entry := poa.DelegationEntry{
                DelegatorID: mandate.Parties.Subject,
                DelegateeID: delegateeID,
                Depth:       1,
                DelegatedAt: time.Now(),
                ScopeHash:   scopeHash,
        }

        if mandate.Parties.Delegation == nil {
                mandate.Parties.Delegation = &poa.DelegationChain{}
        }
        if len(mandate.Parties.Delegation.Entries) > 0 {
                entry.Depth = mandate.Parties.Delegation.Entries[len(mandate.Parties.Delegation.Entries)-1].Depth + 1
        }
        mandate.Parties.Delegation.Entries = append(mandate.Parties.Delegation.Entries, entry)

        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp: time.Now(),
                Action:    "create_delegation",
                ActorID:   actorID,
                Detail:    fmt.Sprintf("Delegated to %s at depth %d", delegateeID, entry.Depth),
        })

        return m.store.Save(mandate)
}

func (m *MandateManager) RevokeDelegation(mandateID, actorID, delegateeID string) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status != poa.StatusActive && mandate.Status != poa.StatusSuspended {
                return fmt.Errorf("%w: cannot revoke delegation from state %s", ErrInvalidTransition, mandate.Status)
        }

        if mandate.Parties.Delegation == nil || len(mandate.Parties.Delegation.Entries) == 0 {
                return fmt.Errorf("gauth: no delegation chain to revoke from")
        }

        found := false
        var remaining []poa.DelegationEntry
        for _, e := range mandate.Parties.Delegation.Entries {
                if e.DelegateeID == delegateeID && !found {
                        found = true
                        continue
                }
                if found {
                        continue
                }
                remaining = append(remaining, e)
        }

        if !found {
                return fmt.Errorf("gauth: delegatee %q not found in delegation chain", delegateeID)
        }

        mandate.Parties.Delegation.Entries = remaining
        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp: time.Now(),
                Action:    "revoke_delegation",
                ActorID:   actorID,
                Detail:    fmt.Sprintf("Revoked delegation for %s and all downstream", delegateeID),
        })

        return m.store.Save(mandate)
}

func (m *MandateManager) AssignGovernanceProfile(mandateID, actorID string, profile poa.GovernanceProfile) error {
        mandate, err := m.store.Get(mandateID)
        if err != nil {
                return err
        }

        if mandate.Status.IsTerminal() {
                return fmt.Errorf("%w: mandate is in terminal state %s", ErrTerminalState, mandate.Status)
        }

        if !profile.IsValid() {
                return fmt.Errorf("%w: invalid governance profile %q", ErrValidationFailed, profile)
        }

        oldProfile := mandate.Scope.GovernanceProfile
        if profile.Level() < oldProfile.Level() {
                return fmt.Errorf("%w: governance profile can only be elevated, not lowered (current: %s, requested: %s)", ErrValidationFailed, oldProfile, profile)
        }

        mandate.Scope.GovernanceProfile = profile

        newChecksum, err := poa.ComputeScopeChecksum(mandate.Scope)
        if err != nil {
                mandate.Scope.GovernanceProfile = oldProfile
                return fmt.Errorf("gauth: recompute scope checksum: %w", err)
        }
        mandate.ScopeChecksum = newChecksum

        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp: time.Now(),
                Action:    "assign_governance_profile",
                ActorID:   actorID,
                Detail:    fmt.Sprintf("Governance profile changed from %s to %s", oldProfile, profile),
        })

        return m.store.Save(mandate)
}

func (m *MandateManager) transitionStatus(mandate *Mandate, newStatus poa.MandateStatus, actorID, detail string) error {
        oldStatus := mandate.Status
        mandate.Status = newStatus
        mandate.UpdatedAt = time.Now()
        mandate.AuditLog = append(mandate.AuditLog, AuditEntry{
                Timestamp:  time.Now(),
                Action:     "status_change",
                ActorID:    actorID,
                FromStatus: string(oldStatus),
                ToStatus:   string(newStatus),
                Detail:     detail,
        })
        return m.store.Save(mandate)
}

func (m *MandateManager) runConsistencyChecks(mandate *Mandate) error {
        if !mandate.Scope.GovernanceProfile.IsValid() {
                return fmt.Errorf("%w: invalid governance profile %q", ErrValidationFailed, mandate.Scope.GovernanceProfile)
        }

        if !mandate.Scope.Phase.IsValid() {
                return fmt.Errorf("%w: invalid phase %q", ErrValidationFailed, mandate.Scope.Phase)
        }

        if !mandate.Requirements.ApprovalMode.IsValid() {
                return fmt.Errorf("%w: invalid approval mode %q", ErrValidationFailed, mandate.Requirements.ApprovalMode)
        }

        if mandate.Requirements.Budget != nil {
                if mandate.Requirements.Budget.TotalCents < 0 {
                        return fmt.Errorf("%w: budget total_cents must be >= 0", ErrValidationFailed)
                }
                if mandate.Requirements.Budget.RemainingCents > mandate.Requirements.Budget.TotalCents {
                        return fmt.Errorf("%w: remaining_cents cannot exceed total_cents", ErrValidationFailed)
                }
        }

        if mandate.Requirements.TTLSeconds > 0 && mandate.Requirements.TTLSeconds < 60 {
                return fmt.Errorf("%w: ttl_seconds must be >= 60", ErrValidationFailed)
        }

        if mandate.Requirements.ApprovalMode == poa.ApprovalFourEyes {
                if len(mandate.Parties.ApprovalChain) == 0 {
                        return fmt.Errorf("%w: four-eyes approval mode requires approval_chain", ErrValidationFailed)
                }
        }

        return nil
}

func validateCreationRequest(req *MandateCreationRequest) error {
        if req.Parties.Subject == "" {
                return fmt.Errorf("%w: parties.subject", ErrMissingRequiredField)
        }
        if req.Parties.CustomerID == "" {
                return fmt.Errorf("%w: parties.customer_id", ErrMissingRequiredField)
        }
        if req.Parties.ProjectID == "" {
                return fmt.Errorf("%w: parties.project_id", ErrMissingRequiredField)
        }
        if req.Parties.IssuedBy == "" {
                return fmt.Errorf("%w: parties.issued_by", ErrMissingRequiredField)
        }
        if !req.Requirements.ApprovalMode.IsValid() {
                return fmt.Errorf("%w: invalid approval_mode", ErrValidationFailed)
        }
        return nil
}

func (mandate *Mandate) BuildPoAMapSummary() poa.PoAMapSummary {
        summary := poa.PoAMapSummary{
                MandateID: mandate.MandateID,
                Subject:   mandate.Parties.Subject,
                Scope:     mandate.Scope,
        }

        var permissions []poa.PoAPermission
        var allowedActions []string
        for verb, policy := range mandate.Scope.CoreVerbs {
                effect := "deny"
                if policy.Allowed {
                        effect = "allow"
                        allowedActions = append(allowedActions, verb)
                }
                permissions = append(permissions, poa.PoAPermission{
                        Action: verb,
                        Effect: effect,
                })
        }
        sort.Slice(permissions, func(i, j int) bool { return permissions[i].Action < permissions[j].Action })
        sort.Strings(allowedActions)
        summary.Permissions = permissions
        summary.AllowedActions = allowedActions

        var allowedDecisions []string
        if mandate.Requirements.ApprovalMode == poa.ApprovalAutonomous {
                allowedDecisions = append(allowedDecisions, "autonomous")
        }
        if mandate.Requirements.ApprovalMode == poa.ApprovalFourEyes {
                allowedDecisions = append(allowedDecisions, "four_eyes")
        }
        if mandate.Requirements.ApprovalMode == poa.ApprovalSupervised {
                allowedDecisions = append(allowedDecisions, "supervised")
        }
        summary.AllowedDecisions = allowedDecisions

        return summary
}

func generateID() string {
        b := make([]byte, 16)
        rand.Read(b)
        return fmt.Sprintf("%x", b)
}
