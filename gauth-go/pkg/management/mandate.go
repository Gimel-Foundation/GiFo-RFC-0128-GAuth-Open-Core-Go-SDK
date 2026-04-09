package management

import (
        "crypto/rand"
        "errors"
        "fmt"
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

func generateID() string {
        b := make([]byte, 16)
        rand.Read(b)
        return fmt.Sprintf("%x", b)
}
