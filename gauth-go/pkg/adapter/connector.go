package adapter

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrSlotNotFound       = errors.New("gauth: unknown connector slot")
	ErrSlotMandatory      = errors.New("gauth: cannot unregister mandatory slot")
	ErrTariffGateBlocked  = errors.New("gauth: tariff gate blocks registration")
	ErrAttestationNeeded  = errors.New("gauth: attestation required for Type C adapter")
	ErrSlotOccupied       = errors.New("gauth: slot already has an active adapter")
	ErrSlotNotPending     = errors.New("gauth: slot is not in pending state")
	ErrSlotNotTypeC       = errors.New("gauth: slot does not require attestation")
	ErrLicenseGateBlocked = errors.New("gauth: license acceptance required")
)

type ConnectorRegistry struct {
	mu              sync.RWMutex
	slots           map[SlotName]*SlotInfo
	tariff          TariffCode
	license         *LicenseState
	manifestVerifier *ManifestVerifier
	eventLog        []RegistryEvent
}

type RegistryEvent struct {
	Type    string   `json:"type"`
	Slot    SlotName `json:"slot"`
	Message string   `json:"message"`
}

type ConnectorRegistration struct {
	SlotName            SlotName
	ImplementationLabel string
	Adapter             interface{}
	ManifestJSON        []byte
}

type ConnectorResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func NewConnectorRegistry(tariff TariffCode) *ConnectorRegistry {
	cr := &ConnectorRegistry{
		slots:            make(map[SlotName]*SlotInfo),
		tariff:           tariff,
		license:          NewLicenseState(),
		manifestVerifier: NewManifestVerifier(),
	}

	for _, slot := range AllSlots {
		cr.slots[slot] = &SlotInfo{
			SlotName:            slot,
			TypeClass:           SlotTypeClass[slot],
			Status:              StatusNull,
			ImplementationLabel: "None",
		}
	}

	return cr
}

func (cr *ConnectorRegistry) SetTariff(tariff TariffCode) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.tariff = tariff
}

func (cr *ConnectorRegistry) GetTariff() TariffCode {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.tariff
}

func (cr *ConnectorRegistry) License() *LicenseState {
	return cr.license
}

func (cr *ConnectorRegistry) ManifestVerifier() *ManifestVerifier {
	return cr.manifestVerifier
}

func (cr *ConnectorRegistry) Register(reg ConnectorRegistration) ConnectorResult {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	slot, ok := cr.slots[reg.SlotName]
	if !ok {
		return ConnectorResult{Success: false, Error: fmt.Sprintf("Unknown slot: %s", reg.SlotName)}
	}

	gate := CheckTariffGate(reg.SlotName, cr.tariff)
	if !gate.Allowed {
		cr.logEvent("tariff_gate_blocked", reg.SlotName, gate.Reason)
		return ConnectorResult{Success: false, Error: gate.Reason}
	}

	typeClass := SlotTypeClass[reg.SlotName]

	if typeClass == TypeClassC {
		if reg.ManifestJSON != nil {
			manifest, err := cr.manifestVerifier.Verify(reg.ManifestJSON, reg.SlotName)
			if err != nil {
				cr.logEvent("manifest_rejected", reg.SlotName, err.Error())
				return ConnectorResult{Success: false, Error: err.Error()}
			}
			slot.Manifest = manifest
			slot.Status = StatusActive
			slot.AttestationSatisfied = true
			slot.Adapter = reg.Adapter
			slot.ImplementationLabel = reg.ImplementationLabel
			cr.logEvent("registered_with_manifest", reg.SlotName, "Type C adapter registered with valid manifest")
			return ConnectorResult{Success: true}
		}

		slot.Status = StatusPending
		slot.Adapter = reg.Adapter
		slot.ImplementationLabel = reg.ImplementationLabel
		slot.AttestationSatisfied = false
		cr.logEvent("registered_pending", reg.SlotName, "Type C adapter registered, awaiting attestation")
		return ConnectorResult{Success: true}
	}

	slot.Status = StatusActive
	slot.Adapter = reg.Adapter
	slot.ImplementationLabel = reg.ImplementationLabel
	cr.logEvent("registered", reg.SlotName, "Adapter registered and active")
	return ConnectorResult{Success: true}
}

func (cr *ConnectorRegistry) Unregister(slot SlotName) ConnectorResult {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	info, ok := cr.slots[slot]
	if !ok {
		return ConnectorResult{Success: false, Error: fmt.Sprintf("Unknown slot: %s", slot)}
	}

	if MandatorySlots[slot] {
		return ConnectorResult{
			Success: false,
			Error:   fmt.Sprintf("Cannot unregister %s — it is mandatory", slot),
		}
	}

	info.Status = StatusNull
	info.Adapter = nil
	info.ImplementationLabel = "None"
	info.AttestationSatisfied = false
	info.Manifest = nil
	cr.logEvent("unregistered", slot, "Slot reset to null")
	return ConnectorResult{Success: true}
}

func (cr *ConnectorRegistry) SatisfyAttestation(slot SlotName) ConnectorResult {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	info, ok := cr.slots[slot]
	if !ok {
		return ConnectorResult{Success: false, Error: fmt.Sprintf("Unknown slot: %s", slot)}
	}

	if SlotTypeClass[slot] != TypeClassC {
		return ConnectorResult{
			Success: false,
			Error:   fmt.Sprintf("Slot %s does not require attestation", slot),
		}
	}

	if info.Status != StatusPending {
		return ConnectorResult{
			Success: false,
			Error:   fmt.Sprintf("Slot %s is not in pending state (current: %s)", slot, info.Status),
		}
	}

	info.AttestationSatisfied = true
	info.Status = StatusActive
	cr.logEvent("attestation_satisfied", slot, "Type C adapter attested and active")
	return ConnectorResult{Success: true}
}

func (cr *ConnectorRegistry) GetSlot(slot SlotName) (*SlotInfo, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	info, ok := cr.slots[slot]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSlotNotFound, slot)
	}
	return info, nil
}

func (cr *ConnectorRegistry) GetStatus() map[SlotName]*SlotInfo {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	result := make(map[SlotName]*SlotInfo)
	for k, v := range cr.slots {
		copy := *v
		result[k] = &copy
	}
	return result
}

func (cr *ConnectorRegistry) SetSlotError(slot SlotName) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	info, ok := cr.slots[slot]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSlotNotFound, slot)
	}
	if info.Status == StatusActive || info.Status == StatusPending {
		info.Status = StatusError
		cr.logEvent("health_check_failed", slot, "Adapter health check failed")
	}
	return nil
}

func (cr *ConnectorRegistry) RecoverSlot(slot SlotName) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	info, ok := cr.slots[slot]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSlotNotFound, slot)
	}
	if info.Status == StatusError {
		info.Status = StatusActive
		cr.logEvent("health_check_recovered", slot, "Adapter health check recovered")
	}
	return nil
}

func (cr *ConnectorRegistry) Events() []RegistryEvent {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	events := make([]RegistryEvent, len(cr.eventLog))
	copy(events, cr.eventLog)
	return events
}

func (cr *ConnectorRegistry) logEvent(eventType string, slot SlotName, message string) {
	cr.eventLog = append(cr.eventLog, RegistryEvent{
		Type:    eventType,
		Slot:    slot,
		Message: message,
	})
}
