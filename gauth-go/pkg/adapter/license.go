// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package adapter

import (
	"errors"
	"time"
)

var (
	ErrLicenseRequired        = errors.New("gauth: platform ToS acceptance required for Gimel-hosted services")
	ErrServiceToSRequired     = errors.New("gauth: proprietary service ToS acceptance required for Type C adapter")
	ErrLicenseVersionOutdated = errors.New("gauth: license version outdated, re-acceptance required")
	ErrServiceToSOutdated     = errors.New("gauth: service ToS version outdated, re-acceptance required")
	ErrNotTypeCSlot           = errors.New("gauth: slot does not require attestation")
)

func NewLicenseState() *LicenseState {
	return &LicenseState{
		LicenseType: LicenseMPL2,
		ServiceToS:  make(map[SlotName]*ServiceToSState),
	}
}

func (ls *LicenseState) AcceptPlatformToS(version string) {
	now := time.Now()
	ls.LicenseType = LicenseGimelToS
	ls.LicenseAcceptedAt = &now
	ls.LicenseVersion = version
}

func (ls *LicenseState) AcceptServiceToS(slot SlotName, version string) error {
	typeClass, ok := SlotTypeClass[slot]
	if !ok || typeClass != TypeClassC {
		return ErrNotTypeCSlot
	}

	now := time.Now()
	ls.ServiceToS[slot] = &ServiceToSState{
		Accepted:   true,
		Version:    version,
		AcceptedAt: &now,
	}
	return nil
}

func (ls *LicenseState) CheckPlatformToS(requiredVersion string) error {
	if ls.LicenseType != LicenseGimelToS {
		return ErrLicenseRequired
	}
	if ls.LicenseVersion != "" && requiredVersion != "" && ls.LicenseVersion < requiredVersion {
		return ErrLicenseVersionOutdated
	}
	return nil
}

func (ls *LicenseState) CheckServiceToS(slot SlotName, requiredVersion string) error {
	typeClass, ok := SlotTypeClass[slot]
	if !ok || typeClass != TypeClassC {
		return ErrNotTypeCSlot
	}

	sts, ok := ls.ServiceToS[slot]
	if !ok || !sts.Accepted {
		return ErrServiceToSRequired
	}

	if sts.Version != "" && requiredVersion != "" && sts.Version < requiredVersion {
		return ErrServiceToSOutdated
	}
	return nil
}

func (ls *LicenseState) RequiresGimelToS(slot SlotName) bool {
	typeClass, ok := SlotTypeClass[slot]
	if !ok {
		return false
	}
	return typeClass == TypeClassA || typeClass == TypeClassB || typeClass == TypeClassC
}
