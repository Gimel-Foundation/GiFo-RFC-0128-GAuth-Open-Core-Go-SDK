// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package poa

import (
        "github.com/gimelfoundation/gauth-go/internal/canonical"
)

type scopeChecksumInput struct {
        GovernanceProfile     GovernanceProfile `json:"governance_profile"`
        Phase                 Phase             `json:"phase"`
        AllowedPaths          []string          `json:"allowed_paths"`
        DeniedPaths           []string          `json:"denied_paths"`
        ActiveModules         []string          `json:"active_modules"`
        AllowedSectors        []string          `json:"allowed_sectors"`
        AllowedRegions        []string          `json:"allowed_regions"`
        ToolPermissionsHash   string            `json:"tool_permissions_hash"`
        PlatformPermHash      string            `json:"platform_permissions_hash"`
}

func ComputeScopeChecksum(scope Scope) (string, error) {
        toolHash, err := ComputeToolPermissionsHash(scope.CoreVerbs)
        if err != nil {
                return "", err
        }

        platHash, err := ComputePlatformPermissionsHash(scope.PlatformPermissions)
        if err != nil {
                return "", err
        }

        input := scopeChecksumInput{
                GovernanceProfile:   scope.GovernanceProfile,
                Phase:               scope.Phase,
                AllowedPaths:        scope.AllowedPaths,
                DeniedPaths:         scope.DeniedPaths,
                ActiveModules:       scope.ActiveModules,
                AllowedSectors:      scope.AllowedSectors,
                AllowedRegions:      scope.AllowedRegions,
                ToolPermissionsHash: toolHash,
                PlatformPermHash:    platHash,
        }

        return canonical.SHA256Hex(input)
}

func ComputeToolPermissionsHash(verbs map[string]ToolPolicy) (string, error) {
        if verbs == nil {
                verbs = make(map[string]ToolPolicy)
        }
        return canonical.SHA256Hex(verbs)
}

func ComputePlatformPermissionsHash(perms *PlatformPermissions) (string, error) {
        if perms == nil {
                perms = &PlatformPermissions{}
        }
        return canonical.SHA256Hex(perms)
}
