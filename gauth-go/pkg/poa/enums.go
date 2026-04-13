// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package poa

type GovernanceProfile string

const (
        ProfileMinimal    GovernanceProfile = "minimal"
        ProfileStandard   GovernanceProfile = "standard"
        ProfileStrict     GovernanceProfile = "strict"
        ProfileEnterprise GovernanceProfile = "enterprise"
        ProfileBehoerde   GovernanceProfile = "behoerde"
)

func (g GovernanceProfile) IsValid() bool {
        switch g {
        case ProfileMinimal, ProfileStandard, ProfileStrict, ProfileEnterprise, ProfileBehoerde:
                return true
        }
        return false
}

func (g GovernanceProfile) Level() int {
        switch g {
        case ProfileMinimal:
                return 1
        case ProfileStandard:
                return 2
        case ProfileStrict:
                return 3
        case ProfileEnterprise:
                return 4
        case ProfileBehoerde:
                return 5
        }
        return 0
}

type ApprovalMode string

const (
        ApprovalAutonomous ApprovalMode = "autonomous"
        ApprovalSupervised ApprovalMode = "supervised"
        ApprovalFourEyes   ApprovalMode = "four-eyes"
)

func (a ApprovalMode) IsValid() bool {
        switch a {
        case ApprovalAutonomous, ApprovalSupervised, ApprovalFourEyes:
                return true
        }
        return false
}

type Phase string

const (
        PhasePlan  Phase = "plan"
        PhaseBuild Phase = "build"
        PhaseRun   Phase = "run"
)

func (p Phase) IsValid() bool {
        switch p {
        case PhasePlan, PhaseBuild, PhaseRun:
                return true
        }
        return false
}

type MandateStatus string

const (
        StatusDraft          MandateStatus = "draft"
        StatusActive         MandateStatus = "active"
        StatusSuspended      MandateStatus = "suspended"
        StatusRevoked        MandateStatus = "revoked"
        StatusExpired        MandateStatus = "expired"
        StatusBudgetExceeded MandateStatus = "budget_exceeded"
        StatusSuperseded     MandateStatus = "superseded"
)

func (m MandateStatus) IsValid() bool {
        switch m {
        case StatusDraft, StatusActive, StatusSuspended, StatusRevoked,
                StatusExpired, StatusBudgetExceeded, StatusSuperseded:
                return true
        }
        return false
}

func (m MandateStatus) IsTerminal() bool {
        switch m {
        case StatusRevoked, StatusExpired, StatusBudgetExceeded, StatusSuperseded:
                return true
        }
        return false
}

type ShellMode string

const (
        ShellModeAny       ShellMode = "any"
        ShellModeDenylist  ShellMode = "denylist"
        ShellModeAllowlist ShellMode = "allowlist"
)

type CredentialFormat string

const (
        FormatJWT   CredentialFormat = "jwt"
        FormatW3CVC CredentialFormat = "w3c_vc"
        FormatSDJWT CredentialFormat = "sd-jwt"
)

type Decision string

const (
        DecisionPermit    Decision = "PERMIT"
        DecisionDeny      Decision = "DENY"
        DecisionConstrain Decision = "CONSTRAIN"
)

type CheckResultStatus string

const (
        CheckPass      CheckResultStatus = "pass"
        CheckFail      CheckResultStatus = "fail"
        CheckSkip      CheckResultStatus = "skip"
        CheckConstrain CheckResultStatus = "constrain"
)

type EnforcementMode string

const (
        ModeStateless EnforcementMode = "stateless"
        ModeStateful  EnforcementMode = "stateful"
)

type ViolationSeverity string

const (
        SeverityError   ViolationSeverity = "error"
        SeverityWarning ViolationSeverity = "warning"
)
