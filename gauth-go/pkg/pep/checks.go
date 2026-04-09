package pep

import (
        "fmt"
        "strings"
        "time"

        "github.com/gimelfoundation/gauth-go/pkg/poa"
)

type checkFunc func(req *EnforcementRequest, snap *PoASnapshot) CheckResult

type checkDef struct {
        ID   string
        Name string
        Fn   checkFunc
}

var checkPipeline = []checkDef{
        {"CHK-01", "Credential Integrity", checkCredentialIntegrity},
        {"CHK-02", "Temporal & Status Validity", checkTemporalStatus},
        {"CHK-03", "Governance Profile Ceiling", checkGovernanceProfile},
        {"CHK-04", "Phase", checkPhase},
        {"CHK-05", "Sector", checkSector},
        {"CHK-06", "Region", checkRegion},
        {"CHK-07", "Path", checkPath},
        {"CHK-08", "Verb Permission", checkVerb},
        {"CHK-09", "Verb Constraints", checkVerbConstraints},
        {"CHK-10", "Platform Permissions", checkPlatformPermissions},
        {"CHK-11", "Transaction Type", checkTransaction},
        {"CHK-12", "Decision Type", checkDecisionType},
        {"CHK-13", "Budget", checkBudget},
        {"CHK-14", "Session Limits", checkSessionLimits},
        {"CHK-15", "Approval", checkApproval},
        {"CHK-16", "Delegation Chain", checkDelegationChain},
}

func checkCredentialIntegrity(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap == nil {
                return CheckResult{
                        CheckID:   "CHK-01",
                        CheckName: "Credential Integrity",
                        Result:    poa.CheckFail,
                        Detail:    "No PoA snapshot available for evaluation",
                }
        }

        if snap.SchemaVersion == "" {
                return CheckResult{
                        CheckID:   "CHK-01",
                        CheckName: "Credential Integrity",
                        Result:    poa.CheckFail,
                        Detail:    "Missing schema_version",
                }
        }

        if snap.SchemaVersion != poa.SchemaVersion {
                return CheckResult{
                        CheckID:   "CHK-01",
                        CheckName: "Credential Integrity",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Schema version mismatch: got %q, expected %q", snap.SchemaVersion, poa.SchemaVersion),
                }
        }

        if snap.ScopeChecksum != "" {
                computed, err := poa.ComputeScopeChecksum(snap.Scope)
                if err != nil {
                        return CheckResult{
                                CheckID:   "CHK-01",
                                CheckName: "Credential Integrity",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Failed to compute scope checksum: %v", err),
                        }
                }
                if computed != snap.ScopeChecksum {
                        return CheckResult{
                                CheckID:   "CHK-01",
                                CheckName: "Credential Integrity",
                                Result:    poa.CheckFail,
                                Detail:    "Scope checksum mismatch: credential may have been tampered with",
                        }
                }
        }

        if snap.MandateID == "" {
                return CheckResult{
                        CheckID:   "CHK-01",
                        CheckName: "Credential Integrity",
                        Result:    poa.CheckFail,
                        Detail:    "Missing mandate_id in credential",
                }
        }

        return CheckResult{
                CheckID:   "CHK-01",
                CheckName: "Credential Integrity",
                Result:    poa.CheckPass,
                Detail:    "Credential integrity verified",
        }
}

func checkTemporalStatus(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        now := time.Now().Unix()

        if snap.ExpiresAt > 0 && now > snap.ExpiresAt {
                return CheckResult{
                        CheckID:   "CHK-02",
                        CheckName: "Temporal & Status Validity",
                        Result:    poa.CheckFail,
                        Detail:    "Credential has expired",
                }
        }

        if snap.NotBefore > 0 && now < snap.NotBefore {
                return CheckResult{
                        CheckID:   "CHK-02",
                        CheckName: "Temporal & Status Validity",
                        Result:    poa.CheckFail,
                        Detail:    "Credential is not yet valid",
                }
        }

        if snap.Subject != "" && req.Agent.AgentID != snap.Subject {
                return CheckResult{
                        CheckID:   "CHK-02",
                        CheckName: "Temporal & Status Validity",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Agent mismatch: request agent %q != credential subject %q", req.Agent.AgentID, snap.Subject),
                }
        }

        if snap.MandateStatus != "" && snap.MandateStatus != poa.StatusActive {
                return CheckResult{
                        CheckID:   "CHK-02",
                        CheckName: "Temporal & Status Validity",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Mandate status is %q, expected active", snap.MandateStatus),
                }
        }

        if req.Context != nil && req.Context.LiveMandateState != nil {
                lms := req.Context.LiveMandateState
                if lms.Status != "active" {
                        return CheckResult{
                                CheckID:   "CHK-02",
                                CheckName: "Temporal & Status Validity",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Live mandate status is %q", lms.Status),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-02",
                CheckName: "Temporal & Status Validity",
                Result:    poa.CheckPass,
                Detail:    "Temporal and status checks passed",
        }
}

func checkGovernanceProfile(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if !snap.Scope.GovernanceProfile.IsValid() {
                return CheckResult{
                        CheckID:   "CHK-03",
                        CheckName: "Governance Profile Ceiling",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Invalid governance profile: %q", snap.Scope.GovernanceProfile),
                }
        }

        return CheckResult{
                CheckID:   "CHK-03",
                CheckName: "Governance Profile Ceiling",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Governance profile %q ceiling check passed", snap.Scope.GovernanceProfile),
        }
}

func checkPhase(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if !snap.Scope.Phase.IsValid() {
                return CheckResult{
                        CheckID:   "CHK-04",
                        CheckName: "Phase",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Invalid phase: %q", snap.Scope.Phase),
                }
        }

        verb := req.Action.Verb
        phase := snap.Scope.Phase

        if phase == poa.PhasePlan {
                if isWriteVerb(verb) {
                        return CheckResult{
                                CheckID:   "CHK-04",
                                CheckName: "Phase",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Verb %q is not permitted in plan phase (read-only)", verb),
                        }
                }
        }

        if isDeployVerb(verb) && phase != poa.PhaseRun {
                return CheckResult{
                        CheckID:   "CHK-04",
                        CheckName: "Phase",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Verb %q requires run phase, current phase is %q", verb, phase),
                }
        }

        return CheckResult{
                CheckID:   "CHK-04",
                CheckName: "Phase",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Action permitted in phase %q", phase),
        }
}

func checkSector(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if len(snap.Scope.AllowedSectors) == 0 {
                return CheckResult{
                        CheckID:   "CHK-05",
                        CheckName: "Sector",
                        Result:    poa.CheckSkip,
                        Detail:    "No sector restrictions defined",
                }
        }

        if req.Action.Sector == "" {
                return CheckResult{
                        CheckID:   "CHK-05",
                        CheckName: "Sector",
                        Result:    poa.CheckFail,
                        Detail:    "Sector restrictions defined but no sector specified in request",
                }
        }

        for _, s := range snap.Scope.AllowedSectors {
                if s == req.Action.Sector {
                        return CheckResult{
                                CheckID:   "CHK-05",
                                CheckName: "Sector",
                                Result:    poa.CheckPass,
                                Detail:    fmt.Sprintf("Sector %q is allowed", req.Action.Sector),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-05",
                CheckName: "Sector",
                Result:    poa.CheckFail,
                Detail:    fmt.Sprintf("Sector %q is not in the allowed sectors", req.Action.Sector),
        }
}

func checkRegion(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if len(snap.Scope.AllowedRegions) == 0 {
                return CheckResult{
                        CheckID:   "CHK-06",
                        CheckName: "Region",
                        Result:    poa.CheckSkip,
                        Detail:    "No region restrictions defined",
                }
        }

        if req.Action.Region == "" {
                return CheckResult{
                        CheckID:   "CHK-06",
                        CheckName: "Region",
                        Result:    poa.CheckFail,
                        Detail:    "Region restrictions defined but no region specified in request",
                }
        }

        for _, r := range snap.Scope.AllowedRegions {
                if r == req.Action.Region {
                        return CheckResult{
                                CheckID:   "CHK-06",
                                CheckName: "Region",
                                Result:    poa.CheckPass,
                                Detail:    fmt.Sprintf("Region %q is allowed", req.Action.Region),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-06",
                CheckName: "Region",
                Result:    poa.CheckFail,
                Detail:    fmt.Sprintf("Region %q is not in the allowed regions", req.Action.Region),
        }
}

func checkPath(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        resource := req.Action.Resource

        for _, denied := range snap.Scope.DeniedPaths {
                if matchPath(resource, denied) {
                        return CheckResult{
                                CheckID:   "CHK-07",
                                CheckName: "Path",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Resource %q matches denied path %q", resource, denied),
                        }
                }
        }

        if len(snap.Scope.AllowedPaths) > 0 {
                allowed := false
                for _, ap := range snap.Scope.AllowedPaths {
                        if matchPath(resource, ap) {
                                allowed = true
                                break
                        }
                }
                if !allowed {
                        return CheckResult{
                                CheckID:   "CHK-07",
                                CheckName: "Path",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Resource %q is not in the allowed paths", resource),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-07",
                CheckName: "Path",
                Result:    poa.CheckPass,
                Detail:    "Path check passed",
        }
}

func checkVerb(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.Scope.CoreVerbs == nil {
                return CheckResult{
                        CheckID:   "CHK-08",
                        CheckName: "Verb Permission",
                        Result:    poa.CheckFail,
                        Detail:    "No core_verbs defined in PoA — all verbs denied by default",
                }
        }

        verbKey := extractVerbKey(req.Action.Verb)
        policy, exists := snap.Scope.CoreVerbs[verbKey]
        if !exists {
                return CheckResult{
                        CheckID:   "CHK-08",
                        CheckName: "Verb Permission",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Verb %q is not defined in the PoA", req.Action.Verb),
                }
        }

        if !policy.Allowed {
                return CheckResult{
                        CheckID:   "CHK-08",
                        CheckName: "Verb Permission",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Verb %q is explicitly disallowed", req.Action.Verb),
                }
        }

        return CheckResult{
                CheckID:   "CHK-08",
                CheckName: "Verb Permission",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Verb %q is permitted", req.Action.Verb),
        }
}

func checkVerbConstraints(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.Scope.CoreVerbs == nil {
                return CheckResult{
                        CheckID:   "CHK-09",
                        CheckName: "Verb Constraints",
                        Result:    poa.CheckFail,
                        Detail:    "No core_verbs defined — constraints cannot be evaluated",
                }
        }

        verbKey := extractVerbKey(req.Action.Verb)
        policy, exists := snap.Scope.CoreVerbs[verbKey]
        if !exists || policy.Constraints == nil {
                return CheckResult{
                        CheckID:   "CHK-09",
                        CheckName: "Verb Constraints",
                        Result:    poa.CheckSkip,
                        Detail:    "No constraints defined for this verb",
                }
        }

        c := policy.Constraints

        if len(c.PathPatterns) > 0 {
                matched := false
                for _, pattern := range c.PathPatterns {
                        if matchPath(req.Action.Resource, pattern) {
                                matched = true
                                break
                        }
                }
                if !matched {
                        return CheckResult{
                                CheckID:   "CHK-09",
                                CheckName: "Verb Constraints",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Resource %q does not match any path pattern constraint", req.Action.Resource),
                        }
                }
        }

        if len(c.DeniedCommands) > 0 && req.Action.ResourceType == "command" {
                for _, denied := range c.DeniedCommands {
                        if req.Action.Resource == denied {
                                return CheckResult{
                                        CheckID:   "CHK-09",
                                        CheckName: "Verb Constraints",
                                        Result:    poa.CheckFail,
                                        Detail:    fmt.Sprintf("Command %q is denied by verb constraints", req.Action.Resource),
                                }
                        }
                }
        }

        if len(c.AllowedCommands) > 0 && req.Action.ResourceType == "command" {
                found := false
                for _, allowed := range c.AllowedCommands {
                        if req.Action.Resource == allowed {
                                found = true
                                break
                        }
                }
                if !found {
                        return CheckResult{
                                CheckID:   "CHK-09",
                                CheckName: "Verb Constraints",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Command %q is not in the allowed commands", req.Action.Resource),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-09",
                CheckName: "Verb Constraints",
                Result:    poa.CheckPass,
                Detail:    "Verb constraints satisfied",
        }
}

func checkPlatformPermissions(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.Scope.PlatformPermissions == nil {
                return CheckResult{
                        CheckID:   "CHK-10",
                        CheckName: "Platform Permissions",
                        Result:    poa.CheckSkip,
                        Detail:    "No platform permissions defined",
                }
        }

        pp := snap.Scope.PlatformPermissions
        rt := req.Action.ResourceType

        switch rt {
        case "database":
                if pp.Database != nil {
                        verb := extractVerbKey(req.Action.Verb)
                        if strings.Contains(verb, "write") && !pp.Database.Write {
                                return CheckResult{
                                        CheckID:   "CHK-10",
                                        CheckName: "Platform Permissions",
                                        Result:    poa.CheckFail,
                                        Detail:    "Database write permission denied",
                                }
                        }
                        if strings.Contains(verb, "migrate") && !pp.Database.Migrate {
                                return CheckResult{
                                        CheckID:   "CHK-10",
                                        CheckName: "Platform Permissions",
                                        Result:    poa.CheckFail,
                                        Detail:    "Database migrate permission denied",
                                }
                        }
                }
        case "deployment":
                if pp.Deployment != nil && !pp.Deployment.AutoDeploy {
                        verb := extractVerbKey(req.Action.Verb)
                        if strings.Contains(verb, "deploy") {
                                return CheckResult{
                                        CheckID:   "CHK-10",
                                        CheckName: "Platform Permissions",
                                        Result:    poa.CheckConstrain,
                                        Detail:    "Auto-deploy is disabled; manual deployment required",
                                }
                        }
                }
        case "secret":
                if pp.Secrets != nil {
                        verb := extractVerbKey(req.Action.Verb)
                        if strings.Contains(verb, "read") && !pp.Secrets.Read {
                                return CheckResult{
                                        CheckID:   "CHK-10",
                                        CheckName: "Platform Permissions",
                                        Result:    poa.CheckFail,
                                        Detail:    "Secret read permission denied",
                                }
                        }
                        if strings.Contains(verb, "create") && !pp.Secrets.Create {
                                return CheckResult{
                                        CheckID:   "CHK-10",
                                        CheckName: "Platform Permissions",
                                        Result:    poa.CheckFail,
                                        Detail:    "Secret create permission denied",
                                }
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-10",
                CheckName: "Platform Permissions",
                Result:    poa.CheckPass,
                Detail:    "Platform permissions check passed",
        }
}

func checkTransaction(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if req.Action.TransactionType == "" {
                return CheckResult{
                        CheckID:   "CHK-11",
                        CheckName: "Transaction Type",
                        Result:    poa.CheckSkip,
                        Detail:    "No transaction type specified",
                }
        }

        return CheckResult{
                CheckID:   "CHK-11",
                CheckName: "Transaction Type",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Transaction type %q accepted", req.Action.TransactionType),
        }
}

func checkDecisionType(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if req.Action.DecisionType == "" {
                return CheckResult{
                        CheckID:   "CHK-12",
                        CheckName: "Decision Type",
                        Result:    poa.CheckSkip,
                        Detail:    "No decision type specified",
                }
        }

        return CheckResult{
                CheckID:   "CHK-12",
                CheckName: "Decision Type",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Decision type %q accepted", req.Action.DecisionType),
        }
}

func checkBudget(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.Budget == nil {
                return CheckResult{
                        CheckID:   "CHK-13",
                        CheckName: "Budget",
                        Result:    poa.CheckSkip,
                        Detail:    "No budget defined",
                }
        }

        remaining := snap.Budget.RemainingCents
        if req.Context != nil && req.Context.LiveMandateState != nil {
                remaining = req.Context.LiveMandateState.BudgetRemainingCents
        }

        if remaining <= 0 {
                return CheckResult{
                        CheckID:   "CHK-13",
                        CheckName: "Budget",
                        Result:    poa.CheckFail,
                        Detail:    "Budget is fully exhausted",
                }
        }

        cost := req.Action.AmountCents()
        if cost > 0 && cost > remaining {
                return CheckResult{
                        CheckID:   "CHK-13",
                        CheckName: "Budget",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Action cost %d cents exceeds remaining budget %d cents", cost, remaining),
                }
        }

        return CheckResult{
                CheckID:   "CHK-13",
                CheckName: "Budget",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Budget check passed (remaining: %d cents)", remaining),
        }
}

func checkSessionLimits(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.Session == nil {
                return CheckResult{
                        CheckID:   "CHK-14",
                        CheckName: "Session Limits",
                        Result:    poa.CheckSkip,
                        Detail:    "No session limits defined",
                }
        }

        if req.Context != nil && req.Context.SessionState != nil {
                ss := req.Context.SessionState
                if snap.Session.MaxToolCalls > 0 && ss.ToolCallsUsed >= snap.Session.MaxToolCalls {
                        return CheckResult{
                                CheckID:   "CHK-14",
                                CheckName: "Session Limits",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Tool calls used (%d) has reached max (%d)", ss.ToolCallsUsed, snap.Session.MaxToolCalls),
                        }
                }
                if snap.Session.MaxLinesPerCommit > 0 && ss.LinesCommitted >= snap.Session.MaxLinesPerCommit {
                        return CheckResult{
                                CheckID:   "CHK-14",
                                CheckName: "Session Limits",
                                Result:    poa.CheckFail,
                                Detail:    fmt.Sprintf("Lines committed (%d) has reached max (%d)", ss.LinesCommitted, snap.Session.MaxLinesPerCommit),
                        }
                }
        }

        return CheckResult{
                CheckID:   "CHK-14",
                CheckName: "Session Limits",
                Result:    poa.CheckPass,
                Detail:    "Session limits check passed",
        }
}

func checkApproval(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        mode := snap.Requirements.ApprovalMode

        if mode == poa.ApprovalAutonomous {
                return CheckResult{
                        CheckID:   "CHK-15",
                        CheckName: "Approval",
                        Result:    poa.CheckPass,
                        Detail:    "Autonomous mode: no approval required",
                }
        }

        if mode == poa.ApprovalFourEyes {
                return CheckResult{
                        CheckID:   "CHK-15",
                        CheckName: "Approval",
                        Result:    poa.CheckConstrain,
                        Detail:    "Four-eyes approval required before execution",
                }
        }

        return CheckResult{
                CheckID:   "CHK-15",
                CheckName: "Approval",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Approval mode %q check passed", mode),
        }
}

func checkDelegationChain(req *EnforcementRequest, snap *PoASnapshot) CheckResult {
        if snap.DelegationChain == nil || len(snap.DelegationChain.Entries) == 0 {
                return CheckResult{
                        CheckID:   "CHK-16",
                        CheckName: "Delegation Chain",
                        Result:    poa.CheckSkip,
                        Detail:    "No delegation chain present",
                }
        }

        maxDepth := 0
        verbKey := extractVerbKey(req.Action.Verb)
        if snap.Scope.CoreVerbs != nil {
                if policy, ok := snap.Scope.CoreVerbs[verbKey]; ok && policy.Constraints != nil && policy.Constraints.MaxDelegationDepth != nil {
                        maxDepth = *policy.Constraints.MaxDelegationDepth
                }
        }

        chainLen := len(snap.DelegationChain.Entries)
        if maxDepth > 0 && chainLen > maxDepth {
                return CheckResult{
                        CheckID:   "CHK-16",
                        CheckName: "Delegation Chain",
                        Result:    poa.CheckFail,
                        Detail:    fmt.Sprintf("Delegation chain depth %d exceeds max %d", chainLen, maxDepth),
                }
        }

        return CheckResult{
                CheckID:   "CHK-16",
                CheckName: "Delegation Chain",
                Result:    poa.CheckPass,
                Detail:    fmt.Sprintf("Delegation chain valid (depth: %d)", chainLen),
        }
}

func matchPath(resource, pattern string) bool {
        if strings.HasSuffix(pattern, "/") {
                return strings.HasPrefix(resource, pattern) || resource == strings.TrimSuffix(pattern, "/")
        }
        return resource == pattern || strings.HasPrefix(resource, pattern+"/")
}

func extractVerbKey(verb string) string {
        if strings.HasPrefix(verb, "urn:gauth:verb:") {
                parts := strings.SplitN(verb, ":", 6)
                if len(parts) >= 6 {
                        return parts[3] + "." + parts[4] + "." + parts[5]
                }
        }
        return verb
}

func isWriteVerb(verb string) bool {
        key := extractVerbKey(verb)
        writeActions := []string{"create", "modify", "delete", "add", "run", "delegate"}
        for _, w := range writeActions {
                if strings.HasSuffix(key, "."+w) {
                        return true
                }
        }
        return false
}

func isDeployVerb(verb string) bool {
        key := extractVerbKey(verb)
        return strings.Contains(key, "deploy") || strings.Contains(key, "deployment")
}
