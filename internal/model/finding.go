package model

import (
	"time"
)

// Severity indicates flight readiness.
type Severity string

const (
	SeverityClear    Severity = "Clear"    // Ready for takeoff; condition met.
	SeverityCaution  Severity = "Caution"  // Advisory; potential instability or minor version mismatch.
	SeverityGrounded Severity = "Grounded" // Hard blocker; flight aborted until resolved.
)

// Category groups the failure locus: tooling, dependencies, machine, or code.
type Category string

const (
	CategoryTooling      Category = "tooling"
	CategoryDependencies Category = "dependencies"
	CategoryMachine      Category = "machine"
	CategoryCode         Category = "code"
)

// RiskLevel represents the risk of applying a fix.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Evidence holds a deterministic fact observed during a probe or repo scan.
type Evidence struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"` // e.g. "probe:node", "file:package.json"
}

// ActionType defines the strict, allowlisted set of remediation actions.
type ActionType string

const (
	ActionInstallToolVersion ActionType = "install_tool_version"
	ActionSetEnvVar          ActionType = "set_env_var"
	ActionEditFile           ActionType = "edit_file"
)

// Fix describes an actionable, typed resolution for a finding.
// Security rule: Fixes are typed actions, not raw shell strings.
type Fix struct {
	ActionType  ActionType        `json:"action_type"` // e.g. "install_tool_version", "set_env_var"
	Title       string            `json:"title"`       // Human-readable title
	Params      map[string]string `json:"params"`      // e.g. {"tool": "node", "version": "20"}
	Explanation string            `json:"explanation"` // Why this fix works
}

// Finding represents a single diagnosed environment condition.
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Category    Category  `json:"category"`
	Severity    Severity  `json:"severity"`
	Evidence    []Evidence `json:"evidence"`
	Fix         *Fix      `json:"fix,omitempty"`
	Risk        RiskLevel `json:"risk,omitempty"`
	Verify      string    `json:"verify"` // Concrete command to verify resolution, e.g. "node -v"
}

// ReportSummary aggregates finding counts.
type ReportSummary struct {
	Total    int `json:"total"`
	Clear    int `json:"clear"`
	Caution  int `json:"caution"`
	Grounded int `json:"grounded"`
}

// Report holds the complete preflight check results.
type Report struct {
	Timestamp   time.Time     `json:"timestamp"`
	TargetDir   string        `json:"target_dir"`
	Findings    []Finding     `json:"findings"`
	Summary     ReportSummary `json:"summary"`
}

// ComputeSummary recalculates summary counts.
func (r *Report) ComputeSummary() {
	r.Summary = ReportSummary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityClear:
			r.Summary.Clear++
		case SeverityCaution:
			r.Summary.Caution++
		case SeverityGrounded:
			r.Summary.Grounded++
		}
	}
}
