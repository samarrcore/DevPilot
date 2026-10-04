package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"devpilot/internal/model"
)

func sampleReport() *model.Report {
	r := &model.Report{
		Timestamp: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		TargetDir: `C:\sample-repo`,
		Findings: []model.Finding{
			{
				ID:       "RULE-NODE-OK",
				Title:    "Node.js runtime is flight-ready",
				Category: model.CategoryTooling,
				Severity: model.SeverityClear,
				Evidence: []model.Evidence{
					{Key: "version", Value: "20.11.0", Source: "probe:node"},
				},
				Verify: "node -v",
			},
			{
				ID:       "RULE-NODE-MISSING",
				Title:    "Node.js runtime is not installed",
				Category: model.CategoryTooling,
				Severity: model.SeverityGrounded,
				Evidence: []model.Evidence{
					{Key: "status", Value: "missing", Source: "probe:node"},
				},
				Fix: &model.Fix{
					ActionType:  model.ActionInstallToolVersion,
					Title:       "Install Node.js",
					Params:      map[string]string{"tool": "node", "version": "lts"},
					Explanation: "Node.js is required to execute project tools.",
				},
				Risk:   model.RiskLow,
				Verify: "node -v",
			},
		},
	}
	r.ComputeSummary()
	return r
}

func TestRenderPlain(t *testing.T) {
	rep := sampleReport()
	var buf bytes.Buffer
	err := RenderPlain(&buf, rep)
	if err != nil {
		t.Fatalf("unexpected error rendering plain report: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "DevPilot Preflight Inspection Report") {
		t.Errorf("missing header in plain report")
	}
	// Verify Grounded comes before Clear in output
	groundedIdx := strings.Index(out, "[GROUNDED]")
	clearIdx := strings.Index(out, "[CLEAR]")
	if groundedIdx == -1 || clearIdx == -1 {
		t.Fatalf("missing badges in report output")
	}
	if groundedIdx > clearIdx {
		t.Errorf("expected Grounded blocker to appear before Clear finding")
	}
}

func TestRenderJSON(t *testing.T) {
	rep := sampleReport()
	var buf bytes.Buffer
	err := RenderJSON(&buf, rep)
	if err != nil {
		t.Fatalf("unexpected error rendering json report: %v", err)
	}

	var parsed model.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if parsed.Summary.Grounded != 1 || parsed.Summary.Clear != 1 {
		t.Fatalf("expected 1 Grounded and 1 Clear, got %d and %d", parsed.Summary.Grounded, parsed.Summary.Clear)
	}
}
