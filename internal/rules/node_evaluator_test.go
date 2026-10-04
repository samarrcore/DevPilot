package rules

import (
	"testing"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
)

func TestEvaluateNode_Missing(t *testing.T) {
	actual := probe.NodeResult{
		Found: false,
		Error: "executable not found",
	}
	expected := &infer.ExpectedEnv{
		NodeRange:  ">=18.0.0",
		NodeSource: "package.json",
	}

	finding := EvaluateNode(actual, expected)
	if finding.Severity != model.SeverityGrounded {
		t.Fatalf("expected Grounded, got %s", finding.Severity)
	}
	if finding.Fix == nil {
		t.Fatalf("expected a Fix recommendation for missing node")
	}
	if finding.Verify != "node -v" {
		t.Fatalf("expected verify command 'node -v', got %s", finding.Verify)
	}
}

func TestEvaluateNode_MismatchMajor(t *testing.T) {
	actual := probe.NodeResult{
		Found:   true,
		Version: "16.14.0",
		Path:    `C:\nodejs\node.exe`,
	}
	expected := &infer.ExpectedEnv{
		NodeRange:  ">=20.0.0",
		NodeSource: "package.json",
	}

	finding := EvaluateNode(actual, expected)
	if finding.Severity != model.SeverityGrounded {
		t.Fatalf("expected Grounded for major version mismatch, got %s", finding.Severity)
	}
	if finding.Fix == nil {
		t.Fatalf("expected a Fix recommendation for version mismatch")
	}
	if finding.Fix.ActionType != model.ActionInstallToolVersion {
		t.Fatalf("expected ActionInstallToolVersion, got %s", finding.Fix.ActionType)
	}
	if finding.Fix.Params["version"] != "20" {
		t.Fatalf("expected target version 20, got %s", finding.Fix.Params["version"])
	}
}

func TestEvaluateNode_MismatchMinor(t *testing.T) {
	actual := probe.NodeResult{
		Found:   true,
		Version: "20.1.0",
		Path:    `C:\nodejs\node.exe`,
	}
	expected := &infer.ExpectedEnv{
		NodeRange:  ">=20.10.0",
		NodeSource: "package.json",
	}

	finding := EvaluateNode(actual, expected)
	if finding.Severity != model.SeverityCaution {
		t.Fatalf("expected Caution for minor version mismatch, got %s", finding.Severity)
	}
}

func TestEvaluateNode_Clear(t *testing.T) {
	actual := probe.NodeResult{
		Found:   true,
		Version: "20.11.0",
		Path:    `C:\nodejs\node.exe`,
	}
	expected := &infer.ExpectedEnv{
		NodeRange:  ">=18.0.0",
		NodeSource: "package.json",
	}

	finding := EvaluateNode(actual, expected)
	if finding.Severity != model.SeverityClear {
		t.Fatalf("expected Clear, got %s", finding.Severity)
	}
	if finding.Fix != nil {
		t.Fatalf("expected no fix needed for Clear finding")
	}
}
