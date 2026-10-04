package rules

import (
	"fmt"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
)

// EvaluateNode evaluates the probed Node.js environment against the project's expected requirements.
func EvaluateNode(actual probe.NodeResult, expected *infer.ExpectedEnv) model.Finding {
	// Case 1: Node is missing entirely -> Hard blocker (Grounded)
	if !actual.Found {
		expectedRange := "installed"
		if expected != nil && expected.NodeRange != "" {
			expectedRange = expected.NodeRange
		}
		return model.Finding{
			ID:       "RULE-NODE-MISSING",
			Title:    "Node.js runtime is not installed or not in PATH",
			Category: model.CategoryTooling,
			Severity: model.SeverityGrounded,
			Evidence: []model.Evidence{
				{Key: "status", Value: "missing", Source: "probe:node"},
				{Key: "expected_version", Value: expectedRange, Source: expectedSource(expected)},
				{Key: "error", Value: actual.Error, Source: "probe:node"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionInstallToolVersion,
				Title:      "Install Node.js (LTS recommended)",
				Params: map[string]string{
					"tool":    "node",
					"version": "lts",
				},
				Explanation: "DevPilot requires Node.js to be installed and available on your system PATH.",
			},
			Risk:   model.RiskLow,
			Verify: "node -v",
		}
	}

	// Case 2: Node is present, but repo has explicit version requirements
	if expected != nil && expected.NodeRange != "" {
		satisfies, err := Satisfies(actual.Version, expected.NodeRange)
		if err != nil || !satisfies {
			// Check if it's a major version discrepancy
			actVer, _ := ParseVersion(actual.Version)
			severity := model.SeverityCaution
			// If major version is completely different, elevate to Grounded blocker
			targetVer, errExp := ExtractVersion(expected.NodeRange)
			if errExp == nil && actVer.Major != targetVer.Major {
				severity = model.SeverityGrounded
			}

			// Format a clean version target
			installTarget := fmt.Sprintf("%d", targetVer.Major)
			if errExp != nil {
				installTarget = "lts"
			}

			return model.Finding{
				ID:       "RULE-NODE-VERSION-MISMATCH",
				Title:    fmt.Sprintf("Node.js version %s does not satisfy %s", actual.Version, expected.NodeRange),
				Category: model.CategoryTooling,
				Severity: severity,
				Evidence: []model.Evidence{
					{Key: "actual_version", Value: actual.Version, Source: "probe:node"},
					{Key: "expected_version", Value: expected.NodeRange, Source: expectedSource(expected)},
					{Key: "executable_path", Value: actual.Path, Source: "probe:node"},
				},
				Fix: &model.Fix{
					ActionType: model.ActionInstallToolVersion,
					Title:      fmt.Sprintf("Switch or update Node.js to match %s", expected.NodeRange),
					Params: map[string]string{
						"tool":    "node",
						"version": installTarget,
					},
					Explanation: "Running an incompatible Node runtime causes syntax failures, module resolution errors, or native build crashes. Recommendation: nvm install " + installTarget + " or winget install OpenJS.NodeJS.LTS",
				},
				Risk:   model.RiskMedium,
				Verify: "node -v",
			}
		}
	}

	// Case 3: Node is present and satisfies requirements -> Ready (Clear)
	evidence := []model.Evidence{
		{Key: "version", Value: actual.Version, Source: "probe:node"},
		{Key: "executable_path", Value: actual.Path, Source: "probe:node"},
	}
	if expected != nil && expected.NodeRange != "" {
		evidence = append(evidence, model.Evidence{
			Key:    "expected_version",
			Value:  expected.NodeRange,
			Source: expectedSource(expected),
		})
	}

	return model.Finding{
		ID:       "RULE-NODE-OK",
		Title:    fmt.Sprintf("Node.js runtime is flight-ready (%s)", actual.Version),
		Category: model.CategoryTooling,
		Severity: model.SeverityClear,
		Evidence: evidence,
		Verify:   "node -v",
	}
}

func expectedSource(expected *infer.ExpectedEnv) string {
	if expected == nil || expected.NodeSource == "" {
		return "default"
	}
	return expected.NodeSource
}
