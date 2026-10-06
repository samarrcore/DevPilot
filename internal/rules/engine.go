package rules

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
	"devpilot/internal/security"
)

// EvaluationContext encapsulates all probed machine facts and inferred project requirements.
type EvaluationContext struct {
	Expected   *infer.ExpectedEnv
	Node       probe.NodeResult
	Npm        probe.ToolResult
	Git        probe.ToolResult
	Java       probe.ToolResult
	Adb        probe.ToolResult
	Gradle     probe.ToolResult
	AndroidSDK probe.AndroidSDKResult
	WinEnv     probe.WindowsEnvResult
}

// Engine evaluates declarative YAML rule packs and compatibility matrices.
type Engine struct {
	Packs []RulePack
}

// NewEngine initializes a RuleEngine with all embedded default rule packs.
func NewEngine() (*Engine, error) {
	packs, err := LoadEmbeddedPacks()
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded rule packs: %w", err)
	}
	return &Engine{Packs: packs}, nil
}

// LoadProjectRules loads optional custom project rules from .agents/rules/ in targetDir.
func (e *Engine) LoadProjectRules(targetDir string) error {
	projectPacks, err := LoadProjectRules(targetDir)
	if err != nil {
		return err
	}
	e.Packs = append(e.Packs, projectPacks...)
	return nil
}

// Evaluate runs all loaded rule packs (matrices and declarative rules) against the context.
func (e *Engine) Evaluate(ctx EvaluationContext) []model.Finding {
	var findings []model.Finding

	for _, pack := range e.Packs {
		// 1. Evaluate compatibility matrices
		for _, matrix := range pack.Matrices {
			matrixFindings := e.evaluateMatrix(matrix, ctx)
			findings = append(findings, matrixFindings...)
		}

		// 2. Evaluate declarative rules
		for _, rule := range pack.Rules {
			if finding, ok := e.evaluateRule(rule, ctx); ok {
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// evaluateMatrix checks toolchain compatibility against a defined compatibility matrix.
func (e *Engine) evaluateMatrix(matrix Matrix, ctx EvaluationContext) []model.Finding {
	if ctx.Expected == nil || (!ctx.Expected.IsExpo && !ctx.Expected.IsReactNative) {
		return nil // Not applicable to this project
	}

	var matchedEntry *MatrixEntry
	var isExpoMatch bool

	// 1. Try to match by Expo SDK version
	if ctx.Expected.IsExpo && ctx.Expected.ExpoSdkVersion != "" {
		expoMajor := extractMajorString(ctx.Expected.ExpoSdkVersion)
		for _, entry := range matrix.Entries {
			if entry.ExpoSDK != "" && (entry.ExpoSDK == expoMajor || entry.ExpoSDK == ctx.Expected.ExpoSdkVersion) {
				m := entry
				matchedEntry = &m
				isExpoMatch = true
				break
			}
		}
	}

	// 2. Fallback: try to match by React Native version
	if matchedEntry == nil && ctx.Expected.IsReactNative && ctx.Expected.RNVersion != "" {
		rnMajorMinor := extractMajorMinorString(ctx.Expected.RNVersion)
		for _, entry := range matrix.Entries {
			if entry.ReactNative != "" {
				entryRN := extractMajorMinorString(entry.ReactNative)
				if entryRN == rnMajorMinor || entry.ReactNative == ctx.Expected.RNVersion {
					m := entry
					matchedEntry = &m
					break
				}
			}
		}
	}

	if matchedEntry == nil {
		return nil
	}

	var findings []model.Finding
	hasMismatch := false

	targetDesc := ""
	if isExpoMatch && matchedEntry.ExpoSDK != "" {
		targetDesc = fmt.Sprintf("Expo SDK %s", matchedEntry.ExpoSDK)
		if matchedEntry.ReactNative != "" {
			targetDesc += fmt.Sprintf(" (React Native %s)", matchedEntry.ReactNative)
		}
	} else {
		targetDesc = fmt.Sprintf("React Native %s", matchedEntry.ReactNative)
	}

	// A. Check React Native version match for Expo projects
	if isExpoMatch && matchedEntry.ReactNative != "" && ctx.Expected.RNVersion != "" {
		rnAct := extractMajorMinorString(ctx.Expected.RNVersion)
		rnExp := extractMajorMinorString(matchedEntry.ReactNative)
		if rnAct != rnExp {
			hasMismatch = true
			findings = append(findings, model.Finding{
				ID:       "RULE-MATRIX-RN-MISMATCH",
				Title:    fmt.Sprintf("React Native version %s does not match Expo SDK %s expected version %s", ctx.Expected.RNVersion, matchedEntry.ExpoSDK, matchedEntry.ReactNative),
				Category: model.CategoryDependencies,
				Severity: model.SeverityGrounded,
				Evidence: []model.Evidence{
					{Key: "actual_rn_version", Value: ctx.Expected.RNVersion, Source: "package.json"},
					{Key: "matrix_expected_rn", Value: matchedEntry.ReactNative, Source: "matrix:react_native"},
					{Key: "expo_sdk", Value: ctx.Expected.ExpoSdkVersion, Source: "app.json"},
				},
				Fix: &model.Fix{
					ActionType: model.ActionEditFile,
					Title:      fmt.Sprintf("Update react-native to %s in package.json", matchedEntry.ReactNative),
					Params: map[string]string{
						"file":       "package.json",
						"dependency": "react-native",
						"version":    matchedEntry.ReactNative,
					},
					Explanation: fmt.Sprintf("Expo SDK %s requires React Native %s for native runtime compatibility.", matchedEntry.ExpoSDK, matchedEntry.ReactNative),
				},
				Risk:   model.RiskMedium,
				Verify: "npx expo doctor",
			})
		}
	}

	// B. Check Node runtime constraint
	if matchedEntry.Node != "" {
		if !ctx.Node.Found {
			hasMismatch = true
			findings = append(findings, model.Finding{
				ID:       "RULE-MATRIX-NODE-MISSING",
				Title:    fmt.Sprintf("Node.js runtime is missing (required %s for %s)", matchedEntry.Node, targetDesc),
				Category: model.CategoryTooling,
				Severity: model.SeverityGrounded,
				Evidence: []model.Evidence{
					{Key: "status", Value: "missing", Source: "probe:node"},
					{Key: "matrix_requirement", Value: matchedEntry.Node, Source: "matrix:react_native"},
				},
				Fix: &model.Fix{
					ActionType: model.ActionInstallToolVersion,
					Title:      fmt.Sprintf("Install Node.js %s", cleanTargetVersion(matchedEntry.Node)),
					Params: map[string]string{
						"tool":    "node",
						"version": cleanTargetVersion(matchedEntry.Node),
					},
					Explanation: fmt.Sprintf("%s toolchain requires Node.js %s. Recommendation: nvm install %s or winget install OpenJS.NodeJS.LTS", targetDesc, matchedEntry.Node, cleanTargetVersion(matchedEntry.Node)),
				},
				Risk:   model.RiskLow,
				Verify: "node -v",
			})
		} else {
			satisfies, err := Satisfies(ctx.Node.Version, matchedEntry.Node)
			if err != nil || !satisfies {
				hasMismatch = true
				actVer, _ := ParseVersion(ctx.Node.Version)
				targetVer, _ := ExtractVersion(matchedEntry.Node)
				sev := model.SeverityCaution
				if actVer.Major != targetVer.Major {
					sev = model.SeverityGrounded
				}
				findings = append(findings, model.Finding{
					ID:       "RULE-MATRIX-NODE-MISMATCH",
					Title:    fmt.Sprintf("Node.js version %s does not satisfy %s required by %s", ctx.Node.Version, matchedEntry.Node, targetDesc),
					Category: model.CategoryTooling,
					Severity: sev,
					Evidence: []model.Evidence{
						{Key: "actual_version", Value: ctx.Node.Version, Source: "probe:node"},
						{Key: "matrix_requirement", Value: matchedEntry.Node, Source: "matrix:react_native"},
					},
					Fix: &model.Fix{
						ActionType: model.ActionInstallToolVersion,
						Title:      fmt.Sprintf("Switch or update Node.js to satisfy %s", matchedEntry.Node),
						Params: map[string]string{
							"tool":    "node",
							"version": cleanTargetVersion(matchedEntry.Node),
						},
						Explanation: fmt.Sprintf("%s toolchain requires Node.js %s. Recommendation: nvm use or winget install OpenJS.NodeJS.LTS", targetDesc, matchedEntry.Node),
					},
					Risk:   model.RiskMedium,
					Verify: "node -v",
				})
			}
		}
	}

	// C. Check Java JDK constraint
	if matchedEntry.JDK != "" {
		if !ctx.Java.Found {
			hasMismatch = true
			findings = append(findings, model.Finding{
				ID:       "RULE-MATRIX-JAVA-MISSING",
				Title:    fmt.Sprintf("Java Development Kit (JDK %s) is missing", matchedEntry.JDK),
				Category: model.CategoryTooling,
				Severity: model.SeverityGrounded,
				Evidence: []model.Evidence{
					{Key: "status", Value: "missing", Source: "probe:java"},
					{Key: "matrix_requirement", Value: fmt.Sprintf("JDK %s", matchedEntry.JDK), Source: "matrix:react_native"},
				},
				Fix: &model.Fix{
					ActionType: model.ActionInstallToolVersion,
					Title:      fmt.Sprintf("Install Java Development Kit (JDK %s)", matchedEntry.JDK),
					Params: map[string]string{
						"tool":    "java",
						"version": matchedEntry.JDK,
					},
					Explanation: fmt.Sprintf("%s Android compilation requires JDK %s. Recommendation: winget install Microsoft.OpenJDK.%s", targetDesc, matchedEntry.JDK, matchedEntry.JDK),
				},
				Risk:   model.RiskMedium,
				Verify: "java -version",
			})
		} else {
			actVer, errAct := ParseVersion(ctx.Java.Version)
			reqMajor, errReq := strconv.Atoi(matchedEntry.JDK)
			mismatch := false
			if errAct == nil && errReq == nil {
				if actVer.Major != reqMajor {
					mismatch = true
				}
			} else {
				ok, _ := Satisfies(ctx.Java.Version, matchedEntry.JDK)
				if !ok {
					mismatch = true
				}
			}

			if mismatch {
				hasMismatch = true
				findings = append(findings, model.Finding{
					ID:       "RULE-MATRIX-JDK-MISMATCH",
					Title:    fmt.Sprintf("Java JDK version %s does not satisfy JDK %s required by %s", ctx.Java.Version, matchedEntry.JDK, targetDesc),
					Category: model.CategoryTooling,
					Severity: model.SeverityGrounded,
					Evidence: []model.Evidence{
						{Key: "actual_version", Value: ctx.Java.Version, Source: "probe:java"},
						{Key: "matrix_requirement", Value: fmt.Sprintf("JDK %s", matchedEntry.JDK), Source: "matrix:react_native"},
					},
					Fix: &model.Fix{
						ActionType: model.ActionInstallToolVersion,
						Title:      fmt.Sprintf("Install Java Development Kit (JDK %s)", matchedEntry.JDK),
						Params: map[string]string{
							"tool":    "java",
							"version": matchedEntry.JDK,
						},
						Explanation: fmt.Sprintf("%s Android compilation requires JDK %s. Recommendation: winget install Microsoft.OpenJDK.%s", targetDesc, matchedEntry.JDK, matchedEntry.JDK),
					},
					Risk:   model.RiskMedium,
					Verify: "java -version",
				})
			}
		}
	}

	// D. Check Gradle constraint
	if matchedEntry.Gradle != "" {
		actualGradle := ""
		source := ""
		if ctx.Expected != nil && ctx.Expected.GradleVersion != "" {
			actualGradle = ctx.Expected.GradleVersion
			source = ctx.Expected.GradleSource
		} else if ctx.Gradle.Found {
			actualGradle = ctx.Gradle.Version
			source = "probe:gradle"
		}

		if actualGradle != "" && actualGradle != "unknown" {
			actG, errG := ParseVersion(actualGradle)
			reqG, errReq := ParseVersion(matchedEntry.Gradle)
			if errG == nil && errReq == nil {
				if actG.Major < reqG.Major || (actG.Major == reqG.Major && actG.Minor < reqG.Minor) {
					hasMismatch = true
					findings = append(findings, model.Finding{
						ID:       "RULE-MATRIX-GRADLE-MISMATCH",
						Title:    fmt.Sprintf("Gradle wrapper version %s does not satisfy Gradle %s required by %s", actualGradle, matchedEntry.Gradle, targetDesc),
						Category: model.CategoryDependencies,
						Severity: model.SeverityCaution,
						Evidence: []model.Evidence{
							{Key: "actual_version", Value: actualGradle, Source: source},
							{Key: "matrix_requirement", Value: matchedEntry.Gradle, Source: "matrix:react_native"},
						},
						Fix: &model.Fix{
							ActionType: model.ActionEditFile,
							Title:      fmt.Sprintf("Update Gradle wrapper to %s", matchedEntry.Gradle),
							Params: map[string]string{
								"file":    "android/gradle/wrapper/gradle-wrapper.properties",
								"version": matchedEntry.Gradle,
							},
							Explanation: fmt.Sprintf("%s expects Gradle %s for build compatibility.", targetDesc, matchedEntry.Gradle),
						},
						Risk:   model.RiskMedium,
						Verify: "./gradlew -v",
					})
				}
			}
		}
	}

	// E. If all matrix constraints passed, emit Clear finding
	if !hasMismatch {
		evidence := []model.Evidence{
			{Key: "target", Value: targetDesc, Source: "matrix:react_native"},
		}
		if ctx.Node.Found {
			evidence = append(evidence, model.Evidence{Key: "node_version", Value: ctx.Node.Version, Source: "probe:node"})
		}
		if ctx.Java.Found {
			evidence = append(evidence, model.Evidence{Key: "jdk_version", Value: ctx.Java.Version, Source: "probe:java"})
		}

		findings = append(findings, model.Finding{
			ID:       "RULE-MATRIX-COMPATIBLE",
			Title:    fmt.Sprintf("Toolchain satisfies compatibility matrix for %s", targetDesc),
			Category: model.CategoryTooling,
			Severity: model.SeverityClear,
			Evidence: evidence,
			Verify:   "node -v",
		})
	}

	return findings
}

// evaluateRule evaluates a single DeclarativeRule against the EvaluationContext.
func (e *Engine) evaluateRule(rule DeclarativeRule, ctx EvaluationContext) (model.Finding, bool) {
	cond := rule.Condition
	matched := false

	switch cond.Target {
	case "node":
		switch cond.State {
		case "missing":
			matched = !ctx.Node.Found
		case "version_mismatch":
			if ctx.Node.Found && ctx.Expected != nil && ctx.Expected.NodeRange != "" {
				sat, err := Satisfies(ctx.Node.Version, ctx.Expected.NodeRange)
				matched = (err != nil || !sat)
			}
		case "ok":
			if ctx.Node.Found {
				if ctx.Expected == nil || ctx.Expected.NodeRange == "" {
					matched = true
				} else {
					sat, err := Satisfies(ctx.Node.Version, ctx.Expected.NodeRange)
					matched = (err == nil && sat)
				}
			}
		default:
			if cond.Range != "" {
				if !ctx.Node.Found {
					matched = true
				} else {
					sat, err := Satisfies(ctx.Node.Version, cond.Range)
					matched = (err != nil || !sat)
				}
			} else if cond.MinVersion != "" {
				if !ctx.Node.Found {
					matched = true
				} else {
					act, err1 := ParseVersion(ctx.Node.Version)
					req, err2 := ParseVersion(cond.MinVersion)
					matched = (err1 == nil && err2 == nil && act.Compare(req) < 0)
				}
			}
		}

	case "android_sdk":
		switch cond.State {
		case "directory_missing":
			matched = !ctx.AndroidSDK.DirectoryExists
		case "platform_tools_missing":
			matched = ctx.AndroidSDK.DirectoryExists && !ctx.AndroidSDK.HasPlatformTools
		case "ok":
			matched = ctx.AndroidSDK.DirectoryExists && ctx.AndroidSDK.HasPlatformTools
		}

	case "adb":
		switch cond.State {
		case "missing":
			matched = !ctx.Adb.Found
		case "ok":
			matched = ctx.Adb.Found
		}

	case "java":
		switch cond.State {
		case "missing":
			matched = !ctx.Java.Found
		case "version_mismatch":
			if ctx.Java.Found && ctx.Expected != nil && ctx.Expected.JavaRange != "" {
				sat, err := Satisfies(ctx.Java.Version, ctx.Expected.JavaRange)
				matched = (err != nil || !sat)
			}
		case "ok":
			if ctx.Java.Found {
				if ctx.Expected == nil || ctx.Expected.JavaRange == "" {
					matched = true
				} else {
					sat, err := Satisfies(ctx.Java.Version, ctx.Expected.JavaRange)
					matched = (err == nil && sat)
				}
			}
		default:
			if cond.MinVersion != "" {
				if !ctx.Java.Found {
					matched = true
				} else {
					act, err1 := ParseVersion(ctx.Java.Version)
					req, err2 := ParseVersion(cond.MinVersion)
					matched = (err1 == nil && err2 == nil && act.Compare(req) < 0)
				}
			}
		}

	case "env":
		if cond.Name != "" {
			val := os.Getenv(cond.Name)
			if cond.State == "unset" {
				matched = (val == "")
			} else if cond.State == "set" {
				matched = (val != "")
			}
		}
	}

	if !matched {
		return model.Finding{}, false
	}

	// Calculate severity, applying elevation rules if requested
	sev := model.Severity(rule.Severity)
	if rule.ElevateIf == "android_required" {
		isAndroidReq := ctx.Expected != nil && (ctx.Expected.IsReactNative || ctx.Expected.CompileSDK != "" || ctx.Expected.GradleVersion != "")
		if isAndroidReq {
			sev = model.SeverityGrounded
		}
	} else if rule.ElevateIf == "major_mismatch" && cond.Target == "node" && ctx.Node.Found && ctx.Expected != nil && ctx.Expected.NodeRange != "" {
		actVer, errAct := ParseVersion(ctx.Node.Version)
		tarVer, errTar := ExtractVersion(ctx.Expected.NodeRange)
		if errAct == nil && errTar == nil && actVer.Major != tarVer.Major {
			sev = model.SeverityGrounded
		}
	}

	// Format Title and Evidence dynamically where appropriate
	title := rule.Title
	var evidence []model.Evidence

	switch rule.ID {
	case "RULE-NODE-MISSING":
		expectedRange := "installed"
		if ctx.Expected != nil && ctx.Expected.NodeRange != "" {
			expectedRange = ctx.Expected.NodeRange
		}
		evidence = []model.Evidence{
			{Key: "status", Value: "missing", Source: "probe:node"},
			{Key: "expected_version", Value: expectedRange, Source: expectedSource(ctx.Expected)},
			{Key: "error", Value: ctx.Node.Error, Source: "probe:node"},
		}

	case "RULE-NODE-VERSION-MISMATCH":
		if ctx.Expected != nil && ctx.Expected.NodeRange != "" {
			title = fmt.Sprintf("Node.js version %s does not satisfy %s", ctx.Node.Version, ctx.Expected.NodeRange)
		}
		evidence = []model.Evidence{
			{Key: "actual_version", Value: ctx.Node.Version, Source: "probe:node"},
			{Key: "expected_version", Value: expectedNodeRange(ctx.Expected), Source: expectedSource(ctx.Expected)},
			{Key: "executable_path", Value: security.RedactPath(ctx.Node.Path), Source: "probe:node"},
		}

	case "RULE-NODE-OK":
		title = fmt.Sprintf("Node.js runtime is flight-ready (%s)", ctx.Node.Version)
		evidence = []model.Evidence{
			{Key: "version", Value: ctx.Node.Version, Source: "probe:node"},
			{Key: "executable_path", Value: security.RedactPath(ctx.Node.Path), Source: "probe:node"},
		}
		if ctx.Expected != nil && ctx.Expected.NodeRange != "" {
			evidence = append(evidence, model.Evidence{
				Key:    "expected_version",
				Value:  ctx.Expected.NodeRange,
				Source: expectedSource(ctx.Expected),
			})
		}

	case "RULE-ANDROID-SDK-MISSING":
		evidence = []model.Evidence{
			{Key: "env_name", Value: ctx.AndroidSDK.EnvName, Source: "probe:android_sdk"},
			{Key: "status", Value: "directory not found", Source: "probe:android_sdk"},
			{Key: "error", Value: ctx.AndroidSDK.Error, Source: "probe:android_sdk"},
		}

	case "RULE-ANDROID-PLATFORM-TOOLS-MISSING":
		evidence = []model.Evidence{
			{Key: "sdk_path", Value: ctx.AndroidSDK.RedactedPath, Source: "probe:android_sdk"},
			{Key: "platform_tools", Value: "missing", Source: "probe:android_sdk"},
		}

	case "RULE-ANDROID-SDK-OK":
		evidence = []model.Evidence{
			{Key: "sdk_path", Value: ctx.AndroidSDK.RedactedPath, Source: "probe:android_sdk"},
			{Key: "platform_tools", Value: "present", Source: "probe:android_sdk"},
		}

	case "RULE-ADB-MISSING":
		evidence = []model.Evidence{
			{Key: "status", Value: "missing from PATH", Source: "probe:adb"},
		}

	case "RULE-ADB-OK":
		title = fmt.Sprintf("Android Debug Bridge is flight-ready (%s)", ctx.Adb.Version)
		evidence = []model.Evidence{
			{Key: "version", Value: ctx.Adb.Version, Source: "probe:adb"},
			{Key: "path", Value: security.RedactPath(ctx.Adb.Path), Source: "probe:adb"},
		}

	default:
		// Default / Custom rule evidence
		for _, ev := range rule.Evidence {
			evidence = append(evidence, model.Evidence{
				Key:    security.RedactString(ev.Key),
				Value:  security.RedactString(ev.Value),
				Source: security.RedactString(ev.Source),
			})
		}
		if len(evidence) == 0 {
			evidence = append(evidence, model.Evidence{
				Key:    "condition_target",
				Value:  cond.Target,
				Source: "rule:" + rule.ID,
			})
		}
	}

	// Build typed fix
	var fix *model.Fix
	if rule.Fix != nil {
		params := make(map[string]string)
		for k, v := range rule.Fix.Params {
			if v == "target" && cond.Target == "node" && ctx.Expected != nil && ctx.Expected.NodeRange != "" {
				params[k] = cleanTargetVersion(ctx.Expected.NodeRange)
			} else {
				params[k] = v
			}
		}
		fix = &model.Fix{
			ActionType:  model.ActionType(rule.Fix.ActionType),
			Title:       rule.Fix.Title,
			Params:      params,
			Explanation: rule.Fix.Explanation,
		}
	}

	risk := model.RiskLow
	if rule.Risk != "" {
		risk = model.RiskLevel(rule.Risk)
	}

	verify := rule.Verify

	return model.Finding{
		ID:       rule.ID,
		Title:    security.RedactString(title),
		Category: model.Category(rule.Category),
		Severity: sev,
		Evidence: evidence,
		Fix:      fix,
		Risk:     risk,
		Verify:   verify,
	}, true
}

// MergeFindings merges and deduplicates base findings with engine findings, ensuring
// matrix mismatches appropriately suppress conflicting ok findings.
func MergeFindings(base []model.Finding, additional []model.Finding) []model.Finding {
	hasNodeMismatch := false
	hasJavaMismatch := false

	for _, f := range additional {
		if (f.ID == "RULE-MATRIX-NODE-MISMATCH" || f.ID == "RULE-MATRIX-NODE-MISSING") && f.Severity != model.SeverityClear {
			hasNodeMismatch = true
		}
		if (f.ID == "RULE-MATRIX-JDK-MISMATCH" || f.ID == "RULE-MATRIX-JAVA-MISSING") && f.Severity != model.SeverityClear {
			hasJavaMismatch = true
		}
	}

	seen := make(map[string]bool)
	var result []model.Finding

	for _, f := range base {
		if hasNodeMismatch && f.ID == "RULE-NODE-OK" {
			continue
		}
		if hasJavaMismatch && f.ID == "RULE-JAVA-OK" {
			continue
		}
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, f)
		}
	}

	for _, f := range additional {
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, f)
		}
	}

	return result
}

func extractMajorString(s string) string {
	v, err := ExtractVersion(s)
	if err == nil {
		return fmt.Sprintf("%d", v.Major)
	}
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimPrefix(s, "~")
	parts := strings.Split(s, ".")
	return parts[0]
}

func extractMajorMinorString(s string) string {
	v, err := ExtractVersion(s)
	if err == nil {
		return fmt.Sprintf("%d.%d", v.Major, v.Minor)
	}
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimPrefix(s, "~")
	parts := strings.Split(s, ".")
	if len(parts) >= 2 {
		return fmt.Sprintf("%s.%s", parts[0], parts[1])
	}
	return s
}

func cleanTargetVersion(rangeStr string) string {
	v, err := ExtractVersion(rangeStr)
	if err == nil {
		return fmt.Sprintf("%d", v.Major)
	}
	return "lts"
}

func expectedNodeRange(expected *infer.ExpectedEnv) string {
	if expected == nil || expected.NodeRange == "" {
		return "installed"
	}
	return expected.NodeRange
}
