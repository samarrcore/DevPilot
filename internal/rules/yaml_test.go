package rules

import (
	"os"
	"path/filepath"
	"testing"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
)

func TestLoadEmbeddedPacks(t *testing.T) {
	packs, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatalf("LoadEmbeddedPacks failed: %v", err)
	}

	if len(packs) < 3 {
		t.Fatalf("expected at least 3 embedded rule packs, got %d", len(packs))
	}

	foundNode := false
	foundRN := false
	foundAndroid := false

	for _, p := range packs {
		switch p.Name {
		case "node-runtime":
			foundNode = true
			if len(p.Rules) == 0 {
				t.Errorf("node-runtime pack has no rules")
			}
		case "react-native-compatibility":
			foundRN = true
			if len(p.Matrices) == 0 {
				t.Errorf("react-native-compatibility pack has no matrices")
			}
		case "android-toolchain":
			foundAndroid = true
			if len(p.Rules) == 0 {
				t.Errorf("android-toolchain pack has no rules")
			}
		}
	}

	if !foundNode {
		t.Errorf("missing node-runtime embedded pack")
	}
	if !foundRN {
		t.Errorf("missing react-native-compatibility embedded pack")
	}
	if !foundAndroid {
		t.Errorf("missing android-toolchain embedded pack")
	}
}

func TestMatrix_Expo51_Compatible(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsExpo:         true,
			ExpoSdkVersion: "51.0.0",
			IsReactNative:  true,
			RNVersion:      "0.74.1",
			GradleVersion:  "8.6",
		},
		Node: probe.NodeResult{
			Found:   true,
			Version: "20.11.0",
			Path:    "C:\\dev\\node.exe",
		},
		Java: probe.ToolResult{
			Name:    "java",
			Found:   true,
			Version: "17.0.10",
			Path:    "C:\\dev\\java.exe",
		},
		AndroidSDK: probe.AndroidSDKResult{
			DirectoryExists:  true,
			HasPlatformTools: true,
			RedactedPath:     "~\\Android\\Sdk",
		},
		Adb: probe.ToolResult{
			Name:    "adb",
			Found:   true,
			Version: "1.0.41",
		},
	}

	findings := engine.Evaluate(ctx)

	var compFinding *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-COMPATIBLE" {
			comp := f
			compFinding = &comp
		}
		if f.ID == "RULE-MATRIX-NODE-MISMATCH" || f.ID == "RULE-MATRIX-JDK-MISMATCH" || f.ID == "RULE-MATRIX-RN-MISMATCH" {
			t.Errorf("unexpected mismatch finding: %s (%s)", f.ID, f.Title)
		}
	}

	if compFinding == nil {
		t.Fatalf("expected RULE-MATRIX-COMPATIBLE finding, but none found")
	}
	if compFinding.Severity != model.SeverityClear {
		t.Errorf("expected SeverityClear, got %s", compFinding.Severity)
	}
	if compFinding.Verify != "node -v" {
		t.Errorf("expected verify 'node -v', got %s", compFinding.Verify)
	}
}

func TestMatrix_Expo51_NodeMismatch(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsExpo:         true,
			ExpoSdkVersion: "51.0.0",
			IsReactNative:  true,
			RNVersion:      "0.74.1",
		},
		Node: probe.NodeResult{
			Found:   true,
			Version: "16.20.0", // Below required >=18.0.0
			Path:    "C:\\dev\\node.exe",
		},
		Java: probe.ToolResult{
			Name:    "java",
			Found:   true,
			Version: "17.0.10",
		},
	}

	findings := engine.Evaluate(ctx)

	var nodeMismatch *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-NODE-MISMATCH" {
			nm := f
			nodeMismatch = &nm
		}
		if f.ID == "RULE-MATRIX-COMPATIBLE" {
			t.Errorf("unexpected RULE-MATRIX-COMPATIBLE finding when Node version is mismatched")
		}
	}

	if nodeMismatch == nil {
		t.Fatalf("expected RULE-MATRIX-NODE-MISMATCH, but none found")
	}
	if nodeMismatch.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded severity for major Node version mismatch, got %s", nodeMismatch.Severity)
	}
	if nodeMismatch.Fix == nil || nodeMismatch.Fix.ActionType != model.ActionInstallToolVersion {
		t.Errorf("expected typed ActionInstallToolVersion fix, got %+v", nodeMismatch.Fix)
	}
	if nodeMismatch.Fix.Params["tool"] != "node" {
		t.Errorf("expected fix tool 'node', got %s", nodeMismatch.Fix.Params["tool"])
	}
}

func TestMatrix_Expo51_JavaMismatch(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsExpo:         true,
			ExpoSdkVersion: "51.0.0",
			IsReactNative:  true,
			RNVersion:      "0.74.1",
		},
		Node: probe.NodeResult{
			Found:   true,
			Version: "20.11.0",
		},
		Java: probe.ToolResult{
			Name:    "java",
			Found:   true,
			Version: "11.0.22", // Expo 51 / RN 0.74 requires JDK 17
		},
	}

	findings := engine.Evaluate(ctx)

	var javaMismatch *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-JDK-MISMATCH" {
			jm := f
			javaMismatch = &jm
		}
	}

	if javaMismatch == nil {
		t.Fatalf("expected RULE-MATRIX-JDK-MISMATCH, got none")
	}
	if javaMismatch.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded severity, got %s", javaMismatch.Severity)
	}
	if javaMismatch.Fix == nil || javaMismatch.Fix.Params["version"] != "17" {
		t.Errorf("expected JDK 17 fix target, got %+v", javaMismatch.Fix)
	}
}

func TestMatrix_Expo51_RNMismatch(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsExpo:         true,
			ExpoSdkVersion: "51.0.0",
			IsReactNative:  true,
			RNVersion:      "0.72.0", // Incompatible with Expo 51 (expects 0.74)
		},
		Node: probe.NodeResult{Found: true, Version: "20.11.0"},
		Java: probe.ToolResult{Name: "java", Found: true, Version: "17.0.10"},
	}

	findings := engine.Evaluate(ctx)

	var rnMismatch *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-RN-MISMATCH" {
			rm := f
			rnMismatch = &rm
		}
	}

	if rnMismatch == nil {
		t.Fatalf("expected RULE-MATRIX-RN-MISMATCH, got none")
	}
	if rnMismatch.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded severity, got %s", rnMismatch.Severity)
	}
	if rnMismatch.Fix == nil || rnMismatch.Fix.ActionType != model.ActionEditFile {
		t.Errorf("expected typed ActionEditFile fix, got %+v", rnMismatch.Fix)
	}
}

func TestMatrix_Expo51_GradleMismatch(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsExpo:         true,
			ExpoSdkVersion: "51.0.0",
			IsReactNative:  true,
			RNVersion:      "0.74.1",
			GradleVersion:  "7.5.1", // Incompatible with Expo 51 (expects 8.6)
			GradleSource:   "gradle-wrapper.properties",
		},
		Node: probe.NodeResult{Found: true, Version: "20.11.0"},
		Java: probe.ToolResult{Name: "java", Found: true, Version: "17.0.10"},
	}

	findings := engine.Evaluate(ctx)

	var gradleMismatch *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-GRADLE-MISMATCH" {
			gm := f
			gradleMismatch = &gm
		}
	}

	if gradleMismatch == nil {
		t.Fatalf("expected RULE-MATRIX-GRADLE-MISMATCH, got none")
	}
	if gradleMismatch.Severity != model.SeverityCaution {
		t.Errorf("expected Caution severity, got %s", gradleMismatch.Severity)
	}
	if gradleMismatch.Fix == nil || gradleMismatch.Fix.ActionType != model.ActionEditFile {
		t.Errorf("expected typed ActionEditFile fix, got %+v", gradleMismatch.Fix)
	}
}

func TestMatrix_ReactNative_Standalone(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsReactNative: true,
			RNVersion:     "0.74.0",
		},
		Node: probe.NodeResult{Found: true, Version: "20.11.0"},
		Java: probe.ToolResult{Name: "java", Found: true, Version: "17.0.10"},
	}

	findings := engine.Evaluate(ctx)

	var comp *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-MATRIX-COMPATIBLE" {
			c := f
			comp = &c
		}
	}

	if comp == nil {
		t.Fatalf("expected RULE-MATRIX-COMPATIBLE for standalone RN 0.74, got none")
	}
}

func TestDeclarativeRules_Node(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// 1. Missing node
	ctxMissing := EvaluationContext{
		Node: probe.NodeResult{Found: false, Error: "not found"},
	}
	findings := engine.Evaluate(ctxMissing)
	foundMissing := false
	for _, f := range findings {
		if f.ID == "RULE-NODE-MISSING" {
			foundMissing = true
			if f.Severity != model.SeverityGrounded {
				t.Errorf("expected Grounded, got %s", f.Severity)
			}
		}
	}
	if !foundMissing {
		t.Errorf("expected RULE-NODE-MISSING")
	}

	// 2. Node OK
	ctxOK := EvaluationContext{
		Node: probe.NodeResult{Found: true, Version: "20.11.0", Path: "C:\\dev\\node.exe"},
	}
	findingsOK := engine.Evaluate(ctxOK)
	foundOK := false
	for _, f := range findingsOK {
		if f.ID == "RULE-NODE-OK" {
			foundOK = true
			if f.Severity != model.SeverityClear {
				t.Errorf("expected Clear, got %s", f.Severity)
			}
		}
	}
	if !foundOK {
		t.Errorf("expected RULE-NODE-OK")
	}
}

func TestDeclarativeRules_Android(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Android required context
	ctx := EvaluationContext{
		Expected: &infer.ExpectedEnv{
			IsReactNative: true,
		},
		AndroidSDK: probe.AndroidSDKResult{
			DirectoryExists:  false,
			EnvName:          "ANDROID_HOME",
			Error:            "missing directory",
		},
		Adb: probe.ToolResult{
			Found: false,
		},
	}

	findings := engine.Evaluate(ctx)

	foundSDKMissing := false
	foundAdbMissing := false

	for _, f := range findings {
		if f.ID == "RULE-ANDROID-SDK-MISSING" {
			foundSDKMissing = true
			if f.Severity != model.SeverityGrounded {
				t.Errorf("expected elevated SeverityGrounded for required Android, got %s", f.Severity)
			}
		}
		if f.ID == "RULE-ADB-MISSING" {
			foundAdbMissing = true
			if f.Severity != model.SeverityGrounded {
				t.Errorf("expected elevated SeverityGrounded for ADB, got %s", f.Severity)
			}
		}
	}

	if !foundSDKMissing {
		t.Errorf("expected RULE-ANDROID-SDK-MISSING")
	}
	if !foundAdbMissing {
		t.Errorf("expected RULE-ADB-MISSING")
	}
}

func TestCustomProjectRules(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-custom-rules-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	customYAML := `name: custom-team-rules
rules:
  - id: RULE-TEAM-NODE-20
    title: Project requires Node 20 or higher
    category: tooling
    severity: Grounded
    condition:
      target: node
      min_version: "20.0.0"
    fix:
      action_type: install_tool_version
      title: Install Node.js 20
      params:
        tool: node
        version: "20"
      explanation: Team standard requires Node 20.
    risk: low
    verify: node -v
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(customYAML), 0644); err != nil {
		t.Fatalf("failed to write custom.yaml: %v", err)
	}

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	if err := engine.LoadProjectRules(tmpDir); err != nil {
		t.Fatalf("LoadProjectRules failed: %v", err)
	}

	ctx := EvaluationContext{
		Node: probe.NodeResult{
			Found:   true,
			Version: "18.19.0", // Violates custom min_version 20.0.0
		},
	}

	findings := engine.Evaluate(ctx)

	var customFinding *model.Finding
	for _, f := range findings {
		if f.ID == "RULE-TEAM-NODE-20" {
			cf := f
			customFinding = &cf
		}
	}

	if customFinding == nil {
		t.Fatalf("expected custom rule RULE-TEAM-NODE-20 finding, got none")
	}
	if customFinding.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded, got %s", customFinding.Severity)
	}
	if customFinding.Fix == nil || customFinding.Fix.ActionType != model.ActionInstallToolVersion {
		t.Errorf("expected typed ActionInstallToolVersion, got %+v", customFinding.Fix)
	}
}

func TestCustomProjectRules_SecurityUntrustedFixDiscarded(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-custom-security-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	// Custom YAML attempting to inject an unapproved shell script fix action (Security Rule 6)
	maliciousYAML := `name: malicious-rule
rules:
  - id: RULE-MALICIOUS-SCRIPT
    title: Untrusted rule with shell command
    category: tooling
    severity: Caution
    condition:
      target: node
      min_version: "22.0.0"
    fix:
      action_type: execute_shell_script
      title: Run untrusted script
      explanation: Danger!
`
	if err := os.WriteFile(filepath.Join(rulesDir, "malicious.yaml"), []byte(maliciousYAML), 0644); err != nil {
		t.Fatalf("failed to write malicious.yaml: %v", err)
	}

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	if err := engine.LoadProjectRules(tmpDir); err != nil {
		t.Fatalf("LoadProjectRules failed: %v", err)
	}

	ctx := EvaluationContext{
		Node: probe.NodeResult{Found: true, Version: "20.0.0"},
	}

	findings := engine.Evaluate(ctx)
	for _, f := range findings {
		if f.ID == "RULE-MALICIOUS-SCRIPT" {
			if f.Fix != nil {
				t.Errorf("Security violation: untrusted action type was not sanitized/discarded: %+v", f.Fix)
			}
		}
	}
}

func TestMergeFindings_MatrixMismatchSuppression(t *testing.T) {
	baseFindings := []model.Finding{
		{ID: "RULE-NODE-OK", Severity: model.SeverityClear, Title: "Node is flight-ready"},
		{ID: "RULE-JAVA-OK", Severity: model.SeverityClear, Title: "Java is flight-ready"},
	}

	engineFindings := []model.Finding{
		{ID: "RULE-MATRIX-NODE-MISMATCH", Severity: model.SeverityGrounded, Title: "Node mismatch"},
	}

	merged := MergeFindings(baseFindings, engineFindings)

	for _, f := range merged {
		if f.ID == "RULE-NODE-OK" {
			t.Errorf("expected RULE-NODE-OK to be suppressed by RULE-MATRIX-NODE-MISMATCH")
		}
	}

	foundJava := false
	foundMatrix := false
	for _, f := range merged {
		if f.ID == "RULE-JAVA-OK" {
			foundJava = true
		}
		if f.ID == "RULE-MATRIX-NODE-MISMATCH" {
			foundMatrix = true
		}
	}

	if !foundJava || !foundMatrix {
		t.Errorf("expected RULE-JAVA-OK and RULE-MATRIX-NODE-MISMATCH in merged findings")
	}
}

func TestCustomProjectRules_MalformedYAMLSkipped(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-malformed-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	corruptYAML := `name: corrupt-yaml
rules:
  - id: [unclosed mapping and invalid yaml :::
`
	if err := os.WriteFile(filepath.Join(rulesDir, "corrupt.yaml"), []byte(corruptYAML), 0644); err != nil {
		t.Fatalf("failed to write corrupt.yaml: %v", err)
	}

	packs, err := LoadProjectRules(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectRules should not return error on malformed YAML, got: %v", err)
	}
	if len(packs) != 0 {
		t.Errorf("expected 0 packs loaded from malformed file, got %d", len(packs))
	}
}

func TestCustomProjectRules_InjectedMatricesStripped(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-injected-matrices-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	matrixYAML := `name: rogue-matrices
matrices:
  - name: fake-matrix
    target: react-native
    entries:
      - node: ">=100.0.0"
rules:
  - id: RULE-ROGUE-CHECK
    title: Rogue check
    category: tooling
    severity: Caution
    condition:
      target: node
      state: missing
`
	if err := os.WriteFile(filepath.Join(rulesDir, "matrix.yaml"), []byte(matrixYAML), 0644); err != nil {
		t.Fatalf("failed to write matrix.yaml: %v", err)
	}

	packs, err := LoadProjectRules(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectRules failed: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packs))
	}
	if packs[0].Matrices != nil {
		t.Errorf("security violation: custom rule pack matrices were not stripped: %+v", packs[0].Matrices)
	}
}

func TestCustomProjectRules_PathTraversalEditFileFixRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-traversal-fix-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	traversalYAML := `name: traversal-rule
rules:
  - id: RULE-TRAVERSAL-FIX
    title: Untrusted rule with path traversal in fix
    category: tooling
    severity: Caution
    condition:
      target: node
      min_version: "22.0.0"
    fix:
      action_type: edit_file
      title: Overwrite system file
      params:
        file: "../../Windows/System32/drivers/etc/hosts"
      explanation: Path traversal exploit attempt
    verify: "node -v; echo exploit"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "traversal.yaml"), []byte(traversalYAML), 0644); err != nil {
		t.Fatalf("failed to write traversal.yaml: %v", err)
	}

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	if err := engine.LoadProjectRules(tmpDir); err != nil {
		t.Fatalf("LoadProjectRules failed: %v", err)
	}

	ctx := EvaluationContext{
		Node: probe.NodeResult{Found: true, Version: "20.0.0"},
	}

	findings := engine.Evaluate(ctx)
	found := false
	for _, f := range findings {
		if f.ID == "RULE-TRAVERSAL-FIX" {
			found = true
			if f.Fix != nil {
				t.Errorf("Security violation: path traversal fix was not rejected: %+v", f.Fix)
			}
			if f.Verify != "" {
				t.Errorf("Security violation: verify with shell chaining command was not sanitized: %q", f.Verify)
			}
		}
	}
	if !found {
		t.Errorf("expected finding RULE-TRAVERSAL-FIX")
	}
}

func TestCustomProjectRules_OversizedRuleFileSkipped(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devpilot-oversized-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := filepath.Join(tmpDir, ".agents", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	// Create file exceeding MaxRuleFileBytes (512KB)
	largeData := make([]byte, MaxRuleFileBytes+1024)
	for i := range largeData {
		largeData[i] = '#' // YAML comments
	}
	copy(largeData, []byte("name: oversized-rules\n"))

	if err := os.WriteFile(filepath.Join(rulesDir, "large.yaml"), largeData, 0644); err != nil {
		t.Fatalf("failed to write large.yaml: %v", err)
	}

	packs, err := LoadProjectRules(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectRules should not fail on oversized file, got: %v", err)
	}
	if len(packs) != 0 {
		t.Errorf("expected oversized rule file to be skipped, got %d packs", len(packs))
	}
}

