package rules

import (
	"testing"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
)

func TestEvaluateGit(t *testing.T) {
	// 1. Found
	fOk := EvaluateGit(probe.ToolResult{Found: true, Version: "2.43.0"})
	if fOk.Severity != model.SeverityClear || fOk.ID != "RULE-GIT-OK" {
		t.Errorf("expected Clear, got: %+v", fOk)
	}

	// 2. Missing
	fMissing := EvaluateGit(probe.ToolResult{Found: false, Error: "not found"})
	if fMissing.Severity != model.SeverityCaution || fMissing.ID != "RULE-GIT-MISSING" {
		t.Errorf("expected Caution for missing git, got: %+v", fMissing)
	}
}

func TestEvaluateNpm(t *testing.T) {
	fOk := EvaluateNpm(probe.ToolResult{Found: true, Version: "10.8.2"})
	if fOk.Severity != model.SeverityClear {
		t.Errorf("expected Clear, got: %+v", fOk)
	}

	fMissing := EvaluateNpm(probe.ToolResult{Found: false})
	if fMissing.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded for missing npm, got: %+v", fMissing)
	}
}

func TestEvaluateJava(t *testing.T) {
	// Missing Java in general project -> Caution
	fMissing := EvaluateJava(probe.ToolResult{Found: false}, probe.WindowsEnvResult{}, nil)
	if fMissing.Severity != model.SeverityCaution {
		t.Errorf("expected Caution for missing java in generic project, got: %+v", fMissing)
	}

	// Missing Java in React Native project -> Grounded blocker
	rnExpected := &infer.ExpectedEnv{IsReactNative: true, JavaRange: "17"}
	fMissingRN := EvaluateJava(probe.ToolResult{Found: false}, probe.WindowsEnvResult{}, rnExpected)
	if fMissingRN.Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded for missing java in RN project, got: %+v", fMissingRN)
	}

	// Java found but JAVA_HOME unset
	fUnset := EvaluateJava(probe.ToolResult{Found: true, Version: "21.0.2"}, probe.WindowsEnvResult{JavaHomeSet: false}, nil)
	if fUnset.ID != "RULE-JAVA-HOME-UNSET" || fUnset.Severity != model.SeverityCaution {
		t.Errorf("expected RULE-JAVA-HOME-UNSET, got: %+v", fUnset)
	}

	// Java found and JAVA_HOME valid
	fOk := EvaluateJava(probe.ToolResult{Found: true, Version: "21.0.2"}, probe.WindowsEnvResult{JavaHomeSet: true, JavaHomeValid: true}, nil)
	if fOk.Severity != model.SeverityClear {
		t.Errorf("expected Clear, got: %+v", fOk)
	}
}

func TestEvaluateAndroid(t *testing.T) {
	// SDK missing in generic project -> Caution
	sdkMissing := probe.AndroidSDKResult{DirectoryExists: false}
	adbMissing := probe.ToolResult{Found: false}
	findings := EvaluateAndroid(sdkMissing, adbMissing, nil)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ID != "RULE-ANDROID-SDK-MISSING" || findings[1].ID != "RULE-ADB-MISSING" {
		t.Errorf("unexpected findings: %+v", findings)
	}
	if findings[0].Severity != model.SeverityCaution {
		t.Errorf("expected Caution for generic project, got: %s", findings[0].Severity)
	}

	// SDK missing in React Native project -> Grounded blocker!
	rnExpected := &infer.ExpectedEnv{IsReactNative: true}
	findingsRN := EvaluateAndroid(sdkMissing, adbMissing, rnExpected)
	if findingsRN[0].Severity != model.SeverityGrounded || findingsRN[1].Severity != model.SeverityGrounded {
		t.Errorf("expected Grounded in RN project for missing SDK & ADB, got: %s and %s", findingsRN[0].Severity, findingsRN[1].Severity)
	}

	// SDK OK, ADB OK
	sdkOk := probe.AndroidSDKResult{DirectoryExists: true, HasPlatformTools: true}
	adbOk := probe.ToolResult{Found: true, Version: "1.0.41"}
	findingsOk := EvaluateAndroid(sdkOk, adbOk, nil)
	if len(findingsOk) != 2 || findingsOk[0].Severity != model.SeverityClear || findingsOk[1].Severity != model.SeverityClear {
		t.Errorf("expected 2 Clear findings, got: %+v", findingsOk)
	}
}

func TestEvaluateWindowsEnvironment(t *testing.T) {
	// Restricted PS policy and App Execution Aliases precedence
	winEnv := probe.WindowsEnvResult{
		EffectivePSPolicy:     "Restricted",
		WindowsAppsPrecedence: true,
	}
	findings := EvaluateWindowsEnvironment(winEnv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ID != "RULE-WIN-PS-RESTRICTED" || findings[1].ID != "RULE-WIN-STORE-SHADOWING" {
		t.Errorf("unexpected findings: %+v", findings)
	}
}
