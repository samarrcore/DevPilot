package rules

import (
	"fmt"

	"devpilot/internal/infer"
	"devpilot/internal/model"
	"devpilot/internal/probe"
)

// EvaluateGit checks git CLI availability.
func EvaluateGit(actual probe.ToolResult) model.Finding {
	if !actual.Found {
		return model.Finding{
			ID:       "RULE-GIT-MISSING",
			Title:    "Git CLI is not installed or not in PATH",
			Category: model.CategoryTooling,
			Severity: model.SeverityCaution,
			Evidence: []model.Evidence{
				{Key: "status", Value: "missing", Source: "probe:git"},
				{Key: "error", Value: actual.Error, Source: "probe:git"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionInstallToolVersion,
				Title:      "Install Git for Windows",
				Params: map[string]string{
					"tool": "git",
				},
				Explanation: "Git is required for version control, cloning submodules, and resolving git dependencies. Recommendation: winget install Git.Git",
			},
			Risk:   model.RiskLow,
			Verify: "git --version",
		}
	}

	return model.Finding{
		ID:       "RULE-GIT-OK",
		Title:    fmt.Sprintf("Git is flight-ready (%s)", actual.Version),
		Category: model.CategoryTooling,
		Severity: model.SeverityClear,
		Evidence: []model.Evidence{
			{Key: "version", Value: actual.Version, Source: "probe:git"},
			{Key: "path", Value: actual.Path, Source: "probe:git"},
		},
		Verify: "git --version",
	}
}

// EvaluateNpm checks npm package manager availability.
func EvaluateNpm(actual probe.ToolResult) model.Finding {
	if !actual.Found {
		return model.Finding{
			ID:       "RULE-NPM-MISSING",
			Title:    "npm package manager is not installed or not in PATH",
			Category: model.CategoryTooling,
			Severity: model.SeverityGrounded,
			Evidence: []model.Evidence{
				{Key: "status", Value: "missing", Source: "probe:npm"},
				{Key: "error", Value: actual.Error, Source: "probe:npm"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionInstallToolVersion,
				Title:      "Install Node.js & npm (LTS)",
				Params: map[string]string{
					"tool":    "npm",
					"version": "lts",
				},
				Explanation: "npm is bundled with Node.js LTS. Recommendation: winget install OpenJS.NodeJS.LTS",
			},
			Risk:   model.RiskLow,
			Verify: "npm -v",
		}
	}

	return model.Finding{
		ID:       "RULE-NPM-OK",
		Title:    fmt.Sprintf("npm package manager is flight-ready (%s)", actual.Version),
		Category: model.CategoryTooling,
		Severity: model.SeverityClear,
		Evidence: []model.Evidence{
			{Key: "version", Value: actual.Version, Source: "probe:npm"},
			{Key: "path", Value: actual.Path, Source: "probe:npm"},
		},
		Verify: "npm -v",
	}
}

// EvaluateJava checks JDK runtime and JAVA_HOME configuration against project requirements.
func EvaluateJava(actual probe.ToolResult, winEnv probe.WindowsEnvResult, expected *infer.ExpectedEnv) model.Finding {
	isJavaRequired := expected != nil && (expected.IsReactNative || expected.GradleVersion != "" || expected.JavaRange != "")

	if !actual.Found {
		severity := model.SeverityCaution
		if isJavaRequired {
			severity = model.SeverityGrounded // Hard blocker for React Native / Android / Gradle projects
		}
		targetVer := "17"
		if expected != nil && expected.JavaRange != "" {
			targetVer = expected.JavaRange
		}
		return model.Finding{
			ID:       "RULE-JAVA-MISSING",
			Title:    "Java runtime (JDK) is not installed or not in PATH",
			Category: model.CategoryTooling,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "status", Value: "missing", Source: "probe:java"},
				{Key: "error", Value: actual.Error, Source: "probe:java"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionInstallToolVersion,
				Title:      fmt.Sprintf("Install Java Development Kit (JDK %s)", targetVer),
				Params: map[string]string{
					"tool":    "java",
					"version": targetVer,
				},
				Explanation: "React Native and Android Gradle builds require JDK. Recommendation: winget install Microsoft.OpenJDK.17",
			},
			Risk:   model.RiskMedium,
			Verify: "java -version",
		}
	}

	// Version match check if project specified or inferred a Java requirement
	if expected != nil && expected.JavaRange != "" {
		satisfies, _ := Satisfies(actual.Version, expected.JavaRange)
		if !satisfies {
			actVer, _ := ParseVersion(actual.Version)
			targetVer, _ := ExtractVersion(expected.JavaRange)
			sev := model.SeverityCaution
			if actVer.Major != targetVer.Major {
				sev = model.SeverityGrounded
			}
			return model.Finding{
				ID:       "RULE-JAVA-VERSION-MISMATCH",
				Title:    fmt.Sprintf("Java JDK version %s does not satisfy %s", actual.Version, expected.JavaRange),
				Category: model.CategoryTooling,
				Severity: sev,
				Evidence: []model.Evidence{
					{Key: "actual_version", Value: actual.Version, Source: "probe:java"},
					{Key: "expected_version", Value: expected.JavaRange, Source: expected.JavaSource},
				},
				Fix: &model.Fix{
					ActionType: model.ActionInstallToolVersion,
					Title:      fmt.Sprintf("Install and switch to JDK %s", expected.JavaRange),
					Params: map[string]string{
						"tool":    "java",
						"version": expected.JavaRange,
					},
					Explanation: "Android Gradle builds fail when compiling with an incompatible JDK. Recommendation: winget install Microsoft.OpenJDK.17",
				},
				Risk:   model.RiskMedium,
				Verify: "java -version",
			}
		}
	}

	// Check if JAVA_HOME is set and points to a valid JDK
	if !winEnv.JavaHomeSet {
		severity := model.SeverityCaution
		if isJavaRequired {
			severity = model.SeverityGrounded
		}
		return model.Finding{
			ID:       "RULE-JAVA-HOME-UNSET",
			Title:    "JAVA_HOME environment variable is not set",
			Category: model.CategoryMachine,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "java_version", Value: actual.Version, Source: "probe:java"},
				{Key: "java_home", Value: "unset", Source: "probe:windows_env"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Set JAVA_HOME to JDK install directory",
				Params: map[string]string{
					"variable": "JAVA_HOME",
				},
				Explanation: "Gradle and Android tools require JAVA_HOME to locate the JDK compiler.",
			},
			Risk:   model.RiskLow,
			Verify: "java -version",
		}
	}

	if !winEnv.JavaHomeValid {
		severity := model.SeverityCaution
		if isJavaRequired {
			severity = model.SeverityGrounded
		}
		return model.Finding{
			ID:       "RULE-JAVA-HOME-INVALID",
			Title:    "JAVA_HOME is set but does not point to a valid JDK directory",
			Category: model.CategoryMachine,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "java_home_status", Value: "invalid (missing bin/java.exe)", Source: "probe:windows_env"},
				{Key: "java_home_path", Value: winEnv.JavaHomeRedacted, Source: "probe:windows_env"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Update JAVA_HOME to valid JDK root directory",
				Params: map[string]string{
					"variable": "JAVA_HOME",
				},
				Explanation: "Ensure JAVA_HOME points to the JDK root folder containing a 'bin' subdirectory.",
			},
			Risk:   model.RiskLow,
			Verify: "java -version",
		}
	}

	return model.Finding{
		ID:       "RULE-JAVA-OK",
		Title:    fmt.Sprintf("Java Development Kit is flight-ready (%s)", actual.Version),
		Category: model.CategoryTooling,
		Severity: model.SeverityClear,
		Evidence: []model.Evidence{
			{Key: "version", Value: actual.Version, Source: "probe:java"},
			{Key: "java_home", Value: "set (valid)", Source: "probe:windows_env"},
		},
		Verify: "java -version",
	}
}

// EvaluateAndroid checks Android SDK and ADB configuration against project requirements.
func EvaluateAndroid(sdk probe.AndroidSDKResult, adb probe.ToolResult, expected *infer.ExpectedEnv) []model.Finding {
	var findings []model.Finding
	isAndroidRequired := expected != nil && (expected.IsReactNative || expected.CompileSDK != "" || expected.GradleVersion != "")

	// 1. Android SDK finding
	if !sdk.DirectoryExists {
		severity := model.SeverityCaution
		if isAndroidRequired {
			severity = model.SeverityGrounded
		}
		findings = append(findings, model.Finding{
			ID:       "RULE-ANDROID-SDK-MISSING",
			Title:    "Android SDK is not configured or directory does not exist",
			Category: model.CategoryTooling,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "env_name", Value: sdk.EnvName, Source: "probe:android_sdk"},
				{Key: "status", Value: "directory not found", Source: "probe:android_sdk"},
				{Key: "error", Value: sdk.Error, Source: "probe:android_sdk"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Install Android Studio / SDK and set ANDROID_HOME",
				Params: map[string]string{
					"variable": "ANDROID_HOME",
				},
				Explanation: "Install Android Studio with SDK Command-line Tools and set ANDROID_HOME to %LOCALAPPDATA%\\Android\\Sdk.",
			},
			Risk:   model.RiskMedium,
			Verify: "adb version",
		})
	} else if !sdk.HasPlatformTools {
		severity := model.SeverityCaution
		if isAndroidRequired {
			severity = model.SeverityGrounded
		}
		findings = append(findings, model.Finding{
			ID:       "RULE-ANDROID-PLATFORM-TOOLS-MISSING",
			Title:    "Android SDK is missing platform-tools component",
			Category: model.CategoryTooling,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "sdk_path", Value: sdk.RedactedPath, Source: "probe:android_sdk"},
				{Key: "platform_tools", Value: "missing", Source: "probe:android_sdk"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionInstallToolVersion,
				Title:      "Install Android SDK Platform-Tools via Android Studio SDK Manager",
				Params: map[string]string{
					"component": "platform-tools",
				},
				Explanation: "Platform-tools includes adb, which is required to communicate with Android devices and emulators.",
			},
			Risk:   model.RiskLow,
			Verify: "adb version",
		})
	} else {
		findings = append(findings, model.Finding{
			ID:       "RULE-ANDROID-SDK-OK",
			Title:    "Android SDK directory is flight-ready",
			Category: model.CategoryTooling,
			Severity: model.SeverityClear,
			Evidence: []model.Evidence{
				{Key: "sdk_path", Value: sdk.RedactedPath, Source: "probe:android_sdk"},
				{Key: "platform_tools", Value: "present", Source: "probe:android_sdk"},
			},
			Verify: "adb version",
		})
	}

	// 2. ADB CLI finding
	if !adb.Found {
		severity := model.SeverityCaution
		if isAndroidRequired {
			severity = model.SeverityGrounded
		}
		findings = append(findings, model.Finding{
			ID:       "RULE-ADB-MISSING",
			Title:    "Android Debug Bridge (adb) is not on PATH",
			Category: model.CategoryTooling,
			Severity: severity,
			Evidence: []model.Evidence{
				{Key: "status", Value: "missing from PATH", Source: "probe:adb"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Add %ANDROID_HOME%\\platform-tools to your User PATH",
				Params: map[string]string{
					"variable": "PATH",
				},
				Explanation: "Adding platform-tools to PATH enables 'adb' and Expo/React Native Android tooling.",
			},
			Risk:   model.RiskLow,
			Verify: "adb version",
		})
	} else {
		findings = append(findings, model.Finding{
			ID:       "RULE-ADB-OK",
			Title:    fmt.Sprintf("Android Debug Bridge is flight-ready (%s)", adb.Version),
			Category: model.CategoryTooling,
			Severity: model.SeverityClear,
			Evidence: []model.Evidence{
				{Key: "version", Value: adb.Version, Source: "probe:adb"},
				{Key: "path", Value: adb.Path, Source: "probe:adb"},
			},
			Verify: "adb version",
		})
	}

	return findings
}

// EvaluateWindowsEnvironment evaluates Windows-specific PATH, PowerShell, and Store aliases.
func EvaluateWindowsEnvironment(winEnv probe.WindowsEnvResult) []model.Finding {
	var findings []model.Finding

	// Check PowerShell Execution Policy
	if winEnv.EffectivePSPolicy == "Restricted" {
		findings = append(findings, model.Finding{
			ID:       "RULE-WIN-PS-RESTRICTED",
			Title:    "PowerShell execution policy is Restricted (may block npm script execution)",
			Category: model.CategoryMachine,
			Severity: model.SeverityCaution,
			Evidence: []model.Evidence{
				{Key: "effective_policy", Value: "Restricted", Source: "probe:windows_env"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Set PowerShell ExecutionPolicy to RemoteSigned for CurrentUser",
				Params: map[string]string{
					"policy": "RemoteSigned",
					"scope":  "CurrentUser",
				},
				Explanation: "Default Windows PowerShell policy blocks npm and npx .ps1 scripts. Run: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned",
			},
			Risk:   model.RiskLow,
			Verify: "Get-ExecutionPolicy",
		})
	} else if winEnv.EffectivePSPolicy != "" {
		findings = append(findings, model.Finding{
			ID:       "RULE-WIN-PS-OK",
			Title:    fmt.Sprintf("PowerShell execution policy is flight-ready (%s)", winEnv.EffectivePSPolicy),
			Category: model.CategoryMachine,
			Severity: model.SeverityClear,
			Evidence: []model.Evidence{
				{Key: "effective_policy", Value: winEnv.EffectivePSPolicy, Source: "probe:windows_env"},
			},
			Verify: "Get-ExecutionPolicy",
		})
	}

	// Check App Execution Aliases precedence
	if winEnv.WindowsAppsPrecedence {
		findings = append(findings, model.Finding{
			ID:       "RULE-WIN-STORE-SHADOWING",
			Title:    "WindowsApps execution aliases precede dev tools in PATH",
			Category: model.CategoryMachine,
			Severity: model.SeverityCaution,
			Evidence: []model.Evidence{
				{Key: "windows_apps_in_path", Value: "true", Source: "probe:windows_env"},
				{Key: "precedence", Value: "WindowsApps precedes development runtimes", Source: "probe:windows_env"},
			},
			Fix: &model.Fix{
				ActionType: model.ActionSetEnvVar,
				Title:      "Reorder PATH or disable App Execution Aliases in Windows Settings",
				Params: map[string]string{
					"recommendation": "move %LOCALAPPDATA%\\Microsoft\\WindowsApps to the end of User PATH",
				},
				Explanation: "Microsoft Store app stubs can intercept commands like 'node' or 'python' and pop up the Windows Store instead of running your installed runtime.",
			},
			Risk:   model.RiskMedium,
			Verify: "where node",
		})
	}

	return findings
}
