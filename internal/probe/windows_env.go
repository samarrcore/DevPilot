//go:build windows

package probe

import (
	"os"
	"path/filepath"
	"strings"

	"devpilot/internal/security"
	"golang.org/x/sys/windows/registry"
)

// WindowsEnvResult encapsulates Windows-specific environment health facts.
type WindowsEnvResult struct {
	MachinePathSet          bool     `json:"machine_path_set"`
	UserPathSet             bool     `json:"user_path_set"`
	MachinePathEntries      int      `json:"machine_path_entries"`
	UserPathEntries         int      `json:"user_path_entries"`
	WindowsAppsInPath       bool     `json:"windows_apps_in_path"`
	WindowsAppsPrecedence   bool     `json:"windows_apps_precedence"` // true if WindowsApps appears before dev runtimes
	PowerShellPolicyMachine string   `json:"powershell_policy_machine"`
	PowerShellPolicyUser    string   `json:"powershell_policy_user"`
	EffectivePSPolicy       string   `json:"effective_ps_policy"`
	JavaHomeSet             bool     `json:"java_home_set"`
	JavaHomeValid           bool     `json:"java_home_valid"`
	JavaHomeRedacted        string   `json:"java_home_redacted"`
}

// ReadWindowsEnvironment inspects Windows registry and system environment health safely.
func ReadWindowsEnvironment() WindowsEnvResult {
	res := WindowsEnvResult{}

	// 1. Read Machine PATH from registry
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `System\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetStringValue("Path"); err == nil && val != "" {
			res.MachinePathSet = true
			res.MachinePathEntries = len(strings.Split(val, ";"))
		}
		k.Close()
	}

	// 2. Read User PATH from registry
	var userPathEntries []string
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetStringValue("Path"); err == nil && val != "" {
			res.UserPathSet = true
			userPathEntries = strings.Split(val, ";")
			res.UserPathEntries = len(userPathEntries)
		}
		k.Close()
	}

	// 3. Inspect WindowsApps (App Execution Aliases) in effective PATH
	effectivePath := os.Getenv("PATH")
	pathParts := strings.Split(effectivePath, string(os.PathListSeparator))
	windowsAppsIdx := -1
	firstDevToolIdx := -1

	for idx, p := range pathParts {
		lowerP := strings.ToLower(p)
		if strings.Contains(lowerP, `microsoft\windowsapps`) {
			res.WindowsAppsInPath = true
			if windowsAppsIdx == -1 {
				windowsAppsIdx = idx
			}
		}
		if (strings.Contains(lowerP, "nodejs") || strings.Contains(lowerP, "java") || strings.Contains(lowerP, "git")) && firstDevToolIdx == -1 {
			firstDevToolIdx = idx
		}
	}

	if windowsAppsIdx != -1 && firstDevToolIdx != -1 && windowsAppsIdx < firstDevToolIdx {
		res.WindowsAppsPrecedence = true
	}

	// 4. Read PowerShell Execution Policy from Registry
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetStringValue("ExecutionPolicy"); err == nil {
			res.PowerShellPolicyMachine = val
		}
		k.Close()
	}

	if k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetStringValue("ExecutionPolicy"); err == nil {
			res.PowerShellPolicyUser = val
		}
		k.Close()
	}

	// Determine effective policy (User overrides Machine if set, default is Restricted)
	res.EffectivePSPolicy = "Restricted"
	if res.PowerShellPolicyMachine != "" {
		res.EffectivePSPolicy = res.PowerShellPolicyMachine
	}
	if res.PowerShellPolicyUser != "" {
		res.EffectivePSPolicy = res.PowerShellPolicyUser
	}

	// 5. Inspect JAVA_HOME without leaking raw value
	jh := os.Getenv("JAVA_HOME")
	if jh != "" {
		res.JavaHomeSet = true
		res.JavaHomeRedacted = security.RedactPath(jh)
		// Validate that bin/java.exe exists inside JAVA_HOME
		javaExe := filepath.Join(jh, "bin", "java.exe")
		if info, err := os.Stat(javaExe); err == nil && !info.IsDir() {
			res.JavaHomeValid = true
		}
	}

	return res
}
