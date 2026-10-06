//go:build !windows

package probe

// WindowsEnvResult encapsulates Windows-specific environment health facts.
type WindowsEnvResult struct {
	MachinePathSet          bool     `json:"machine_path_set"`
	UserPathSet             bool     `json:"user_path_set"`
	MachinePathEntries      int      `json:"machine_path_entries"`
	UserPathEntries         int      `json:"user_path_entries"`
	WindowsAppsInPath       bool     `json:"windows_apps_in_path"`
	WindowsAppsPrecedence   bool     `json:"windows_apps_precedence"`
	PowerShellPolicyMachine string   `json:"powershell_policy_machine"`
	PowerShellPolicyUser    string   `json:"powershell_policy_user"`
	EffectivePSPolicy       string   `json:"effective_ps_policy"`
	JavaHomeSet             bool     `json:"java_home_set"`
	JavaHomeValid           bool     `json:"java_home_valid"`
	JavaHomeRedacted        string   `json:"java_home_redacted"`
}

// ReadWindowsEnvironment is a no-op fallback on non-Windows platforms.
func ReadWindowsEnvironment() WindowsEnvResult {
	return WindowsEnvResult{}
}
