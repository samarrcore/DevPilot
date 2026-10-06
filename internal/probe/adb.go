package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

var adbVersionRegex = regexp.MustCompile(`(?i)Android Debug Bridge version (\d+\.\d+\.\d+)`)

// ProbeAdb safely checks for the presence and version of Android Debug Bridge (ADB).
func ProbeAdb(ctx context.Context, execer Execer) ToolResult {
	res := ToolResult{Name: "adb"}

	path, err := execer.LookPath("adb")
	if err != nil {
		res.Found = false
		res.Error = "adb executable was not found on PATH"
		return res
	}
	res.Path = security.RedactPath(path)

	stdout, stderr, err := execer.Run(ctx, "adb", "version")
	if err != nil {
		res.Found = false
		errMsg := err.Error()
		if stderr != "" {
			errMsg = stderr
		}
		res.Error = security.RedactString(errMsg)
		return res
	}

	combined := strings.TrimSpace(stdout + "\n" + stderr)
	res.RawOutput = combined

	matches := adbVersionRegex.FindStringSubmatch(combined)
	if len(matches) >= 2 {
		res.Found = true
		res.Version = matches[1]
	} else {
		res.Found = true
		res.Version = "installed"
	}

	return res
}
