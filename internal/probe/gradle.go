package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

var gradleVersionRegex = regexp.MustCompile(`(?i)Gradle\s+(\d+\.\d+(?:\.\d+)?)`)

// ProbeGradle safely checks for the presence and version of system Gradle.
func ProbeGradle(ctx context.Context, execer Execer) ToolResult {
	res := ToolResult{Name: "gradle"}

	path, err := execer.LookPath("gradle")
	if err != nil {
		res.Found = false
		res.Error = "gradle executable was not found on PATH"
		return res
	}
	res.Path = security.RedactPath(path)

	stdout, stderr, err := execer.Run(ctx, "gradle", "-v")
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

	matches := gradleVersionRegex.FindStringSubmatch(combined)
	if len(matches) >= 2 {
		res.Found = true
		res.Version = matches[1]
	} else {
		res.Found = true
		res.Version = "unknown"
	}

	return res
}
