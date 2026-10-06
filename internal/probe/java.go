package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

var javaVersionRegex = regexp.MustCompile(`(?:version|openjdk)\s+"?(\d+(?:\.\d+)*)(?:_(\d+))?`)

// ProbeJava safely checks for the presence and version of Java (JDK/JRE) on the system.
// Note: 'java -version' canonically prints to STDERR rather than STDOUT.
func ProbeJava(ctx context.Context, execer Execer) ToolResult {
	res := ToolResult{Name: "java"}

	path, err := execer.LookPath("java")
	if err != nil {
		res.Found = false
		res.Error = "java executable was not found on PATH"
		return res
	}
	res.Path = security.RedactPath(path)

	stdout, stderr, err := execer.Run(ctx, "java", "-version")
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

	matches := javaVersionRegex.FindStringSubmatch(combined)
	if len(matches) >= 2 {
		rawVer := matches[1]
		// Normalize 1.8.x -> 8
		if strings.HasPrefix(rawVer, "1.8") {
			res.Version = "8"
		} else {
			res.Version = rawVer
		}
		res.Found = true
	} else {
		res.Found = true
		res.Version = "unknown"
	}

	return res
}
