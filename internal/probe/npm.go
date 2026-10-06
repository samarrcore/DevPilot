package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

var npmVersionRegex = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

// ProbeNpm safely checks for the presence and version of npm on the system.
func ProbeNpm(ctx context.Context, execer Execer) ToolResult {
	res := ToolResult{Name: "npm"}

	path, err := execer.LookPath("npm")
	if err != nil {
		res.Found = false
		res.Error = "npm executable was not found on PATH"
		return res
	}
	res.Path = security.RedactPath(path)

	stdout, stderr, err := execer.Run(ctx, "npm", "-v")
	if err != nil {
		res.Found = false
		errMsg := err.Error()
		if stderr != "" {
			errMsg = stderr
		}
		res.Error = security.RedactString(errMsg)
		return res
	}

	res.RawOutput = stdout
	matches := npmVersionRegex.FindStringSubmatch(stdout)
	if len(matches) >= 2 {
		res.Found = true
		res.Version = matches[1]
	} else {
		res.Found = true
		res.Version = strings.TrimSpace(stdout)
	}

	return res
}
