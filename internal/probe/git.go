package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

var gitVersionRegex = regexp.MustCompile(`git version (\d+\.\d+\.\d+)`)

// ProbeGit safely checks for the presence and version of git on the system.
func ProbeGit(ctx context.Context, execer Execer) ToolResult {
	res := ToolResult{Name: "git"}

	path, err := execer.LookPath("git")
	if err != nil {
		res.Found = false
		res.Error = "git executable was not found on PATH"
		return res
	}
	res.Path = security.RedactPath(path)

	stdout, stderr, err := execer.Run(ctx, "git", "--version")
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
	matches := gitVersionRegex.FindStringSubmatch(stdout)
	if len(matches) >= 2 {
		res.Found = true
		res.Version = matches[1]
	} else {
		res.Found = true
		res.Version = strings.TrimPrefix(strings.TrimSpace(stdout), "git version ")
	}

	return res
}
