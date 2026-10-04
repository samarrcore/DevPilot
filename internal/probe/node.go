package probe

import (
	"context"
	"regexp"
	"strings"

	"devpilot/internal/security"
)

// NodeResult contains probed information about the local Node runtime.
type NodeResult struct {
	Found     bool
	Version   string // e.g. "20.11.0" (without leading 'v')
	RawOutput string // e.g. "v20.11.0"
	Path      string // Redacted path to binary
	Error     string // Redacted error message if failed
}

var nodeVersionRegex = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

// ProbeNode safely checks for the presence and version of node.js on the system.
func ProbeNode(ctx context.Context, execer Execer) NodeResult {
	result := NodeResult{}

	// Locate binary path
	path, err := execer.LookPath("node")
	if err != nil {
		result.Found = false
		result.Error = "Node.js executable was not found on PATH"
		return result
	}
	result.Path = security.RedactPath(path)

	// Run version probe
	stdout, stderr, err := execer.Run(ctx, "node", "-v")
	if err != nil {
		result.Found = false
		errMsg := err.Error()
		if stderr != "" {
			errMsg = stderr
		}
		result.Error = security.RedactString(errMsg)
		return result
	}

	result.RawOutput = stdout
	matches := nodeVersionRegex.FindStringSubmatch(stdout)
	if len(matches) >= 2 {
		result.Found = true
		result.Version = matches[1]
	} else {
		// Found binary, but output was not recognized
		result.Found = true
		result.Version = strings.TrimPrefix(stdout, "v")
	}

	return result
}
