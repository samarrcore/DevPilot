package probe

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Execer abstracts command execution for testability and safety.
type Execer interface {
	Run(ctx context.Context, command string, args ...string) (stdout string, stderr string, err error)
	LookPath(file string) (string, error)
}

// AllowedCommands maps an approved binary to its permitted arguments.
// Any command invocation outside this allowlist is rejected immediately.
var AllowedCommands = map[string][]string{
	"node":   {"-v", "--version"},
	"npm":    {"-v", "--version"},
	"java":   {"-version", "--version"},
	"adb":    {"version"},
	"git":    {"--version"},
	"gradle": {"-v", "--version"},
}

const (
	// MaxOutputBytes limits captured output to 64KB per probe (Security Rule 2).
	MaxOutputBytes = 64 * 1024
)

// limitedBuffer captures up to max bytes, discarding excess to avoid memory exhaustion.
type limitedBuffer struct {
	buf   strings.Builder
	limit int
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		return len(p), nil // Discard excess cleanly
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}

// OSExecer runs commands against the local OS with strict timeouts, allowlisting, and neutral working dir.
type OSExecer struct {
	Timeout time.Duration
}

// NewOSExecer initializes an OSExecer with a default 3-second timeout.
func NewOSExecer() *OSExecer {
	return &OSExecer{Timeout: 3 * time.Second}
}

func (e *OSExecer) Run(ctx context.Context, command string, args ...string) (string, string, error) {
	// Security check: Binary must be in allowlist
	allowedArgs, ok := AllowedCommands[command]
	if !ok {
		return "", "", fmt.Errorf("security violation: execution of %q is not in the probe allowlist", command)
	}

	// Security check: Arguments must match allowlist
	argJoined := strings.Join(args, " ")
	matched := false
	for _, allowed := range allowedArgs {
		if argJoined == allowed {
			matched = true
			break
		}
	}
	if !matched {
		return "", "", fmt.Errorf("security violation: arguments %q for command %q are not allowed", argJoined, command)
	}

	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, command, args...)
	// Security Rule 5: Run probes from neutral directory, never the project directory
	cmd.Dir = os.TempDir()

	stdoutBuf := newLimitedBuffer(MaxOutputBytes)
	stderrBuf := newLimitedBuffer(MaxOutputBytes)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	err := cmd.Run()
	return strings.TrimSpace(stdoutBuf.String()), strings.TrimSpace(stderrBuf.String()), err
}

func (e *OSExecer) LookPath(file string) (string, error) {
	// Security Rule 5: Never resolve probe executable from current/project directory
	path, err := exec.LookPath(file)
	if err != nil {
		return "", err
	}
	// Check for Go's ErrDot or relative path
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("security violation: executable %q resolved to relative path %q", file, path)
	}
	return path, nil
}
