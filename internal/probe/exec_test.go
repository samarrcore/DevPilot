package probe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestOSExecer_AllowlistRejection(t *testing.T) {
	execer := NewOSExecer()
	ctx := context.Background()

	// 1. Rejected binary
	_, _, err := execer.Run(ctx, "powershell", "-Command", "Get-Process")
	if err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Fatalf("expected security violation for unallowlisted binary, got: %v", err)
	}

	// 2. Rejected arguments for an allowlisted binary
	_, _, err = execer.Run(ctx, "node", "-e", "console.log('pwned')")
	if err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Fatalf("expected security violation for unallowed arguments, got: %v", err)
	}
}

func TestOSExecer_AllowedExecution(t *testing.T) {
	execer := NewOSExecer()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stdout, stderr, err := execer.Run(ctx, "node", "-v")
	if err != nil {
		t.Skipf("node not available on host system: %v (stderr: %s)", err, stderr)
	}
	if !strings.HasPrefix(stdout, "v") {
		t.Errorf("expected node -v output to start with 'v', got: %s", stdout)
	}
}
