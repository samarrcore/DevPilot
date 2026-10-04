package probe

import (
	"context"
	"errors"
	"testing"
)

type mockExecer struct {
	lookPathFn func(file string) (string, error)
	runFn      func(ctx context.Context, command string, args ...string) (string, string, error)
}

func (m *mockExecer) LookPath(file string) (string, error) {
	if m.lookPathFn != nil {
		return m.lookPathFn(file)
	}
	return "", errors.New("not found")
}

func (m *mockExecer) Run(ctx context.Context, command string, args ...string) (string, string, error) {
	if m.runFn != nil {
		return m.runFn(ctx, command, args...)
	}
	return "", "", errors.New("command failed")
}

func TestProbeNode_Found(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\Program Files\nodejs\node.exe`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			return "v20.11.0", "", nil
		},
	}

	res := ProbeNode(context.Background(), mock)
	if !res.Found {
		t.Fatalf("expected node to be found, but it was not")
	}
	if res.Version != "20.11.0" {
		t.Fatalf("expected version 20.11.0, got %s", res.Version)
	}
}

func TestProbeNode_NotFound(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return "", errors.New("exec: \"node\": executable file not found in %PATH%")
		},
	}

	res := ProbeNode(context.Background(), mock)
	if res.Found {
		t.Fatalf("expected node not found, but it was marked found")
	}
	if res.Error == "" {
		t.Fatalf("expected error message when not found")
	}
}
