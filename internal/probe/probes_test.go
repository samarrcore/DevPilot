package probe

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

func TestProbeNpm_Found(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\Program Files\nodejs\npm.cmd`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			return "10.8.2", "", nil
		},
	}

	res := ProbeNpm(context.Background(), mock)
	if !res.Found || res.Version != "10.8.2" {
		t.Fatalf("expected npm 10.8.2, got: %+v", res)
	}
}

func TestProbeGit_Found(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\Program Files\Git\cmd\git.exe`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			return "git version 2.43.0.windows.1", "", nil
		},
	}

	res := ProbeGit(context.Background(), mock)
	if !res.Found || res.Version != "2.43.0" {
		t.Fatalf("expected git 2.43.0, got: %+v", res)
	}
}

func TestProbeJava_StderrVersion(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\Program Files\Java\jdk-21\bin\java.exe`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			// java -version prints to stderr
			return "", "openjdk version \"21.0.2\" 2024-01-16\nOpenJDK Runtime Environment", nil
		},
	}

	res := ProbeJava(context.Background(), mock)
	if !res.Found || res.Version != "21.0.2" {
		t.Fatalf("expected java 21.0.2, got: %+v", res)
	}
}

func TestProbeAdb_Found(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\Android\Sdk\platform-tools\adb.exe`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			return "Android Debug Bridge version 1.0.41", "", nil
		},
	}

	res := ProbeAdb(context.Background(), mock)
	if !res.Found || res.Version != "1.0.41" {
		t.Fatalf("expected adb 1.0.41, got: %+v", res)
	}
}

func TestProbeGradle_Found(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return `C:\gradle-8.5\bin\gradle.bat`, nil
		},
		runFn: func(ctx context.Context, command string, args ...string) (string, string, error) {
			return "------------------------------------------------------------\nGradle 8.5\n------------------------------------------------------------", "", nil
		},
	}

	res := ProbeGradle(context.Background(), mock)
	if !res.Found || res.Version != "8.5" {
		t.Fatalf("expected gradle 8.5, got: %+v", res)
	}
}

func TestProbeTools_NotFound(t *testing.T) {
	mock := &mockExecer{
		lookPathFn: func(file string) (string, error) {
			return "", errors.New("file not found")
		},
	}

	ctx := context.Background()
	if ProbeNpm(ctx, mock).Found {
		t.Errorf("expected npm not found")
	}
	if ProbeGit(ctx, mock).Found {
		t.Errorf("expected git not found")
	}
	if ProbeJava(ctx, mock).Found {
		t.Errorf("expected java not found")
	}
	if ProbeAdb(ctx, mock).Found {
		t.Errorf("expected adb not found")
	}
	if ProbeGradle(ctx, mock).Found {
		t.Errorf("expected gradle not found")
	}
}

func TestReadWindowsEnvironment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows registry test on non-windows")
	}

	res := ReadWindowsEnvironment()
	// On Windows, Machine PATH should typically be set
	if !res.MachinePathSet {
		t.Logf("Notice: MachinePathSet is false (may happen in restricted environments)")
	}
	if res.EffectivePSPolicy == "" {
		t.Errorf("expected effective PowerShell policy to be populated")
	}
}
