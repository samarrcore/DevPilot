package infer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInferPackageJSON(t *testing.T) {
	tempDir := t.TempDir()
	content := `{
		"name": "sample-project",
		"engines": {
			"node": ">=20.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.NodeRange != ">=20.0.0" {
		t.Fatalf("expected node range >=20.0.0, got %s", env.NodeRange)
	}
	if env.NodeSource != "package.json (engines.node)" {
		t.Fatalf("expected source package.json, got %s", env.NodeSource)
	}
}

func TestInferNVMRC(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, ".nvmrc"), []byte("20.11.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.NodeRange != "20.11.0" {
		t.Fatalf("expected 20.11.0, got %s", env.NodeRange)
	}
}

func TestReadUntrustedManifest_PathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	_, err := readUntrustedManifest(tempDir, "../../../etc/passwd")
	if err == nil {
		t.Fatalf("expected path traversal error, got nil")
	}
}

func TestReadUntrustedManifest_Oversized(t *testing.T) {
	tempDir := t.TempDir()
	largeFile := filepath.Join(tempDir, "package.json")
	// Create file slightly larger than MaxManifestBytes (1MB + 10 bytes)
	data := make([]byte, MaxManifestBytes+10)
	if err := os.WriteFile(largeFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := readUntrustedManifest(tempDir, "package.json")
	if err == nil {
		t.Fatalf("expected oversized manifest error, got nil")
	}
}
