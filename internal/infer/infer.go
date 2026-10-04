package infer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExpectedEnv holds expectations inferred deterministically from repository manifests.
type ExpectedEnv struct {
	NodeRange  string // e.g. ">=18.0.0", "^20.0.0", "20.11.0"
	NodeSource string // file where requirement was detected: "package.json", ".nvmrc", ".node-version"
}

type packageJSON struct {
	Engines struct {
		Node string `json:"node"`
	} `json:"engines"`
}

const (
	// MaxManifestBytes limits repo manifest reads to 1MB (Security Rule 4).
	MaxManifestBytes = 1024 * 1024
)

// readUntrustedManifest safely reads a manifest from rootDir, enforcing size limits,
// preventing path traversal, and disallowing symlinks escaping rootDir.
func readUntrustedManifest(rootDir, filename string) ([]byte, error) {
	cleanRoot := filepath.Clean(rootDir)
	targetPath := filepath.Clean(filepath.Join(cleanRoot, filename))

	// Path traversal check
	rel, err := filepath.Rel(cleanRoot, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("security violation: path traversal detected: %s", filename)
	}

	// Symlink check: resolve and verify destination remains inside rootDir
	realTarget, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return nil, err
	}
	realRel, err := filepath.Rel(cleanRoot, realTarget)
	if err != nil || strings.HasPrefix(realRel, "..") {
		return nil, fmt.Errorf("security violation: symlink %q escapes project directory", filename)
	}

	info, err := os.Stat(realTarget)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("security violation: manifest %q exceeds size limit (%d bytes)", filename, info.Size())
	}

	f, err := os.Open(realTarget)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(io.LimitReader(f, MaxManifestBytes))
}

// Infer inspects project files in the specified directory to extract environment requirements.
func Infer(dir string) (*ExpectedEnv, error) {
	expected := &ExpectedEnv{}

	// 1. Check package.json
	if data, err := readUntrustedManifest(dir, "package.json"); err == nil {
		var pkg packageJSON
		if err := json.Unmarshal(data, &pkg); err == nil && pkg.Engines.Node != "" {
			expected.NodeRange = strings.TrimSpace(pkg.Engines.Node)
			expected.NodeSource = "package.json (engines.node)"
			return expected, nil
		}
	}

	// 2. Check .nvmrc
	if data, err := readUntrustedManifest(dir, ".nvmrc"); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "" {
			expected.NodeRange = val
			expected.NodeSource = ".nvmrc"
			return expected, nil
		}
	}

	// 3. Check .node-version
	if data, err := readUntrustedManifest(dir, ".node-version"); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "" {
			expected.NodeRange = val
			expected.NodeSource = ".node-version"
			return expected, nil
		}
	}

	return expected, nil
}
