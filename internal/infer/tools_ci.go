package infer

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ciNodeVersionRegex = regexp.MustCompile(`(?i)node-version:\s*['"]?([0-9.x]+)`)
	ciJavaVersionRegex = regexp.MustCompile(`(?i)java-version:\s*['"]?([0-9.x]+)`)
)

// inferToolVersions parses .tool-versions (asdf / mise).
func inferToolVersions(dir string, expected *ExpectedEnv) {
	if data, err := readUntrustedManifest(dir, ".tool-versions"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				tool := strings.ToLower(parts[0])
				version := parts[1]
				switch tool {
				case "nodejs", "node":
					if expected.NodeRange == "" {
						expected.NodeRange = version
						expected.NodeSource = ".tool-versions"
					}
				case "java":
					if expected.JavaRange == "" {
						// e.g. "openjdk-17.0.2" -> "17.0.2"
						if idx := strings.LastIndex(version, "-"); idx != -1 {
							version = version[idx+1:]
						}
						expected.JavaRange = version
						expected.JavaSource = ".tool-versions"
					}
				case "gradle":
					if expected.GradleVersion == "" {
						expected.GradleVersion = version
						expected.GradleSource = ".tool-versions"
					}
				}
			}
		}
	}
}

// inferCI inspects GitHub Actions workflow files for node and java runtime declarations.
func inferCI(dir string, expected *ExpectedEnv) {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			relPath := filepath.Join(".github", "workflows", name)
			if data, err := readUntrustedManifest(dir, relPath); err == nil {
				str := string(data)
				if expected.NodeRange == "" {
					if m := ciNodeVersionRegex.FindStringSubmatch(str); len(m) >= 2 {
						expected.NodeRange = m[1]
						expected.NodeSource = relPath + " (node-version)"
					}
				}
				if expected.JavaRange == "" {
					if m := ciJavaVersionRegex.FindStringSubmatch(str); len(m) >= 2 {
						expected.JavaRange = m[1]
						expected.JavaSource = relPath + " (java-version)"
					}
				}
			}
		}
	}
}
