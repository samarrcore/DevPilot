package rules

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"devpilot/internal/model"
	"devpilot/internal/security"
	"gopkg.in/yaml.v3"
)

//go:embed packs/*.yaml
var embeddedPacksFS embed.FS

const (
	// MaxRuleFileBytes limits custom rule files to 512KB (Security Rule 4).
	MaxRuleFileBytes = 512 * 1024
	// MaxRuleFiles limits total number of custom rule files parsed to prevent DoS.
	MaxRuleFiles = 50
)

// RulePack represents a declarative pack containing compatibility matrices and/or declarative rules.
type RulePack struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Version     string            `yaml:"version,omitempty"`
	Matrices    []Matrix          `yaml:"matrices,omitempty"`
	Rules       []DeclarativeRule `yaml:"rules,omitempty"`
}

// Matrix defines a compatibility matrix across toolchains and runtimes.
type Matrix struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description,omitempty"`
	Target      string        `yaml:"target,omitempty"`
	Entries     []MatrixEntry `yaml:"entries"`
}

// MatrixEntry defines compatible versions for Expo, React Native, Node, JDK, Gradle, etc.
type MatrixEntry struct {
	ExpoSDK     string `yaml:"expo_sdk,omitempty"`
	ReactNative string `yaml:"react_native,omitempty"`
	Node        string `yaml:"node,omitempty"`
	JDK         string `yaml:"jdk,omitempty"`
	Gradle      string `yaml:"gradle,omitempty"`
	CompileSDK  string `yaml:"compile_sdk,omitempty"`
	TargetSDK   string `yaml:"target_sdk,omitempty"`
	MinSDK      string `yaml:"min_sdk,omitempty"`
}

// DeclarativeRule defines a declarative rule check.
type DeclarativeRule struct {
	ID        string         `yaml:"id"`
	Title     string         `yaml:"title"`
	Category  string         `yaml:"category"`
	Severity  string         `yaml:"severity"`
	ElevateIf string         `yaml:"elevate_if,omitempty"`
	Condition RuleCondition  `yaml:"condition"`
	Evidence  []RuleEvidence `yaml:"evidence,omitempty"`
	Fix       *RuleFix       `yaml:"fix,omitempty"`
	Risk      string         `yaml:"risk,omitempty"`
	Verify    string         `yaml:"verify,omitempty"`
}

// RuleCondition specifies the condition that triggers the rule finding.
type RuleCondition struct {
	Target     string `yaml:"target"`                // "node", "java", "android_sdk", "adb", "git", "npm", "env"
	State      string `yaml:"state,omitempty"`       // "missing", "ok", "version_mismatch", "directory_missing", "platform_tools_missing", "set", "unset"
	Name       string `yaml:"name,omitempty"`        // for target "env"
	MinVersion string `yaml:"min_version,omitempty"` // e.g. "20.0.0"
	Range      string `yaml:"range,omitempty"`       // e.g. ">=20.0.0"
}

// RuleEvidence defines deterministic evidence template.
type RuleEvidence struct {
	Key    string `yaml:"key"`
	Value  string `yaml:"value"`
	Source string `yaml:"source"`
}

// RuleFix defines an actionable, typed resolution for a finding in YAML.
type RuleFix struct {
	ActionType  string            `yaml:"action_type"`
	Title       string            `yaml:"title"`
	Params      map[string]string `yaml:"params,omitempty"`
	Explanation string            `yaml:"explanation"`
}

// LoadEmbeddedPacks loads and parses all built-in rule packs embedded in the binary.
func LoadEmbeddedPacks() ([]RulePack, error) {
	entries, err := embeddedPacksFS.ReadDir("packs")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded packs directory: %w", err)
	}

	var packs []RulePack
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := embeddedPacksFS.ReadFile("packs/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded pack %s: %w", entry.Name(), err)
		}
		var pack RulePack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			return nil, fmt.Errorf("failed to parse embedded pack %s: %w", entry.Name(), err)
		}
		packs = append(packs, pack)
	}

	return packs, nil
}

// LoadProjectRules safely reads and parses custom YAML rules from .agents/rules/ in the project directory.
// Follows Security Rule 4 (untrusted manifests), Rule 6 (typed fixes), and Rule 8 (redaction).
func LoadProjectRules(targetDir string) ([]RulePack, error) {
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target directory: %w", err)
	}
	cleanTarget := filepath.Clean(absTarget)
	rulesDir := filepath.Join(cleanTarget, ".agents", "rules")

	// 1. Path traversal check
	rel, err := filepath.Rel(cleanTarget, rulesDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("security violation: path traversal detected: %s", rulesDir)
	}

	// 2. Check if directory exists
	info, err := os.Stat(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No custom rules directory, expected for standard repos
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf(".agents/rules is not a directory")
	}

	// 3. Symlink escape check on the directory itself
	realDir, err := filepath.EvalSymlinks(rulesDir)
	if err != nil {
		return nil, err
	}
	realRel, err := filepath.Rel(cleanTarget, realDir)
	if err != nil || strings.HasPrefix(realRel, "..") {
		return nil, fmt.Errorf("security violation: .agents/rules symlink escapes project directory")
	}

	entries, err := os.ReadDir(realDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read .agents/rules directory: %w", err)
	}

	var packs []RulePack
	count := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		count++
		if count > MaxRuleFiles {
			return packs, fmt.Errorf("exceeded maximum custom rule files limit (%d)", MaxRuleFiles)
		}

		filePath := filepath.Join(realDir, name)

		// Symlink escape check on the file
		realFile, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			continue
		}
		realFileRel, err := filepath.Rel(cleanTarget, realFile)
		if err != nil || strings.HasPrefix(realFileRel, "..") {
			continue // Skip symlink escaping project root
		}

		fileInfo, err := os.Stat(realFile)
		if err != nil || fileInfo.Size() > MaxRuleFileBytes {
			continue // Skip oversized or inaccessible files
		}

		f, err := os.Open(realFile)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(f, MaxRuleFileBytes))
		f.Close()
		if err != nil {
			continue
		}

		var pack RulePack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			// Skip or discard unparseable custom files
			continue
		}

		// Sanitize untrusted pack rules
		pack = sanitizeRulePack(pack)
		packs = append(packs, pack)
	}

	return packs, nil
}

// sanitizeRulePack enforces Security Rules 4 (matrices), 6 (typed fixes), and 8 (redaction) on untrusted rule packs.
func sanitizeRulePack(pack RulePack) RulePack {
	// Untrusted custom rule packs must not tamper with core compatibility matrices.
	pack.Matrices = nil
	pack.Name = security.RedactString(pack.Name)
	pack.Description = security.RedactString(pack.Description)

	var sanitizedRules []DeclarativeRule
	for _, r := range pack.Rules {
		r.ID = security.RedactString(r.ID)
		r.Title = security.RedactString(r.Title)

		// Sanitize/validate Verify: if it contains shell chaining or redirection characters, clear it
		if strings.ContainsAny(r.Verify, "&;|><$`"+"`") {
			r.Verify = ""
		} else {
			r.Verify = security.RedactString(r.Verify)
		}

		// Sanitize Fix: strictly enforce allowlisted typed actions (Security Rule 6)
		if r.Fix != nil {
			switch r.Fix.ActionType {
			case string(model.ActionInstallToolVersion),
				string(model.ActionSetEnvVar),
				string(model.ActionEditFile):
				// Valid allowlisted action
				if r.Fix.ActionType == string(model.ActionEditFile) {
					filePath, hasFile := r.Fix.Params["file"]
					cleanFile := filepath.Clean(filePath)
					if !hasFile || cleanFile == "." || cleanFile == "" || filepath.IsAbs(cleanFile) || strings.HasPrefix(cleanFile, "..") || filepath.VolumeName(cleanFile) != "" || strings.HasPrefix(cleanFile, "/") || strings.HasPrefix(cleanFile, "\\") {
						r.Fix = nil
					} else {
						if r.Fix.Params == nil {
							r.Fix.Params = make(map[string]string)
						}
						r.Fix.Params["file"] = cleanFile
					}
				}

				if r.Fix != nil {
					r.Fix.Title = security.RedactString(r.Fix.Title)
					r.Fix.Explanation = security.RedactString(r.Fix.Explanation)
					if r.Fix.Params != nil {
						for k, v := range r.Fix.Params {
							r.Fix.Params[k] = security.RedactString(v)
						}
					}
				}
			default:
				// Disallow arbitrary actions (Security Rule 6)
				r.Fix = nil
			}
		}

		sanitizedRules = append(sanitizedRules, r)
	}
	pack.Rules = sanitizedRules
	return pack
}
