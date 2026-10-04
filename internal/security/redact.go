package security

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	tokenRegex    = regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9_\-\.]{20,}|ghp_[a-zA-Z0-9]{30,}|gho_[a-zA-Z0-9]{30,}|xox[baprs]-[0-9a-zA-Z]{10,})`)
	secretEnvRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*\S+`)
)

// RedactPath replaces user profile directories and usernames in file paths
// with generic placeholders (~, <user>) to prevent leaking PII.
func RedactPath(path string) string {
	if path == "" {
		return ""
	}

	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" && strings.HasPrefix(strings.ToLower(path), strings.ToLower(userProfile)) {
		rel := path[len(userProfile):]
		return filepath.Join("~", rel)
	}

	home := os.Getenv("HOME")
	if home != "" && strings.HasPrefix(path, home) {
		rel := path[len(home):]
		return filepath.Join("~", rel)
	}

	// Case-insensitive Windows username path redaction
	username := os.Getenv("USERNAME")
	if username != "" {
		reUser := regexp.MustCompile(`(?i)([\\/]Users[\\/])` + regexp.QuoteMeta(username) + `([\\/]|$)`)
		path = reUser.ReplaceAllString(path, "${1}<user>${2}")
	}

	return path
}

// RedactString sanitizes arbitrary string output from probes, error logs, and JSON.
func RedactString(s string) string {
	if s == "" {
		return ""
	}

	// 1. Redact user profile directory
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		reProf := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(userProfile))
		s = reProf.ReplaceAllString(s, "~")
	}

	// 2. Redact username if in standard user path
	username := os.Getenv("USERNAME")
	if username != "" {
		reUser := regexp.MustCompile(`(?i)([\\/]Users[\\/])` + regexp.QuoteMeta(username) + `([\\/]|$)`)
		s = reUser.ReplaceAllString(s, "${1}<user>${2}")
	}

	// 3. Redact hostname / computer name
	compName := os.Getenv("COMPUTERNAME")
	if compName != "" && len(compName) > 2 {
		reComp := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(compName))
		s = reComp.ReplaceAllString(s, "<host>")
	}
	if host, err := os.Hostname(); err == nil && len(host) > 2 {
		reHost := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(host))
		s = reHost.ReplaceAllString(s, "<host>")
	}

	// 4. Redact tokens and secret patterns
	s = tokenRegex.ReplaceAllString(s, "<redacted-token>")
	s = secretEnvRegex.ReplaceAllString(s, "${1}: <redacted-secret>")

	return s
}
