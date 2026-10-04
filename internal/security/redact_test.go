package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactPath(t *testing.T) {
	origProfile := os.Getenv("USERPROFILE")
	defer os.Setenv("USERPROFILE", origProfile)

	os.Setenv("USERPROFILE", `C:\Users\testpilot`)
	input := `C:\Users\testpilot\AppData\Local\Programs\node.exe`
	redacted := RedactPath(input)

	if strings.Contains(redacted, "testpilot") {
		t.Fatalf("RedactPath failed to hide username, got: %s", redacted)
	}
	expected := filepath.Join("~", `AppData\Local\Programs\node.exe`)
	if redacted != expected {
		t.Fatalf("expected %s, got %s", expected, redacted)
	}
}

func TestRedactPath_CaseInsensitive(t *testing.T) {
	origUser := os.Getenv("USERNAME")
	defer os.Setenv("USERNAME", origUser)

	os.Setenv("USERNAME", "AlexSmith")
	// Input has different casing (alexsmith vs AlexSmith)
	input := `C:\Users\alexsmith\AppData\Local\node.exe`
	redacted := RedactPath(input)

	if strings.Contains(strings.ToLower(redacted), "alexsmith") {
		t.Fatalf("RedactPath failed to redact case-insensitive username, got: %s", redacted)
	}
	if !strings.Contains(redacted, `C:\Users\<user>\`) {
		t.Fatalf("expected C:\\Users\\<user>\\, got: %s", redacted)
	}
}

func TestRedactString(t *testing.T) {
	origUser := os.Getenv("USERNAME")
	defer os.Setenv("USERNAME", origUser)

	os.Setenv("USERNAME", "secretdev")
	msg := "failed to open C:\\Users\\secretdev\\.npmrc"
	redacted := RedactString(msg)

	if strings.Contains(redacted, "secretdev") {
		t.Fatalf("RedactString leaked username: %s", redacted)
	}
	if !strings.Contains(redacted, "<user>") {
		t.Fatalf("RedactString did not replace username: %s", redacted)
	}
}

func TestRedactString_TokensAndSecrets(t *testing.T) {
	msg := "Connecting with ghp_1234567890abcdef1234567890abcdef and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	redacted := RedactString(msg)

	if strings.Contains(redacted, "ghp_") {
		t.Fatalf("RedactString leaked GitHub token: %s", redacted)
	}
	if strings.Contains(redacted, "eyJhbGci") {
		t.Fatalf("RedactString leaked Bearer token: %s", redacted)
	}
	if !strings.Contains(redacted, "<redacted-token>") {
		t.Fatalf("RedactString missing <redacted-token> placeholder: %s", redacted)
	}
}
