package rules

import (
	"testing"
)

func TestSatisfies(t *testing.T) {
	tests := []struct {
		actual   string
		rangeStr string
		expected bool
	}{
		{"20.11.0", ">=18.0.0", true},
		{"16.14.0", ">=18.0.0", false},
		{"20.11.0", "^20.0.0", true},
		{"21.0.0", "^20.0.0", false},
		{"18.19.0", "18.x", true},
		{"20.11.0", "18.x", false},
		{"20.11.0", ">=18.0.0 <22.0.0", true},
		{"22.5.0", ">=18.0.0 <22.0.0", false},
		{"20.11.0", "", true},
		{"20.11.0", "*", true},
	}

	for _, tt := range tests {
		got, err := Satisfies(tt.actual, tt.rangeStr)
		if err != nil {
			t.Fatalf("unexpected error for (%s, %s): %v", tt.actual, tt.rangeStr, err)
		}
		if got != tt.expected {
			t.Errorf("Satisfies(%q, %q) = %v; want %v", tt.actual, tt.rangeStr, got, tt.expected)
		}
	}
}
