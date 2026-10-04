package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a semver trio (Major.Minor.Patch).
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses a version string like "20.11.0" or "v18.0.0".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) == 0 || parts[0] == "" {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version %q", parts[0])
	}

	minor := 0
	if len(parts) > 1 && parts[1] != "x" && parts[1] != "*" {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return Version{}, fmt.Errorf("invalid minor version %q", parts[1])
		}
	}

	patch := 0
	if len(parts) > 2 && parts[2] != "x" && parts[2] != "*" {
		patchStr := strings.Split(parts[2], "-")[0] // strip prerelease
		patch, err = strconv.Atoi(patchStr)
		if err != nil {
			return Version{}, fmt.Errorf("invalid patch version %q", patchStr)
		}
	}

	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// ExtractVersion attempts to parse a Version from a string that may contain range prefixes (e.g. ">=20.0.0", "^18.19.0").
func ExtractVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ">=")
	s = strings.TrimPrefix(s, "<=")
	s = strings.TrimPrefix(s, ">")
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimPrefix(s, "~")
	s = strings.TrimSpace(s)
	// If compound range like "18.0.0 <22.0.0", take first clause
	fields := strings.Fields(s)
	if len(fields) > 0 {
		s = fields[0]
	}
	return ParseVersion(s)
}

// Compare returns -1 if v < other, 0 if v == other, 1 if v > other.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}
	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}
	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}
	return 0
}

// Satisfies checks whether a version satisfies a simple range expression:
// Supports: ">=X.Y.Z", ">X.Y.Z", "<=X.Y.Z", "<X.Y.Z", "^X.Y.Z", "~X.Y.Z", "X.Y.Z", "X.x"
func Satisfies(actualStr, rangeStr string) (bool, error) {
	actual, err := ParseVersion(actualStr)
	if err != nil {
		return false, err
	}

	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" || rangeStr == "*" {
		return true, nil
	}

	// Handle compound ranges like ">=18.0.0 <22.0.0" or ">=18.0.0"
	clauses := strings.Fields(rangeStr)
	for _, clause := range clauses {
		ok, err := satisfiesClause(actual, clause)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func satisfiesClause(actual Version, clause string) (bool, error) {
	if strings.HasPrefix(clause, ">=") {
		target, err := ParseVersion(strings.TrimPrefix(clause, ">="))
		if err != nil {
			return false, err
		}
		return actual.Compare(target) >= 0, nil
	}
	if strings.HasPrefix(clause, ">") {
		target, err := ParseVersion(strings.TrimPrefix(clause, ">"))
		if err != nil {
			return false, err
		}
		return actual.Compare(target) > 0, nil
	}
	if strings.HasPrefix(clause, "<=") {
		target, err := ParseVersion(strings.TrimPrefix(clause, "<="))
		if err != nil {
			return false, err
		}
		return actual.Compare(target) <= 0, nil
	}
	if strings.HasPrefix(clause, "<") {
		target, err := ParseVersion(strings.TrimPrefix(clause, "<"))
		if err != nil {
			return false, err
		}
		return actual.Compare(target) < 0, nil
	}
	if strings.HasPrefix(clause, "^") {
		target, err := ParseVersion(strings.TrimPrefix(clause, "^"))
		if err != nil {
			return false, err
		}
		if actual.Major != target.Major {
			return false, nil
		}
		return actual.Compare(target) >= 0, nil
	}
	if strings.HasPrefix(clause, "~") {
		target, err := ParseVersion(strings.TrimPrefix(clause, "~"))
		if err != nil {
			return false, err
		}
		if actual.Major != target.Major || actual.Minor != target.Minor {
			return false, nil
		}
		return actual.Compare(target) >= 0, nil
	}

	// Exact or X.x pattern
	if strings.HasSuffix(clause, ".x") || strings.HasSuffix(clause, ".*") {
		prefix := strings.TrimSuffix(strings.TrimSuffix(clause, ".x"), ".*")
		majorOnly, err := strconv.Atoi(prefix)
		if err == nil {
			return actual.Major == majorOnly, nil
		}
	}

	target, err := ParseVersion(clause)
	if err != nil {
		return false, err
	}
	return actual.Compare(target) == 0, nil
}
