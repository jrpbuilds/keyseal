package repo

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateLogicalGlob checks that pattern is a usable logical-name glob.
// Empty, absolute, backslash, and ".." patterns are rejected.
//
// filepath.Clean collapses "**" into "*", so segment checks use the raw
// pattern rather than the cleaned form.
func ValidateLogicalGlob(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("logical glob must not be empty")
	}
	if strings.Contains(pattern, "\\") {
		return fmt.Errorf("logical glob %q must use forward slashes", pattern)
	}
	if filepath.IsAbs(pattern) || strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("logical glob %q must be relative", pattern)
	}

	for _, part := range strings.Split(pattern, "/") {
		if part == "" {
			return fmt.Errorf("logical glob %q contains an empty path segment", pattern)
		}
		if part == "." || part == ".." {
			return fmt.Errorf("logical glob %q must not traverse directories", pattern)
		}
	}

	clean := filepath.ToSlash(filepath.Clean(pattern))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("logical glob %q must not traverse directories", pattern)
	}
	return nil
}

// MatchLogicalGlob reports whether logical matches pattern.
//
// "*" matches one path segment and does not cross "/".
// "**" matches zero or more segments.
// A pattern with no glob characters is an exact match.
func MatchLogicalGlob(logical, pattern string) (bool, error) {
	if err := ValidateLogicalName(logical); err != nil {
		return false, err
	}
	if err := ValidateLogicalGlob(pattern); err != nil {
		return false, err
	}
	return matchGlobSegments(strings.Split(logical, "/"), strings.Split(pattern, "/")), nil
}

// MatchesAnyLogicalGlob reports whether logical matches any of the patterns.
func MatchesAnyLogicalGlob(logical string, patterns []string) (bool, error) {
	for _, pattern := range patterns {
		ok, err := MatchLogicalGlob(logical, pattern)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// matchGlobSegments implements segment-aware matching with "**" backtracking.
func matchGlobSegments(name, pattern []string) bool {
	ni, pi := 0, 0
	nameStar, patternStar := -1, -1

	for ni < len(name) {
		if pi < len(pattern) && pattern[pi] == "**" {
			nameStar = ni
			patternStar = pi
			pi++
			continue
		}
		if pi < len(pattern) && matchSegment(name[ni], pattern[pi]) {
			ni++
			pi++
			continue
		}
		if patternStar >= 0 {
			nameStar++
			ni = nameStar
			pi = patternStar + 1
			continue
		}
		return false
	}

	for pi < len(pattern) && pattern[pi] == "**" {
		pi++
	}
	return pi == len(pattern)
}

func matchSegment(name, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return name == pattern
	}
	// Segment-local shell-style matching without crossing "/".
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}
