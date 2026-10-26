// Package versionreq compares a running Keyseal binary version against
// repository or bootstrap constraints without network access.
//
// These checks trust the binary's self-reported build stamp (typically set via
// linker flags). They are local policy gates for automation, not package
// provenance or remote attestation: a modified binary can forge its version
// string. Prefer release artifacts and package integrity controls when you
// need stronger trust.
package versionreq

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// gitDescribeSuffix matches the git-describe fragment after a release tag:
// -<digits>-g<hex> with an optional -dirty suffix. Real prereleases such as
// -rc.1 or -beta.1 must not match.
var gitDescribeSuffix = regexp.MustCompile(`^(\d+\.\d+\.\d+)-(\d+)-g([0-9a-fA-F]+)(-dirty)?$`)

// Normalize prepares a stamped Keyseal version string for semver comparison.
//
// It strips an optional leading "v", rewrites git-describe forms
// X.Y.Z-<n>-g<sha>[-dirty] to X.Y.Z+<n>.g<sha>[.dirty] (build metadata), and
// rejects empty, "dev", and other non-semver values. Real prereleases such as
// 1.2.0-rc.1 are left unchanged.
func Normalize(version string) (string, error) {
	raw := strings.TrimSpace(version)
	if raw == "" {
		return "", fmt.Errorf("Keyseal binary version is empty and cannot be compared")
	}
	if strings.EqualFold(raw, "dev") {
		return "", fmt.Errorf("Keyseal binary version %q is not a stamped semantic version", raw)
	}

	trimmed := strings.TrimPrefix(raw, "v")
	trimmed = strings.TrimPrefix(trimmed, "V")
	if trimmed == "" {
		return "", fmt.Errorf("Keyseal binary version %q is not a stamped semantic version", raw)
	}

	if match := gitDescribeSuffix.FindStringSubmatch(trimmed); match != nil {
		meta := match[2] + ".g" + match[3]
		if match[4] != "" {
			meta += ".dirty"
		}
		trimmed = match[1] + "+" + meta
	}

	if _, err := semver.StrictNewVersion(trimmed); err != nil {
		// StrictNewVersion rejects incomplete forms; NewVersion is more
		// tolerant of release stamps while still rejecting garbage.
		if _, err := semver.NewVersion(trimmed); err != nil {
			return "", fmt.Errorf("Keyseal binary version %q is not a stamped semantic version", raw)
		}
	}
	// Prefer the Strict form when possible so comparison uses a canonical string.
	if v, err := semver.StrictNewVersion(trimmed); err == nil {
		return v.String(), nil
	}
	v, err := semver.NewVersion(trimmed)
	if err != nil {
		return "", fmt.Errorf("Keyseal binary version %q is not a stamped semantic version", raw)
	}
	return v.String(), nil
}

// ParseConstraint parses a Masterminds-style semver constraint expression.
// Empty or whitespace-only expressions are rejected.
func ParseConstraint(expr string) (*semver.Constraints, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, fmt.Errorf("requirements.keyseal must not be empty")
	}
	c, err := semver.NewConstraint(trimmed)
	if err != nil {
		return nil, fmt.Errorf("requirements.keyseal %q is not a valid version constraint: %w", trimmed, err)
	}
	return c, nil
}

// Check reports whether running satisfies constraint.
//
// On failure the error names both the running Keyseal binary version (as
// displayed) and the required constraint. running is normalized before
// comparison; unstamped values such as "dev" fail closed.
func Check(running, constraint string) error {
	c, err := ParseConstraint(constraint)
	if err != nil {
		return err
	}
	normalized, err := Normalize(running)
	if err != nil {
		return fmt.Errorf("%w (required %s)", err, strings.TrimSpace(constraint))
	}
	v, err := semver.NewVersion(normalized)
	if err != nil {
		return fmt.Errorf("Keyseal binary version %q is not a stamped semantic version (required %s)", running, strings.TrimSpace(constraint))
	}
	if !c.Check(v) {
		return fmt.Errorf("Keyseal binary version %s does not satisfy requirements.keyseal %s", displayRunning(running), strings.TrimSpace(constraint))
	}
	return nil
}

func displayRunning(running string) string {
	trimmed := strings.TrimSpace(running)
	if trimmed == "" {
		return "(empty)"
	}
	return trimmed
}
