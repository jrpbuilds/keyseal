package doctor

import (
	"fmt"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/repo"
)

const checkNameScopeSelection = "scope selection"

// documentFilter decides which logical documents are in scope for a doctor or
// verify run. When active is false, every document is included (full mode).
type documentFilter struct {
	active  bool
	include []string
	exclude []string
	info    ScopeInfo
}

// resolveDocumentFilter turns CLI Options into a documentFilter.
// Conflicting selectors, unknown profiles, and invalid globs return a failed
// scope-selection check. Callers should stop decrypt work after that failure.
func resolveDocumentFilter(opts Options, cfg config.Config) (documentFilter, *CheckResult) {
	selectorCount := 0
	if len(opts.ScopePatterns) > 0 {
		selectorCount++
	}
	if strings.TrimSpace(opts.Profile) != "" {
		selectorCount++
	}
	if strings.TrimSpace(opts.IdentityProfile) != "" {
		selectorCount++
	}
	if selectorCount > 1 {
		return documentFilter{}, scopeSelectionFail(
			"Conflicting document selectors",
			[]string{"Use only one of --scope, --profile, or --identity-profile."},
			[]string{"Rerun with a single selector."},
		)
	}
	if selectorCount == 0 {
		return documentFilter{info: ScopeInfo{Mode: ScopeModeFull}}, nil
	}

	if len(opts.ScopePatterns) > 0 {
		return filterFromScopePatterns(opts.ScopePatterns)
	}
	if name := strings.TrimSpace(opts.IdentityProfile); name != "" {
		return filterFromAccessProfile(name, ScopeModeIdentity, cfg)
	}
	return filterFromAccessProfile(strings.TrimSpace(opts.Profile), ScopeModeProfile, cfg)
}

func filterFromScopePatterns(patterns []string) (documentFilter, *CheckResult) {
	for _, pattern := range patterns {
		if err := repo.ValidateLogicalGlob(pattern); err != nil {
			return documentFilter{}, scopeSelectionFail(
				"Invalid --scope pattern",
				[]string{err.Error()},
				[]string{"Pass logical-name globs such as production/**."},
			)
		}
	}
	copied := append([]string(nil), patterns...)
	return documentFilter{
		active:  true,
		include: copied,
		info: ScopeInfo{
			Mode:     ScopeModeGlob,
			Patterns: append([]string(nil), patterns...),
		},
	}, nil
}

func filterFromAccessProfile(name string, mode ScopeMode, cfg config.Config) (documentFilter, *CheckResult) {
	profile, ok := cfg.AccessProfiles[name]
	if !ok {
		details := []string{
			fmt.Sprintf("access_profiles.%s is not defined in keyseal.yaml.", name),
		}
		if _, renderOK := cfg.Profiles[name]; renderOK {
			details = append(details, fmt.Sprintf(
				"%q exists under profiles (render profiles), which is separate from access_profiles.",
				name,
			))
		}
		return documentFilter{}, scopeSelectionFail(
			fmt.Sprintf("Unknown access profile %q", name),
			details,
			[]string{"Define the access profile in keyseal.yaml under access_profiles, or choose an existing name."},
		)
	}
	return documentFilter{
		active:  true,
		include: append([]string(nil), profile.Include...),
		exclude: append([]string(nil), profile.Exclude...),
		info: ScopeInfo{
			Mode:    mode,
			Profile: name,
		},
	}, nil
}

func scopeSelectionFail(summary string, details, remediation []string) *CheckResult {
	return &CheckResult{
		Name:        checkNameScopeSelection,
		Status:      StatusFail,
		Severity:    SeverityError,
		Summary:     summary,
		Details:     details,
		Remediation: remediation,
	}
}

// includes reports whether logical belongs in the active document set.
func (f documentFilter) includes(logical string) (bool, error) {
	if !f.active {
		return true, nil
	}
	return config.AccessProfile{
		Include: f.include,
		Exclude: f.exclude,
	}.Matches(logical)
}

// requestedScopeInfo records the selector the caller asked for even when
// keyseal.yaml could not be loaded and the filter was never applied.
func requestedScopeInfo(opts Options) ScopeInfo {
	switch {
	case len(opts.ScopePatterns) > 0:
		return ScopeInfo{
			Mode:     ScopeModeGlob,
			Patterns: append([]string(nil), opts.ScopePatterns...),
		}
	case strings.TrimSpace(opts.IdentityProfile) != "":
		return ScopeInfo{
			Mode:    ScopeModeIdentity,
			Profile: strings.TrimSpace(opts.IdentityProfile),
		}
	case strings.TrimSpace(opts.Profile) != "":
		return ScopeInfo{
			Mode:    ScopeModeProfile,
			Profile: strings.TrimSpace(opts.Profile),
		}
	default:
		return ScopeInfo{Mode: ScopeModeFull}
	}
}
