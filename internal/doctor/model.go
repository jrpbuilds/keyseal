// Package doctor performs repository health checks without exposing secret data.
package doctor

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Status describes the outcome of a single doctor check.
type Status string

const (
	StatusOK          Status = "ok"
	StatusWarn        Status = "warn"
	StatusFail        Status = "fail"
	StatusSkip        Status = "skip"
	StatusExcluded    Status = "excluded"
	StatusUnavailable Status = "unavailable"
)

// Severity describes how urgent a doctor finding is.
type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityWarning       Severity = "warning"
	SeverityError         Severity = "error"
)

// ScopeMode identifies how doctor/verify selected documents.
type ScopeMode string

const (
	ScopeModeFull     ScopeMode = "full"
	ScopeModeGlob     ScopeMode = "glob"
	ScopeModeProfile  ScopeMode = "profile"
	ScopeModeIdentity ScopeMode = "identity"
)

// ScopeInfo is the machine-readable document selection for a doctor/verify run.
type ScopeInfo struct {
	Mode     ScopeMode `json:"mode"`
	Profile  string    `json:"profile,omitempty"`
	Patterns []string  `json:"patterns,omitempty"`
}

// Options controls document selection for doctor and verify.
// The zero value is full-repository mode. At most one of ScopePatterns,
// Profile, or IdentityProfile may be set by CLI callers.
type Options struct {
	ScopePatterns   []string // --scope values (OR-ed logical-name globs)
	Profile         string   // --profile access_profiles name
	IdentityProfile string   // --identity-profile access_profiles name
}

// CheckResult is one structured doctor finding.
type CheckResult struct {
	Name        string   `json:"name"`
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Details     []string `json:"details,omitempty"`
	Remediation []string `json:"remediation,omitempty"`
}

// Counts summarizes the number of checks in each status bucket.
type Counts struct {
	OK          int `json:"ok"`
	Warn        int `json:"warn"`
	Fail        int `json:"fail"`
	Skip        int `json:"skip"`
	Excluded    int `json:"excluded"`
	Unavailable int `json:"unavailable"`
	Total       int `json:"total"`
}

// Result contains every doctor check, the computed summary counts, and the
// active document scope.
type Result struct {
	Checks []CheckResult `json:"checks"`
	Scope  ScopeInfo     `json:"-"`
}

// Add appends a check result.
func (r *Result) Add(check CheckResult) {
	r.Checks = append(r.Checks, check)
}

// HasFailures reports whether any doctor check failed.
// Unavailable findings are intentionally excluded so existing callers that
// treat HasFailures as fail-only keep their meaning.
func (r Result) HasFailures() bool {
	return r.Counts().Fail > 0
}

// HasUnavailable reports whether any identity-availability check failed.
func (r Result) HasUnavailable() bool {
	return r.Counts().Unavailable > 0
}

// HasWarnings reports whether any doctor check produced a warning.
func (r Result) HasWarnings() bool {
	return r.Counts().Warn > 0
}

// DoctorFailed reports whether the doctor CLI should exit non-zero.
func (r Result) DoctorFailed() bool {
	return r.HasFailures() || r.HasUnavailable()
}

// VerifyPassed reports whether the result is clean enough for strict CI
// verification, where failures, warnings, and unavailable identities are
// release blockers. Exclusions do not fail verify.
func (r Result) VerifyPassed() bool {
	counts := r.Counts()
	return counts.Fail == 0 && counts.Warn == 0 && counts.Unavailable == 0
}

// Counts computes the current per-status totals.
func (r Result) Counts() Counts {
	var counts Counts
	for _, check := range r.Checks {
		switch check.Status {
		case StatusOK:
			counts.OK++
		case StatusWarn:
			counts.Warn++
		case StatusFail:
			counts.Fail++
		case StatusSkip:
			counts.Skip++
		case StatusExcluded:
			counts.Excluded++
		case StatusUnavailable:
			counts.Unavailable++
		}
	}
	counts.Total = len(r.Checks)
	return counts
}

// RenderText formats the doctor report for humans.
func (r Result) RenderText() string {
	counts := r.Counts()
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "doctor summary: %d ok, %d warning(s), %d failure(s), %d skipped", counts.OK, counts.Warn, counts.Fail, counts.Skip)
	if counts.Excluded > 0 {
		fmt.Fprintf(buf, ", %d excluded", counts.Excluded)
	}
	if counts.Unavailable > 0 {
		fmt.Fprintf(buf, ", %d unavailable", counts.Unavailable)
	}
	buf.WriteByte('\n')
	for _, check := range r.Checks {
		fmt.Fprintf(buf, "[%s] %s: %s\n", displayStatus(check.Status), check.Name, check.Summary)
		for _, detail := range check.Details {
			fmt.Fprintf(buf, "  - %s\n", detail)
		}
		for _, remediation := range check.Remediation {
			fmt.Fprintf(buf, "  Fix: %s\n", remediation)
		}
	}
	return buf.String()
}

// RenderVerifyText formats a concise strict-verification report for CI logs.
func (r Result) RenderVerifyText() string {
	counts := r.Counts()
	buf := &bytes.Buffer{}
	if r.VerifyPassed() {
		fmt.Fprintf(buf, "verify passed: %d check(s) ok", counts.OK)
		if counts.Skip > 0 {
			fmt.Fprintf(buf, ", %d skipped", counts.Skip)
		}
		if counts.Excluded > 0 {
			fmt.Fprintf(buf, ", %d excluded", counts.Excluded)
		}
		buf.WriteByte('\n')
		return buf.String()
	}

	fmt.Fprintf(buf, "verify failed: %d failure(s), %d warning(s), %d skipped", counts.Fail, counts.Warn, counts.Skip)
	if counts.Excluded > 0 {
		fmt.Fprintf(buf, ", %d excluded", counts.Excluded)
	}
	if counts.Unavailable > 0 {
		fmt.Fprintf(buf, ", %d unavailable", counts.Unavailable)
	}
	buf.WriteByte('\n')
	for _, check := range r.Checks {
		if check.Status == StatusOK || check.Status == StatusExcluded {
			continue
		}
		fmt.Fprintf(buf, "[%s] %s: %s\n", displayStatus(check.Status), check.Name, check.Summary)
		for _, detail := range check.Details {
			fmt.Fprintf(buf, "  - %s\n", detail)
		}
		for _, remediation := range check.Remediation {
			fmt.Fprintf(buf, "  Fix: %s\n", remediation)
		}
	}
	return buf.String()
}

// RenderJSON formats the doctor report for machine-readable consumers.
func (r Result) RenderJSON() ([]byte, error) {
	payload := struct {
		Summary Counts        `json:"summary"`
		Scope   ScopeInfo     `json:"scope"`
		Checks  []CheckResult `json:"checks"`
	}{
		Summary: r.Counts(),
		Scope:   r.scopeOrFull(),
		Checks:  r.Checks,
	}
	return json.MarshalIndent(payload, "", "  ")
}

// RenderVerifyJSON formats strict verification results for machine-readable CI
// consumers while preserving the doctor summary and checks shape.
func (r Result) RenderVerifyJSON() ([]byte, error) {
	payload := struct {
		Verified bool          `json:"verified"`
		Summary  Counts        `json:"summary"`
		Scope    ScopeInfo     `json:"scope"`
		Checks   []CheckResult `json:"checks"`
	}{
		Verified: r.VerifyPassed(),
		Summary:  r.Counts(),
		Scope:    r.scopeOrFull(),
		Checks:   r.Checks,
	}
	return json.MarshalIndent(payload, "", "  ")
}

func (r Result) scopeOrFull() ScopeInfo {
	if r.Scope.Mode == "" {
		return ScopeInfo{Mode: ScopeModeFull}
	}
	return r.Scope
}

func displayStatus(status Status) string {
	switch status {
	case StatusOK:
		return "OK"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	case StatusSkip:
		return "SKIP"
	case StatusExcluded:
		return "EXCLUDED"
	case StatusUnavailable:
		return "UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}
