package versionreq_test

import (
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/versionreq"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "release with v", input: "v1.1.0", want: "1.1.0"},
		{name: "release without v", input: "1.1.0", want: "1.1.0"},
		{name: "git describe", input: "v1.1.0-6-gfdac110", want: "1.1.0+6.gfdac110"},
		{name: "git describe dirty", input: "1.1.0-6-gfdac110-dirty", want: "1.1.0+6.gfdac110.dirty"},
		{name: "prerelease rc kept", input: "1.2.0-rc.1", want: "1.2.0-rc.1"},
		{name: "prerelease beta kept", input: "v1.2.0-beta.1", want: "1.2.0-beta.1"},
		{name: "dev rejected", input: "dev", wantErr: "not a stamped semantic version"},
		{name: "ci rejected", input: "ci", wantErr: "not a stamped semantic version"},
		{name: "empty rejected", input: "  ", wantErr: "empty"},
		{name: "garbage rejected", input: "not-a-version", wantErr: "not a stamped semantic version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := versionreq.Normalize(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Normalize(%q) succeeded with %q, want error containing %q", tt.input, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalize(%q) error %q, want substring %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseConstraint(t *testing.T) {
	t.Parallel()

	if _, err := versionreq.ParseConstraint(">=1.1.0"); err != nil {
		t.Fatalf("ParseConstraint valid: %v", err)
	}
	if _, err := versionreq.ParseConstraint("  "); err == nil {
		t.Fatal("ParseConstraint empty: expected error")
	}
	if _, err := versionreq.ParseConstraint("not a constraint !!!"); err == nil {
		t.Fatal("ParseConstraint malformed: expected error")
	}
	if err := versionreq.Check("1.0.0", "  "); err == nil || !strings.Contains(err.Error(), "requirements.keyseal") {
		t.Fatalf("Check empty constraint error = %v", err)
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		running    string
		constraint string
		wantErr    string
	}{
		{name: "older fails", running: "v0.2.0", constraint: ">=1.1.0", wantErr: "does not satisfy"},
		{name: "matching passes", running: "v1.1.0", constraint: ">=1.1.0"},
		{name: "newer passes", running: "v1.2.0", constraint: ">=1.1.0"},
		{name: "prerelease below release", running: "1.1.0-rc.1", constraint: ">=1.1.0", wantErr: "does not satisfy"},
		{name: "git describe satisfies base", running: "v1.1.0-6-gfdac110", constraint: ">=1.1.0"},
		{name: "dev fails closed", running: "dev", constraint: ">=1.1.0", wantErr: "not a stamped semantic version"},
		{name: "malformed running", running: "bogus", constraint: ">=1.1.0", wantErr: "not a stamped semantic version"},
		{name: "malformed constraint", running: "v1.1.0", constraint: ">>>>", wantErr: "not a valid version constraint"},
		{name: "error names both sides", running: "v0.2.0", constraint: ">=1.1.0", wantErr: "v0.2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := versionreq.Check(tt.running, tt.constraint)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Check(%q, %q) unexpected error: %v", tt.running, tt.constraint, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check(%q, %q) succeeded, want error containing %q", tt.running, tt.constraint, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Check(%q, %q) error %q, want substring %q", tt.running, tt.constraint, err, tt.wantErr)
			}
			if tt.wantErr == "does not satisfy" || tt.wantErr == "v0.2.0" {
				if !strings.Contains(err.Error(), tt.constraint) {
					t.Fatalf("error %q missing required constraint %q", err, tt.constraint)
				}
			}
		})
	}
}
