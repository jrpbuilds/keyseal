package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
)

func TestRootVersionFlag(t *testing.T) {
	restoreBuildInfo(t, "v0.2.0", "abc1234", "2026-04-19T13:10:00Z")

	output, err := runRootCommand(t, t.TempDir(), "--version")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if output != "keyseal v0.2.0 (abc1234)\n" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestVersionCommand(t *testing.T) {
	restoreBuildInfo(t, "v0.2.0", "abc1234", "2026-04-19T13:10:00Z")

	output, err := runRootCommand(t, t.TempDir(), "version")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	want := "keyseal v0.2.0 (abc1234)\ntag: v0.2.0\ncommit: abc1234\nbuilt: 2026-04-19T13:10:00Z\n"
	if output != want {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestVersionCommandShort(t *testing.T) {
	restoreBuildInfo(t, "v0.2.0", "abc1234", "2026-04-19T13:10:00Z")

	output, err := runRootCommand(t, t.TempDir(), "version", "--short")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if strings.TrimSpace(output) != "v0.2.0" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestVersionCommandCheckSatisfied(t *testing.T) {
	restoreBuildInfo(t, "v1.2.0", "abc1234", "2026-04-19T13:10:00Z")

	output, err := runRootCommand(t, t.TempDir(), "version", "--check", ">=1.1.0")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if strings.TrimSpace(output) != "ok: v1.2.0 satisfies >=1.1.0" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestVersionCommandCheckFails(t *testing.T) {
	restoreBuildInfo(t, "v0.2.0", "abc1234", "2026-04-19T13:10:00Z")

	_, err := runRootCommand(t, t.TempDir(), "version", "--check", ">=1.1.0")
	if err == nil {
		t.Fatal("expected version --check to fail for older binary")
	}
	msg := err.Error()
	if !strings.Contains(msg, "v0.2.0") || !strings.Contains(msg, ">=1.1.0") {
		t.Fatalf("error should name running and required versions, got: %v", err)
	}
}

func TestVersionCommandCheckConflictsWithShort(t *testing.T) {
	restoreBuildInfo(t, "v1.2.0", "abc1234", "2026-04-19T13:10:00Z")

	_, err := runRootCommand(t, t.TempDir(), "version", "--check", ">=1.1.0", "--short")
	if err == nil || !strings.Contains(err.Error(), "--check and --short") {
		t.Fatalf("expected conflict error, got: %v", err)
	}
}

func TestVersionAvailableWithStrictRequirement(t *testing.T) {
	restoreBuildInfo(t, "v0.2.0", "abc1234", "2026-04-19T13:10:00Z")

	dir := t.TempDir()
	writeFileForCLI(t, filepath.Join(dir, "keyseal.yaml"), "version: 1\nrepository:\n  root: .\nrequirements:\n  keyseal: \">=1.1.0\"\n")

	output, err := runRootCommand(t, dir, "version", "--short")
	if err != nil {
		t.Fatalf("version must remain available when repo requires newer binary: %v", err)
	}
	if strings.TrimSpace(output) != "v0.2.0" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func restoreBuildInfo(t *testing.T, version, commit, date string) {
	t.Helper()

	origVersion, origCommit, origDate := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	buildinfo.Version = version
	buildinfo.Commit = commit
	buildinfo.Date = date
	t.Cleanup(func() {
		buildinfo.Version = origVersion
		buildinfo.Commit = origCommit
		buildinfo.Date = origDate
	})
}
