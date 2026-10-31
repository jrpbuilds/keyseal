package execenv_test

import (
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/execenv"
)

func TestMergeEnvOverridesExistingValues(t *testing.T) {
	merged := execenv.MergeEnv(
		[]string{"APP_ENV=local", "HOME=/tmp/home"},
		map[string]string{"APP_ENV": "production", "DB_HOST": "db"},
	)
	got := strings.Join(merged, "\n")
	if !strings.Contains(got, "APP_ENV=production") {
		t.Fatalf("expected override to win, got %q", got)
	}
	if !strings.Contains(got, "HOME=/tmp/home") {
		t.Fatalf("expected inherited env to remain, got %q", got)
	}
	if !strings.Contains(got, "DB_HOST=db") {
		t.Fatalf("expected injected env key, got %q", got)
	}
}

func TestBuildBaseEnvDefaultInheritsParent(t *testing.T) {
	parent := []string{"PATH=/bin", "HOME=/tmp/home"}
	base, err := execenv.BuildBaseEnv(parent, execenv.Options{})
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	if strings.Join(base, "\n") != strings.Join(parent, "\n") {
		t.Fatalf("expected full parent inheritance, got %q", base)
	}
}

func TestBuildBaseEnvCleanDropsUnrelatedAndReturnsNonNil(t *testing.T) {
	parent := []string{
		"PATH=/bin",
		"AWS_SECRET_ACCESS_KEY=keyseal-test-unrelated",
	}
	base, err := execenv.BuildBaseEnv(parent, execenv.Options{CleanEnv: true})
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	if base == nil {
		t.Fatal("expected non-nil empty base for clean env")
	}
	if len(base) != 0 {
		t.Fatalf("expected empty base, got %q", base)
	}

	merged := execenv.MergeEnv(base, nil)
	if merged == nil {
		t.Fatal("expected non-nil empty merged env")
	}
	if len(merged) != 0 {
		t.Fatalf("expected empty merged env, got %q", merged)
	}
	joined := strings.Join(merged, "\n")
	if strings.Contains(joined, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("unrelated credential leaked into child env: %q", joined)
	}
}

func TestBuildBaseEnvKeepAllowlistExactMatch(t *testing.T) {
	parent := []string{
		"PATH=/bin",
		"PATH_EXTRA=/opt",
		"HOME=/tmp/home",
		"AWS_SECRET_ACCESS_KEY=keyseal-test-unrelated",
	}
	base, err := execenv.BuildBaseEnv(parent, execenv.Options{
		CleanEnv: true,
		KeepEnv:  []string{"PATH", "HOME"},
	})
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	got := strings.Join(base, "\n")
	if !strings.Contains(got, "PATH=/bin") {
		t.Fatalf("expected PATH to be kept, got %q", got)
	}
	if !strings.Contains(got, "HOME=/tmp/home") {
		t.Fatalf("expected HOME to be kept, got %q", got)
	}
	if strings.Contains(got, "PATH_EXTRA") {
		t.Fatalf("prefix match must not keep PATH_EXTRA, got %q", got)
	}
	if strings.Contains(got, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("unrelated credential leaked into allowlist base: %q", got)
	}
}

func TestMergeEnvSecretsOverrideKeptValues(t *testing.T) {
	base, err := execenv.BuildBaseEnv(
		[]string{"APP_ENV=local", "PATH=/bin"},
		execenv.Options{CleanEnv: true, KeepEnv: []string{"APP_ENV", "PATH"}},
	)
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	merged := execenv.MergeEnv(base, map[string]string{"APP_ENV": "production"})
	got := strings.Join(merged, "\n")
	if !strings.Contains(got, "APP_ENV=production") {
		t.Fatalf("expected secret to override kept value, got %q", got)
	}
	if strings.Contains(got, "APP_ENV=local") {
		t.Fatalf("expected local APP_ENV to be replaced, got %q", got)
	}
	if !strings.Contains(got, "PATH=/bin") {
		t.Fatalf("expected kept PATH to remain, got %q", got)
	}
}

func TestBuildBaseEnvKeepsEmptyValue(t *testing.T) {
	base, err := execenv.BuildBaseEnv(
		[]string{"HOME="},
		execenv.Options{CleanEnv: true, KeepEnv: []string{"HOME"}},
	)
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	if len(base) != 1 || base[0] != "HOME=" {
		t.Fatalf("expected empty HOME value to be preserved, got %q", base)
	}
}

func TestBuildBaseEnvMissingKeepNamesFailClosed(t *testing.T) {
	parent := []string{"PATH=/bin", "SECRET_VALUE=must-not-appear"}
	_, err := execenv.BuildBaseEnv(parent, execenv.Options{
		CleanEnv: true,
		KeepEnv:  []string{"PATH", "HOME", "LANG"},
	})
	if err == nil {
		t.Fatal("expected missing keep-env names to fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "HOME") || !strings.Contains(msg, "LANG") {
		t.Fatalf("expected missing names in error, got %q", msg)
	}
	if strings.Contains(msg, "must-not-appear") || strings.Contains(msg, "SECRET_VALUE=") {
		t.Fatalf("error must not include parent values, got %q", msg)
	}
	if strings.Contains(msg, "PATH=/bin") {
		t.Fatalf("error must not include parent values, got %q", msg)
	}
}

func TestBuildBaseEnvRejectsInvalidKeepNames(t *testing.T) {
	cases := []struct {
		name string
		keep []string
	}{
		{name: "empty", keep: []string{""}},
		{name: "whitespace", keep: []string{"   "}},
		{name: "equals", keep: []string{"A=B"}},
		{name: "space", keep: []string{"A B"}},
		{name: "nul", keep: []string{"BAD\x00"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := execenv.BuildBaseEnv(nil, execenv.Options{
				CleanEnv: true,
				KeepEnv:  tc.keep,
			})
			if err == nil {
				t.Fatal("expected invalid keep-env name to fail")
			}
			if !strings.Contains(err.Error(), "invalid keep-env variable name") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildBaseEnvKeepRequiresClean(t *testing.T) {
	_, err := execenv.BuildBaseEnv(
		[]string{"PATH=/bin"},
		execenv.Options{KeepEnv: []string{"PATH"}},
	)
	if err == nil {
		t.Fatal("expected --keep-env without --clean-env to fail")
	}
	if !strings.Contains(err.Error(), "--keep-env requires --clean-env") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildBaseEnvDeduplicatesKeepNames(t *testing.T) {
	base, err := execenv.BuildBaseEnv(
		[]string{"PATH=/bin"},
		execenv.Options{CleanEnv: true, KeepEnv: []string{"PATH", " PATH ", "PATH"}},
	)
	if err != nil {
		t.Fatalf("BuildBaseEnv returned error: %v", err)
	}
	if len(base) != 1 || base[0] != "PATH=/bin" {
		t.Fatalf("expected a single PATH entry, got %q", base)
	}
}
