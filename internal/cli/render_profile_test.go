package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProfilesKeysealConfig overwrites keyseal.yaml with a valid base config
// whose profiles section is the given YAML fragment.
func writeProfilesKeysealConfig(t *testing.T, root, profiles string) {
	t.Helper()
	body := `version: 1

repository:
  root: .
  encrypted_extension: .enc.yaml

sops:
  binary: sops
  age_binary: age
  age_key_file: ~/.config/sops/age/keys.txt

git:
  auto_commit: false

defaults:
  output_format: dotenv
  output_dir: /run/secrets
  file_mode: "0600"

validation:
  require_values: true
  key_pattern: "^[A-Z0-9_]+$"

profiles:
` + profiles
	writeCLIFile(t, filepath.Join(root, "keyseal.yaml"), body)
}

// seedRenderProfileRepo wires a decrypt-capable repo with one valid encrypted
// fixture and the given profiles block.
func seedRenderProfileRepo(t *testing.T, profiles string) string {
	t.Helper()
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	writeProfilesKeysealConfig(t, repoRoot, profiles)
	return repoRoot
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("expected %s mode %o, got %o", path, want, got)
	}
}

// TestRenderProfile verifies the happy path: both renders are written with the
// right content and owner-only mode, and empty format/mode fields fall back to
// cfg.Defaults.
func TestRenderProfile(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: json
        out: out/app.json
        mode: "0600"
      - name: merged
        inputs:
          - production/platform/app
        out: out/merged.env
`)
	writeEncryptedFixture(t, repoRoot, "staging/platform/app.enc.yaml")

	output, err := runRootCommand(t, repoRoot, "render", "--profile", "prod")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, `rendered 2 profile output(s) for profile "prod"`) {
		t.Fatalf("unexpected render output: %q", output)
	}

	appBody, err := os.ReadFile(filepath.Join(repoRoot, "out", "app.json"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(appBody), `"APP_ENV": "production"`) {
		t.Fatalf("expected json render content, got %q", string(appBody))
	}
	assertFileMode(t, filepath.Join(repoRoot, "out", "app.json"), 0o600)

	// Second render omits format/mode: both must fall back to cfg.Defaults.
	mergedBody, err := os.ReadFile(filepath.Join(repoRoot, "out", "merged.env"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(mergedBody), `APP_ENV="production"`) {
		t.Fatalf("expected dotenv render content from defaults fallback, got %q", string(mergedBody))
	}
	assertFileMode(t, filepath.Join(repoRoot, "out", "merged.env"), 0o600)
}

// TestRenderProfileUnsafeModeRequiresForce verifies the owner-only write
// contract for profile renders, matching explicit render.
func TestRenderProfileUnsafeModeRequiresForce(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/app.env
        mode: "0644"
`)

	if _, err := runRootCommand(t, repoRoot, "render", "--profile", "prod"); err == nil {
		t.Fatal("expected unsafe profile mode to be rejected without --force")
	}
	if _, statErr := os.Stat(filepath.Join(repoRoot, "out", "app.env")); !os.IsNotExist(statErr) {
		t.Fatal("expected no output file after unsafe-mode rejection")
	}

	if _, err := runRootCommand(t, repoRoot, "render", "--profile", "prod", "--force"); err != nil {
		t.Fatalf("expected --force to write the profile output: %v", err)
	}
	assertFileMode(t, filepath.Join(repoRoot, "out", "app.env"), 0o644)
}

// TestRenderProfileUnsafeModeNoPartialWrite verifies all-or-nothing execution:
// when a later render has an unsafe mode, the whole run fails during Phase A
// and no earlier render's output is written either.
func TestRenderProfileUnsafeModeNoPartialWrite(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/first.env
        mode: "0600"
      - name: insecure
        inputs:
          - production/platform/app
        out: out/second.env
        mode: "0644"
`)

	_, err := runRootCommand(t, repoRoot, "render", "--profile", "prod")
	if err == nil {
		t.Fatal("expected unsafe mode on a later render to fail the whole profile run")
	}
	if !strings.Contains(err.Error(), "mode 0644 is not owner-only; use --force to override") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, rel := range []string{"out/first.env", "out/second.env"} {
		if _, statErr := os.Stat(filepath.Join(repoRoot, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("expected %s to not exist after unsafe-mode failure (no partial writes)", rel)
		}
	}
}

// TestRenderProfileDryRunFailsOnUnsafeMode verifies dry-run applies the same
// Phase A mode-safety pre-flight, so it fails on a profile whose real run
// would be rejected instead of printing a successful plan.
func TestRenderProfileDryRunFailsOnUnsafeMode(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/first.env
        mode: "0600"
      - name: insecure
        inputs:
          - production/platform/app
        out: out/second.env
        mode: "0644"
`)

	if _, err := runRootCommand(t, repoRoot, "render", "--profile", "prod", "--dry-run"); err == nil {
		t.Fatal("expected dry-run to fail on an unsafe mode")
	}
	for _, rel := range []string{"out/first.env", "out/second.env"} {
		if _, statErr := os.Stat(filepath.Join(repoRoot, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("expected %s to not exist after failed dry-run", rel)
		}
	}
}

// TestRenderProfileMissingInputAborts verifies decrypt-before-write: when the
// second render's input is missing, the whole run fails and no output file
// from either render exists.
func TestRenderProfileMissingInputAborts(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/one.env
      - name: broken
        inputs:
          - staging/platform/missing
        out: out/two.env
`)

	_, err := runRootCommand(t, repoRoot, "render", "--profile", "prod")
	if err == nil {
		t.Fatal("expected profile render to fail on the missing input")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, rel := range []string{"out/one.env", "out/two.env"} {
		if _, statErr := os.Stat(filepath.Join(repoRoot, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("expected %s to not exist after aborted run", rel)
		}
	}
}

// TestRenderProfileDryRunNoLeak verifies --dry-run validates all inputs, prints
// plan metadata only, writes nothing, and never exposes decrypted values.
func TestRenderProfileDryRunNoLeak(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: dotenv
        out: out/app.env
        mode: "0600"
      - name: merged
        inputs:
          - production/platform/app
        format: json
        out: out/merged.json
        mode: "0600"
`)

	output, err := runRootCommand(t, repoRoot, "render", "--profile", "prod", "--dry-run")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}

	for _, want := range []string{
		`dry-run: profile "prod" would render 2 output(s)`,
		`render "app"`,
		`inputs: production/platform/app`,
		`format: dotenv`,
		`out: out/app.env`,
		`mode: 0600`,
		`render "merged"`,
		`format: json`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected plan to contain %q, got %q", want, output)
		}
	}

	// Decrypted values must not appear: neither dotenv nor JSON renderings.
	for _, leaked := range []string{`APP_ENV="`, `"APP_ENV"`, `DB_HOST`} {
		if strings.Contains(output, leaked) {
			t.Fatalf("dry-run output leaked decrypted content %q: %q", leaked, output)
		}
	}

	for _, rel := range []string{"out/app.env", "out/merged.json"} {
		if _, statErr := os.Stat(filepath.Join(repoRoot, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("expected dry-run to not write %s", rel)
		}
	}
}

// TestRenderProfileDryRunStillSurfacesInputErrors verifies a dry-run still
// resolves and validates inputs and fails without writing anything.
func TestRenderProfileDryRunStillSurfacesInputErrors(t *testing.T) {
	repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - staging/platform/missing
        out: out/app.env
`)

	if _, err := runRootCommand(t, repoRoot, "render", "--profile", "prod", "--dry-run"); err == nil {
		t.Fatal("expected dry-run to fail on the missing input")
	}
	if _, statErr := os.Stat(filepath.Join(repoRoot, "out", "app.env")); !os.IsNotExist(statErr) {
		t.Fatal("expected no output file after failed dry-run")
	}
}

// TestRenderProfileLoadExitCodes verifies profile renders map decrypt and
// invalid-document failures to the same stable exit codes as explicit render.
func TestRenderProfileLoadExitCodes(t *testing.T) {
	t.Run("decrypt failure exits 3", func(t *testing.T) {
		repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/app.env
`)
		wrongKeyPath := filepath.Join(repoRoot, "wrong-age.key")
		if err := os.WriteFile(wrongKeyPath, []byte(cliSecondAgeKey), 0o600); err != nil {
			t.Fatalf("write wrong age key: %v", err)
		}
		t.Setenv("SOPS_AGE_KEY_FILE", wrongKeyPath)

		_, err := runRootCommand(t, repoRoot, "render", "--profile", "prod")
		if err == nil {
			t.Fatal("expected decrypt failure")
		}
		if exitCodeOf(t, err) != 3 {
			t.Fatalf("expected exit code 3, got %d (%v)", exitCodeOf(t, err), err)
		}
		if !strings.Contains(err.Error(), `profiles.prod.renders[0] ("app")`) {
			t.Fatalf("expected profile label in error, got %q", err.Error())
		}
		if _, statErr := os.Stat(filepath.Join(repoRoot, "out", "app.env")); !os.IsNotExist(statErr) {
			t.Fatal("expected no output file after decrypt failure")
		}
	})

	t.Run("invalid document exits 4", func(t *testing.T) {
		realSOPSPath(t)
		repoRoot := t.TempDir()
		writeTestConfig(t, repoRoot)
		configureLibraryDecryptFixture(t, repoRoot)
		writeProfilesKeysealConfig(t, repoRoot, `  prod:
    renders:
      - name: bad
        inputs:
          - production/platform/bad
        out: out/bad.env
`)
		putEncryptedInvalidKind(t, repoRoot, "production/platform/bad", "ksl-profile-invalid-kind")

		_, err := runRootCommand(t, repoRoot, "render", "--profile", "prod")
		if err == nil {
			t.Fatal("expected invalid document failure")
		}
		if exitCodeOf(t, err) != 4 {
			t.Fatalf("expected exit code 4, got %d (%v)", exitCodeOf(t, err), err)
		}
		if !strings.Contains(err.Error(), `profiles.prod.renders[0] ("bad")`) {
			t.Fatalf("expected profile label in error, got %q", err.Error())
		}
		if strings.Contains(err.Error(), "ksl-profile-invalid-kind") {
			t.Fatalf("invalid-document error leaked sentinel value: %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(repoRoot, "out", "bad.env")); !os.IsNotExist(statErr) {
			t.Fatal("expected no output file after invalid document failure")
		}
	})
}

// TestRenderProfileFlagConflicts verifies the --profile path rejects
// conflicting flags and args before any work, and that --dry-run without
// --profile is rejected.
func TestRenderProfileFlagConflicts(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "positional arg with profile",
			args:    []string{"render", "--profile", "prod", "production/platform/app"},
			wantErr: "positional logical names cannot be combined with --profile",
		},
		{
			name:    "stdout with profile",
			args:    []string{"render", "--profile", "prod", "--stdout"},
			wantErr: "--stdout cannot be combined with --profile",
		},
		{
			name:    "format with profile",
			args:    []string{"render", "--profile", "prod", "--format", "json"},
			wantErr: "--format cannot be combined with --profile",
		},
		{
			name:    "out with profile",
			args:    []string{"render", "--profile", "prod", "--out", "out/x.env"},
			wantErr: "--out cannot be combined with --profile",
		},
		{
			name:    "mode with profile",
			args:    []string{"render", "--profile", "prod", "--mode", "0600"},
			wantErr: "--mode cannot be combined with --profile",
		},
		{
			name:    "select with profile",
			args:    []string{"render", "--profile", "prod", "--select", "APP_ENV"},
			wantErr: "--select cannot be combined with --profile",
		},
		{
			name:    "require-all with profile",
			args:    []string{"render", "--profile", "prod", "--require-all"},
			wantErr: "--require-all cannot be combined with --profile",
		},
		{
			name:    "dry-run without profile",
			args:    []string{"render", "production/platform/app", "--dry-run"},
			wantErr: "--dry-run is only supported together with --profile",
		},
		{
			name:    "unknown profile lists available names",
			args:    []string{"render", "--profile", "nope"},
			wantErr: `profile "nope" does not exist in keyseal.yaml; available profiles: default, prod`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoRoot := seedRenderProfileRepo(t, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: out/app.env
`)
			_, err := runRootCommand(t, repoRoot, tt.args...)
			if err == nil {
				t.Fatalf("expected %v to fail", tt.args)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to contain %q, got %q", tt.wantErr, err.Error())
			}
			if _, statErr := os.Stat(filepath.Join(repoRoot, "out")); !os.IsNotExist(statErr) {
				t.Fatalf("expected no output directory after %v", tt.args)
			}
		})
	}
}

// TestRenderExplicitUnaffected is the regression guard for the preserved
// explicit render workflow, including the behavior correction that a malformed
// profile now fails config load for the explicit path too.
func TestRenderExplicitUnaffected(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")

	t.Run("explicit stdout render still works", func(t *testing.T) {
		output, err := runRootCommand(t, repoRoot, "render", "production/platform/app", "--stdout")
		if err != nil {
			t.Fatalf("runRootCommand returned error: %v", err)
		}
		if !strings.Contains(output, `APP_ENV="production"`) {
			t.Fatalf("expected explicit stdout render output, got %q", output)
		}
	})

	t.Run("explicit out render still works", func(t *testing.T) {
		outPath := filepath.Join(repoRoot, "runtime", "app.env")
		if _, err := runRootCommand(t, repoRoot, "render", "production/platform/app", "--out", outPath, "--mode", "0600"); err != nil {
			t.Fatalf("runRootCommand returned error: %v", err)
		}
		body, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		if !strings.Contains(string(body), `APP_ENV="production"`) {
			t.Fatalf("expected explicit out render content, got %q", string(body))
		}
		assertFileMode(t, outPath, 0o600)
	})

	t.Run("malformed profile fails config load for explicit render", func(t *testing.T) {
		writeProfilesKeysealConfig(t, repoRoot, `  prod:
    renders:
      - name: broken
        inputs: []
        out: out/broken.env
`)
		_, err := runRootCommand(t, repoRoot, "render", "production/platform/app", "--stdout")
		if err == nil {
			t.Fatal("expected explicit render to fail config load when a profile is malformed")
		}
		if !strings.Contains(err.Error(), "inputs must list at least one logical secret name") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestVerifyFailsOnProfile verifies verify inherits the doctor profile checks:
// it fails on invalid profiles and missing profile inputs, and passes with
// clean profiles.
func TestVerifyFailsOnProfile(t *testing.T) {
	t.Run("invalid profile fails verify", func(t *testing.T) {
		repoRoot := seedVerifyRepo(t)
		writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
		writeProfilesKeysealConfig(t, repoRoot, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: xml
        out: /run/secrets/app.env
        mode: "0600"
`)

		output, err := runRootCommand(t, repoRoot, "verify")
		if err == nil {
			t.Fatal("expected verify to fail on invalid profile")
		}
		if !strings.Contains(output, "[FAIL]") || !strings.Contains(output, `profile "prod" render "app"`) {
			t.Fatalf("expected profile render failure in verify output, got %q", output)
		}
	})

	t.Run("missing profile input fails verify", func(t *testing.T) {
		repoRoot := seedVerifyRepo(t)
		writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
		writeProfilesKeysealConfig(t, repoRoot, `  prod:
    renders:
      - name: app
        inputs:
          - staging/platform/missing
        out: /run/secrets/app.env
        mode: "0600"
`)

		output, err := runRootCommand(t, repoRoot, "verify")
		if err == nil {
			t.Fatal("expected verify to fail on missing profile input")
		}
		if !strings.Contains(output, "is missing at") {
			t.Fatalf("expected missing-input detail in verify output, got %q", output)
		}
	})

	t.Run("clean profiles pass verify", func(t *testing.T) {
		repoRoot := seedVerifyRepo(t)
		writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
		writeProfilesKeysealConfig(t, repoRoot, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: json
        out: `+filepath.ToSlash(filepath.Join(repoRoot, "out", "app.env"))+`
        mode: "0600"
`)

		output, err := runRootCommand(t, repoRoot, "verify")
		if err != nil {
			t.Fatalf("expected verify to pass with clean profiles: %v\noutput=%s", err, output)
		}
		if !strings.Contains(output, "verify passed:") {
			t.Fatalf("expected verify pass output, got %q", output)
		}
	})
}
